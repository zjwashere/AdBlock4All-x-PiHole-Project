/**
 * Pi-hole Dashboard Proxy Server — Pi-hole v6 compatible
 *
 * Pi-hole v6 uses session-based auth:
 *   POST /api/auth  { password }  →  { session: { sid, validity } }
 *   All subsequent requests include header:  X-FTL-SID: <sid>
 *
 * This proxy:
 *   1. Reads the password from /etc/pihole/pihole.toml  (or env var PIHOLE_PASSWORD)
 *   2. Authenticates once and caches the session SID
 *   3. Re-authenticates automatically when the session expires or is rejected
 *   4. Serves the dashboard on port 3000
 *
 * Setup:
 *   npm install express
 *   sudo node server.js        (sudo needed to read /etc/pihole/pihole.toml)
 *
 * Override password without touching the config file:
 *   sudo PIHOLE_PASSWORD=mypassword node server.js
 */

const express = require('express');
const fs      = require('fs');
const path    = require('path');
const http    = require('http');

const app  = express();
const PORT = 3000;

// Pi-hole v6 API base (same machine, always localhost)
const PIHOLE_BASE   = 'http://127.0.0.1';
const PIHOLE_API    = `${PIHOLE_BASE}/api`;

// DHCP leases file (still the same in v6)
const DHCP_LEASES_FILE = '/etc/pihole/dhcp.leases';

// Pi-hole v6 config file
const PIHOLE_TOML = '/etc/pihole/pihole.toml';

// ─── Password reader ──────────────────────────────────────────────────────────
// Priority: PIHOLE_PASSWORD env var → pihole.toml → empty string (no password set)

function readPassword() {
  // 1. Environment variable override
  if (process.env.PIHOLE_PASSWORD) {
    console.log('[auth] Using password from PIHOLE_PASSWORD env var');
    return process.env.PIHOLE_PASSWORD;
  }

  // 2. Parse pihole.toml
  // The password hash lives under [webserver.api] as app_sudo or the plain
  // password is never stored — Pi-hole stores a bcrypt hash.
  // HOWEVER: we don't need the hash. We need the PLAIN password the user set.
  // Pi-hole v6 does NOT store the plain password anywhere on disk (by design).
  //
  // Solution: store the plain password in a separate local file that only
  // root can read, OR pass it via the environment variable above.
  //
  // We also check for a simple password file at /etc/pihole/dashboard.password
  const passwordFile = '/etc/pihole/dashboard.password';
  try {
    const pw = fs.readFileSync(passwordFile, 'utf8').trim();
    if (pw) {
      console.log('[auth] Using password from', passwordFile);
      return pw;
    }
  } catch (_) {}

  // 3. No password found
  console.warn('[auth] No password found. Set one using one of these methods:');
  console.warn('       a) sudo sh -c \'echo "yourpassword" > /etc/pihole/dashboard.password && chmod 600 /etc/pihole/dashboard.password\'');
  console.warn('       b) sudo PIHOLE_PASSWORD=yourpassword node server.js');
  return '';
}

// ─── Session manager ──────────────────────────────────────────────────────────

let sessionSid       = null;
let sessionExpiresAt = 0;   // epoch ms
let authInFlight     = null; // deduplicate concurrent auth attempts

async function getSession() {
  // Return cached session if still valid (with 30s buffer)
  if (sessionSid && Date.now() < sessionExpiresAt - 30_000) {
    return sessionSid;
  }

  // Deduplicate: if auth is already in progress, wait for it
  if (authInFlight) return authInFlight;

  authInFlight = (async () => {
    const password = readPassword();

    console.log('[auth] Authenticating with Pi-hole v6 API…');

    const body = JSON.stringify({ password });
    const data = await jsonRequest('POST', `${PIHOLE_API}/auth`, body, null);

    if (data?.session?.sid) {
      sessionSid       = data.session.sid;
      // validity is in seconds
      const validity   = data.session.validity ?? 300;
      sessionExpiresAt = Date.now() + validity * 1000;
      console.log(`[auth] Session obtained. Expires in ${validity}s`);
      return sessionSid;
    }

    // Pi-hole returns { session: { sid: null } } when no password is set
    if (data?.session?.sid === null) {
      console.log('[auth] Pi-hole has no password set — proceeding unauthenticated');
      sessionSid       = '';   // empty string = no auth needed
      sessionExpiresAt = Date.now() + 3_600_000; // cache for 1h
      return sessionSid;
    }

    throw new Error(`Auth failed: ${JSON.stringify(data)}`);
  })().finally(() => { authInFlight = null; });

  return authInFlight;
}

// Invalidate session (called when API returns 401)
function invalidateSession() {
  console.log('[auth] Session invalidated — will re-authenticate on next request');
  sessionSid       = null;
  sessionExpiresAt = 0;
}

// ─── HTTP helper ──────────────────────────────────────────────────────────────

function jsonRequest(method, url, body, sid) {
  return new Promise((resolve, reject) => {
    const urlObj  = new URL(url);
    const options = {
      hostname: urlObj.hostname,
      port:     urlObj.port || 80,
      path:     urlObj.pathname + urlObj.search,
      method,
      headers: {
        'Content-Type':  'application/json',
        'Accept':        'application/json',
      },
    };

    if (sid)  options.headers['X-FTL-SID'] = sid;
    if (body) options.headers['Content-Length'] = Buffer.byteLength(body);

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        // Attach status code so callers can check for 401
        let parsed;
        try   { parsed = JSON.parse(data); }
        catch { parsed = { _raw: data }; }
        parsed._status = res.statusCode;
        resolve(parsed);
      });
    });

    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

// Authenticated GET to Pi-hole v6 API — auto-retries once on 401
async function apiGet(endpoint) {
  const sid  = await getSession();
  const data = await jsonRequest('GET', `${PIHOLE_API}${endpoint}`, null, sid);

  if (data._status === 401) {
    invalidateSession();
    // Retry once with a fresh session
    const newSid  = await getSession();
    const retried = await jsonRequest('GET', `${PIHOLE_API}${endpoint}`, null, newSid);
    if (retried._status === 401) throw new Error('Authentication failed after retry');
    return retried;
  }

  return data;
}

// ─── DHCP lease reader ────────────────────────────────────────────────────────

function readDhcpLeases() {
  const leases = [];
  try {
    const lines = fs.readFileSync(DHCP_LEASES_FILE, 'utf8').split('\n');
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 4) {
        leases.push({
          expiry:   parts[0],
          mac:      parts[1].toUpperCase(),
          ip:       parts[2],
          hostname: parts[3] === '*' ? null : parts[3],
          clientId: parts[4] || null,
        });
      }
    }
  } catch (err) {
    console.warn('[dhcp] Could not read leases:', err.message);
  }
  return leases;
}

// ─── Static dashboard ─────────────────────────────────────────────────────────

app.use(express.static(path.join(__dirname)));

// ─── Routes ───────────────────────────────────────────────────────────────────

// Health check
app.get('/api/status', async (req, res) => {
  try {
    const sid = await getSession();
    res.json({
      proxy:       'ok',
      authenticated: !!sid || sid === '',
      pihole:      PIHOLE_API,
      piholeVersion: 'v6',
    });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// Summary stats  →  GET /api/stats/summary
app.get('/api/summary', async (req, res) => {
  try {
    const data = await apiGet('/stats/summary');
    // Normalise v6 response shape to match what the frontend expects
    // v6 returns: { queries: { total, blocked, percent_blocked }, domains: { gravity } }
    res.json({
      dns_queries_today:      data.queries?.total          ?? 0,
      ads_blocked_today:      data.queries?.blocked        ?? 0,
      ads_percentage_today:   data.queries?.percent_blocked ?? 0,
      domains_being_blocked:  data.gravity?.domains_being_blocked
                              ?? data.domains?.gravity      ?? 0,
      status: data.ftl?.blocking_active ? 'enabled' : 'disabled',
      _raw: data,
    });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// Over-time data  →  GET /api/history  (v6 replaces overTimeData10mins)
app.get('/api/overtime', async (req, res) => {
  try {
    const data = await apiGet('/history');
    // v6 shape: { history: [ { timestamp, total, blocked } ] }
    // Re-map to the legacy shape the frontend canvas uses
    const history = data.history ?? [];
    const domains_over_time = {};
    const ads_over_time     = {};
    history.forEach(pt => {
      domains_over_time[pt.timestamp] = pt.total   ?? 0;
      ads_over_time[pt.timestamp]     = pt.blocked ?? 0;
    });
    res.json({ domains_over_time, ads_over_time });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// Top domains  →  GET /api/stats/top_domains & top_blocked
app.get('/api/top', async (req, res) => {
  try {
    const [allowed, blocked] = await Promise.all([
      apiGet('/stats/top_domains?blocked=false&count=10'),
      apiGet('/stats/top_domains?blocked=true&count=10'),
    ]);

    // v6 shape: { domains: [ { domain, count } ] }
    const toObj = arr => Object.fromEntries((arr ?? []).map(d => [d.domain, d.count]));

    res.json({
      top_queries: toObj(allowed.domains),
      top_ads:     toObj(blocked.domains),
    });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// Top clients (total + blocked)  →  used by leaderboard
app.get('/api/clients', async (req, res) => {
  try {
    const data = await apiGet('/stats/top_clients?count=50');
    res.json(data);
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// ─── Leaderboard ─────────────────────────────────────────────────────────────

app.get('/api/leaderboard', async (req, res) => {
  try {
    // Fetch total and blocked clients in parallel
    const [totalData, blockedData] = await Promise.all([
      apiGet('/stats/top_clients?blocked=false&count=100').catch(() => ({})),
      apiGet('/stats/top_clients?blocked=true&count=100').catch(() => ({})),
    ]);

    // v6: { clients: [ { ip, name, count } ] }
    const totalPerClient   = {};
    for (const c of (totalData.clients ?? [])) {
      totalPerClient[c.ip] = c.count ?? 0;
    }

    const blockedPerClient = {};
    for (const c of (blockedData.clients ?? [])) {
      blockedPerClient[c.ip] = c.count ?? 0;
    }

    // DHCP leases for MAC + hostname enrichment
    const leases   = readDhcpLeases();
    const leaseMap = {};
    for (const l of leases) leaseMap[l.ip] = l;

    // Also use the name field Pi-hole itself resolved
    const nameFromApi = {};
    for (const c of [...(totalData.clients ?? []), ...(blockedData.clients ?? [])]) {
      if (c.ip && c.name) nameFromApi[c.ip] = c.name;
    }

    const allIps = new Set([
      ...Object.keys(totalPerClient),
      ...Object.keys(blockedPerClient),
    ]);

    const entries = [];
    for (const ip of allIps) {
      const lease     = leaseMap[ip] || {};
      const blocked   = blockedPerClient[ip] || 0;
      const total     = totalPerClient[ip]   || 0;
      const blockRate = total > 0
        ? parseFloat(((blocked / total) * 100).toFixed(1))
        : 0;

      // Prefer DHCP hostname → Pi-hole resolved name → null
      const hostname = lease.hostname || nameFromApi[ip] || null;

      entries.push({
        ip,
        mac:      lease.mac || null,
        hostname,
        blocked,
        total,
        blockRate,
      });
    }

    entries.sort((a, b) => b.blocked - a.blocked);

    res.json({
      leaderboard:   entries,
      dhcpAvailable: leases.length > 0,
      updatedAt:     Date.now(),
    });
  } catch (err) {
    console.error('[leaderboard]', err.message);
    res.status(502).json({ error: err.message });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(PORT, '0.0.0.0', async () => {
  console.log(`\n🕳️  Pi-hole v6 proxy → http://0.0.0.0:${PORT}`);
  console.log(`   Dashboard : http://localhost:${PORT}`);
  console.log(`   Pi-hole   : ${PIHOLE_API}`);
  console.log(`   DHCP from : ${DHCP_LEASES_FILE}\n`);

  // Eagerly authenticate so errors surface at startup
  try {
    await getSession();
  } catch (e) {
    console.error('[startup] Auth error:', e.message);
  }
});

/*
─────────────────────────────────────────────────────────────────────────────
  HOW TO SET YOUR PASSWORD
─────────────────────────────────────────────────────────────────────────────

  Option A — password file (recommended, persists across reboots):

    sudo sh -c 'echo "your_pihole_password" > /etc/pihole/dashboard.password'
    sudo chmod 600 /etc/pihole/dashboard.password

  Option B — environment variable (good for testing):

    sudo PIHOLE_PASSWORD=your_pihole_password node server.js

  Option C — systemd EnvironmentFile:
    Create /etc/pihole/dashboard.env:
      PIHOLE_PASSWORD=your_pihole_password
    Then in the service unit add:
      EnvironmentFile=/etc/pihole/dashboard.env

─────────────────────────────────────────────────────────────────────────────
  SYSTEMD SERVICE
  Save as: /etc/systemd/system/pihole-dashboard.service
─────────────────────────────────────────────────────────────────────────────

[Unit]
Description=Pi-hole Dashboard Proxy
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/pihole-dashboard
EnvironmentFile=-/etc/pihole/dashboard.env
ExecStart=/usr/bin/node /opt/pihole-dashboard/server.js
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target

─────────────────────────────────────────────────────────────────────────────
  Deploy:
    sudo mkdir -p /opt/pihole-dashboard
    sudo cp server.js index.html /opt/pihole-dashboard/
    cd /opt/pihole-dashboard && sudo npm init -y && sudo npm install express
    sudo systemctl daemon-reload
    sudo systemctl enable --now pihole-dashboard
─────────────────────────────────────────────────────────────────────────────
*/
