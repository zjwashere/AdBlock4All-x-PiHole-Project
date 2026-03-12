/**
 * Pi-hole Dashboard Proxy Server — Pi-hole v6 compatible
 *
 * Pi-hole v6 uses session-based auth:
 *   POST /api/auth  { password }  →  { session: { sid, validity } }
 *   All subsequent requests include header:  X-FTL-SID: <sid>
 *
 * Setup:
 *   npm install express
 *   sudo node server.js   (sudo needed to read /etc/pihole/ files)
 *
 * Password options (pick one):
 *   a) sudo sh -c 'echo "PIHOLE_PASSWORD=yourpassword" > /etc/pihole/dashboard.env'
 *   b) sudo PIHOLE_PASSWORD=yourpassword node server.js
 */

const express = require('express');
const fs      = require('fs');
const path    = require('path');
const http    = require('http');

const app  = express();
const PORT = 3000;

const PIHOLE_BASE      = `http://127.0.0.1:${process.env.PIHOLE_PORT || 8080}`;
const PIHOLE_API       = `${PIHOLE_BASE}/api`;
const DHCP_LEASES_FILE = '/etc/pihole/dhcp.leases';
const PIHOLE_TOML      = '/etc/pihole/pihole.toml';

// ─── Password reader ──────────────────────────────────────────────────────────

function readPassword() {
  if (process.env.PIHOLE_PASSWORD) {
    console.log('[auth] Using PIHOLE_PASSWORD env var');
    return process.env.PIHOLE_PASSWORD;
  }
  const passwordFile = '/etc/pihole/dashboard.password';
  try {
    const pw = fs.readFileSync(passwordFile, 'utf8').trim();
    if (pw) { console.log('[auth] Using password from', passwordFile); return pw; }
  } catch (_) {}
  console.warn('[auth] No password found. Set via /etc/pihole/dashboard.password or PIHOLE_PASSWORD env var.');
  return '';
}

// ─── Session manager ──────────────────────────────────────────────────────────

let sessionSid       = null;
let sessionExpiresAt = 0;
let authInFlight     = null;

async function getSession() {
  if (sessionSid !== null && Date.now() < sessionExpiresAt - 30_000) return sessionSid;
  if (authInFlight) return authInFlight;

  authInFlight = (async () => {
    const password = readPassword();
    console.log('[auth] Authenticating with Pi-hole v6…');
    const body = JSON.stringify({ password });
    const data = await jsonRequest('POST', `${PIHOLE_API}/auth`, body, null);

    if (data?.session?.sid) {
      sessionSid       = data.session.sid;
      sessionExpiresAt = Date.now() + (data.session.validity ?? 300) * 1000;
      console.log(`[auth] Session OK, expires in ${data.session.validity}s`);
      return sessionSid;
    }
    if (data?.session?.sid === null) {
      console.log('[auth] No password set on Pi-hole — unauthenticated mode');
      sessionSid = ''; sessionExpiresAt = Date.now() + 3_600_000;
      return sessionSid;
    }
    throw new Error(`Auth failed: ${JSON.stringify(data)}`);
  })().finally(() => { authInFlight = null; });

  return authInFlight;
}

function invalidateSession() {
  console.log('[auth] Session invalidated, will re-auth on next request');
  sessionSid = null; sessionExpiresAt = 0;
}

// ─── HTTP helper ──────────────────────────────────────────────────────────────

function jsonRequest(method, url, body, sid) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const options = {
      hostname: u.hostname, port: u.port || 80,
      path: u.pathname + u.search, method,
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    };
    if (sid)  options.headers['X-FTL-SID'] = sid;
    if (body) options.headers['Content-Length'] = Buffer.byteLength(body);

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(data); } catch { parsed = { _raw: data }; }
        parsed._status = res.statusCode;
        resolve(parsed);
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function apiGet(endpoint) {
  const sid  = await getSession();
  const data = await jsonRequest('GET', `${PIHOLE_API}${endpoint}`, null, sid);
  if (data._status === 401) {
    invalidateSession();
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
          expiry: parts[0], mac: parts[1].toUpperCase(),
          ip: parts[2], hostname: parts[3] === '*' ? null : parts[3],
          clientId: parts[4] || null,
        });
      }
    }
  } catch (err) { console.warn('[dhcp] Could not read leases:', err.message); }
  return leases;
}

// ─── Static dashboard ─────────────────────────────────────────────────────────

app.use(express.static(path.join(__dirname)));

// ─── Routes ───────────────────────────────────────────────────────────────────

app.get('/api/status', async (req, res) => {
  try {
    const sid = await getSession();
    res.json({ proxy: 'ok', authenticated: sid !== null, piholeVersion: 'v6', pihole: PIHOLE_API });
  } catch (e) { res.status(502).json({ error: e.message }); }
});

// Returns the caller's IP address and any DHCP info we have for it.
// The frontend uses this to identify "Your Device".
app.get('/api/whoami', (req, res) => {
  // Get real client IP — works behind nginx proxy too
  const ip = (
    req.headers['x-forwarded-for']?.split(',')[0].trim() ||
    req.headers['x-real-ip'] ||
    req.socket.remoteAddress ||
    ''
  ).replace(/^::ffff:/, ''); // strip IPv4-mapped IPv6 prefix

  const leases  = readDhcpLeases();
  const lease   = leases.find(l => l.ip === ip) || {};

  res.json({
    ip,
    mac:      lease.mac      || null,
    hostname: lease.hostname || null,
  });
});

app.get('/api/summary', async (req, res) => {
  try {
    const [data, blocking] = await Promise.all([
      apiGet('/stats/summary'),
      apiGet('/dns/blocking'),
    ]);
    res.json({
      dns_queries_today:     data.queries?.total           ?? 0,
      ads_blocked_today:     data.queries?.blocked         ?? 0,
      ads_percentage_today:  data.queries?.percent_blocked ?? 0,
      domains_being_blocked: data.gravity?.domains_being_blocked ?? 0,
      status: blocking.blocking === 'enabled' ? 'enabled' : 'disabled',
    });
  } catch (e) { res.status(502).json({ error: e.message }); }
});

app.get('/api/overtime', async (req, res) => {
  try {
    const data    = await apiGet('/history');
    const history = data.history ?? [];
    const domains_over_time = {}, ads_over_time = {};
    history.forEach(pt => {
      domains_over_time[pt.timestamp] = pt.total   ?? 0;
      ads_over_time[pt.timestamp]     = pt.blocked ?? 0;
    });
    res.json({ domains_over_time, ads_over_time });
  } catch (e) { res.status(502).json({ error: e.message }); }
});

app.get('/api/top', async (req, res) => {
  try {
    const [allowed, blocked] = await Promise.all([
      apiGet('/stats/top_domains?blocked=false&count=10'),
      apiGet('/stats/top_domains?blocked=true&count=10'),
    ]);
    const toObj = arr => Object.fromEntries((arr ?? []).map(d => [d.domain, d.count]));
    res.json({ top_queries: toObj(allowed.domains), top_ads: toObj(blocked.domains) });
  } catch (e) { res.status(502).json({ error: e.message }); }
});

app.get('/api/clients', async (req, res) => {
  try { res.json(await apiGet('/stats/top_clients?count=50')); }
  catch (e) { res.status(502).json({ error: e.message }); }
});

app.get('/api/leaderboard', async (req, res) => {
  try {
    const [totalData, blockedData] = await Promise.all([
      apiGet('/stats/top_clients?blocked=false&count=100').catch(() => ({})),
      apiGet('/stats/top_clients?blocked=true&count=100').catch(() => ({})),
    ]);

    const totalPerClient = {}, blockedPerClient = {}, nameFromApi = {};

    for (const c of (totalData.clients ?? [])) {
      totalPerClient[c.ip] = c.count ?? 0;
      if (c.name) nameFromApi[c.ip] = c.name;
    }
    for (const c of (blockedData.clients ?? [])) {
      blockedPerClient[c.ip] = c.count ?? 0;
      if (c.name) nameFromApi[c.ip] = c.name;
    }

    const leases = readDhcpLeases();
    const leaseMap = {};
    for (const l of leases) leaseMap[l.ip] = l;

    const allIps = new Set([...Object.keys(totalPerClient), ...Object.keys(blockedPerClient)]);
    const entries = [];

    for (const ip of allIps) {
      const lease     = leaseMap[ip] || {};
      const blocked   = blockedPerClient[ip] || 0;
      const total     = totalPerClient[ip]   || 0;
      const blockRate = total > 0 ? parseFloat(((blocked / total) * 100).toFixed(1)) : 0;
      entries.push({
        ip, mac: lease.mac || null,
        hostname: lease.hostname || nameFromApi[ip] || null,
        blocked, total, blockRate,
      });
    }

    entries.sort((a, b) => b.blocked - a.blocked);
    res.json({ leaderboard: entries, dhcpAvailable: leases.length > 0, updatedAt: Date.now() });
  } catch (err) {
    console.error('[leaderboard]', err.message);
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/raw', async (req, res) => {
  const q = req.query.q;
  if (!q) return res.status(400).json({ error: 'Missing ?q=' });
  if (!/^[a-zA-Z0-9=&_]+$/.test(q)) return res.status(400).json({ error: 'Invalid query' });
  try { res.json(await apiGet('/' + q)); }
  catch (e) { res.status(502).json({ error: e.message }); }
});

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(PORT, '0.0.0.0', async () => {
  console.log(`\n🕳️  Pi-hole v6 proxy → http://0.0.0.0:${PORT}`);
  console.log(`   Dashboard : http://localhost:${PORT}`);
  console.log(`   Pi-hole   : ${PIHOLE_API}`);
  console.log(`   DHCP from : ${DHCP_LEASES_FILE}\n`);
  try { await getSession(); } catch (e) { console.error('[startup] Auth error:', e.message); }
});

/*
─────────────────────────────────────────────────────────────────────────────
  SYSTEMD SERVICE — /etc/systemd/system/pihole-dashboard.service
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
    sudo cp server.js index.html /opt/pihole-dashboard/
    sudo systemctl daemon-reload
    sudo systemctl enable --now pihole-dashboard
─────────────────────────────────────────────────────────────────────────────
*/
