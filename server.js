const express = require('express');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'vcc2024';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// Static
app.use('/assets', express.static(path.join(__dirname, 'public')));

// ═══ DATA STORE ═══
const apiKeys = new Map();
const requestLogs = [];
const startTime = new Date();

// Default key
function genKey(name) {
  const key = 'vcc_' + crypto.randomBytes(24).toString('hex');
  const data = { id: crypto.randomBytes(8).toString('hex'), name, key, requests: 0, active: true, createdAt: new Date().toISOString() };
  apiKeys.set(key, data);
  return data;
}
genKey('Default');

// ═══ RATE LIMIT ═══
const rateLimits = new Map();
function rateLimit(req, res, next) {
  const id = req.headers['x-api-key'] || req.ip;
  const now = Date.now();
  if (!rateLimits.has(id)) { rateLimits.set(id, { count: 1, resetAt: now + 60000 }); return next(); }
  const lim = rateLimits.get(id);
  if (now > lim.resetAt) { lim.count = 1; lim.resetAt = now + 60000; return next(); }
  lim.count++;
  res.set('X-RateLimit-Remaining', Math.max(0, 100 - lim.count));
  if (lim.count > 100) return res.status(429).json({ error: true, message: 'Rate limit asildi' });
  next();
}

// ═══ API AUTH ═══
function apiKeyAuth(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key) return res.status(401).json({ error: true, message: 'API key gerekli (X-API-Key header)' });
  const keyData = apiKeys.get(key);
  if (!keyData) return res.status(401).json({ error: true, message: 'Gecersiz API key' });
  if (!keyData.active) return res.status(403).json({ error: true, message: 'API key pasif' });
  keyData.requests++;

  const elapsed = Date.now() - startTime.getTime();
  requestLogs.unshift({ method: req.method, path: req.originalUrl, key: keyData.name, ip: req.ip, status: 200, timestamp: new Date().toISOString() });
  if (requestLogs.length > 500) requestLogs.pop();

  next();
}

// ═══ ADMIN AUTH ═══
function adminAuth(req, res, next) {
  if (req.session && req.session.admin) return next();
  res.redirect('/login');
}

app.use(rateLimit);

// ═══════════════════════════════════════════════
//  PUBLIC API
// ═══════════════════════════════════════════════
app.get('/api/status', (req, res) => {
  res.json({ status: 'ok', gateway: 'active', server: 'VCC API Dashboard', uptime: Math.floor((Date.now() - startTime.getTime()) / 1000) + 's', timestamp: new Date().toISOString() });
});

app.get('/api/me', apiKeyAuth, (req, res) => {
  res.json({ status: 200, message: 'Hosgeldin!', server: 'VCC API Dashboard', verified: true });
});

app.get('/api/users', apiKeyAuth, (req, res) => {
  res.json({ status: 200, count: 3, users: [
    { id: 1, name: 'Ali', email: 'ali@example.com', role: 'admin' },
    { id: 2, name: 'Ayse', email: 'ayse@example.com', role: 'user' },
    { id: 3, name: 'Mehmet', email: 'mehmet@example.com', role: 'user' }
  ]});
});

app.post('/api/data', apiKeyAuth, (req, res) => {
  res.json({ status: 200, message: 'Veri alindi', received: req.body, at: new Date().toISOString() });
});

app.get('/api/info', apiKeyAuth, (req, res) => {
  res.json({ name: 'VCC API Dashboard', version: '1.0.0', node: process.version, memory: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + ' MB' });
});

app.get('/api/time', apiKeyAuth, (req, res) => {
  const now = new Date();
  res.json({ utc: now.toISOString(), turkey: now.toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul' }) });
});

// ═══════════════════════════════════════════════
//  LOGIN
// ═══════════════════════════════════════════════
app.get('/login', (req, res) => {
  if (req.session && req.session.admin) return res.redirect('/panel');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    req.session.admin = true;
    return res.json({ success: true, redirect: '/panel' });
  }
  res.status(401).json({ success: false, message: 'Kullanici adi veya sifre hatali' });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// ═══════════════════════════════════════════════
//  ADMIN API (panel icerisinden kullanilir)
// ═══════════════════════════════════════════════
app.get('/admin/stats', adminAuth, (req, res) => {
  const uptime = Math.floor((Date.now() - startTime.getTime()) / 1000);
  const mem = process.memoryUsage();
  const activeKeys = [...apiKeys.values()].filter(k => k.active).length;
  const totalRequests = [...apiKeys.values()].reduce((s, k) => s + k.requests, 0);
  res.json({ uptime: uptime + 's', activeKeys, totalKeys: apiKeys.size, totalRequests, memory: Math.round(mem.heapUsed / 1024 / 1024) + ' MB' });
});

app.get('/admin/keys', adminAuth, (req, res) => {
  const keys = [...apiKeys.values()];
  res.json({ keys });
});

app.post('/admin/keys', adminAuth, (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'name gerekli' });
  const key = genKey(name);
  res.json({ success: true, key });
});

app.delete('/admin/keys/:id', adminAuth, (req, res) => {
  for (const [k, v] of apiKeys) {
    if (v.id === req.params.id) { apiKeys.delete(k); return res.json({ success: true }); }
  }
  res.status(404).json({ error: 'Key bulunamadi' });
});

app.put('/admin/keys/:id/toggle', adminAuth, (req, res) => {
  for (const [k, v] of apiKeys) {
    if (v.id === req.params.id) { v.active = !v.active; return res.json({ success: true, active: v.active }); }
  }
  res.status(404).json({ error: 'Key bulunamadi' });
});

app.get('/admin/logs', adminAuth, (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  res.json({ logs: requestLogs.slice(0, limit) });
});

// ═══════════════════════════════════════════════
//  PANEL (admin)
// ═══════════════════════════════════════════════
app.get('/panel', adminAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'panel.html'));
});

// ═══ PUBLIC SITE ═══
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// Catch
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Endpoint bulunamadi' });
  res.redirect('/');
});

app.listen(PORT, () => {
  console.log('  VCC API Dashboard calisiyor: http://localhost:' + PORT);
  console.log('  Admin: ' + ADMIN_USER + ' / ' + ADMIN_PASS);
});
