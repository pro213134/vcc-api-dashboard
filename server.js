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

// CORS — her yerden, her sey acik
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
  res.header('Access-Control-Allow-Headers', '*');
  res.header('Access-Control-Max-Age', '86400');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

app.use('/assets', express.static(path.join(__dirname, 'public')));

// ═══ DATA STORE ═══
const apiKeys = new Map();
const requestLogs = [];
const startTime = new Date();

function genKey(name) {
  const key = 'vcc_' + crypto.randomBytes(24).toString('hex');
  const data = { id: crypto.randomBytes(8).toString('hex'), name, key, requests: 0, active: true, createdAt: new Date().toISOString() };
  apiKeys.set(key, data);
  return data;
}
genKey('Default');

// ═══ NO RATE LIMIT ═══

// ═══ API AUTH (opsiyonel — key yoksa da calisir) ═══
function apiKeyAuth(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key) { req.apiKeyData = null; return next(); }
  const keyData = apiKeys.get(key);
  if (keyData && keyData.active) {
    keyData.requests++;
    req.apiKeyData = keyData;
  } else {
    req.apiKeyData = null;
  }
  next();
}

// ═══ ADMIN AUTH ═══
function adminAuth(req, res, next) {
  if (req.session && req.session.admin) return next();
  if (req.headers.accept && req.headers.accept.includes('application/json')) {
    return res.status(401).json({ status: 200, error: false, message: 'Giris gerekli' });
  }
  res.redirect('/login');
}

// ═══════════════════════════════════════════════
//  PUBLIC API — HER ZAMAN 200 DONER
// ═══════════════════════════════════════════════

// Her istegi logla
app.use((req, res, next) => {
  const originalJson = res.json.bind(res);
  res.json = function(data) {
    // Her zaman 200 don
    res.status(200);
    // Log
    requestLogs.unshift({
      method: req.method,
      path: req.originalUrl,
      ip: req.ip,
      key: req.apiKeyData ? req.apiKeyData.name : null,
      timestamp: new Date().toISOString()
    });
    if (requestLogs.length > 2000) requestLogs.pop();
    return originalJson(data);
  };
  next();
});

// Durum
app.get('/api/status', apiKeyAuth, (req, res) => {
  res.json({
    status: 'ok',
    error: false,
    gateway: 'active',
    server: 'VCC API Dashboard',
    version: '1.0.0',
    uptime: Math.floor((Date.now() - startTime.getTime()) / 1000) + 's',
    timestamp: new Date().toISOString()
  });
});

// Dogrulama
app.get('/api/me', apiKeyAuth, (req, res) => {
  res.json({ status: 200, error: false, message: 'Hosgeldin!', server: 'VCC API Dashboard', verified: true });
});

// Kullanicilar
app.get('/api/users', apiKeyAuth, (req, res) => {
  res.json({ status: 200, error: false, count: 3, users: [
    { id: 1, name: 'Ali', email: 'ali@example.com', role: 'admin' },
    { id: 2, name: 'Ayse', email: 'ayse@example.com', role: 'user' },
    { id: 3, name: 'Mehmet', email: 'mehmet@example.com', role: 'user' }
  ]});
});

// Kullanici ekle
app.post('/api/users', apiKeyAuth, (req, res) => {
  const { name, email, role } = req.body;
  if (!name || !email) return res.json({ status: 200, error: false, message: 'name ve email gerekli', received: req.body });
  res.json({ status: 200, error: false, message: 'Kullanici eklendi', user: { id: Date.now(), name, email, role: role || 'user' } });
});

// Veri gonder
app.post('/api/data', apiKeyAuth, (req, res) => {
  res.json({ status: 200, error: false, message: 'Veri alindi', received: req.body, at: new Date().toISOString() });
});

// Proje bilgisi
app.get('/api/info', apiKeyAuth, (req, res) => {
  res.json({
    status: 200, error: false,
    name: 'VCC API Dashboard',
    version: '1.0.0',
    author: 'VCC',
    node: process.version,
    memory: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + ' MB',
    uptime: Math.floor((Date.now() - startTime.getTime()) / 1000) + 's',
    endpoints: ['/api/status', '/api/me', '/api/users', '/api/data', '/api/info', '/api/time', '/api/health', '/api/config']
  });
});

// Sunucu zamani
app.get('/api/time', apiKeyAuth, (req, res) => {
  const now = new Date();
  res.json({
    status: 200, error: false,
    utc: now.toISOString(),
    turkey: now.toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul' }),
    unix: Math.floor(now.getTime() / 1000)
  });
});

// Saglik kontrolu
app.get('/api/health', apiKeyAuth, (req, res) => {
  const mem = process.memoryUsage();
  res.json({
    status: 200, error: false, health: 'healthy',
    uptime: Math.floor((Date.now() - startTime.getTime()) / 1000),
    memory: { used: Math.round(mem.heapUsed / 1024 / 1024) + ' MB', total: Math.round(mem.heapTotal / 1024 / 1024) + ' MB' },
    keys: { active: [...apiKeys.values()].filter(k => k.active).length, total: apiKeys.size },
    requests: { total: requestLogs.length },
    timestamp: new Date().toISOString()
  });
});

// Config endpoint (emulator icin)
app.get('/api/config', apiKeyAuth, (req, res) => {
  res.json({
    status: 200, error: false,
    server: 'VCC API Dashboard',
    version: '1.0.0',
    features: {
      cors: true,
      rateLimit: false,
      auth: 'optional',
      maxLogSize: 2000
    },
    endpoints: {
      status: '/api/status',
      health: '/api/health',
      config: '/api/config',
      users: '/api/users',
      data: '/api/data',
      info: '/api/info',
      time: '/api/time',
      me: '/api/me'
    },
    timestamp: new Date().toISOString()
  });
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
  res.json({ success: false, message: 'Kullanici adi veya sifre hatali' });
});

app.get('/logout', (req, res) => { req.session.destroy(); res.redirect('/login'); });

// ═══════════════════════════════════════════════
//  ADMIN API
// ═══════════════════════════════════════════════
app.get('/admin/stats', adminAuth, (req, res) => {
  const uptime = Math.floor((Date.now() - startTime.getTime()) / 1000);
  const mem = process.memoryUsage();
  const activeKeys = [...apiKeys.values()].filter(k => k.active).length;
  const totalRequests = [...apiKeys.values()].reduce((s, k) => s + k.requests, 0);
  res.json({ uptime: uptime + 's', activeKeys, totalKeys: apiKeys.size, totalRequests, memory: Math.round(mem.heapUsed / 1024 / 1024) + ' MB' });
});

app.get('/admin/keys', adminAuth, (req, res) => { res.json({ keys: [...apiKeys.values()] }); });

app.post('/admin/keys', adminAuth, (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'name gerekli' });
  const key = genKey(name);
  res.json({ success: true, key });
});

app.delete('/admin/keys/:id', adminAuth, (req, res) => {
  for (const [k, v] of apiKeys) { if (v.id === req.params.id) { apiKeys.delete(k); return res.json({ success: true }); } }
  res.status(404).json({ error: 'Key bulunamadi' });
});

app.put('/admin/keys/:id/toggle', adminAuth, (req, res) => {
  for (const [k, v] of apiKeys) { if (v.id === req.params.id) { v.active = !v.active; return res.json({ success: true, active: v.active }); } }
  res.status(404).json({ error: 'Key bulunamadi' });
});

app.get('/admin/logs', adminAuth, (req, res) => { res.json({ logs: requestLogs.slice(0, parseInt(req.query.limit) || 50) }); });

// ═══ PANEL ═══
app.get('/panel', adminAuth, (req, res) => { res.sendFile(path.join(__dirname, 'public', 'panel.html')); });
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// Catch — her zaman 200
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.json({ status: 200, error: false, message: 'Endpoint bulunamadi: ' + req.path });
  res.redirect('/');
});

app.listen(PORT, () => {
  console.log('  VCC API calisiyor: http://localhost:' + PORT);
  console.log('  Rate Limit: KAPALI');
  console.log('  Auth: Opsiyonel');
  console.log('  Admin: ' + ADMIN_USER + ' / ' + ADMIN_PASS);
});
