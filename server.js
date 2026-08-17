const express = require('express');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const API_KEY = 'gw_50e2714951ee6ffde2ace9c419b8f615fb826abf49c28e4b';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const startTime = new Date();

// Rate limit
const rateLimits = new Map();

function rateLimit(req, res, next) {
  const id = req.headers['x-api-key'] || req.ip;
  const now = Date.now();
  const windowMs = 60000;
  const max = 100;

  if (!rateLimits.has(id)) {
    rateLimits.set(id, { count: 1, resetAt: now + windowMs });
    return next();
  }
  const lim = rateLimits.get(id);
  if (now > lim.resetAt) { lim.count = 1; lim.resetAt = now + windowMs; return next(); }
  lim.count++;
  res.set('X-RateLimit-Remaining', Math.max(0, max - lim.count));
  if (lim.count > max) return res.status(429).json({ error: true, message: 'Rate limit asildi. 1 dk bekle.' });
  next();
}

// Auth
function auth(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key || key !== API_KEY) return res.status(401).json({ error: true, message: 'Gecersiz veya eksik API key' });
  next();
}

app.use(rateLimit);

// ═══ PUBLIC ═══
app.get('/api/status', (req, res) => {
  res.json({ status: 'ok', gateway: 'active', uptime: Math.floor((Date.now() - startTime.getTime()) / 1000) + 's', timestamp: new Date().toISOString() });
});

// ═══ PROTECTED ═══
app.get('/api/me', auth, (req, res) => {
  res.json({ status: 200, message: 'Hosgeldin! Key dogru.', server: 'VCC API Dashboard', role: 'admin' });
});

app.get('/api/users', auth, (req, res) => {
  res.json({
    status: 200, count: 3,
    users: [
      { id: 1, name: 'Ali', email: 'ali@example.com', role: 'admin' },
      { id: 2, name: 'Ayse', email: 'ayse@example.com', role: 'user' },
      { id: 3, name: 'Mehmet', email: 'mehmet@example.com', role: 'user' }
    ]
  });
});

app.post('/api/data', auth, (req, res) => {
  res.json({ status: 200, message: 'Veri alindi', received: req.body, at: new Date().toISOString() });
});

app.get('/api/info', auth, (req, res) => {
  res.json({
    name: 'VCC API Dashboard', version: '1.0.0', node: process.version,
    memory: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + ' MB',
    uptime: Math.floor((Date.now() - startTime.getTime()) / 1000) + 's'
  });
});

app.get('/api/time', auth, (req, res) => {
  const now = new Date();
  res.json({
    utc: now.toISOString(),
    turkey: now.toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul' })
  });
});

// Catch
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════════╗');
  console.log('  ║        VCC API DASHBOARD — API           ║');
  console.log('  ╠══════════════════════════════════════════╣');
  console.log('  ║  Site:  http://localhost:' + PORT + '            ║');
  console.log('  ║  Key:   ' + API_KEY + '  ║');
  console.log('  ╚══════════════════════════════════════════╝');
  console.log('');
});
