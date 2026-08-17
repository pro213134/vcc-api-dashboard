const tls = require('tls');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const RELAY_PORT = parseInt(process.env.RELAY_PORT) || 51820;
const API_URL = process.env.API_URL || 'https://vccapiservice-production.up.railway.app';
const VG_VERSION = '1.18.5.11';

// ═══ RSA KEYS ═══
const VGW_RSA_PRIV_PEM = fs.readFileSync(path.join(__dirname, 'gateway', 'vanguard_gateaway_key.pem'), 'utf8').trim();
const VGW_RIOT_PUBKEY_PEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxABI8XC5dAnqbJX6ZLWj
wiAPl18Pj/5q1E8I8raxRRJb7i7wmCuUEExKfwOBjbF4y4Wiugt8cloQniGqTzL7
JfvjpaZWYuM7OTd9YjACJRmm6CDjNsAxAA6PzH7B9LJd49Cp4ViHME65uUorsnQ6
riq0wbZSwNLaKWi9yoLlEX8Ru2CRgHJte35Fo1BcbB2S36SfwBu9tKMUbn1sAqjG
Mnzu8Slm9smtIoeugfvBEz4rpPpBH8n4/Nv89pZPf12O/64bHBfuK4v/g6Ig3T4M
T73MmXfxP4Hv3pI9+9ydnkzc3uZ+4LZbONVCyjJHcndeOcTzw2VIcJP5gVAxgaW
6WQIDAQAB
-----END PUBLIC KEY-----`;

const HT_SUFFIX = Buffer.from('F4AD529CDE170EE1D1029B4A3CA89820', 'hex');
const VG_USER_AGENT = 'vanguard/1.18.5-11+20260730.010201';
const GW_PATH = '/vanguard/v1/gateway';
const GW_PORT = 8443;

// ═══ PROTOBUF HELPERS ═══
function pbVarint(buf, val) {
  do {
    let b = Number(val) & 0x7F;
    val = BigInt(val) >> 7n;
    if (val > 0n) b |= 0x80;
    buf.push(b);
  } while (BigInt(val) > 0n);
}

function pbTag(buf, field, wire) {
  pbVarint(buf, (BigInt(field) << 3n) | BigInt(wire));
}

function pbString(buf, field, s) {
  if (!s || !s.length) return;
  pbTag(buf, field, 2);
  const b = Buffer.from(s, 'utf8');
  pbVarint(buf, b.length);
  for (const x of b) buf.push(x);
}

function pbInt32(buf, field, val) {
  if (val === 0) return;
  pbTag(buf, field, 0);
  pbVarint(buf, val < 0 ? BigInt(val) + (1n << 64n) : BigInt(val));
}

function pbEmbedded(buf, field, inner) {
  if (!inner || !inner.length) return;
  pbTag(buf, field, 2);
  pbVarint(buf, inner.length);
  for (const x of inner) buf.push(x);
}

// ═══ CRYPTO ═══
function randomBytes(n) {
  return crypto.randomBytes(n);
}

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}

function computeHt(machineId) {
  const tokens = {};
  for (const part of machineId.split('||')) {
    if (part) tokens[part[0]] = part;
  }
  const concat = (tokens['6'] || '') + (tokens['1'] || '') + (tokens['2'] || '') +
    (tokens['3'] || '') + (tokens['5'] || '') + VG_VERSION;
  const data = Buffer.concat([Buffer.from(concat, 'ascii'), HT_SUFFIX]);
  return crypto.createHash('sha1').update(data).digest();
}

function rsaOaepSha512Encrypt(pubKeyPem, data) {
  const pubKey = crypto.createPublicKey(pubKeyPem);
  return crypto.publicEncrypt({ key: pubKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha512' }, data);
}

function rsaOaepSha512Decrypt(privKeyPem, data) {
  const privKey = crypto.createPrivateKey(privKeyPem);
  return crypto.privateDecrypt({ key: privKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha512' }, data);
}

function aesGcmEncrypt(key, plaintext) {
  const iv = randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ciphertext, tag, iv };
}

function aesGcmDecrypt(key, iv, ciphertext, tag) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function buildPayload(protoData, pubkeyPem, typeByte) {
  const aesKey = randomBytes(32);
  const { ciphertext, tag, iv } = aesGcmEncrypt(aesKey, protoData);
  const rsaEncKey = rsaOaepSha512Encrypt(pubkeyPem, aesKey);
  if (rsaEncKey.length !== 256) throw new Error('RSA key length mismatch');

  const rito = [];
  rito.push(0x52, 0x47, 0x01, 0x00); // magic
  for (const b of rsaEncKey) rito.push(b);
  for (const b of iv) rito.push(b);
  for (const b of ciphertext) rito.push(b);
  for (const b of tag) rito.push(b);

  const env = [];
  env.push(0x08, typeByte, 0x12);
  const lenBuf = [];
  pbVarint(lenBuf, rito.length);
  for (const b of lenBuf) env.push(b);
  for (const b of rito) env.push(b);
  return Buffer.from(env);
}

function decryptGatewayResponse(payload) {
  let pos = 0;
  if (pos >= payload.length || payload[pos++] !== 0x08) return null;
  if (pos >= payload.length) return null;
  const type = payload[pos++];
  if (pos >= payload.length || payload[pos++] !== 0x12) return null;

  const { value: len, newOffset: lenEnd } = readVarint(payload, pos);
  pos = lenEnd;
  if (pos + len > payload.length) return null;

  if (pos + 4 > payload.length) return null;
  if (payload[pos] !== 0x52 || payload[pos+1] !== 0x47 || payload[pos+2] !== 0x01 || payload[pos+3] !== 0x00) return null;
  pos += 4;

  if (len < (4 + 256 + 12 + 16)) return null;
  const encKey = payload.slice(pos, pos + 256); pos += 256;
  const iv = payload.slice(pos, pos + 12); pos += 12;
  const cipherLen = len - (4 + 256 + 12 + 16);
  const cipher = payload.slice(pos, pos + cipherLen); pos += cipherLen;
  const tag = payload.slice(pos, pos + 16);

  const aesKey = rsaOaepSha512Decrypt(VGW_RSA_PRIV_PEM, encKey);
  if (aesKey.length !== 32) return null;
  return aesGcmDecrypt(aesKey, iv, cipher, tag);
}

function readVarint(buf, offset) {
  let val = 0n, shift = 0, pos = offset;
  while (pos < buf.length) {
    const b = buf[pos++];
    val |= BigInt(b & 0x7F) << BigInt(shift);
    if (!(b & 0x80)) break;
    shift += 7;
  }
  return { value: Number(val), newOffset: pos };
}

function decodeAuthResponse(data) {
  const resp = { token: '', expiry: '', server_rsa_public_key: '', session_id: '', ephemeral_identifiers: '' };
  let pos = 0;
  while (pos < data.length) {
    const { value: tag, newOffset } = readVarint(data, pos);
    pos = newOffset;
    const field = tag >> 3;
    const wire = tag & 0x7;
    if (wire === 0) {
      const { value, newOffset: no } = readVarint(data, pos);
      pos = no;
    } else if (wire === 2) {
      const { value: slen, newOffset: so } = readVarint(data, pos);
      pos = so;
      const s = data.slice(pos, pos + slen).toString('utf8');
      pos += slen;
      if (field === 1) resp.token = s;
      if (field === 2) resp.expiry = s;
      if (field === 4) resp.server_rsa_public_key = s;
      if (field === 8) resp.session_id = s;
      if (field === 10) resp.ephemeral_identifiers = s;
    } else if (wire === 5) { pos += 4; }
    else if (wire === 1) { pos += 8; }
    else break;
  }
  return resp;
}

function parseLPStr(buf, offset) {
  if (offset + 4 > buf.length) return { value: '', newOffset: offset };
  const len = (buf[offset] << 24) | (buf[offset+1] << 16) | (buf[offset+2] << 8) | buf[offset+3];
  offset += 4;
  if (offset + len > buf.length) return { value: '', newOffset: offset };
  return { value: buf.slice(offset, offset + len).toString('utf8'), newOffset: offset + len };
}

function parseLPBytes(buf, offset) {
  if (offset + 4 > buf.length) return { value: Buffer.alloc(0), newOffset: offset };
  const len = (buf[offset] << 24) | (buf[offset+1] << 16) | (buf[offset+2] << 8) | buf[offset+3];
  offset += 4;
  if (offset + len > buf.length) return { value: Buffer.alloc(0), newOffset: offset };
  return { value: buf.slice(offset, offset + len), newOffset: offset + len };
}

function pushU32BE(buf, x) {
  buf.push((x >> 24) & 0xFF, (x >> 16) & 0xFF, (x >> 8) & 0xFF, x & 0xFF);
}

function pushU64BE(buf, x) {
  const bi = BigInt(x);
  for (let i = 7; i >= 0; i--) buf.push(Number((bi >> BigInt(i * 8)) & 0xFFn));
}

function pushLenStr(buf, s) {
  const b = Buffer.from(s || '', 'utf8');
  pushU32BE(buf, b.length);
  for (const x of b) buf.push(x);
}

function pushLenBytes(buf, bytes) {
  pushU32BE(buf, bytes.length);
  for (const x of bytes) buf.push(x);
}

// ═══ PROTOBUF BUILDERS ═══
function encodeSubProto(f1, f2, version, variant = 0) {
  const buf = [];
  pbInt32(buf, 1, f1); pbInt32(buf, 2, f2);
  if (variant !== 0) pbInt32(buf, 3, variant);
  pbString(buf, 4, version);
  return Buffer.from(buf);
}

function encodeVgVersion(a, b, c, d) {
  const buf = [];
  pbInt32(buf, 1, a); pbInt32(buf, 2, b); pbInt32(buf, 3, c); pbInt32(buf, 4, d);
  return Buffer.from(buf);
}

function encodeMapEntry(key, val) {
  const buf = [];
  pbString(buf, 1, key); pbString(buf, 2, val);
  return Buffer.from(buf);
}

function encodeSecurityFeature(name, state = 1) {
  const buf = [];
  pbString(buf, 1, name); pbInt32(buf, 2, state);
  return Buffer.from(buf);
}

function encodeAuthRequest(machineId, gameToken, externalSid, gameId, bootState, clientPubkey, htVal, ephemeralId, cpuBrand, cpuModel, gpuModel, osVariant, osVersion) {
  const buf = [];
  pbString(buf, 1, machineId);
  pbEmbedded(buf, 2, encodeSubProto(1, 2, '10.0.19045'));
  pbString(buf, 4, gameToken);
  pbString(buf, 5, clientPubkey);
  const vgver = encodeVgVersion(1, 18, 5, 11);
  pbEmbedded(buf, 6, vgver);
  pbEmbedded(buf, 7, vgver);
  pbString(buf, 8, gameId);
  pbInt32(buf, 9, bootState);
  if (ephemeralId) pbString(buf, 10, ephemeralId);
  {
    const core = [];
    const cpu = [];
    pbString(cpu, 1, cpuBrand); pbString(cpu, 2, cpuModel);
    pbEmbedded(core, 1, Buffer.from(cpu));
    const gpu = [];
    pbString(gpu, 2, gpuModel);
    pbEmbedded(core, 2, Buffer.from(gpu));
    const osi = [];
    pbInt32(osi, 3, 1);
    pbString(osi, 4, osVersion || '10.0.19045');
    pbEmbedded(core, 3, Buffer.from(osi));
    pbEmbedded(buf, 11, Buffer.from(core));
  }
  if (externalSid) pbString(buf, 13, externalSid);
  pbEmbedded(buf, 14, encodeSecurityFeature('HVCI', 1));
  pbEmbedded(buf, 14, encodeSecurityFeature('IOMMU', 1));
  pbEmbedded(buf, 14, encodeSecurityFeature('SB', 1));
  pbEmbedded(buf, 14, encodeSecurityFeature('TPM2', 1));
  pbEmbedded(buf, 14, encodeSecurityFeature('VBS', 1));
  if (htVal) pbEmbedded(buf, 15, encodeMapEntry('ht', htVal));
  return Buffer.from(buf);
}

function encodeAccessRequest(token) {
  const buf = [];
  pbString(buf, 1, token);
  return Buffer.from(buf);
}

function encodeHeartbeatRequest(token) {
  const buf = [];
  const nowMs = Date.now();
  pbString(buf, 1, token);
  pbTag(buf, 2, 0); pbVarint(buf, nowMs);
  pbInt32(buf, 4, 1);
  pbTag(buf, 6, 0); pbVarint(buf, 1);
  return Buffer.from(buf);
}

function buildGatewayAuthPayload(gameToken, externalSid, machineId, htOverride, ephemeralId, cpuBrand, cpuModel, gpuModel, osVariant, osVersion) {
  const clientPubkey = 'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArZ9KPHbgRlwgsJSDZKXNge4iG99WocrlS8Vy8tm9DlnnAcJZJGYWv1EFhr5ZgV43v4eyh/QI+czayvSuBckXNbYuyMh1a8ML9nqZDalXhc06eCWINsDPCEfo+cW9Qewk2sq9gXqIaAyfRDlZEr5Z0ScKxoE/Petd7kfp0OgaYc9NfoNOLLEeHjw58vppnLBEO8A82orcqzUtOj3YltrfbSI3oJrxhIwMR+DfCHY0RF11Pk6vNc4w6ePIaz/FBycZ3v+s+roBf56iujh01MOqOfzCHwlK7pm+uuMvpFruNgkOJlga1Vui2JCukZ0LXdd3vjBoNvEsLsCTVm2akQdL7auUQvwFfsNugx9iqBlvz8BVFovg7oyyUWKg7jPLMCZW3kq4kkZBGVEmJAXmooOTLSuWS2M7CvO8X5YVwCNSqk5gsFmT9JqQ3VlY30zmF5BQwb/GtRF2hdMZrZUrQIKQsIZvWqIQrWo7tpxxv9e5biInUohyqv1U5UFhmrRNmuof3axhpuD5OAQVF6RjpoUkhIkjxkTBeeeSpvehLHsC+IZ7Jy5uUFglAI7aWWORYvliK2Ivhdy1BfyV3QA2nh4uRQiKcp38W8IRzZJo6UApGdBzbx2OOIKQt0IJMWWHU+GuSz4d27lqt72nMFAk1yBe6VWJsbcBW+I4xxj/ZKpbCQcCAwEAAQ==';
  let mid = machineId || '';
  let htVal = htOverride || '';
  if (!mid || !htVal) {
    if (mid && !htVal) {
      htVal = computeHt(mid).toString('base64');
    } else {
      mid = '||1;' + randomBytes(16).toString('base64') +
            '||2;' + randomBytes(64).toString('base64') +
            '||3;' + randomBytes(64).toString('base64') +
            '||4' +
            '||5;' + randomBytes(6).toString('base64') +
            '||6;' + randomBytes(48).toString('base64') + ';' +
            randomBytes(48).toString('base64') + ';' +
            randomBytes(48).toString('base64') + ';' +
            randomBytes(48).toString('base64') + ';' +
            randomBytes(48).toString('base64');
      htVal = computeHt(mid).toString('base64');
    }
  }
  const proto = encodeAuthRequest(mid, gameToken, externalSid, 'com.riotgames.valorant', 3, clientPubkey, htVal, ephemeralId || '', cpuBrand || '', cpuModel || '', gpuModel || '', osVariant || 'Windows 10 Pro', osVersion || '10.0.19045');
  return buildPayload(proto, VGW_RIOT_PUBKEY_PEM, 0x03);
}

function buildGatewayAccessPayload(gatewayAuthResponse, outServerPubkey, outToken, outEphemeralId) {
  const decrypted = decryptGatewayResponse(gatewayAuthResponse);
  if (!decrypted) return null;
  const resp = decodeAuthResponse(decrypted);
  outServerPubkey.value = resp.server_rsa_public_key;
  outToken.value = resp.token;
  if (outEphemeralId) outEphemeralId.value = resp.ephemeral_identifiers;
  if (!resp.server_rsa_public_key) return null;

  const accessProto = encodeAccessRequest(resp.token);
  return buildPayload(accessProto, resp.server_rsa_public_key, 0x04);
}

function buildGatewayHeartbeatPayload(prevAuthResponse, outServerPubkey, outEphemeralId) {
  const decrypted = decryptGatewayResponse(prevAuthResponse);
  if (!decrypted) return null;
  const resp = decodeAuthResponse(decrypted);
  outServerPubkey.value = resp.server_rsa_public_key;
  if (outEphemeralId) outEphemeralId.value = resp.ephemeral_identifiers;
  if (!resp.server_rsa_public_key) return null;

  const hbProto = encodeHeartbeatRequest(resp.token);
  return buildPayload(hbProto, resp.server_rsa_publickey || resp.server_rsa_public_key, 0x07);
}

// ═══ GATEWAY HTTP POST ═══
function regionToHost(region) {
  const map = {
    la: 'latam.vg.ac.pvp.net', br: 'br.vg.ac.pvp.net',
    na: 'na.vg.ac.pvp.net', eu: 'eu.vg.ac.pvp.net',
    ap: 'ap.vg.ac.pvp.net', kr: 'kr.vg.ac.pvp.net'
  };
  return map[region] || 'na.vg.ac.pvp.net';
}

function postToGateway(envelope, puuid, region, vgType) {
  return new Promise((resolve) => {
    const host = regionToHost(region || 'na');
    const headers = {
      'User-Agent': VG_USER_AGENT,
      'Content-Type': 'application/x-protobuf',
      'X-VG-1': String(vgType),
      'X-VG-3': '1',
      'Accept': '*/*'
    };
    if (puuid) headers['X-VG-2'] = puuid;

    const options = {
      hostname: host,
      port: GW_PORT,
      path: GW_PATH,
      method: 'POST',
      headers,
      rejectUnauthorized: false,
      timeout: 15000
    };

    const req = https.request(options, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const body = Buffer.concat(chunks);
        console.log(`[GW] HTTP ${res.statusCode} action=${vgType} body=${body.length}B`);
        if (res.statusCode === 200 && body.length > 0) {
          resolve(body);
        } else {
          console.log('[GW] non-200 or empty, returning empty');
          resolve(Buffer.alloc(0));
        }
      });
    });

    req.on('error', (e) => {
      console.log('[GW] request error: ' + e.message);
      resolve(Buffer.alloc(0));
    });

    req.on('timeout', () => {
      console.log('[GW] request timeout');
      req.destroy();
      resolve(Buffer.alloc(0));
    });

    req.write(envelope);
    req.end();
  });
}

// ═══ BINARY PROTOCOL ═══
function packMsg(type, payload) {
  const pkt = Buffer.alloc(8 + payload.length);
  pkt.writeUInt32BE(type, 0);
  pkt.writeUInt32BE(payload.length, 4);
  payload.copy(pkt, 8);
  return pkt;
}

// ═══ SESSIONS ═══
const sessions = new Map();

function createSession(jwt, puuid, region, machineId, hwidFp) {
  const sid = crypto.randomUUID();
  const s = {
    id: sid, jwt, puuid, region: region || 'na',
    machineId: machineId || '', hwidFp: hwidFp || '',
    createdAt: Date.now(), lastActivity: Date.now(),
    hbCount: 0, lastGwResponse: null
  };
  sessions.set(sid, s);
  console.log(`[SESSION] Created ${sid.substring(0, 8)} region=${region} puuid=${puuid ? puuid.substring(0, 8) : '?'}`);
  return s;
}

// ═══ TLS SERVER ═══
function startRelay() {
  const pfxPath = path.join(__dirname, 'gateway', 'server.pfx');
  let options = null;

  if (fs.existsSync(pfxPath)) {
    try {
      const pfx = fs.readFileSync(pfxPath);
      if (pfx.length > 0) {
        options = { pfx, passphrase: 'password' };
      }
    } catch (e) {
      console.log('[SRV] WARNING: server.pfx read failed: ' + e.message);
    }
  }

  if (!options) {
    console.log('[SRV] Generating self-signed cert...');
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    let cert = null;
    try {
      const { execSync } = require('child_process');
      cert = execSync(
        'openssl req -new -x509 -key /dev/stdin -out /dev/stdout -days 365 -subj "/CN=VCCGateway"',
        { input: privateKey.export({ type: 'pkcs8', format: 'pem' }) }
      ).toString();
      console.log('[SRV] Generated cert via openssl');
    } catch (_) {
      try {
        const selfCert = crypto.createCertificate({ publicKey, privateKey, serialNumber: '01', validity: { notBefore: new Date(), notAfter: new Date(Date.now() + 365 * 86400000) }, subject: { CN: 'VCCGateway' }, issuer: { CN: 'VCCGateway' } });
        cert = selfCert.toString();
        console.log('[SRV] Generated cert via Node.js crypto');
      } catch (e2) {
        console.log('[SRV] FATAL: Cannot create TLS cert: ' + e2.message);
        return;
      }
    }
    options = { key: privateKey.export({ type: 'pkcs8', format: 'pem' }), cert };
  }

  const server = tls.createServer(options, (socket) => {
    console.log('[SRV] Client connected from ' + socket.remoteAddress);
    let buffer = Buffer.alloc(0);
    let sessionId = '';

    socket.on('data', async (data) => {
      buffer = Buffer.concat([buffer, data]);

      while (buffer.length >= 8) {
        const msgType = buffer.readUInt32BE(0);
        const msgLen = buffer.readUInt32BE(4);
        if (buffer.length < 8 + msgLen) break;

        const payload = buffer.slice(8, 8 + msgLen);
        buffer = buffer.slice(8 + msgLen);

        try {
          await handleMessage(socket, msgType, payload, sessionId, (sid) => { sessionId = sid; });
        } catch (e) {
          console.log('[SRV] Error handling msg: ' + e.message);
          const errBuf = Buffer.from('relay_error');
          socket.write(packMsg(9, errBuf));
        }
      }
    });

    socket.on('error', (e) => console.log('[SRV] Socket error: ' + e.message));
    socket.on('close', () => console.log('[SRV] Client disconnected'));
  });

  server.listen(RELAY_PORT, '127.0.0.1', () => {
    console.log(`[SRV] Gateway relay listening on 127.0.0.1:${RELAY_PORT}`);
    console.log('[SRV] C++ gateway SERVER_HOST = "127.0.0.1" olmali');
  });

  server.on('error', (e) => {
    console.log('[SRV] Server error: ' + e.message);
    if (e.code === 'EADDRINUSE') {
      console.log(`[SRV] Port ${RELAY_PORT} baska bir surec tarafindan kullaniliyor`);
    }
  });
}

async function handleMessage(socket, msgType, payload, sessionId, setSessionId) {
  const typeNames = { 1:'HELLO',2:'HELLO_OK',3:'SYNC',4:'IOCTL',5:'IOCTL_RESP',6:'HB_BUFFER',
    7:'PING',8:'PONG',9:'ERROR',10:'JWT_UPDATE',11:'JWT_OK',12:'PIPE_AUTH',13:'PIPE_AUTH_OK',
    14:'SESSION_AUTH',15:'SESSION_AUTH_OK',16:'SESSION_ACCESS',17:'SESSION_ACCESS_OK',
    18:'SESSION_HEARTBEAT',19:'SESSION_HEARTBEAT_OK' };
  console.log(`[MSG] type=${msgType}(${typeNames[msgType]||'?'}) size=${payload.length}B`);

  // ═══ MSG_PING → MSG_PONG ═══
  if (msgType === 7) {
    socket.write(packMsg(8, Buffer.alloc(0)));
    return;
  }

  // ═══ MSG_SESSION_AUTH (14) ═══
  if (msgType === 14) {
    let off = 0;
    const authKey = parseLPStr(payload, off); off = authKey.newOffset;
    const gwMachineId = parseLPBytes(payload, off); off = gwMachineId.newOffset;
    const jwt = parseLPStr(payload, off); off = jwt.newOffset;
    const puuid = parseLPStr(payload, off); off = puuid.newOffset;
    const valPid = (off + 4 <= payload.length) ? payload.readUInt32BE(off) : 0; off += 4;
    const clientTsMs = (off + 8 <= payload.length) ? Number(payload.readBigUInt64BE(off)) : 0; off += 8;
    const region = parseLPStr(payload, off); off = region.newOffset;
    const hwidFp = parseLPBytes(payload, off); off = hwidFp.newOffset;
    const riotAcct = parseLPStr(payload, off); off = riotAcct.newOffset;
    const hostname = parseLPStr(payload, off); off = hostname.newOffset;

    console.log(`[AUTH] puuid=${puuid.value ? puuid.value.substring(0,8) : '?'} region=${region.value || 'na'}`);

    const effectiveRegion = region.value || 'na';
    const effectivePuuid = puuid.value || '';

    const session = createSession(jwt.value, effectivePuuid, effectiveRegion, gwMachineId.value.toString('base64'), hwidFp.value.toString('base64'));
    setSessionId(session.id);

    // Build auth envelope
    let gwEnvelope;
    try {
      gwEnvelope = buildGatewayAuthPayload(
        jwt.value, effectivePuuid, gwMachineId.value.toString('utf8'),
        '', '', '', '', '', 'Windows 10 Pro', '10.0.19045'
      );
    } catch (e) {
      console.log('[AUTH] BuildGatewayAuthPayload failed: ' + e.message);
      gwEnvelope = Buffer.alloc(0);
    }

    const okPayload = [];
    pushLenStr(okPayload, session.id);
    pushU32BE(okPayload, gwEnvelope.length);
    for (const b of gwEnvelope) okPayload.push(b);

    socket.write(packMsg(15, Buffer.from(okPayload)));
    console.log(`[AUTH] SESSION_AUTH_OK session=${session.id.substring(0,8)} envelope=${gwEnvelope.length}B`);
    return;
  }

  // ═══ MSG_SESSION_ACCESS (16) ═══
  if (msgType === 16) {
    let off = 0;
    const sid = parseLPStr(payload, off); off = sid.newOffset;
    const envLen = (off + 4 <= payload.length) ? payload.readUInt32BE(off) : 0; off += 4;
    const envelope = payload.slice(off, off + envLen);

    const session = sessions.get(sessionId);
    const effectiveRegion = session ? session.region : 'na';
    const effectivePuuid = session ? session.puuid : '';

    console.log(`[ACCESS] envelope=${envelope.length}B session=${sessionId.substring(0,8)}`);

    // Build access payload
    let serverPubKey = { value: '' };
    let token = { value: '' };
    let accessEnvelope;
    try {
      accessEnvelope = buildGatewayAccessPayload(envelope, serverPubKey, token);
    } catch (e) {
      console.log('[ACCESS] BuildGatewayAccessPayload failed: ' + e.message);
      accessEnvelope = null;
    }

    if (!accessEnvelope) {
      console.log('[ACCESS] Failed to build access envelope, sending empty');
      const emptyPayload = [];
      pushLenStr(emptyPayload, sessionId);
      pushU32BE(emptyPayload, 0);
      socket.write(packMsg(17, Buffer.from(emptyPayload)));
      return;
    }

    // Post to Riot gateway
    const accessResp = await postToGateway(accessEnvelope, effectivePuuid, effectiveRegion, 4);

    if (session) session.lastGwResponse = accessResp;

    const okPayload = [];
    pushLenStr(okPayload, sessionId);
    pushU32BE(okPayload, accessResp.length);
    for (const b of accessResp) okPayload.push(b);

    socket.write(packMsg(17, Buffer.from(okPayload)));
    console.log(`[ACCESS] SESSION_ACCESS_OK resp=${accessResp.length}B`);
    return;
  }

  // ═══ MSG_SESSION_HEARTBEAT (18) ═══
  if (msgType === 18) {
    let off = 0;
    const sid = parseLPStr(payload, off); off = sid.newOffset;
    const envLen = (off + 4 <= payload.length) ? payload.readUInt32BE(off) : 0; off += 4;
    const prevResp = payload.slice(off, off + envLen);

    const session = sessions.get(sessionId);
    const effectiveRegion = session ? session.region : 'na';
    const effectivePuuid = session ? session.puuid : '';

    if (session) {
      session.hbCount++;
      session.lastActivity = Date.now();
    }

    console.log(`[HB] prev_resp=${prevResp.length}B session=${sessionId.substring(0,8)} hb#${session ? session.hbCount : '?'}`);

    // Build heartbeat payload
    let serverPubKey = { value: '' };
    let hbEnvelope;
    try {
      hbEnvelope = buildGatewayHeartbeatPayload(prevResp, serverPubKey);
    } catch (e) {
      console.log('[HB] BuildGatewayHeartbeatPayload failed: ' + e.message);
      hbEnvelope = null;
    }

    if (!hbEnvelope) {
      console.log('[HB] Failed to build heartbeat envelope, sending empty');
      const emptyPayload = [];
      pushLenStr(emptyPayload, sessionId);
      pushU32BE(emptyPayload, 0);
      socket.write(packMsg(19, Buffer.from(emptyPayload)));
      return;
    }

    // Post to Riot gateway
    const hbResp = await postToGateway(hbEnvelope, effectivePuuid, effectiveRegion, 7);

    if (session) session.lastGwResponse = hbResp;

    const okPayload = [];
    pushLenStr(okPayload, sessionId);
    pushU32BE(okPayload, hbResp.length);
    for (const b of hbResp) okPayload.push(b);

    socket.write(packMsg(19, Buffer.from(okPayload)));
    console.log(`[HB] SESSION_HEARTBEAT_OK resp=${hbResp.length}B`);
    return;
  }

  // ═══ MSG_SYNC (3) ═══
  if (msgType === 3) {
    console.log('[SYNC] Received — empty response');
    socket.write(packMsg(3, Buffer.alloc(0)));
    return;
  }

  // ═══ MSG_IOCTL (4) ═══
  if (msgType === 4) {
    const resp = [];
    pushU32BE(resp, 0);
    socket.write(packMsg(5, Buffer.from(resp)));
    return;
  }

  // ═══ MSG_JWT_UPDATE (10) ═══
  if (msgType === 10) {
    let off = 0;
    const newJwt = parseLPStr(payload, off); off = newJwt.newOffset;
    const newPuuid = parseLPStr(payload, off); off = newPuuid.newOffset;
    const session = sessions.get(sessionId);
    if (session) {
      session.jwt = newJwt.value;
      session.puuid = newPuuid.value || session.puuid;
    }
    socket.write(packMsg(11, Buffer.alloc(0)));
    console.log('[JWT] JWT_UPDATE_OK');
    return;
  }

  // ═══ MSG_PIPE_AUTH (12) ═══
  if (msgType === 12) {
    socket.write(packMsg(13, Buffer.alloc(0)));
    return;
  }

  // ═══ MSG_HELLO (1) ═══
  if (msgType === 1) {
    const errBuf = Buffer.from('use_session_auth');
    socket.write(packMsg(9, errBuf));
    return;
  }

  // ═══ UNKNOWN — always 200 ═══
  console.log(`[MSG] Unknown type ${msgType} — sending OK`);
  socket.write(packMsg(msgType + 1, Buffer.alloc(0)));
}

// ═══ MAIN ═══
console.log('========================================');
console.log('  VCC Gateway Relay');
console.log('  Port: ' + RELAY_PORT);
console.log('  API:  ' + API_URL);
console.log('  HATA: HER ZAMAN 200');
console.log('========================================');
startRelay();
