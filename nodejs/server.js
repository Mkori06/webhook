require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const API_SECRET = process.env.SMARTQR_API_SECRET || '';
const WEBHOOK_BEARER = process.env.SMARTQR_WEBHOOK_BEARER || '';
const TOLERANCE_SECONDS = parseInt(process.env.TIMESTAMP_TOLERANCE_SECONDS || '300', 10);

const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'events.json');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// In-memory event store with file persistence
let events = [];
if (fs.existsSync(DB_FILE)) {
  try {
    events = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch (err) {
    console.warn('[Storage] Could not parse existing events.json, starting fresh:', err.message);
    events = [];
  }
}

function saveEventsToFile() {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(events.slice(0, 500), null, 2), 'utf8');
  } catch (err) {
    console.error('[Storage Error] Failed to write events:', err.message);
  }
}

// Timing-safe string comparison
function timingSafeEqualStr(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// Connected SSE clients for live dashboard feed
const sseClients = new Set();
function broadcastSSE(eventData) {
  const payload = `data: ${JSON.stringify(eventData)}\n\n`;
  for (const client of sseClients) {
    client.write(payload);
  }
}

// Serve static assets from public/
app.use(express.static(path.join(__dirname, 'public')));

// Webhook receiver endpoint: raw body parser is critical for HMAC signature verification
const rawParser = express.raw({ type: '*/*', limit: '2mb' });

app.post(['/webhooks/gate-scan', '/webhook'], rawParser, (req, res) => {
  const rawBody = req.body || Buffer.alloc(0);
  const authHeader = req.get('authorization') || '';
  const sigHeader = req.get('x-webhook-signature') || '';
  const tsHeader = req.get('x-webhook-timestamp') || '';
  const userAgent = req.get('user-agent') || '';

  const verification = {
    bearerChecked: Boolean(WEBHOOK_BEARER),
    bearerValid: null,
    signatureChecked: Boolean(API_SECRET),
    signatureValid: null,
    timestampChecked: Boolean(tsHeader),
    timestampValid: null,
    timestampDiffSeconds: null,
    computedSignature: null,
    isDuplicate: false,
    rejectedReason: null
  };

  function reject(status, reason) {
    verification.rejectedReason = reason;
    console.warn(`[WEBHOOK ${status} REJECTED] ${reason}`);

    let parsed = null;
    try {
      parsed = JSON.parse(rawBody.toString('utf8'));
    } catch (_) {
      parsed = { rawText: rawBody.toString('utf8') };
    }

    const rawSha256 = crypto.createHash('sha256').update(rawBody).digest('hex');
    const record = {
      id: crypto.randomUUID(),
      receivedAt: new Date().toISOString(),
      rawSha256,
      dedupeKey: 'REJECTED_' + rawSha256,
      headers: {
        'content-type': req.get('content-type'),
        'accept': req.get('accept'),
        'user-agent': userAgent,
        'authorization': authHeader ? (authHeader.substring(0, 15) + '...') : '(none)',
        'x-webhook-signature': sigHeader || '(none)',
        'x-webhook-timestamp': tsHeader || '(none)'
      },
      verification,
      payload: {
        event: 'gate_scan',
        token: parsed?.token || 'UNKNOWN_REJECTED',
        device_id: parsed?.device_id || 'UNKNOWN',
        scanned_at: parsed?.scanned_at || new Date().toISOString(),
        result: 'REJECTED_401',
        status: `Rejected: ${reason}`,
        usage: parsed?.usage || null,
        payload_version: parsed?.payload_version || '1.1'
      }
    };

    events.unshift(record);
    if (events.length > 500) events.pop();
    saveEventsToFile();
    broadcastSSE(record);

    return res.status(status).json({ error: reason });
  }

  // 1. Bearer Token Verification
  if (WEBHOOK_BEARER) {
    if (!authHeader) {
      verification.bearerValid = false;
      return reject(401, `Missing 'Authorization' header (server requires Bearer token: '${WEBHOOK_BEARER}')`);
    }
    const expectedAuth = `Bearer ${WEBHOOK_BEARER}`;
    const valid = timingSafeEqualStr(authHeader, expectedAuth);
    verification.bearerValid = valid;
    if (!valid) {
      return reject(401, `Invalid Authorization Bearer Token. Received: '${authHeader}'`);
    }
  }

  // 2. HMAC-SHA256 Signature Verification
  if (API_SECRET) {
    const computedSig = crypto.createHmac('sha256', API_SECRET).update(rawBody).digest('hex');
    verification.computedSignature = computedSig;
    if (!sigHeader) {
      verification.signatureValid = false;
      return reject(401, `Missing 'X-Webhook-Signature' header (server configured with signing secret)`);
    }
    const valid = timingSafeEqualStr(sigHeader.toLowerCase(), computedSig.toLowerCase());
    verification.signatureValid = valid;
    if (!valid) {
      return reject(401, `Invalid HMAC signature. Received: '${sigHeader}', Expected: '${computedSig}'`);
    }
  }

  // 3. Timestamp Replay Attack Protection
  if (tsHeader) {
    const tsNumber = Number(tsHeader);
    const nowSeconds = Math.floor(Date.now() / 1000);
    const diff = Math.abs(nowSeconds - tsNumber);
    verification.timestampDiffSeconds = diff;
    const valid = !isNaN(tsNumber) && diff <= TOLERANCE_SECONDS;
    verification.timestampValid = valid;
    if (!valid) {
      return reject(401, `Stale timestamp (${diff}s drift exceeds ${TOLERANCE_SECONDS}s tolerance)`);
    }
  }

  // 4. Respond fast with 200 OK (Spec Rule: respond within < 3 seconds)
  res.status(200).json({ ok: true });

  // 5. Asynchronous processing after response
  setImmediate(() => {
    let parsed = null;
    try {
      parsed = JSON.parse(rawBody.toString('utf8'));
    } catch (err) {
      console.error('[WEBHOOK ERROR] Could not parse JSON body:', err.message);
      parsed = { rawText: rawBody.toString('utf8') };
    }

    const rawSha256 = crypto.createHash('sha256').update(rawBody).digest('hex');
    const dedupeKey = parsed && parsed.token && parsed.device_id && parsed.scanned_at
      ? `${parsed.token}|${parsed.device_id}|${parsed.scanned_at}|${parsed.result}`
      : rawSha256;

    const duplicate = events.some(e => e.rawSha256 === rawSha256 || e.dedupeKey === dedupeKey);
    verification.isDuplicate = duplicate;

    const record = {
      id: crypto.randomUUID(),
      receivedAt: new Date().toISOString(),
      rawSha256,
      dedupeKey,
      headers: {
        'content-type': req.get('content-type'),
        'accept': req.get('accept'),
        'user-agent': userAgent,
        'authorization': authHeader ? (authHeader.substring(0, 15) + '...') : null,
        'x-webhook-signature': sigHeader,
        'x-webhook-timestamp': tsHeader
      },
      verification,
      payload: parsed
    };

    events.unshift(record);
    if (events.length > 500) events.pop();
    saveEventsToFile();
    broadcastSSE(record);

    const token = parsed?.token || 'N/A';
    const result = parsed?.result || 'UNKNOWN';
    const device = parsed?.device_id || 'N/A';
    const status = parsed?.status || 'N/A';
    const remaining = parsed?.usage ? `${parsed.usage.used}/${parsed.usage.max_uses} (left: ${parsed.usage.remaining})` : 'N/A';

    console.log(`[WEBHOOK OK] ${result === 'ALLOWED' ? '🟢 ALLOWED' : '🔴 DENIED'} | Token: ${token} | Gate: ${device} | Usage: ${remaining} | Status: "${status}"`);
  });
});

// JSON parser for API routes
app.use(express.json());

// API: Get recorded events & summary stats
app.get('/api/events', (req, res) => {
  const allowedCount = events.filter(e => e.payload?.result === 'ALLOWED').length;
  const deniedCount = events.filter(e => e.payload?.result === 'DENIED').length;
  const totalCount = events.length;

  res.json({
    stats: {
      total: totalCount,
      allowed: allowedCount,
      denied: deniedCount
    },
    config: {
      port: PORT,
      secretConfigured: Boolean(API_SECRET),
      bearerConfigured: Boolean(WEBHOOK_BEARER),
      toleranceSeconds: TOLERANCE_SECONDS
    },
    events
  });
});

// API: Clear event history
app.post('/api/clear', (req, res) => {
  events = [];
  saveEventsToFile();
  broadcastSSE({ type: 'CLEARED' });
  res.json({ ok: true, message: 'Event history cleared' });
});

// API: SSE Live Stream
app.get('/api/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  sseClients.add(res);
  res.write(`data: ${JSON.stringify({ type: 'CONNECTED', message: 'SSE stream connected' })}\n\n`);

  req.on('close', () => {
    sseClients.delete(res);
  });
});

// API: Internal simulator endpoint to test without external curl
app.post('/api/simulate', async (req, res) => {
  const type = req.body?.type || 'allowed'; // 'allowed', 'denied', 'bad_sig', 'bad_bearer', 'stale'
  const customToken = req.body?.token || `TOK-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  const deviceId = req.body?.device_id || 'DEV-GATE-001D848D';

  const now = new Date();
  const pad = n => String(n).padStart(2, '0');
  const scannedAt = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;

  let payload = {
    event: 'gate_scan',
    token: customToken,
    device_id: deviceId,
    scanned_at: scannedAt,
    result: type === 'denied' ? 'DENIED' : 'ALLOWED',
    status: type === 'denied' ? 'Token Usage Limit Reached (2/2)' : 'Access Granted (Gate Unlocked)',
    usage: {
      max_uses: 2,
      used: type === 'denied' ? 2 : 1,
      remaining: type === 'denied' ? 0 : 1,
      token_status: type === 'denied' ? 'USED' : 'ACTIVE',
      expires_at: '2026-10-31 23:59:59'
    },
    payload_version: '1.1'
  };

  const raw = Buffer.from(JSON.stringify(payload), 'utf8');
  let ts = Math.floor(Date.now() / 1000);
  if (type === 'stale') {
    ts -= 600; // 10 minutes ago
  }

  let bearer = WEBHOOK_BEARER;
  if (type === 'bad_bearer') {
    bearer = 'INVALID_BEARER_TOKEN';
  }

  let sig = '';
  if (API_SECRET) {
    if (type === 'bad_sig') {
      sig = 'bad000000000000000000000000000000000000000000000000000000000beef';
    } else {
      sig = crypto.createHmac('sha256', API_SECRET).update(raw).digest('hex');
    }
  }

  // Dispatch local HTTP POST to itself
  try {
    const fetch = global.fetch || (await import('node-fetch')).default;
    const headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'User-Agent': 'SmartQR-Access-Webhook/1.0',
      'X-Webhook-Timestamp': String(ts)
    };
    if (bearer) headers['Authorization'] = `Bearer ${bearer}`;
    if (sig) headers['X-Webhook-Signature'] = sig;

    const response = await fetch(`http://127.0.0.1:${PORT}/webhooks/gate-scan`, {
      method: 'POST',
      headers,
      body: raw
    });

    const respText = await response.text();
    let respJson = null;
    try { respJson = JSON.parse(respText); } catch (_) { respJson = respText; }

    res.json({
      simulatedType: type,
      status: response.status,
      response: respJson
    });
  } catch (err) {
    res.status(500).json({ error: 'Simulation failed: ' + err.message });
  }
});

app.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(` Smart QR Webhook Receiver (Node.js)`);
  console.log(` Server running at: http://localhost:${PORT}`);
  console.log(` Webhook URL:       http://localhost:${PORT}/webhooks/gate-scan`);
  console.log(` Dashboard UI:      http://localhost:${PORT}/`);
  console.log(` Secret configured: ${API_SECRET ? 'YES (' + API_SECRET.length + ' chars)' : 'NO (verification disabled)'}`);
  console.log(` Bearer configured: ${WEBHOOK_BEARER ? 'YES' : 'NO'}`);
  console.log(` Timestamp check:   Within ±${TOLERANCE_SECONDS}s`);
  console.log(`====================================================`);
});
