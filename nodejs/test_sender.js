#!/usr/bin/env node
/**
 * Smart QR Access - Webhook Test Sender CLI (Node.js)
 * Simulates gate scan webhooks with real HMAC-SHA256 signatures and timestamps.
 */
require('dotenv').config();
const crypto = require('crypto');
const http = require('http');
const https = require('https');

const TARGET_URL = process.env.TEST_TARGET_URL || `http://localhost:${process.env.PORT || 3000}/webhooks/gate-scan`;
const API_SECRET = process.env.SMARTQR_API_SECRET || 'my_smartqr_test_secret_123';
const BEARER_TOKEN = process.env.SMARTQR_WEBHOOK_BEARER || 'test_bearer_token_xyz';

const args = process.argv.slice(2);
const testType = (args[0] || 'allowed').toLowerCase();

function generatePayload(type) {
  const now = new Date();
  const pad = n => String(n).padStart(2, '0');
  const scannedAt = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
  const randomHex = crypto.randomBytes(4).toString('hex').toUpperCase();

  if (type === 'denied' || type === 'denied_limit') {
    return {
      event: 'gate_scan',
      token: `DENIED_${randomHex}`,
      device_id: 'DEV-GATE-001D848D',
      scanned_at: scannedAt,
      result: 'DENIED',
      status: 'Token Usage Limit Reached (2/2)',
      usage: {
        max_uses: 2,
        used: 2,
        remaining: 0,
        token_status: 'USED',
        expires_at: '2026-10-31 23:59:59'
      },
      payload_version: '1.1'
    };
  }

  if (type === 'denied_not_found') {
    return {
      event: 'gate_scan',
      token: `UNKNOWN_${randomHex}`,
      device_id: 'DEV-GATE-001D848D',
      scanned_at: scannedAt,
      result: 'DENIED',
      status: 'Token Not Found in Database',
      usage: null,
      payload_version: '1.1'
    };
  }

  // Default ALLOWED
  return {
    event: 'gate_scan',
    token: `ALLOW_${randomHex}`,
    device_id: 'DEV-GATE-001D848D',
    scanned_at: scannedAt,
    result: 'ALLOWED',
    status: 'Access Granted (Gate Unlocked)',
    usage: {
      max_uses: 2,
      used: 1,
      remaining: 1,
      token_status: 'ACTIVE',
      expires_at: '2026-10-31 23:59:59'
    },
    payload_version: '1.1'
  };
}

async function sendTest(scenario) {
  console.log(`\n======================================================`);
  console.log(`🚀 Dispatching Test Webhook: [${scenario.toUpperCase()}]`);
  console.log(`Target URL: ${TARGET_URL}`);

  const payload = generatePayload(scenario);
  const rawBody = Buffer.from(JSON.stringify(payload), 'utf8');

  let timestamp = Math.floor(Date.now() / 1000);
  if (scenario === 'stale') {
    timestamp -= 600; // 10 minutes ago, exceeds 300s tolerance
    console.log(`⚠️  Intentionally sending stale timestamp: ${timestamp} (-600s)`);
  }

  let bearer = BEARER_TOKEN;
  if (scenario === 'bad_bearer') {
    bearer = 'INVALID_INCORRECT_BEARER';
    console.log(`⚠️  Intentionally sending wrong Bearer token`);
  }

  let signature = '';
  if (API_SECRET) {
    if (scenario === 'bad_sig') {
      signature = 'deadbeef0000000000000000000000000000000000000000000000000000bad0';
      console.log(`⚠️  Intentionally sending corrupted HMAC signature`);
    } else {
      signature = crypto.createHmac('sha256', API_SECRET).update(rawBody).digest('hex');
    }
  }

  const urlObj = new URL(TARGET_URL);
  const isHttps = urlObj.protocol === 'https:';
  const client = isHttps ? https : http;

  const headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'User-Agent': 'SmartQR-Access-Webhook/1.0',
    'X-Webhook-Timestamp': String(timestamp),
    'Content-Length': rawBody.length
  };

  if (bearer) headers['Authorization'] = `Bearer ${bearer}`;
  if (signature) headers['X-Webhook-Signature'] = signature;

  const reqOptions = {
    method: 'POST',
    hostname: urlObj.hostname,
    port: urlObj.port || (isHttps ? 443 : 80),
    path: urlObj.pathname + urlObj.search,
    headers: headers
  };

  const req = client.request(reqOptions, (res) => {
    let responseData = '';
    res.on('data', chunk => responseData += chunk);
    res.on('end', () => {
      console.log(`\n📥 Response Status: ${res.statusCode} ${res.statusMessage}`);
      console.log(`📥 Response Body:   ${responseData}`);
      if (res.statusCode === 200) {
        console.log(`✅ SUCCESS: Webhook accepted!`);
      } else if (res.statusCode === 401 && (scenario === 'bad_sig' || scenario === 'bad_bearer' || scenario === 'stale')) {
        console.log(`✅ EXPECTED REJECTION: Endpoint correctly rejected invalid/stale webhook!`);
      } else {
        console.log(`❌ FAILED: Unexpected status code.`);
      }
      console.log(`======================================================\n`);
    });
  });

  req.on('error', (err) => {
    console.error(`❌ Network error connecting to ${TARGET_URL}:`, err.message);
  });

  req.write(rawBody);
  req.end();
}

if (testType === 'all') {
  (async () => {
    await sendTest('allowed');
    setTimeout(() => sendTest('denied'), 600);
    setTimeout(() => sendTest('bad_sig'), 1200);
    setTimeout(() => sendTest('bad_bearer'), 1800);
    setTimeout(() => sendTest('stale'), 2400);
  })();
} else {
  sendTest(testType);
}
