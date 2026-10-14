# Smart QR Access — Webhook Receiver & Test Suite (Node.js)

A fully featured, production-ready webhook testing server and live inspector for the **Smart QR Access** gate scan webhook notifications, built according to `webhook_handoff_spec.md`.

---

## Features
- **Strict Spec Verification:**
  - Raw body processing before JSON parsing.
  - Constant-time HMAC-SHA256 signature verification (`X-Webhook-Signature`).
  - Constant-time Bearer token authentication (`Authorization: Bearer <token>`).
  - Replay attack protection with configurable timestamp tolerance (`|now - X-Webhook-Timestamp| <= 300s`).
  - Fast 200 OK response (`{"ok": true}`) well within the required 3-second limit.
  - Idempotency / deduplication tracking using SHA-256 raw body hashes and `(token, device_id, scanned_at, result)` tuples.
- **Modern Dashboard UI:**
  - Real-time Server-Sent Events (SSE) live feed.
  - Visual metrics: Total, ALLOWED, DENIED scans.
  - Usage progress bars: `used / max_uses`, `remaining`, with depleted warnings.
  - Inspect Modal showing full payload, verification results, and raw headers.
- **Built-in Webhook Simulator:**
  - Send simulated scans (ALLOWED, DENIED, Bad HMAC, Stale Timestamp, Bad Bearer) directly from the Web UI or via CLI!

---

## Quick Start

### 1. Configure Environment
Copy `.env.example` to `.env` (or use the preconfigured defaults):
```env
PORT=3000
SMARTQR_API_SECRET=my_smartqr_test_secret_123
SMARTQR_WEBHOOK_BEARER=test_bearer_token_xyz
TIMESTAMP_TOLERANCE_SECONDS=300
```
- `SMARTQR_API_SECRET`: Set to the `api_secret` from your Smart QR Access client account.
- `SMARTQR_WEBHOOK_BEARER`: Set if you configured a Bearer token in the Developer Portal.

### 2. Start the Server
```bash
# Option A: Double click start.bat (on Windows)
# Option B: Run npm start
npm start
```
The server will start at:
- **Dashboard UI:** `http://localhost:3000/`
- **Webhook Endpoint:** `http://localhost:3000/webhooks/gate-scan`

### 3. Test with the CLI Simulator
In another terminal:
```bash
# Test valid ALLOWED scan:
npm run test:send allowed

# Test valid DENIED scan (limit reached):
npm run test:send denied

# Test rejection on bad HMAC signature (expects HTTP 401):
npm run test:send bad_sig

# Test rejection on stale timestamp (expects HTTP 401):
npm run test:send stale

# Run all test cases in sequence:
npm run test:send all
```

---

## Exposing for Smart QR Access Platform Testing
The Smart QR Access platform requires an HTTPS callback URL:
1. Use **Cloudflare Tunnel** or **ngrok**:
   ```bash
   ngrok http 3000
   ```
2. In the Smart QR Access Developer Portal:
   - Click navbar **"Webhook Setup"**
   - Toggle **Enable**
   - Set **Callback URL**: `https://<your-tunnel-subdomain>.ngrok-free.app/webhooks/gate-scan`
   - Set **Bearer Token** to match `SMARTQR_WEBHOOK_BEARER` in `.env`
   - Click **Save**
3. Scan a QR code using the gate simulator `tools/esp32_gui_simulator.py` or gate device. The scan event will appear instantly on the dashboard!
