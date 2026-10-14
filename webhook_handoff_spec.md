# Smart QR Access — Webhook Scan Notifications: Handoff Spec (for another AI agent)

This document describes, end-to-end, how the **Webhook Scan Notifications** feature works in the Smart QR Access platform, and exactly how a **client website** must implement the receiving endpoint. It is self-contained — no other context required.

---

## 1. What the feature does

Every time a QR token is scanned at a gate device (ESP32), the platform validates it and then — if the client has enabled webhooks — sends a real-time **HTTP POST** with the scan result to the client's **Callback URL**. This happens for **both ALLOWED and DENIED** scans, regardless of the validation mode.

```
ESP32 gate ──scan──▶ Smart QR server ──validate──▶ DB
                            │
                            ├─▶ stores event (dashboard live feed / SSE)
                            └─▶ POST JSON ──▶ Client Callback URL (if enabled)
```

---

## 2. Settings (Developer Portal)

Location: Developer Portal → navbar **"Webhook Setup"** button → reveals the *Webhook Scan Notifications* card (hidden by default; also auto-opens via `?open=webhook_setup`).

| Field | Form name | DB column (`api_clients`) | Rules |
|---|---|---|---|
| Enable toggle | `webhook_enabled` | `webhook_enabled TINYINT(1) DEFAULT 0` | `1` = on, `0` = off. Unchecked checkbox is sent explicitly as `0` by JS. |
| Callback URL | `webhook_callback_url` | `webhook_callback_url VARCHAR(512) NULL` | **Required when enabled.** Must be HTTPS in production (TLS is verified). |
| Bearer Token | `webhook_bearer_token` | `webhook_bearer_token` | Optional. Falls back to `provider_bearer_token` if empty. |
| Signing secret | — | `api_secret` (existing) | Used for HMAC signature. Not edited in this card. |

**Save endpoint:** `DeveloperDashboardController::updateValidationSettings()` (session-authenticated, JSON or form body).
Validation:
- Not logged in → `401`
- `webhook_enabled=1` and empty callback URL → `400 "Callback URL is required when enabling Webhook Notifications."`
- Success → `{"status":"SUCCESS","message":"Validation settings saved successfully."}`

**Status badge:** shows `● ACTIVE` only when enabled **and** callback URL is set; otherwise `○ DISABLED`.

---

## 3. Dispatch logic (server side)

Implemented in `TokenValidationService::notifyClientTokenUsed()` → `dispatchWebhookNotification()`.

1. Called after every scan decision (ALLOWED or DENIED) once the device is linked to a client.
2. Re-reads the token row to build the `usage` block (read **after** the use is consumed, so `used` includes this scan).
3. Stores the event in DB (dashboard live feed).
4. If `webhook_enabled == 1` **and** `webhook_callback_url` is non-empty → POST.
5. Delivery characteristics:
   - Connect timeout **2 s**, total timeout **3 s** (never blocks the gate).
   - **Fire-and-forget: no retries, no queue.** Failures are only logged (`[WEBHOOK ERROR]`).
   - Any `2xx` response = success. Response body is ignored.

---

## 4. HTTP request the client receives

**Method:** `POST`   **Body:** raw JSON

**Headers:**

| Header | Value | Present when |
|---|---|---|
| `Content-Type` | `application/json` | always |
| `Accept` | `application/json` | always |
| `User-Agent` | `SmartQR-Access-Webhook/1.0` | always |
| `X-Webhook-Timestamp` | Unix seconds, e.g. `1791934029` | always |
| `Authorization` | `Bearer <webhook_bearer_token>` | if a bearer token is configured |
| `X-Webhook-Signature` | lowercase hex `HMAC-SHA256(raw_body, api_secret)` | if client has an `api_secret` |

> Signature is computed over the **raw request body only** (timestamp is NOT part of the signed string).

**Body (payload_version 1.1):**

```json
{
  "event": "gate_scan",
  "token": "HAWL5Y2U6AAZMW8M",
  "device_id": "DEV-GATE-001D848D",
  "scanned_at": "2026-10-14 00:57:09",
  "result": "ALLOWED",
  "status": "Access Granted (Gate Unlocked)",
  "usage": {
    "max_uses": 2,
    "used": 1,
    "remaining": 1,
    "token_status": "ACTIVE",
    "expires_at": "2026-10-15 00:00:00"
  },
  "payload_version": "1.1"
}
```

| Field | Type | Notes |
|---|---|---|
| `event` | string | Always `gate_scan`. |
| `token` | string | Scanned token string. |
| `device_id` | string | Gate device that scanned. |
| `scanned_at` | string | `Y-m-d H:i:s`, **server local time (Asia/Kolkata, IST)**, no timezone suffix. |
| `result` | `ALLOWED` \| `DENIED` | Final decision. |
| `status` | string | Human-readable reason (see list below). Do not parse strictly. |
| `usage` | object \| `null` | `null` when the token isn't in DB (e.g. "Token Not Found") or in External Provider mode. |
| `usage.max_uses` | int | Allowed uses. |
| `usage.used` | int | Uses consumed **including this scan** (if ALLOWED). |
| `usage.remaining` | int | `max(0, max_uses - used)`. |
| `usage.token_status` | string | `ACTIVE`, `USED`, `EXPIRED`, … |
| `usage.expires_at` | string | Token expiry, same format as `scanned_at`. |
| `payload_version` | string | `1.1` (v1.0 lacked `usage`). |

**Known `status` values:**
- `Access Granted (Gate Unlocked)` — ALLOWED (local mode)
- `ALLOWED (EXTERNAL PROVIDER)` — ALLOWED (provider mode)
- `Token Not Found in Database`
- `Token Expired at <datetime>`
- `Token Usage Limit Reached (<used>/<max>)`
- `Token Usage Limit Reached (concurrent scan)`
- `Token Status is <STATUS> (Not ACTIVE)`
- `Unauthorized Device: ...`
- Provider-defined message (provider mode, DENIED)

---

## 5. How the client website must implement the receiver

### Required behaviour
1. Accept `POST` at the configured URL over HTTPS.
2. Read the **raw body** before JSON-parsing (needed for signature).
3. If a bearer token is configured → compare `Authorization` header (constant-time). Mismatch → `401`.
4. If `api_secret` is known → compute `hex(HMAC_SHA256(raw_body, api_secret))` and constant-time compare with `X-Webhook-Signature`. Mismatch → `401`.
5. Reject if `|now - X-Webhook-Timestamp| > 300` s → `401` (replay protection).
6. **Respond `200` within < 3 s.** Do heavy work asynchronously (queue/background job) after responding.
7. **Idempotency:** there is no event ID. Deduplicate using `sha256(raw_body)` or the tuple `(token, device_id, scanned_at, result)`.
8. Since there are no retries, treat webhooks as best-effort; reconcile with the platform API if exact counts matter.

### Reference — PHP
```php
<?php
$raw       = file_get_contents('php://input');
$secret    = getenv('SMARTQR_API_SECRET');      // client's api_secret
$bearer    = getenv('SMARTQR_WEBHOOK_BEARER');  // optional

$h = array_change_key_case(getallheaders(), CASE_LOWER);

if ($bearer && !hash_equals('Bearer ' . $bearer, $h['authorization'] ?? '')) {
    http_response_code(401); exit('bad auth');
}
if ($secret && !hash_equals(hash_hmac('sha256', $raw, $secret), $h['x-webhook-signature'] ?? '')) {
    http_response_code(401); exit('bad signature');
}
if (abs(time() - (int)($h['x-webhook-timestamp'] ?? 0)) > 300) {
    http_response_code(401); exit('stale');
}

$e = json_decode($raw, true);
// dedupe on hash('sha256', $raw), then persist / enqueue:
// $e['result'], $e['token'], $e['usage']['remaining'] ?? null ...

http_response_code(200);
header('Content-Type: application/json');
echo '{"ok":true}';
```

### Reference — Node.js (Express)
```js
const express = require('express');
const crypto  = require('crypto');
const app = express();

app.post('/webhooks/gate-scan', express.raw({ type: 'application/json' }), (req, res) => {
  const raw    = req.body; // Buffer
  const secret = process.env.SMARTQR_API_SECRET;
  const bearer = process.env.SMARTQR_WEBHOOK_BEARER;
  const eq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));

  if (bearer && !eq(req.get('authorization') || '', `Bearer ${bearer}`)) return res.sendStatus(401);
  if (secret) {
    const sig = crypto.createHmac('sha256', secret).update(raw).digest('hex');
    if (!eq(req.get('x-webhook-signature') || '', sig)) return res.sendStatus(401);
  }
  if (Math.abs(Date.now() / 1000 - Number(req.get('x-webhook-timestamp'))) > 300) return res.sendStatus(401);

  const e = JSON.parse(raw.toString('utf8'));
  res.json({ ok: true });          // respond fast
  setImmediate(() => handle(e));   // then process
});
```

### Suggested website features using the payload
- Live "Scan log" table: time, device, token, result badge (green/red), status text.
- Per-token usage bar: `used / max_uses`, show `remaining`; mark exhausted when `remaining == 0`.
- Alerts on repeated `DENIED` for the same token/device (possible misuse).

---

## 6. Testing
1. Get a URL from https://webhook.site and paste it as Callback URL, toggle **Enable**, Save.
2. Scan with the Python simulator `tools/esp32_gui_simulator.py` (server URL locally: `http://localhost:8080`).
3. Verify headers + JSON at webhook.site. Scan past `max_uses` to see a `DENIED` with `Token Usage Limit Reached (n/n)`.

> Note: local development with webhook.site requires outbound internet from the Docker container; HTTPS certificates are verified (`CURLOPT_SSL_VERIFYPEER = true`).
