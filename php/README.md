# Smart QR Access — Webhook Receiver & Test Suite (PHP)

A standalone, dependency-free webhook testing receiver and live dashboard for the **Smart QR Access** gate scan webhook notifications, built strictly adhering to `webhook_handoff_spec.md`.

---

## Features
- **Strict Spec Verification:**
  - Reads raw body via `php://input` before JSON decoding.
  - Constant-time HMAC-SHA256 signature verification via `hash_equals()`.
  - Constant-time Bearer token verification via `hash_equals()`.
  - Replay attack mitigation with 300s window (`abs(time() - ts) <= 300`).
  - Fast 200 OK response (`{"ok": true}`).
  - Event deduplication and storage in `data/events.json`.
- **Zero Composer Dependencies:**
  - Works directly with standard PHP 8.0+ or XAMPP PHP.
- **Modern Dashboard UI:**
  - Auto-refreshing scan feed with metrics (Total, Allowed, Denied).
  - Usage progress bars: `used / max_uses`, `remaining`, and visual depletion alert.
  - Inspect Modal with complete payload JSON, verification breakdown, and headers.
  - Direct 1-click webhook simulation triggers from the UI!

---

## Quick Start

### 1. Configure Environment
Copy `.env.example` to `.env` (or use the defaults):
```env
SMARTQR_API_SECRET=my_smartqr_test_secret_123
SMARTQR_WEBHOOK_BEARER=test_bearer_token_xyz
TIMESTAMP_TOLERANCE_SECONDS=300
```
- `SMARTQR_API_SECRET`: Set to the `api_secret` from your Smart QR Access client account.
- `SMARTQR_WEBHOOK_BEARER`: Set if you specified a Bearer token in the Developer Portal.

### 2. Start the Server
```bash
# Option A: Double click start.bat (on Windows)
# Option B: Run via CLI (using your PHP executable):
php -S localhost:8000
# (or with XAMPP PHP):
"D:\xampp\php\php.exe" -S localhost:8000
```
Access the server:
- **Dashboard UI:** `http://localhost:8000/`
- **Webhook Endpoint:** `http://localhost:8000/webhook.php`

### 3. Test with the CLI Simulator
In another terminal:
```bash
# Test valid ALLOWED scan:
php test_sender.php allowed

# Test valid DENIED scan (limit reached):
php test_sender.php denied

# Test rejection on bad HMAC signature (expects HTTP 401):
php test_sender.php bad_sig

# Test rejection on stale timestamp (expects HTTP 401):
php test_sender.php stale

# Run all test cases in sequence:
php test_sender.php all
```

---

## Exposing for Smart QR Access Platform Testing
The Smart QR Access platform requires an HTTPS callback URL:
1. Expose your local port via **Cloudflare Tunnel** or **ngrok**:
   ```bash
   ngrok http 8000
   ```
2. In the Smart QR Access Developer Portal:
   - Click navbar **"Webhook Setup"**
   - Toggle **Enable**
   - Set **Callback URL**: `https://<your-tunnel-subdomain>.ngrok-free.app/webhook.php`
   - Set **Bearer Token** to match `SMARTQR_WEBHOOK_BEARER` in `.env`
   - Click **Save**
3. Scan a QR code using the gate simulator `tools/esp32_gui_simulator.py` or gate device. The scan event will appear in the dashboard!
