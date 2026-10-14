# Smart QR Access — Webhook Testing Projects

This repository contains two complete, standalone webhook testing receiver suites built strictly according to [`webhook_handoff_spec.md`](./webhook_handoff_spec.md):

1. **[`nodejs/`](./nodejs/)** — Node.js & Express receiver with real-time Server-Sent Events (SSE) live feed, interactive dashboard, and automated test sender.
2. **[`php/`](./php/)** — Standalone PHP receiver with zero dependencies (runs on PHP 8.0+ / XAMPP), live dashboard, and test sender.

---

## Comparison & Summary

| Feature | Node.js Suite (`nodejs/`) | PHP Suite (`php/`) |
|---|---|---|
| **Runtime** | Node.js 18+ (Express) | PHP 8.0+ (Standard / XAMPP) |
| **Default Port** | `3000` | `8000` |
| **Webhook Endpoint** | `/webhooks/gate-scan` | `/webhook.php` |
| **Dashboard UI** | `http://localhost:3000/` | `http://localhost:8000/` |
| **Live Updates** | Server-Sent Events (SSE) | Auto-polling (2.5s) |
| **Quick Launch** | `start.bat` or `npm start` | `start.bat` or `php -S localhost:8000` |
| **Test Sender** | `npm run test:send` / `node test_sender.js` | `php test_sender.php` |
| **Dependencies** | `express`, `dotenv` | Zero dependencies |

---

## Security Verification Features Included in Both
- ✅ **Raw Body HMAC-SHA256 Verification:** Constant-time `crypto.timingSafeEqual` / `hash_equals` against `X-Webhook-Signature`.
- ✅ **Bearer Token Auth:** Constant-time check on `Authorization: Bearer <token>`.
- ✅ **Replay Attack Protection:** Validates `X-Webhook-Timestamp` within ±300s window.
- ✅ **Fast 200 OK (< 3s):** Returns fast response before heavy operations.
- ✅ **Deduplication:** Hash and tuple idempotency checking.
- ✅ **Inspection Dashboard:** Web UI displaying live stats, token usage progress bars, ALLOWED/DENIED badges, and raw JSON headers inspection.
