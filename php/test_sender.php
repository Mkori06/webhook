<?php
/**
 * Smart QR Access — Webhook Test Sender CLI (PHP)
 * Simulates gate scan webhooks with real HMAC-SHA256 signatures and timestamps.
 */

require_once __DIR__ . '/config.php';

$targetUrl = getenv('TEST_TARGET_URL') ?: 'http://localhost:8000/webhook.php';
$secret = SMARTQR_API_SECRET ?: 'my_smartqr_test_secret_123';
$bearer = SMARTQR_WEBHOOK_BEARER ?: 'test_bearer_token_xyz';

$scenario = $argv[1] ?? 'allowed';

function generatePayload($type) {
    $now = date('Y-m-d H:i:s');
    $rand = strtoupper(bin2hex(random_bytes(4)));

    if ($type === 'denied' || $type === 'denied_limit') {
        return [
            'event' => 'gate_scan',
            'token' => "DENIED_$rand",
            'device_id' => 'DEV-GATE-001D848D',
            'scanned_at' => $now,
            'result' => 'DENIED',
            'status' => 'Token Usage Limit Reached (2/2)',
            'usage' => [
                'max_uses' => 2,
                'used' => 2,
                'remaining' => 0,
                'token_status' => 'USED',
                'expires_at' => '2026-10-31 23:59:59'
            ],
            'payload_version' => '1.1'
        ];
    }

    if ($type === 'denied_not_found') {
        return [
            'event' => 'gate_scan',
            'token' => "UNKNOWN_$rand",
            'device_id' => 'DEV-GATE-001D848D',
            'scanned_at' => $now,
            'result' => 'DENIED',
            'status' => 'Token Not Found in Database',
            'usage' => null,
            'payload_version' => '1.1'
        ];
    }

    return [
        'event' => 'gate_scan',
        'token' => "ALLOW_$rand",
        'device_id' => 'DEV-GATE-001D848D',
        'scanned_at' => $now,
        'result' => 'ALLOWED',
        'status' => 'Access Granted (Gate Unlocked)',
        'usage' => [
            'max_uses' => 2,
            'used' => 1,
            'remaining' => 1,
            'token_status' => 'ACTIVE',
            'expires_at' => '2026-10-31 23:59:59'
        ],
        'payload_version' => '1.1'
    ];
}

function sendTest($scenario, $targetUrl, $secret, $bearer) {
    echo "\n======================================================\n";
    echo "🚀 Dispatching Test Webhook: [" . strtoupper($scenario) . "]\n";
    echo "Target URL: $targetUrl\n";

    $payload = generatePayload($scenario);
    $rawBody = json_encode($payload);

    $timestamp = time();
    if ($scenario === 'stale') {
        $timestamp -= 600; // 10 minutes ago
        echo "⚠️  Intentionally sending stale timestamp: $timestamp (-600s)\n";
    }

    $activeBearer = $bearer;
    if ($scenario === 'bad_bearer') {
        $activeBearer = 'INVALID_INCORRECT_BEARER';
        echo "⚠️  Intentionally sending wrong Bearer token\n";
    }

    $signature = '';
    if (!empty($secret)) {
        if ($scenario === 'bad_sig') {
            $signature = 'deadbeef0000000000000000000000000000000000000000000000000000bad0';
            echo "⚠️  Intentionally sending corrupted HMAC signature\n";
        } else {
            $signature = hash_hmac('sha256', $rawBody, $secret);
        }
    }

    $headers = [
        'Content-Type: application/json',
        'Accept: application/json',
        'User-Agent: SmartQR-Access-Webhook/1.0',
        "X-Webhook-Timestamp: $timestamp"
    ];
    if (!empty($activeBearer)) {
        $headers[] = "Authorization: Bearer $activeBearer";
    }
    if (!empty($signature)) {
        $headers[] = "X-Webhook-Signature: $signature";
    }

    $ch = curl_init($targetUrl);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $rawBody);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);

    if ($error) {
        echo "❌ Network error: $error\n";
        return;
    }

    echo "📥 Response Status: $httpCode\n";
    echo "📥 Response Body:   $response\n";

    if ($httpCode === 200) {
        echo "✅ SUCCESS: Webhook accepted!\n";
    } elseif ($httpCode === 401 && in_array($scenario, ['bad_sig', 'bad_bearer', 'stale'])) {
        echo "✅ EXPECTED REJECTION: Endpoint correctly rejected invalid/stale webhook!\n";
    } else {
        echo "❌ FAILED: Unexpected status code.\n";
    }
    echo "======================================================\n";
}

if ($scenario === 'all') {
    foreach (['allowed', 'denied', 'bad_sig', 'bad_bearer', 'stale'] as $s) {
        sendTest($s, $targetUrl, $secret, $bearer);
        usleep(300000); // 300ms pause
    }
} else {
    sendTest($scenario, $targetUrl, $secret, $bearer);
}
