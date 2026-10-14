<?php
/**
 * Smart QR Webhook Testing Dashboard - Backend API (PHP)
 */

require_once __DIR__ . '/config.php';
header('Content-Type: application/json');

$action = $_GET['action'] ?? 'events';

if ($action === 'events') {
    $events = [];
    if (file_exists(EVENTS_FILE)) {
        $content = file_get_contents(EVENTS_FILE);
        $events = json_decode($content, true) ?: [];
    }

    $allowed = 0;
    $denied = 0;
    foreach ($events as $e) {
        $res = $e['payload']['result'] ?? '';
        if ($res === 'ALLOWED') $allowed++;
        elseif ($res === 'DENIED' || $res === 'REJECTED_401') $denied++;
    }

    echo json_encode([
        'stats' => [
            'total' => count($events),
            'allowed' => $allowed,
            'denied' => $denied
        ],
        'config' => [
            'secretConfigured' => !empty(SMARTQR_API_SECRET),
            'bearerConfigured' => !empty(SMARTQR_WEBHOOK_BEARER),
            'toleranceSeconds' => TIMESTAMP_TOLERANCE_SECONDS
        ],
        'events' => $events
    ]);
    exit;
}

if ($action === 'clear' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    @file_put_contents(EVENTS_FILE, json_encode([]));
    echo json_encode(['ok' => true, 'message' => 'Events cleared']);
    exit;
}

if ($action === 'simulate' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $type = $input['type'] ?? 'allowed';
    $customToken = $input['token'] ?? ('PHP_' . strtoupper(bin2hex(random_bytes(4))));
    $deviceId = $input['device_id'] ?? 'DEV-GATE-001D848D';

    $scannedAt = date('Y-m-d H:i:s'); // IST local server time

    $payload = [
        'event' => 'gate_scan',
        'token' => $customToken,
        'device_id' => $deviceId,
        'scanned_at' => $scannedAt,
        'result' => ($type === 'denied') ? 'DENIED' : 'ALLOWED',
        'status' => ($type === 'denied') ? 'Token Usage Limit Reached (2/2)' : 'Access Granted (Gate Unlocked)',
        'usage' => [
            'max_uses' => 2,
            'used' => ($type === 'denied') ? 2 : 1,
            'remaining' => ($type === 'denied') ? 0 : 1,
            'token_status' => ($type === 'denied') ? 'USED' : 'ACTIVE',
            'expires_at' => '2026-10-31 23:59:59'
        ],
        'payload_version' => '1.1'
    ];

    $raw = json_encode($payload);
    $ts = time();
    if ($type === 'stale') {
        $ts -= 600; // 10 mins ago
    }

    $bearer = SMARTQR_WEBHOOK_BEARER;
    if ($type === 'bad_bearer') {
        $bearer = 'INVALID_PHP_BEARER';
    }

    $sig = '';
    if (!empty(SMARTQR_API_SECRET)) {
        if ($type === 'bad_sig') {
            $sig = 'bad000000000000000000000000000000000000000000000000000000000beef';
        } else {
            $sig = hash_hmac('sha256', $raw, SMARTQR_API_SECRET);
        }
    }

    // Call local webhook.php directly or via HTTP
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost:8000';
    $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
    $webhookUrl = "$scheme://$host/webhook.php";

    $httpHeaders = [
        'Content-Type: application/json',
        'Accept: application/json',
        'User-Agent: SmartQR-Access-Webhook/1.0',
        "X-Webhook-Timestamp: $ts"
    ];
    if ($bearer) $httpHeaders[] = "Authorization: Bearer $bearer";
    if ($sig) $httpHeaders[] = "X-Webhook-Signature: $sig";

    $opts = [
        'http' => [
            'method' => 'POST',
            'header' => implode("\r\n", $httpHeaders),
            'content' => $raw,
            'ignore_errors' => true,
            'timeout' => 3
        ]
    ];

    $context = stream_context_create($opts);
    $responseBody = @file_get_contents($webhookUrl, false, $context);

    $statusCode = 200;
    if (isset($http_response_header[0]) && preg_match('{HTTP\/\S*\s(\d{3})}', $http_response_header[0], $m)) {
        $statusCode = (int)$m[1];
    }

    echo json_encode([
        'simulatedType' => $type,
        'status' => $statusCode,
        'response' => json_decode($responseBody, true) ?: $responseBody
    ]);
    exit;
}

http_response_code(400);
echo json_encode(['error' => 'Unknown action']);
