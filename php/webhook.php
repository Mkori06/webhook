<?php
/**
 * Smart QR Access — Webhook Scan Notification Endpoint (PHP)
 * Spec reference: Section 5 of webhook_handoff_spec.md
 */

require_once __DIR__ . '/config.php';

// 1. Read raw body before any processing (critical for signature calculation)
$rawBody = file_get_contents('php://input');

// 2. Comprehensive Header Extraction (supporting all server SAPI environments)
$headers = [];
if (function_exists('getallheaders')) {
    foreach (getallheaders() as $name => $value) {
        $headers[strtolower($name)] = $value;
    }
}
foreach ($_SERVER as $name => $value) {
    if (str_starts_with($name, 'HTTP_')) {
        $headerKey = strtolower(str_replace('_', '-', substr($name, 5)));
        if (!isset($headers[$headerKey])) {
            $headers[$headerKey] = $value;
        }
    }
}
if (!isset($headers['content-type']) && isset($_SERVER['CONTENT_TYPE'])) {
    $headers['content-type'] = $_SERVER['CONTENT_TYPE'];
}
if (!isset($headers['authorization'])) {
    if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
        $headers['authorization'] = $_SERVER['HTTP_AUTHORIZATION'];
    } elseif (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
        $headers['authorization'] = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
    }
}

$secret = SMARTQR_API_SECRET;
$bearer = SMARTQR_WEBHOOK_BEARER;
$tolerance = TIMESTAMP_TOLERANCE_SECONDS;

$authHeader = $headers['authorization'] ?? '';
$sigHeader  = $headers['x-webhook-signature'] ?? '';
$tsHeader   = $headers['x-webhook-timestamp'] ?? '';

$verification = [
    'bearerChecked' => !empty($bearer),
    'bearerValid' => null,
    'signatureChecked' => !empty($secret),
    'signatureValid' => null,
    'timestampChecked' => !empty($tsHeader),
    'timestampValid' => null,
    'timestampDiffSeconds' => null,
    'computedSignature' => null,
    'isDuplicate' => false,
    'rejectedReason' => null
];

// Helper to log and record rejected webhook attempts for easy debugging
function rejectWebhook($httpCode, $reason, $rawBody, $headers, $verification) {
    http_response_code($httpCode);
    header('Content-Type: application/json');

    $verification['rejectedReason'] = $reason;
    error_log("[WEBHOOK $httpCode REJECTED] $reason");

    // Also persist rejected attempts so they can be inspected in the Web Dashboard
    $payload = json_decode($rawBody, true) ?: ['rawText' => $rawBody];
    $rawSha256 = hash('sha256', $rawBody);

    $record = [
        'id' => bin2hex(random_bytes(8)),
        'receivedAt' => date('c'),
        'rawSha256' => $rawSha256,
        'dedupeKey' => 'REJECTED_' . $rawSha256,
        'headers' => [
            'content-type' => $headers['content-type'] ?? null,
            'accept' => $headers['accept'] ?? null,
            'user-agent' => $headers['user-agent'] ?? null,
            'authorization' => !empty($headers['authorization']) ? (substr($headers['authorization'], 0, 15) . '...') : '(none)',
            'x-webhook-signature' => $headers['x-webhook-signature'] ?? '(none)',
            'x-webhook-timestamp' => $headers['x-webhook-timestamp'] ?? '(none)'
        ],
        'verification' => $verification,
        'payload' => [
            'event' => 'gate_scan',
            'token' => $payload['token'] ?? 'UNKNOWN_REJECTED',
            'device_id' => $payload['device_id'] ?? 'UNKNOWN',
            'scanned_at' => $payload['scanned_at'] ?? date('Y-m-d H:i:s'),
            'result' => 'REJECTED_401',
            'status' => "Rejected: $reason",
            'usage' => $payload['usage'] ?? null,
            'payload_version' => $payload['payload_version'] ?? '1.1'
        ]
    ];

    $events = [];
    if (file_exists(EVENTS_FILE)) {
        $events = json_decode(file_get_contents(EVENTS_FILE), true) ?: [];
    }
    array_unshift($events, $record);
    if (count($events) > 500) $events = array_slice($events, 0, 500);
    @file_put_contents(EVENTS_FILE, json_encode($events, JSON_PRETTY_PRINT));

    echo json_encode(['error' => $reason]);
    exit;
}

// 3. Bearer Token Authentication (Timing-safe comparison)
if (!empty($bearer)) {
    if (empty($authHeader)) {
        $msg = "Missing 'Authorization' header (server requires Bearer token: '$bearer')";
        $verification['bearerValid'] = false;
        rejectWebhook(401, $msg, $rawBody, $headers, $verification);
    }
    $expectedAuth = 'Bearer ' . $bearer;
    $valid = hash_equals($expectedAuth, $authHeader);
    $verification['bearerValid'] = $valid;
    if (!$valid) {
        $msg = "Invalid Authorization Bearer Token. Received: '$authHeader'";
        rejectWebhook(401, $msg, $rawBody, $headers, $verification);
    }
}

// 4. HMAC-SHA256 Signature Verification (Timing-safe comparison)
if (!empty($secret)) {
    $computedSig = hash_hmac('sha256', $rawBody, $secret);
    $verification['computedSignature'] = $computedSig;

    if (empty($sigHeader)) {
        $msg = "Missing 'X-Webhook-Signature' header (server configured with signing secret)";
        $verification['signatureValid'] = false;
        rejectWebhook(401, $msg, $rawBody, $headers, $verification);
    }

    $valid = hash_equals($computedSig, strtolower($sigHeader));
    $verification['signatureValid'] = $valid;
    if (!$valid) {
        $msg = "Invalid HMAC signature. Received: '$sigHeader', Expected: '$computedSig'";
        rejectWebhook(401, $msg, $rawBody, $headers, $verification);
    }
}

// 5. Replay Protection (Timestamp within ±300 seconds)
if (!empty($tsHeader)) {
    $ts = (int)$tsHeader;
    $now = time();
    $diff = abs($now - $ts);
    $verification['timestampDiffSeconds'] = $diff;
    $valid = ($diff <= $tolerance);
    $verification['timestampValid'] = $valid;
    if (!$valid) {
        $msg = "Stale request: timestamp drift of {$diff}s exceeds tolerance of {$tolerance}s";
        rejectWebhook(401, $msg, $rawBody, $headers, $verification);
    }
}

// 6. Fast response: 200 OK (< 3 seconds)
http_response_code(200);
header('Content-Type: application/json');
echo json_encode(['ok' => true]);

// Flush output immediately if supported by fastcgi
if (function_exists('fastcgi_finish_request')) {
    fastcgi_finish_request();
} else {
    if (ob_get_level() > 0) {
        ob_end_flush();
    }
    flush();
}

// 7. Post-response processing & persistence
$payload = json_decode($rawBody, true);
$rawSha256 = hash('sha256', $rawBody);
$dedupeKey = ($payload && isset($payload['token'], $payload['device_id'], $payload['scanned_at'], $payload['result']))
    ? ($payload['token'] . '|' . $payload['device_id'] . '|' . $payload['scanned_at'] . '|' . $payload['result'])
    : $rawSha256;

// Load existing events
$events = [];
if (file_exists(EVENTS_FILE)) {
    $content = file_get_contents(EVENTS_FILE);
    $events = json_decode($content, true) ?: [];
}

$isDuplicate = false;
foreach ($events as $e) {
    if (($e['rawSha256'] ?? '') === $rawSha256 || ($e['dedupeKey'] ?? '') === $dedupeKey) {
        $isDuplicate = true;
        break;
    }
}
$verification['isDuplicate'] = $isDuplicate;

$record = [
    'id' => bin2hex(random_bytes(8)),
    'receivedAt' => date('c'),
    'rawSha256' => $rawSha256,
    'dedupeKey' => $dedupeKey,
    'headers' => [
        'content-type' => $headers['content-type'] ?? null,
        'accept' => $headers['accept'] ?? null,
        'user-agent' => $headers['user-agent'] ?? null,
        'authorization' => !empty($authHeader) ? (substr($authHeader, 0, 15) . '...') : null,
        'x-webhook-signature' => $sigHeader,
        'x-webhook-timestamp' => $tsHeader
    ],
    'verification' => $verification,
    'payload' => $payload ?: ['rawText' => $rawBody]
];

array_unshift($events, $record);
if (count($events) > 500) {
    $events = array_slice($events, 0, 500);
}

@file_put_contents(EVENTS_FILE, json_encode($events, JSON_PRETTY_PRINT));
error_log("[WEBHOOK 200 OK] " . ($payload['result'] ?? 'PROCESSED') . " | Token: " . ($payload['token'] ?? 'N/A'));
