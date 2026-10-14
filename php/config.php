<?php
/**
 * Configuration loader for Smart QR Webhook Receiver (PHP)
 */

function loadEnv($path = __DIR__ . '/.env') {
    if (!file_exists($path)) {
        return;
    }
    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) {
            continue;
        }
        $parts = explode('=', $line, 2);
        if (count($parts) === 2) {
            $name = trim($parts[0]);
            $val = trim($parts[1]);
            // Strip surrounding quotes if present
            if ((str_starts_with($val, '"') && str_ends_with($val, '"')) ||
                (str_starts_with($val, "'") && str_ends_with($val, "'"))) {
                $val = substr($val, 1, -1);
            }
            if (!isset($_SERVER[$name]) && !isset($_ENV[$name])) {
                putenv("$name=$val");
                $_ENV[$name] = $val;
                $_SERVER[$name] = $val;
            }
        }
    }
}

loadEnv();

function config($key, $default = null) {
    $val = getenv($key);
    if ($val !== false && $val !== '') {
        return $val;
    }
    if (isset($_ENV[$key])) {
        return $_ENV[$key];
    }
    if (isset($_SERVER[$key])) {
        return $_SERVER[$key];
    }
    return $default;
}

define('SMARTQR_API_SECRET', config('SMARTQR_API_SECRET', ''));
define('SMARTQR_WEBHOOK_BEARER', config('SMARTQR_WEBHOOK_BEARER', ''));
define('TIMESTAMP_TOLERANCE_SECONDS', (int)config('TIMESTAMP_TOLERANCE_SECONDS', 300));
define('DATA_DIR', __DIR__ . '/data');
define('EVENTS_FILE', DATA_DIR . '/events.json');

// Ensure data folder exists
if (!is_dir(DATA_DIR)) {
    @mkdir(DATA_DIR, 0777, true);
}
