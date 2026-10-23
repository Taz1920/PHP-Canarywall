<?php
/**
 * PHP Sentinel — Canary Endpoint
 *
 * Forces PHP to fully parse the request through every SAPI code path
 * that php2shell targets: multipart boundary parsing, session upload
 * progress callbacks, POST body handling, and OOM cleanup.
 *
 * If the worker survives, the request is clean.
 * If the worker crashes, the proxy catches it (502) and drops the request.
 */

// Health check
if ($_SERVER['REQUEST_URI'] === '/__canary/health') {
    header('Content-Type: application/json');
    echo json_encode(['status' => 'ok', 'pid' => getmypid()]);
    exit(0);
}

// Test mode — simulate failure scenarios with X-Sentinel-Test header.
// Remove this block in production.
$test_mode = isset($_SERVER['HTTP_X_SENTINEL_TEST']) ? $_SERVER['HTTP_X_SENTINEL_TEST'] : '';
if ($test_mode === 'crash') {
    // Kill the worker hard — SIGKILL can't be caught, FPM worker dies, nginx returns 502
    posix_kill(getmypid(), 9);
    exit(1);
} elseif ($test_mode === 'timeout') {
    // Simulate a hung worker — exceeds request_terminate_timeout (3s)
    sleep(10);
    exit(1);
} elseif ($test_mode === 'oom') {
    // Simulate OOM — allocate until the worker is killed
    $leak = [];
    while (true) { $leak[] = str_repeat('X', 1024 * 1024); }
}

// Force PHP to fully populate all request superglobals.
// This exercises the SAPI parsing paths that php2shell exploits.

// 1. POST body parsing (multipart boundary handling)
$post = $_POST;

// 2. File upload parsing (multipart file sections)
//    PHP streams uploads to disk — read them back into memory so oversized
//    uploads hit memory_limit the same way raw bodies do.
$files = $_FILES;
foreach ($_FILES as $f) {
    $tmp = is_array($f['tmp_name']) ? $f['tmp_name'] : array($f['tmp_name']);
    foreach ($tmp as $path) {
        if ($path && is_uploaded_file($path)) {
            $data = file_get_contents($path);
        }
    }
}

// 3. Cookie parsing
$cookies = $_COOKIE;

// 4. Raw input (php://input)
$raw = file_get_contents('php://input');

// 5. Session upload progress (CVE-2026-109619 vector)
//    If the request includes a PHP_SESSION_UPLOAD_PROGRESS cookie and
//    a matching POST field, PHP's session upload progress handler fires
//    during multipart parsing — this is the exact code path the
//    use-after-free lives in.
if (isset($_COOKIE[ini_get('session.upload_progress.name')])) {
    session_start();
    $progress = isset($_SESSION) ? $_SESSION : [];
    session_write_close();
}

// Survived — request parsed cleanly.
header('Content-Type: text/plain');
http_response_code(200);
echo "OK\n";
