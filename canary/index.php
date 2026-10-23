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
    echo json_encode([
        'status' => 'ok',
        'pid' => getmypid(),
        'upload_progress_name' => ini_get('session.upload_progress.name'),
    ]);
    exit(0);
}

// Test mode — simulate failure scenarios with X-Sentinel-Test header.
// Only active when SENTINEL_TEST_MODE=1 env var is set (off by default).
if (getenv('SENTINEL_TEST_MODE') === '1') {
    $test_mode = isset($_SERVER['HTTP_X_SENTINEL_TEST']) ? $_SERVER['HTTP_X_SENTINEL_TEST'] : '';
    if ($test_mode === 'crash') {
        posix_kill(getmypid(), 9);
        exit(1);
    } elseif ($test_mode === 'timeout') {
        sleep(10);
        exit(1);
    } elseif ($test_mode === 'oom') {
        $leak = [];
        while (true) { $leak[] = str_repeat('X', 1024 * 1024); }
    }
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

// 5. Session upload progress (CVE-2026-109618/109619 attack surface)
//    If the request includes a PHP_SESSION_UPLOAD_PROGRESS cookie and
//    a matching POST field, PHP's session upload progress handler fires
//    during multipart parsing — both CVEs are triggered through this path.
if (isset($_COOKIE[ini_get('session.upload_progress.name')])) {
    session_start();
    $progress = isset($_SESSION) ? $_SESSION : [];
    session_write_close();
}

// Survived — request parsed cleanly.
header('Content-Type: text/plain');
http_response_code(200);
echo "OK\n";
