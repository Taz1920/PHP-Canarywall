<?php
header('Content-Type: text/html');
echo "<h1>PHP Backend</h1>";
echo "<p>This request was validated by PHP Sentinel.</p>";
echo "<p>Method: " . htmlspecialchars($_SERVER['REQUEST_METHOD']) . "</p>";
echo "<p>Time: " . date('Y-m-d H:i:s') . "</p>";
