<?php
session_start();
$page = isset($_GET['page']) ? $_GET['page'] : 'home';
$message = '';

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($page === 'upload' && isset($_FILES['file'])) {
        $f = $_FILES['file'];
        if ($f['error'] === UPLOAD_ERR_OK) {
            $message = "Uploaded: " . htmlspecialchars($f['name']) . " (" . number_format($f['size']) . " bytes)";
        } else {
            $message = "Upload error code: " . $f['error'];
        }
    } elseif ($page === 'contact') {
        $name = isset($_POST['name']) ? $_POST['name'] : '';
        $email = isset($_POST['email']) ? $_POST['email'] : '';
        $body = isset($_POST['message']) ? $_POST['message'] : '';
        $message = "Message received from " . htmlspecialchars($name) . " &lt;" . htmlspecialchars($email) . "&gt;";
    } elseif ($page === 'login') {
        $user = isset($_POST['username']) ? $_POST['username'] : '';
        $pass = isset($_POST['password']) ? $_POST['password'] : '';
        if ($user === 'admin' && $pass === 'admin') {
            $_SESSION['user'] = $user;
            $message = "Logged in as " . htmlspecialchars($user);
        } else {
            $message = "Invalid credentials";
        }
    }
}

if ($page === 'logout') {
    session_destroy();
    header('Location: ?page=home');
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Test App</title>
<style>
body { font-family: sans-serif; max-width: 700px; margin: 40px auto; padding: 0 20px; }
nav { background: #333; padding: 10px; margin-bottom: 20px; }
nav a { color: #fff; text-decoration: none; margin-right: 15px; }
nav a:hover { text-decoration: underline; }
.msg { background: #e8f5e9; border: 1px solid #4caf50; padding: 10px; margin-bottom: 15px; }
.err { background: #ffebee; border: 1px solid #f44336; }
form { margin-bottom: 20px; }
label { display: block; margin: 8px 0 4px; font-weight: bold; }
input, textarea, select { width: 100%; padding: 8px; box-sizing: border-box; margin-bottom: 10px; }
button { background: #333; color: #fff; border: none; padding: 10px 20px; cursor: pointer; }
table { width: 100%; border-collapse: collapse; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background: #f5f5f5; }
</style>
</head>
<body>
<nav>
<a href="?page=home">Home</a>
<a href="?page=upload">Upload</a>
<a href="?page=contact">Contact</a>
<a href="?page=search">Search</a>
<a href="?page=login"><?php echo isset($_SESSION['user']) ? 'Profile' : 'Login'; ?></a>
<?php if (isset($_SESSION['user'])): ?><a href="?page=logout">Logout</a><?php endif; ?>
</nav>

<?php if ($message): ?>
<div class="msg"><?php echo $message; ?></div>
<?php endif; ?>

<?php if ($page === 'home'): ?>
<h1>Test PHP App</h1>
<p>A basic PHP app for testing Sentinel in shadow mode. Exercises common request patterns:</p>
<ul>
<li>GET requests with query strings</li>
<li>POST form submissions (multipart and urlencoded)</li>
<li>File uploads</li>
<li>Session/cookie handling</li>
<li>Various content types</li>
</ul>
<table>
<tr><th>Server</th><td><?php echo htmlspecialchars($_SERVER['SERVER_SOFTWARE'] ?? 'unknown'); ?></td></tr>
<tr><th>PHP</th><td><?php echo phpversion(); ?></td></tr>
<tr><th>Time</th><td><?php echo date('Y-m-d H:i:s'); ?></td></tr>
<tr><th>Method</th><td><?php echo htmlspecialchars($_SERVER['REQUEST_METHOD']); ?></td></tr>
<tr><th>Session</th><td><?php echo session_id(); ?></td></tr>
</table>

<?php elseif ($page === 'upload'): ?>
<h1>File Upload</h1>
<form method="POST" enctype="multipart/form-data">
<label>Choose a file:</label>
<input type="file" name="file" required>
<label>Description:</label>
<input type="text" name="description" placeholder="Optional description">
<button type="submit">Upload</button>
</form>

<?php elseif ($page === 'contact'): ?>
<h1>Contact Form</h1>
<form method="POST">
<label>Name:</label>
<input type="text" name="name" required>
<label>Email:</label>
<input type="email" name="email" required>
<label>Subject:</label>
<select name="subject">
<option>General</option>
<option>Support</option>
<option>Billing</option>
</select>
<label>Message:</label>
<textarea name="message" rows="5" required></textarea>
<button type="submit">Send</button>
</form>

<?php elseif ($page === 'search'): ?>
<h1>Search</h1>
<form method="GET">
<input type="hidden" name="page" value="search">
<input type="text" name="q" placeholder="Search..." value="<?php echo htmlspecialchars(isset($_GET['q']) ? $_GET['q'] : ''); ?>">
<button type="submit">Search</button>
</form>
<?php if (isset($_GET['q']) && $_GET['q'] !== ''): ?>
<p>Results for: <strong><?php echo htmlspecialchars($_GET['q']); ?></strong></p>
<p>No results found. (This is a test app.)</p>
<?php endif; ?>

<?php elseif ($page === 'login'): ?>
<?php if (isset($_SESSION['user'])): ?>
<h1>Profile</h1>
<p>Logged in as: <strong><?php echo htmlspecialchars($_SESSION['user']); ?></strong></p>
<p>Session ID: <?php echo session_id(); ?></p>
<?php else: ?>
<h1>Login</h1>
<form method="POST">
<label>Username:</label>
<input type="text" name="username" required>
<label>Password:</label>
<input type="password" name="password" required>
<button type="submit">Login</button>
</form>
<p><small>Hint: admin / admin</small></p>
<?php endif; ?>

<?php endif; ?>

<hr>
<small>Validated by PHP Sentinel | <?php echo date('Y-m-d H:i:s'); ?></small>
</body>
</html>
