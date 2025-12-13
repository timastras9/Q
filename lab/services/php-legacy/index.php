<?php
/**
 * Legacy PHP Application - Intentionally Vulnerable
 * Contains: SQLi, XSS, LFI, RCE, Insecure Deserialization
 */

error_reporting(E_ALL); // VULNERABILITY: Shows errors in production
ini_set('display_errors', 1);

// VULNERABILITY: Hardcoded database credentials
$db_host = 'mysql';
$db_user = 'root';
$db_pass = 'root123';
$db_name = 'legacy_app';

// Database connection (would be used if MySQL is available)
// $conn = new mysqli($db_host, $db_user, $db_pass, $db_name);

// Simulated user data
$users = [
    ['id' => 1, 'username' => 'admin', 'password' => md5('admin123'), 'email' => 'admin@company.com', 'role' => 'admin'],
    ['id' => 2, 'username' => 'john', 'password' => md5('password'), 'email' => 'john@company.com', 'role' => 'user'],
    ['id' => 3, 'username' => 'guest', 'password' => md5('guest'), 'email' => 'guest@company.com', 'role' => 'guest'],
];

session_start();

?>
<!DOCTYPE html>
<html>
<head>
    <title>Legacy Internal Portal</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        .vuln-section { margin: 20px 0; padding: 20px; background: #fff3cd; border: 1px solid #ffc107; border-radius: 4px; }
        input, textarea { padding: 10px; margin: 5px 0; width: 100%; box-sizing: border-box; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; cursor: pointer; }
        pre { background: #f4f4f4; padding: 10px; overflow-x: auto; }
        .error { color: red; }
        .success { color: green; }
    </style>
</head>
<body>
<div class="container">
    <h1>Legacy Internal Portal v1.0</h1>

    <!-- VULNERABILITY 1: SQL Injection -->
    <div class="vuln-section">
        <h3>1. User Search (SQL Injection)</h3>
        <form method="GET">
            <input type="text" name="search" placeholder="Search username..." value="<?php echo @$_GET['search']; ?>">
            <button type="submit">Search</button>
        </form>
        <?php
        if (isset($_GET['search'])) {
            $search = $_GET['search'];
            // VULNERABILITY: Direct SQL injection (simulated)
            echo "<p>Query: SELECT * FROM users WHERE username LIKE '%$search%'</p>";

            // Simulate results
            foreach ($users as $user) {
                if (stripos($user['username'], $search) !== false || $search === "' OR '1'='1") {
                    echo "<pre>Found: " . htmlspecialchars($user['username']) . " - " . $user['email'] . "</pre>";
                }
            }

            // Show injection worked
            if (strpos($search, "'") !== false) {
                echo "<p class='success'>SQL Injection detected! Query modified.</p>";
            }
        }
        ?>
    </div>

    <!-- VULNERABILITY 2: Reflected XSS -->
    <div class="vuln-section">
        <h3>2. Welcome Message (Reflected XSS)</h3>
        <form method="GET">
            <input type="text" name="name" placeholder="Enter your name" value="<?php echo @$_GET['name']; ?>">
            <button type="submit">Greet</button>
        </form>
        <?php
        if (isset($_GET['name'])) {
            // VULNERABILITY: No output encoding
            echo "<h4>Welcome, " . $_GET['name'] . "!</h4>";
        }
        ?>
    </div>

    <!-- VULNERABILITY 3: Local File Inclusion -->
    <div class="vuln-section">
        <h3>3. Documentation Viewer (LFI)</h3>
        <form method="GET">
            <input type="text" name="page" placeholder="Page name (e.g., about)" value="<?php echo @$_GET['page']; ?>">
            <button type="submit">View Page</button>
        </form>
        <?php
        if (isset($_GET['page'])) {
            $page = $_GET['page'];
            // VULNERABILITY: Path traversal / LFI
            $file = "pages/" . $page . ".php";
            echo "<p>Loading: $file</p>";

            if (file_exists($file)) {
                include($file);
            } else {
                // Also try without extension for more flexibility (worse)
                $file2 = "pages/" . $page;
                if (file_exists($file2)) {
                    include($file2);
                } else {
                    // Try direct path (worst)
                    if (file_exists($page)) {
                        echo "<pre>" . htmlspecialchars(file_get_contents($page)) . "</pre>";
                    } else {
                        echo "<p class='error'>Page not found: $page</p>";
                    }
                }
            }
        }
        ?>
    </div>

    <!-- VULNERABILITY 4: Command Injection -->
    <div class="vuln-section">
        <h3>4. Server Diagnostics (Command Injection)</h3>
        <form method="POST">
            <input type="text" name="host" placeholder="Host to ping" value="<?php echo @$_POST['host']; ?>">
            <button type="submit" name="ping">Ping Host</button>
        </form>
        <?php
        if (isset($_POST['ping']) && isset($_POST['host'])) {
            $host = $_POST['host'];
            // VULNERABILITY: Command injection
            $output = shell_exec("ping -c 2 " . $host . " 2>&1");
            echo "<pre>$output</pre>";
        }
        ?>
    </div>

    <!-- VULNERABILITY 5: Insecure File Upload -->
    <div class="vuln-section">
        <h3>5. Profile Picture Upload (Unrestricted Upload)</h3>
        <form method="POST" enctype="multipart/form-data">
            <input type="file" name="avatar">
            <button type="submit" name="upload">Upload</button>
        </form>
        <?php
        if (isset($_POST['upload']) && isset($_FILES['avatar'])) {
            $uploadDir = 'uploads/';
            if (!is_dir($uploadDir)) mkdir($uploadDir, 0777, true);

            // VULNERABILITY: No file type validation
            $filename = $_FILES['avatar']['name'];
            $targetPath = $uploadDir . $filename;

            if (move_uploaded_file($_FILES['avatar']['tmp_name'], $targetPath)) {
                echo "<p class='success'>Uploaded to: <a href='$targetPath'>$targetPath</a></p>";
            } else {
                echo "<p class='error'>Upload failed</p>";
            }
        }
        ?>
    </div>

    <!-- VULNERABILITY 6: Insecure Deserialization -->
    <div class="vuln-section">
        <h3>6. Session Restore (Insecure Deserialization)</h3>
        <form method="POST">
            <textarea name="session_data" placeholder="Paste session data (base64 encoded)"></textarea>
            <button type="submit" name="restore">Restore Session</button>
        </form>
        <?php
        // Vulnerable class
        class UserSession {
            public $username;
            public $role;
            public $logFile;

            function __wakeup() {
                // VULNERABILITY: Arbitrary file write on deserialization
                if ($this->logFile) {
                    file_put_contents($this->logFile, "Session restored for: " . $this->username);
                }
            }
        }

        if (isset($_POST['restore']) && isset($_POST['session_data'])) {
            $data = base64_decode($_POST['session_data']);
            // VULNERABILITY: Unserialize user input
            $session = unserialize($data);
            if ($session) {
                echo "<p class='success'>Session restored for: " . htmlspecialchars($session->username) . "</p>";
            }
        }
        ?>
    </div>

    <!-- VULNERABILITY 7: SSRF -->
    <div class="vuln-section">
        <h3>7. URL Fetcher (SSRF)</h3>
        <form method="POST">
            <input type="text" name="url" placeholder="URL to fetch" value="<?php echo @$_POST['url']; ?>">
            <button type="submit" name="fetch">Fetch URL</button>
        </form>
        <?php
        if (isset($_POST['fetch']) && isset($_POST['url'])) {
            $url = $_POST['url'];
            // VULNERABILITY: SSRF - no URL validation
            $content = @file_get_contents($url);
            if ($content) {
                echo "<pre>" . htmlspecialchars(substr($content, 0, 5000)) . "</pre>";
            } else {
                echo "<p class='error'>Could not fetch URL</p>";
            }
        }
        ?>
    </div>

    <!-- VULNERABILITY 8: Hardcoded Secrets in Comments -->
    <!--
        TODO: Remove before production
        Admin password: SuperSecretAdmin2024!
        API Key: sk-live-abc123xyz789
        Database backup at: /var/backups/db_dump.sql
        SSH key location: /home/deploy/.ssh/id_rsa
    -->

    <!-- VULNERABILITY 9: Debug Information Disclosure -->
    <div class="vuln-section">
        <h3>8. System Information</h3>
        <?php
        if (isset($_GET['debug'])) {
            echo "<h4>Server Information:</h4>";
            echo "<pre>";
            echo "PHP Version: " . phpversion() . "\n";
            echo "Server: " . $_SERVER['SERVER_SOFTWARE'] . "\n";
            echo "Document Root: " . $_SERVER['DOCUMENT_ROOT'] . "\n";
            echo "Current User: " . get_current_user() . "\n";
            phpinfo(); // VULNERABILITY: Full phpinfo exposed
            echo "</pre>";
        } else {
            echo "<p><a href='?debug=1'>Show Debug Info</a></p>";
        }
        ?>
    </div>

    <!-- VULNERABILITY 10: Weak Password Storage -->
    <div class="vuln-section">
        <h3>9. Login (Weak Password Hashing)</h3>
        <form method="POST">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit" name="login">Login</button>
        </form>
        <?php
        if (isset($_POST['login'])) {
            $username = $_POST['username'];
            $password = $_POST['password'];

            // VULNERABILITY: MD5 for password hashing
            $hash = md5($password);

            foreach ($users as $user) {
                if ($user['username'] === $username && $user['password'] === $hash) {
                    $_SESSION['user'] = $user;
                    echo "<p class='success'>Logged in as: " . htmlspecialchars($username) . "</p>";
                    echo "<p>Password hash (MD5): $hash</p>"; // Info leak
                    break;
                }
            }
        }
        ?>
    </div>

    <hr>
    <p style="color: #999; font-size: 12px;">
        Legacy Portal v1.0 - Internal Use Only<br>
        Contact IT: admin@internal.company.local
    </p>
</div>
</body>
</html>
