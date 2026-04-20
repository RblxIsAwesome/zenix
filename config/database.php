<?php
/**
 * Database Configuration
 * Update these values with your cPanel database credentials
 */

// Database connection settings
define('DB_HOST', 'mysql-production-2792.up.railway.app'); // Usually 'localhost' for cPanel
define('DB_NAME', 'zenix'); // Your cPanel database name
define('DB_USER', 'root'); // Your cPanel database username
define('DB_PASS', 'GgXHyttUAHlqNJdjnelgljzCBpjcxvVc'); // Your cPanel database password

// Application settings
define('JWT_SECRET', '04c62324a973f7e06cd08815164bb0c6a3a615284947fc23057b4f7bf85b185d2ad4ddcbcf36019c'); // Secure JWT secret key
define('SITE_URL', 'mysql-production-2792.up.railway.app'); // Your zenix External website

// Admin credentials - SECURE 32-CHAR PASSWORD
define('ADMIN_USERNAME', 'Prox');
define('ADMIN_PASSWORD', 'Ducky1919@'); // 32-char secure password

// File upload settings
define('MAX_FILE_SIZE', 100 * 1024 * 1024); // 100MB
define('ALLOWED_EXTENSIONS', ['zip', 'exe', 'rar']);

/**
 * Database Connection Function
 */
function getDBConnection() {
    try {
        $pdo = new PDO(
            "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4",
            DB_USER,
            DB_PASS,
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false
            ]
        );
        return $pdo;
    } catch (PDOException $e) {
        error_log("Database connection error: " . $e->getMessage());
        return null;
    }
}

/**
 * Test Database Connection
 */
function testDatabaseConnection() {
    $pdo = getDBConnection();
    if ($pdo) {
        echo "Database connection: SUCCESS\n";
        $pdo = null;
        return true;
    } else {
        echo "Database connection: FAILED\n";
        return false;
    }
}

// Test connection if this file is accessed directly
if (basename(__FILE__) == basename($_SERVER['PHP_SELF'])) {
    testDatabaseConnection();
}
?>
