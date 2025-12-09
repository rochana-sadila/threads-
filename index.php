<?php
/**
 * Hela-Threads Discussion Board Application
 * Main Entry Point
 * 
 * @package HelaThreads
 * @version 1.0.0
 * @author rochana-sadila
 */

// Define application root path
define('ROOT_PATH', dirname(__FILE__));
define('APP_VERSION', '1.0.0');
define('APP_NAME', 'Hela-Threads');

// Error reporting
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Include configuration file
require_once ROOT_PATH . '/config/config.php';

// Include database connection
require_once ROOT_PATH . '/config/database.php';

// Include autoloader
require_once ROOT_PATH . '/includes/Autoloader.php';

// Start session
session_start();

// Initialize application
try {
    // Load routing system
    require_once ROOT_PATH . '/includes/Router.php';
    
    // Get requested URI
    $request_uri = $_SERVER['REQUEST_URI'];
    $request_method = $_SERVER['REQUEST_METHOD'];
    
    // Route the request
    $router = new Router();
    $router->route($request_uri, $request_method);
    
} catch (Exception $e) {
    // Log error
    error_log($e->getMessage());
    
    // Display error page
    http_response_code(500);
    include ROOT_PATH . '/views/error.php';
    exit;
}

?>
