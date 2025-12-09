<?php
/**
 * Hela-Threads Discussion Board Application
 * Main Entry Point
 * 
 * Features:
 * - Database initialization and connection
 * - User authentication (login/register)
 * - Thread management (create, read, update, delete)
 * - Voting system (upvote/downvote)
 * - Replies and nested comments
 * - RESTful API endpoints
 * - Session management
 * 
 * @author Hela-Threads Team
 * @version 1.0.0
 * @date 2025-12-09
 */

// ============================================================================
// ERROR HANDLING & CONFIGURATION
// ============================================================================

ini_set('display_errors', 1);
error_reporting(E_ALL);

// Set header to JSON for API requests
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit(json_encode(['status' => 'success', 'message' => 'CORS preflight passed']));
}

// ============================================================================
// DATABASE CONFIGURATION
// ============================================================================

define('DB_HOST', getenv('DB_HOST') ?: 'localhost');
define('DB_USER', getenv('DB_USER') ?: 'root');
define('DB_PASS', getenv('DB_PASS') ?: '');
define('DB_NAME', getenv('DB_NAME') ?: 'hela_threads');
define('DB_PORT', getenv('DB_PORT') ?: 3306);

// Application constants
define('APP_NAME', 'Hela-Threads');
define('APP_VERSION', '1.0.0');
define('SESSION_TIMEOUT', 3600); // 1 hour
define('MAX_UPLOAD_SIZE', 5 * 1024 * 1024); // 5MB

// ============================================================================
// DATABASE CLASS
// ============================================================================

class Database {
    private $connection;
    private static $instance = null;

    private function __construct() {
        try {
            $this->connection = new mysqli(
                DB_HOST,
                DB_USER,
                DB_PASS,
                DB_NAME,
                DB_PORT
            );

            if ($this->connection->connect_error) {
                throw new Exception('Database connection failed: ' . $this->connection->connect_error);
            }

            $this->connection->set_charset('utf8mb4');
        } catch (Exception $e) {
            http_response_code(500);
            exit(json_encode(['status' => 'error', 'message' => 'Database connection error']));
        }
    }

    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new Database();
        }
        return self::$instance;
    }

    public function getConnection() {
        return $this->connection;
    }

    public function initialize() {
        $this->createTables();
    }

    private function createTables() {
        $queries = [
            // Users table
            "CREATE TABLE IF NOT EXISTS users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                display_name VARCHAR(100),
                avatar_url VARCHAR(255),
                bio TEXT,
                is_active BOOLEAN DEFAULT 1,
                is_admin BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL,
                INDEX idx_username (username),
                INDEX idx_email (email)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

            // Threads/Topics table
            "CREATE TABLE IF NOT EXISTS threads (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT NOT NULL,
                category VARCHAR(50),
                title VARCHAR(255) NOT NULL,
                content LONGTEXT NOT NULL,
                slug VARCHAR(255) UNIQUE,
                views INT DEFAULT 0,
                is_pinned BOOLEAN DEFAULT 0,
                is_locked BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_category (category),
                INDEX idx_created_at (created_at),
                INDEX idx_user_id (user_id),
                FULLTEXT idx_search (title, content)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

            // Replies/Comments table
            "CREATE TABLE IF NOT EXISTS replies (
                id INT PRIMARY KEY AUTO_INCREMENT,
                thread_id INT NOT NULL,
                user_id INT NOT NULL,
                parent_reply_id INT,
                content LONGTEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (thread_id) REFERENCES threads(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (parent_reply_id) REFERENCES replies(id) ON DELETE CASCADE,
                INDEX idx_thread_id (thread_id),
                INDEX idx_user_id (user_id),
                INDEX idx_parent_reply_id (parent_reply_id),
                INDEX idx_created_at (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

            // Votes table
            "CREATE TABLE IF NOT EXISTS votes (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT NOT NULL,
                votable_type ENUM('thread', 'reply') NOT NULL,
                votable_id INT NOT NULL,
                vote_type ENUM('upvote', 'downvote') NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE KEY unique_vote (user_id, votable_type, votable_id),
                INDEX idx_votable (votable_type, votable_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

            // Thread votes summary table
            "CREATE TABLE IF NOT EXISTS thread_votes (
                thread_id INT PRIMARY KEY,
                upvotes INT DEFAULT 0,
                downvotes INT DEFAULT 0,
                FOREIGN KEY (thread_id) REFERENCES threads(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

            // Reply votes summary table
            "CREATE TABLE IF NOT EXISTS reply_votes (
                reply_id INT PRIMARY KEY,
                upvotes INT DEFAULT 0,
                downvotes INT DEFAULT 0,
                FOREIGN KEY (reply_id) REFERENCES replies(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

            // User sessions table
            "CREATE TABLE IF NOT EXISTS sessions (
                id VARCHAR(64) PRIMARY KEY,
                user_id INT NOT NULL,
                user_agent VARCHAR(255),
                ip_address VARCHAR(45),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_id (user_id),
                INDEX idx_expires_at (expires_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        ];

        foreach ($queries as $query) {
            if (!$this->connection->query($query)) {
                error_log('Database initialization error: ' . $this->connection->error);
            }
        }
    }

    public function query($sql, $params = []) {
        $stmt = $this->connection->prepare($sql);
        if (!$stmt) {
            throw new Exception('Prepare failed: ' . $this->connection->error);
        }

        if (!empty($params)) {
            $types = '';
            foreach ($params as $param) {
                if (is_int($param)) {
                    $types .= 'i';
                } elseif (is_float($param)) {
                    $types .= 'd';
                } else {
                    $types .= 's';
                }
            }
            $stmt->bind_param($types, ...$params);
        }

        $stmt->execute();
        return $stmt;
    }

    public function queryAssoc($sql, $params = []) {
        $stmt = $this->query($sql, $params);
        $result = $stmt->get_result();
        return $result->fetch_all(MYSQLI_ASSOC);
    }

    public function queryOne($sql, $params = []) {
        $stmt = $this->query($sql, $params);
        $result = $stmt->get_result();
        return $result->fetch_assoc();
    }

    public function lastInsertId() {
        return $this->connection->insert_id;
    }

    public function affectedRows() {
        return $this->connection->affected_rows;
    }
}

// ============================================================================
// AUTHENTICATION CLASS
// ============================================================================

class Auth {
    private $db;
    private $session_id;
    private $user_id;
    private $user_data;

    public function __construct() {
        $this->db = Database::getInstance();
        session_start();
        $this->loadSession();
    }

    private function loadSession() {
        if (isset($_SESSION['user_id'])) {
            $this->user_id = $_SESSION['user_id'];
            $this->loadUserData();
        }
    }

    private function loadUserData() {
        if ($this->user_id) {
            $result = $this->db->queryOne(
                "SELECT id, username, email, display_name, avatar_url, is_admin FROM users WHERE id = ?",
                [$this->user_id]
            );
            $this->user_data = $result;
        }
    }

    public function register($username, $email, $password) {
        // Validation
        if (strlen($username) < 3 || strlen($username) > 50) {
            return ['success' => false, 'message' => 'Username must be between 3 and 50 characters'];
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ['success' => false, 'message' => 'Invalid email address'];
        }

        if (strlen($password) < 8) {
            return ['success' => false, 'message' => 'Password must be at least 8 characters'];
        }

        // Check if username/email already exists
        $existing = $this->db->queryOne("SELECT id FROM users WHERE username = ? OR email = ?", [$username, $email]);
        if ($existing) {
            return ['success' => false, 'message' => 'Username or email already exists'];
        }

        // Create user
        $password_hash = password_hash($password, PASSWORD_BCRYPT);
        $result = $this->db->query(
            "INSERT INTO users (username, email, password_hash, display_name) VALUES (?, ?, ?, ?)",
            [$username, $email, $password_hash, $username]
        );

        if ($result) {
            return ['success' => true, 'message' => 'Registration successful', 'user_id' => $this->db->lastInsertId()];
        }

        return ['success' => false, 'message' => 'Registration failed'];
    }

    public function login($username, $password) {
        $user = $this->db->queryOne("SELECT * FROM users WHERE username = ? OR email = ?", [$username, $username]);

        if (!$user || !password_verify($password, $user['password_hash'])) {
            return ['success' => false, 'message' => 'Invalid credentials'];
        }

        if (!$user['is_active']) {
            return ['success' => false, 'message' => 'Account is inactive'];
        }

        // Update last login
        $this->db->query("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", [$user['id']]);

        // Create session
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['email'] = $user['email'];
        $_SESSION['is_admin'] = $user['is_admin'];

        $this->user_id = $user['id'];
        $this->loadUserData();

        return ['success' => true, 'message' => 'Login successful', 'user' => $this->getUserData()];
    }

    public function logout() {
        session_destroy();
        $this->user_id = null;
        $this->user_data = null;
        return ['success' => true, 'message' => 'Logged out successfully'];
    }

    public function isLoggedIn() {
        return $this->user_id !== null;
    }

    public function getUserId() {
        return $this->user_id;
    }

    public function getUserData() {
        return $this->user_data;
    }

    public function isAdmin() {
        return isset($_SESSION['is_admin']) && $_SESSION['is_admin'];
    }

    public function requireLogin() {
        if (!$this->isLoggedIn()) {
            http_response_code(401);
            exit(json_encode(['status' => 'error', 'message' => 'Authentication required']));
        }
    }
}

// ============================================================================
// VOTING SYSTEM CLASS
// ============================================================================

class VotingSystem {
    private $db;
    private $auth;

    public function __construct($db, $auth) {
        $this->db = $db;
        $this->auth = $auth;
    }

    public function vote($type, $votable_type, $votable_id, $vote_type) {
        $this->auth->requireLogin();
        $user_id = $this->auth->getUserId();

        if (!in_array($votable_type, ['thread', 'reply'])) {
            return ['success' => false, 'message' => 'Invalid votable type'];
        }

        if (!in_array($vote_type, ['upvote', 'downvote'])) {
            return ['success' => false, 'message' => 'Invalid vote type'];
        }

        // Check if already voted
        $existing = $this->db->queryOne(
            "SELECT id FROM votes WHERE user_id = ? AND votable_type = ? AND votable_id = ?",
            [$user_id, $votable_type, $votable_id]
        );

        if ($existing) {
            // Remove existing vote
            $this->db->query(
                "DELETE FROM votes WHERE user_id = ? AND votable_type = ? AND votable_id = ?",
                [$user_id, $votable_type, $votable_id]
            );
        }

        // Add new vote
        $this->db->query(
            "INSERT INTO votes (user_id, votable_type, votable_id, vote_type) VALUES (?, ?, ?, ?)",
            [$user_id, $votable_type, $votable_id, $vote_type]
        );

        // Update vote counts
        $this->updateVoteCounts($votable_type, $votable_id);

        return ['success' => true, 'message' => 'Vote recorded'];
    }

    private function updateVoteCounts($votable_type, $votable_id) {
        $upvotes = $this->db->queryOne(
            "SELECT COUNT(*) as count FROM votes WHERE votable_type = ? AND votable_id = ? AND vote_type = 'upvote'",
            [$votable_type, $votable_id]
        )['count'];

        $downvotes = $this->db->queryOne(
            "SELECT COUNT(*) as count FROM votes WHERE votable_type = ? AND votable_id = ? AND vote_type = 'downvote'",
            [$votable_type, $votable_id]
        )['count'];

        if ($votable_type === 'thread') {
            $existing = $this->db->queryOne("SELECT * FROM thread_votes WHERE thread_id = ?", [$votable_id]);
            if ($existing) {
                $this->db->query(
                    "UPDATE thread_votes SET upvotes = ?, downvotes = ? WHERE thread_id = ?",
                    [$upvotes, $downvotes, $votable_id]
                );
            } else {
                $this->db->query(
                    "INSERT INTO thread_votes (thread_id, upvotes, downvotes) VALUES (?, ?, ?)",
                    [$votable_id, $upvotes, $downvotes]
                );
            }
        } elseif ($votable_type === 'reply') {
            $existing = $this->db->queryOne("SELECT * FROM reply_votes WHERE reply_id = ?", [$votable_id]);
            if ($existing) {
                $this->db->query(
                    "UPDATE reply_votes SET upvotes = ?, downvotes = ? WHERE reply_id = ?",
                    [$upvotes, $downvotes, $votable_id]
                );
            } else {
                $this->db->query(
                    "INSERT INTO reply_votes (reply_id, upvotes, downvotes) VALUES (?, ?, ?)",
                    [$votable_id, $upvotes, $downvotes]
                );
            }
        }
    }

    public function getThreadVotes($thread_id) {
        $result = $this->db->queryOne(
            "SELECT upvotes, downvotes FROM thread_votes WHERE thread_id = ?",
            [$thread_id]
        );
        return $result ?: ['upvotes' => 0, 'downvotes' => 0];
    }

    public function getReplyVotes($reply_id) {
        $result = $this->db->queryOne(
            "SELECT upvotes, downvotes FROM reply_votes WHERE reply_id = ?",
            [$reply_id]
        );
        return $result ?: ['upvotes' => 0, 'downvotes' => 0];
    }
}

// ============================================================================
// THREAD MANAGEMENT CLASS
// ============================================================================

class ThreadManager {
    private $db;
    private $auth;
    private $voting;

    public function __construct($db, $auth, $voting) {
        $this->db = $db;
        $this->auth = $auth;
        $this->voting = $voting;
    }

    public function createThread($title, $content, $category = 'general') {
        $this->auth->requireLogin();

        if (empty($title) || empty($content)) {
            return ['success' => false, 'message' => 'Title and content are required'];
        }

        $user_id = $this->auth->getUserId();
        $slug = $this->generateSlug($title);

        $result = $this->db->query(
            "INSERT INTO threads (user_id, title, content, category, slug) VALUES (?, ?, ?, ?, ?)",
            [$user_id, $title, $content, $category, $slug]
        );

        if ($result) {
            $thread_id = $this->db->lastInsertId();
            return ['success' => true, 'message' => 'Thread created', 'thread_id' => $thread_id];
        }

        return ['success' => false, 'message' => 'Failed to create thread'];
    }

    public function getThread($thread_id) {
        $thread = $this->db->queryOne(
            "SELECT t.*, u.username, u.display_name, u.avatar_url FROM threads t 
             JOIN users u ON t.user_id = u.id WHERE t.id = ?",
            [$thread_id]
        );

        if ($thread) {
            $this->db->query("UPDATE threads SET views = views + 1 WHERE id = ?", [$thread_id]);
            $thread['votes'] = $this->voting->getThreadVotes($thread_id);
            $thread['reply_count'] = $this->db->queryOne(
                "SELECT COUNT(*) as count FROM replies WHERE thread_id = ?",
                [$thread_id]
            )['count'];
        }

        return $thread;
    }

    public function getThreads($category = null, $limit = 20, $offset = 0) {
        if ($category) {
            $threads = $this->db->queryAssoc(
                "SELECT t.*, u.username, u.display_name, u.avatar_url, 
                        COUNT(DISTINCT r.id) as reply_count
                 FROM threads t 
                 JOIN users u ON t.user_id = u.id 
                 LEFT JOIN replies r ON t.id = r.thread_id
                 WHERE t.category = ? AND t.is_locked = 0
                 GROUP BY t.id
                 ORDER BY t.is_pinned DESC, t.created_at DESC 
                 LIMIT ? OFFSET ?",
                [$category, $limit, $offset]
            );
        } else {
            $threads = $this->db->queryAssoc(
                "SELECT t.*, u.username, u.display_name, u.avatar_url, 
                        COUNT(DISTINCT r.id) as reply_count
                 FROM threads t 
                 JOIN users u ON t.user_id = u.id 
                 LEFT JOIN replies r ON t.id = r.thread_id
                 WHERE t.is_locked = 0
                 GROUP BY t.id
                 ORDER BY t.is_pinned DESC, t.created_at DESC 
                 LIMIT ? OFFSET ?",
                [$limit, $offset]
            );
        }

        foreach ($threads as &$thread) {
            $thread['votes'] = $this->voting->getThreadVotes($thread['id']);
        }

        return $threads;
    }

    public function updateThread($thread_id, $title, $content) {
        $this->auth->requireLogin();
        $thread = $this->getThread($thread_id);

        if (!$thread || ($thread['user_id'] != $this->auth->getUserId() && !$this->auth->isAdmin())) {
            return ['success' => false, 'message' => 'Unauthorized'];
        }

        $this->db->query(
            "UPDATE threads SET title = ?, content = ? WHERE id = ?",
            [$title, $content, $thread_id]
        );

        return ['success' => true, 'message' => 'Thread updated'];
    }

    public function deleteThread($thread_id) {
        $this->auth->requireLogin();
        $thread = $this->getThread($thread_id);

        if (!$thread || ($thread['user_id'] != $this->auth->getUserId() && !$this->auth->isAdmin())) {
            return ['success' => false, 'message' => 'Unauthorized'];
        }

        $this->db->query("DELETE FROM threads WHERE id = ?", [$thread_id]);

        return ['success' => true, 'message' => 'Thread deleted'];
    }

    private function generateSlug($title) {
        $slug = strtolower(trim(preg_replace('/[^a-z0-9-]+/', '-', $title), '-'));
        $slug .= '-' . uniqid();
        return $slug;
    }
}

// ============================================================================
// REPLY MANAGEMENT CLASS
// ============================================================================

class ReplyManager {
    private $db;
    private $auth;
    private $voting;

    public function __construct($db, $auth, $voting) {
        $this->db = $db;
        $this->auth = $auth;
        $this->voting = $voting;
    }

    public function createReply($thread_id, $content, $parent_reply_id = null) {
        $this->auth->requireLogin();

        if (empty($content)) {
            return ['success' => false, 'message' => 'Content is required'];
        }

        $user_id = $this->auth->getUserId();

        $result = $this->db->query(
            "INSERT INTO replies (thread_id, user_id, parent_reply_id, content) VALUES (?, ?, ?, ?)",
            [$thread_id, $user_id, $parent_reply_id, $content]
        );

        if ($result) {
            return ['success' => true, 'message' => 'Reply created', 'reply_id' => $this->db->lastInsertId()];
        }

        return ['success' => false, 'message' => 'Failed to create reply'];
    }

    public function getThreadReplies($thread_id, $limit = 50, $offset = 0) {
        $replies = $this->db->queryAssoc(
            "SELECT r.*, u.username, u.display_name, u.avatar_url 
             FROM replies r 
             JOIN users u ON r.user_id = u.id 
             WHERE r.thread_id = ? AND r.parent_reply_id IS NULL
             ORDER BY r.created_at ASC 
             LIMIT ? OFFSET ?",
            [$thread_id, $limit, $offset]
        );

        foreach ($replies as &$reply) {
            $reply['votes'] = $this->voting->getReplyVotes($reply['id']);
            $reply['nested'] = $this->getNestedReplies($reply['id']);
        }

        return $replies;
    }

    private function getNestedReplies($parent_reply_id) {
        $replies = $this->db->queryAssoc(
            "SELECT r.*, u.username, u.display_name, u.avatar_url 
             FROM replies r 
             JOIN users u ON r.user_id = u.id 
             WHERE r.parent_reply_id = ? 
             ORDER BY r.created_at ASC",
            [$parent_reply_id]
        );

        foreach ($replies as &$reply) {
            $reply['votes'] = $this->voting->getReplyVotes($reply['id']);
            $reply['nested'] = $this->getNestedReplies($reply['id']);
        }

        return $replies;
    }

    public function updateReply($reply_id, $content) {
        $this->auth->requireLogin();
        $reply = $this->db->queryOne("SELECT user_id FROM replies WHERE id = ?", [$reply_id]);

        if (!$reply || ($reply['user_id'] != $this->auth->getUserId() && !$this->auth->isAdmin())) {
            return ['success' => false, 'message' => 'Unauthorized'];
        }

        $this->db->query("UPDATE replies SET content = ? WHERE id = ?", [$content, $reply_id]);

        return ['success' => true, 'message' => 'Reply updated'];
    }

    public function deleteReply($reply_id) {
        $this->auth->requireLogin();
        $reply = $this->db->queryOne("SELECT user_id FROM replies WHERE id = ?", [$reply_id]);

        if (!$reply || ($reply['user_id'] != $this->auth->getUserId() && !$this->auth->isAdmin())) {
            return ['success' => false, 'message' => 'Unauthorized'];
        }

        $this->db->query("DELETE FROM replies WHERE id = ?", [$reply_id]);

        return ['success' => true, 'message' => 'Reply deleted'];
    }
}

// ============================================================================
// API ROUTER CLASS
// ============================================================================

class Router {
    private $db;
    private $auth;
    private $voting;
    private $threads;
    private $replies;
    private $method;
    private $path;
    private $segments;

    public function __construct() {
        $this->db = Database::getInstance();
        $this->auth = new Auth();
        $this->voting = new VotingSystem($this->db, $this->auth);
        $this->threads = new ThreadManager($this->db, $this->auth, $this->voting);
        $this->replies = new ReplyManager($this->db, $this->auth, $this->voting);

        $this->parseRequest();
    }

    private function parseRequest() {
        $this->method = $_SERVER['REQUEST_METHOD'];
        $this->path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        $this->segments = array_filter(explode('/', $this->path));
    }

    public function route() {
        // Initialize database
        $this->db->initialize();

        // Route requests
        $action = $this->segments[1] ?? 'home';

        try {
            switch ($action) {
                // Authentication endpoints
                case 'api':
                    $this->handleApiRequest();
                    break;

                case 'auth':
                    $this->handleAuth();
                    break;

                case 'user':
                    $this->handleUser();
                    break;

                default:
                    $this->handleHome();
                    break;
            }
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['status' => 'error', 'message' => $e->getMessage()]);
        }
    }

    private function handleApiRequest() {
        $resource = $this->segments[2] ?? null;

        switch ($resource) {
            case 'threads':
                $this->handleThreadsApi();
                break;

            case 'replies':
                $this->handleRepliesApi();
                break;

            case 'votes':
                $this->handleVotesApi();
                break;

            default:
                http_response_code(404);
                echo json_encode(['status' => 'error', 'message' => 'Not found']);
                break;
        }
    }

    private function handleThreadsApi() {
        $id = $this->segments[3] ?? null;
        $input = $this->getInput();

        if ($this->method === 'GET') {
            if ($id) {
                $thread = $this->threads->getThread($id);
                if ($thread) {
                    echo json_encode(['status' => 'success', 'data' => $thread]);
                } else {
                    http_response_code(404);
                    echo json_encode(['status' => 'error', 'message' => 'Thread not found']);
                }
            } else {
                $category = $_GET['category'] ?? null;
                $limit = $_GET['limit'] ?? 20;
                $offset = $_GET['offset'] ?? 0;
                $threads = $this->threads->getThreads($category, $limit, $offset);
                echo json_encode(['status' => 'success', 'data' => $threads]);
            }
        } elseif ($this->method === 'POST') {
            $result = $this->threads->createThread(
                $input['title'] ?? '',
                $input['content'] ?? '',
                $input['category'] ?? 'general'
            );
            echo json_encode($result);
        } elseif ($this->method === 'PUT' && $id) {
            $result = $this->threads->updateThread($id, $input['title'] ?? '', $input['content'] ?? '');
            echo json_encode($result);
        } elseif ($this->method === 'DELETE' && $id) {
            $result = $this->threads->deleteThread($id);
            echo json_encode($result);
        }
    }

    private function handleRepliesApi() {
        $id = $this->segments[3] ?? null;
        $input = $this->getInput();

        if ($this->method === 'GET') {
            if ($id) {
                $thread_id = $this->segments[3];
                $limit = $_GET['limit'] ?? 50;
                $offset = $_GET['offset'] ?? 0;
                $replies = $this->replies->getThreadReplies($thread_id, $limit, $offset);
                echo json_encode(['status' => 'success', 'data' => $replies]);
            }
        } elseif ($this->method === 'POST') {
            $result = $this->replies->createReply(
                $input['thread_id'] ?? '',
                $input['content'] ?? '',
                $input['parent_reply_id'] ?? null
            );
            echo json_encode($result);
        } elseif ($this->method === 'PUT' && $id) {
            $result = $this->replies->updateReply($id, $input['content'] ?? '');
            echo json_encode($result);
        } elseif ($this->method === 'DELETE' && $id) {
            $result = $this->replies->deleteReply($id);
            echo json_encode($result);
        }
    }

    private function handleVotesApi() {
        $input = $this->getInput();

        if ($this->method === 'POST') {
            $result = $this->voting->vote(
                $input['type'] ?? '',
                $input['votable_type'] ?? '',
                $input['votable_id'] ?? '',
                $input['vote_type'] ?? ''
            );
            echo json_encode($result);
        }
    }

    private function handleAuth() {
        $action = $this->segments[2] ?? null;
        $input = $this->getInput();

        if ($action === 'register' && $this->method === 'POST') {
            $result = $this->auth->register(
                $input['username'] ?? '',
                $input['email'] ?? '',
                $input['password'] ?? ''
            );
            echo json_encode($result);
        } elseif ($action === 'login' && $this->method === 'POST') {
            $result = $this->auth->login(
                $input['username'] ?? '',
                $input['password'] ?? ''
            );
            echo json_encode($result);
        } elseif ($action === 'logout' && $this->method === 'POST') {
            $result = $this->auth->logout();
            echo json_encode($result);
        } elseif ($action === 'status' && $this->method === 'GET') {
            if ($this->auth->isLoggedIn()) {
                echo json_encode([
                    'status' => 'success',
                    'loggedIn' => true,
                    'user' => $this->auth->getUserData()
                ]);
            } else {
                echo json_encode(['status' => 'success', 'loggedIn' => false]);
            }
        }
    }

    private function handleUser() {
        $action = $this->segments[2] ?? null;

        if ($this->method === 'GET' && $action) {
            $user = $this->db->queryOne(
                "SELECT id, username, display_name, avatar_url, bio, created_at FROM users WHERE username = ?",
                [$action]
            );

            if ($user) {
                $user['thread_count'] = $this->db->queryOne(
                    "SELECT COUNT(*) as count FROM threads WHERE user_id = ?",
                    [$user['id']]
                )['count'];

                $user['reply_count'] = $this->db->queryOne(
                    "SELECT COUNT(*) as count FROM replies WHERE user_id = ?",
                    [$user['id']]
                )['count'];

                echo json_encode(['status' => 'success', 'data' => $user]);
            } else {
                http_response_code(404);
                echo json_encode(['status' => 'error', 'message' => 'User not found']);
            }
        }
    }

    private function handleHome() {
        echo json_encode([
            'status' => 'success',
            'message' => APP_NAME . ' - Discussion Board API',
            'version' => APP_VERSION,
            'endpoints' => [
                'GET /api/threads' => 'List all threads',
                'GET /api/threads/{id}' => 'Get specific thread',
                'POST /api/threads' => 'Create new thread',
                'PUT /api/threads/{id}' => 'Update thread',
                'DELETE /api/threads/{id}' => 'Delete thread',
                'GET /api/replies/{thread_id}' => 'Get thread replies',
                'POST /api/replies' => 'Create reply',
                'PUT /api/replies/{id}' => 'Update reply',
                'DELETE /api/replies/{id}' => 'Delete reply',
                'POST /api/votes' => 'Vote on thread/reply',
                'POST /auth/register' => 'Register new user',
                'POST /auth/login' => 'Login user',
                'POST /auth/logout' => 'Logout user',
                'GET /auth/status' => 'Get authentication status',
                'GET /user/{username}' => 'Get user profile'
            ]
        ]);
    }

    private function getInput() {
        $input = json_decode(file_get_contents('php://input'), true);
        return is_array($input) ? $input : [];
    }
}

// ============================================================================
// INITIALIZATION
// ============================================================================

try {
    $router = new Router();
    $router->route();
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Internal server error']);
}
?>
