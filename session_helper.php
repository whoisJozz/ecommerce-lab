<?php
function startSecureSession() {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.use_only_cookies', 1);
    ini_set('session.cookie_samesite', 'Strict');
    session_start();

    $timeout = 120; // 2 minutos

    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $timeout) {
        session_unset();
        session_destroy();
        session_start();
        $_SESSION['expired'] = true;
    }

    $_SESSION['last_activity'] = time();
}

function requireAuth() {
    if (!isset($_SESSION['authenticated_user_id'])) {
        header("Location: index.php");
        exit;
    }
}

function requireRole(array $roles) {
    requireAuth();
    if (!in_array($_SESSION['rol'], $roles)) {
        header("Location: productos.php");
        exit;
    }
}

function regenerateSessionOnLogin() {
    session_regenerate_id(true);
}

function generateCsrfToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCsrfToken(?string $token): bool {
    return isset($_SESSION['csrf_token']) && $token !== null && hash_equals($_SESSION['csrf_token'], $token);
}


