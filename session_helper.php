<?php
require_once __DIR__ . '/jwt_helper.php';

const SESSION_TIMEOUT = 120; // segundos de inactividad (2 minutos)

function startSecureSession() {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.use_only_cookies', 1);
    ini_set('session.use_strict_mode', 1);
    ini_set('session.cookie_samesite', 'Strict');
    session_start();

    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > SESSION_TIMEOUT) {
        session_unset();
        session_destroy();
        jwt_clear_cookie();
        session_start();
        $_SESSION['expired'] = true;
    }

    $_SESSION['last_activity'] = time();
}

function destroySessionAndRedirect(): void {
    session_unset();
    session_destroy();
    jwt_clear_cookie();
    header("Location: index.php");
    exit;
}

// Exige sesión de servidor + JWT válido y coherente (misma identidad y mismo rol)
function requireAuth() {
    if (!isset($_SESSION['authenticated_user_id'])) {
        header("Location: index.php");
        exit;
    }

    try {
        $claims = jwt_current_claims();
    } catch (Throwable $e) {
        error_log('[JWT] ' . $e->getMessage());
        http_response_code(500);
        die('Error de configuración del servidor.');
    }

    if ($claims === null
        || (int)$claims['sub'] !== (int)$_SESSION['authenticated_user_id']
        || (string)$claims['rol'] !== (string)($_SESSION['rol'] ?? '')) {
        destroySessionAndRedirect();
    }
}

function requireRole(array $roles) {
    requireAuth();
    if (!in_array($_SESSION['rol'], $roles, true)) {
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
