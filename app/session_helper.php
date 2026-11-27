<?php
require_once __DIR__ . '/jwt_helper.php';

const SESSION_TIMEOUT = 120; // segundos de inactividad (2 minutos)

function acquireUserSessionLock(int $userId): bool {
    $lockFile = sys_get_temp_dir() . '/ec_user_lock_' . $userId . '.json';
    $ahora = time();
    $sidActual = session_id();

    if (is_file($lockFile)) {
        $data = json_decode((string)@file_get_contents($lockFile), true);
        if (is_array($data)
            && !empty($data['sid'])
            && ($data['exp'] ?? 0) > $ahora
            && $data['sid'] !== $sidActual) {
            return false;
        }
    }

    @file_put_contents($lockFile, json_encode([
        'sid' => $sidActual,
        'exp' => $ahora + SESSION_TIMEOUT,
    ]), LOCK_EX);
    return true;
}

function refreshUserSessionLock(int $userId): void {
    $lockFile = sys_get_temp_dir() . '/ec_user_lock_' . $userId . '.json';
    @file_put_contents($lockFile, json_encode([
        'sid' => session_id(),
        'exp' => time() + SESSION_TIMEOUT,
    ]), LOCK_EX);
}

function releaseUserSessionLock(?int $userId): void {
    if ($userId !== null && $userId > 0) {
        $lockFile = sys_get_temp_dir() . '/ec_user_lock_' . $userId . '.json';
        if (is_file($lockFile)) {
            @unlink($lockFile);
        }
    }
}

function startSecureSession() {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.use_only_cookies', 1);
    ini_set('session.use_strict_mode', 1);
    ini_set('session.cookie_samesite', 'Strict');
    session_start();

    if (!headers_sent()) {
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('Expires: 0');
    }

    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > SESSION_TIMEOUT) {
        $uid = isset($_SESSION['authenticated_user_id']) ? (int)$_SESSION['authenticated_user_id'] : null;
        releaseUserSessionLock($uid);
        session_unset();
        session_destroy();
        jwt_clear_cookie();
        session_start();
        $_SESSION['expired'] = true;
    }

    $_SESSION['last_activity'] = time();
}

function destroySessionAndRedirect(): void {
    $uid = isset($_SESSION['authenticated_user_id']) ? (int)$_SESSION['authenticated_user_id'] : null;
    releaseUserSessionLock($uid);
    session_unset();
    session_destroy();
    jwt_clear_cookie();
    header("Location: login.php");
    exit;
}

// Exige sesión de servidor + JWT válido y coherente + bloqueo único por usuario
function requireAuth() {
    if (!isset($_SESSION['authenticated_user_id'])) {
        header("Location: login.php");
        exit;
    }

    $uid = (int)$_SESSION['authenticated_user_id'];
    $lockFile = sys_get_temp_dir() . '/ec_user_lock_' . $uid . '.json';
    if (is_file($lockFile)) {
        $data = json_decode((string)@file_get_contents($lockFile), true);
        if (!is_array($data) || ($data['sid'] ?? '') !== session_id() || ($data['exp'] ?? 0) <= time()) {
            destroySessionAndRedirect();
        }
    }
    refreshUserSessionLock($uid);

    try {
        $claims = jwt_current_claims();
    } catch (Throwable $e) {
        error_log('[JWT] ' . $e->getMessage());
        http_response_code(500);
        die('Error de configuración del servidor.');
    }

    if ($claims === null
        || (int)$claims['sub'] !== $uid
        || (string)$claims['rol'] !== (string)($_SESSION['rol'] ?? '')) {
        destroySessionAndRedirect();
    }

    // NAV_ENCAJONADA: bloquea saltos manuales editando la URL en la barra de direcciones
    $paginaActual = basename($_SERVER['PHP_SELF'] ?? '');
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET' && $paginaActual !== 'api_whoami.php') {
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        $hostActual = parse_url('http://' . ($_SERVER['HTTP_HOST'] ?? ''), PHP_URL_HOST);
        $hostReferer = $referer !== '' ? parse_url($referer, PHP_URL_HOST) : null;

        if ($hostReferer === null || $hostActual === null || strcasecmp($hostReferer, $hostActual) !== 0) {
            $destinoFijo = $_SESSION['ultima_pagina']
                ?? (($_SESSION['rol'] ?? '') === 'admin' ? 'usuarios.php' : 'productos.php');
            if ($destinoFijo !== $paginaActual) {
                header("Location: " . $destinoFijo);
                exit;
            }
        }

        $_SESSION['ultima_pagina'] = $paginaActual;
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