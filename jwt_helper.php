<?php
// app/jwt_helper.php
// JWT (JSON Web Token) 100% nativo: Base64URL + HMAC-SHA256 (HS256).
// Sin librerías externas. Solo hash_hmac, hash_equals, random_bytes, json_*.

const JWT_ISSUER      = 'ecommerce-lab';
const JWT_AUDIENCE    = 'ecommerce-lab-web';
const JWT_TTL         = 900;          // vida máxima absoluta del token: 15 minutos
const JWT_LEEWAY      = 5;            // tolerancia de reloj (segundos)
const JWT_COOKIE_NAME = 'auth_token';
const JWT_MAX_LENGTH  = 4096;

// ---------------------------------------------------------------
// Base64URL (RFC 7515 §2): alfabeto URL-safe y sin relleno '='
// ---------------------------------------------------------------
function base64url_encode(string $data): string {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64url_decode(string $data): ?string {
    if ($data === '' || !preg_match('/^[A-Za-z0-9_-]+$/', $data)) {
        return null;
    }
    $padding = strlen($data) % 4;
    if ($padding === 1) {
        return null; // longitud imposible en Base64
    }
    if ($padding > 0) {
        $data .= str_repeat('=', 4 - $padding);
    }
    $decoded = base64_decode(strtr($data, '-_', '+/'), true);
    return $decoded === false ? null : $decoded;
}

// ---------------------------------------------------------------
// Secreto de firma (variable de entorno JWT_SECRET, mínimo 32 caracteres)
// ---------------------------------------------------------------
function jwt_secret(): string {
    $secret = getenv('JWT_SECRET');
    if ($secret === false || strlen($secret) < 32) {
        throw new RuntimeException('JWT_SECRET no configurado o demasiado corto (mínimo 32 caracteres).');
    }
    return $secret;
}

// ---------------------------------------------------------------
// Emisión
// ---------------------------------------------------------------
function jwt_encode(array $claims, string $secret): string {
    $header = ['alg' => 'HS256', 'typ' => 'JWT'];
    $h = base64url_encode(json_encode($header, JSON_UNESCAPED_SLASHES));
    $p = base64url_encode(json_encode($claims, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    $signature = hash_hmac('sha256', "$h.$p", $secret, true);
    return "$h.$p." . base64url_encode($signature);
}

// ---------------------------------------------------------------
// Validación estricta. Devuelve ['valid'=>bool, 'claims'=>array|null, 'error'=>string]
// ---------------------------------------------------------------
function jwt_decode(string $jwt, string $secret): array {
    $fail = fn(string $msg): array => ['valid' => false, 'claims' => null, 'error' => $msg];

    if ($jwt === '' || strlen($jwt) > JWT_MAX_LENGTH) {
        return $fail('Token vacío o demasiado largo');
    }

    $parts = explode('.', $jwt);
    if (count($parts) !== 3) {
        return $fail('Formato de token inválido');
    }
    [$h64, $p64, $s64] = $parts;

    $headerJson  = base64url_decode($h64);
    $payloadJson = base64url_decode($p64);
    $signature   = base64url_decode($s64);
    if ($headerJson === null || $payloadJson === null || $signature === null) {
        return $fail('Codificación Base64URL inválida');
    }

    try {
        $header  = json_decode($headerJson, true, 8, JSON_THROW_ON_ERROR);
        $payload = json_decode($payloadJson, true, 8, JSON_THROW_ON_ERROR);
    } catch (JsonException $e) {
        return $fail('JSON inválido');
    }
    if (!is_array($header) || !is_array($payload)) {
        return $fail('Estructura inválida');
    }

    // El algoritmo se fija en el servidor: se rechaza "none" y cualquier otro (ataque alg-confusion)
    if (($header['alg'] ?? null) !== 'HS256' || ($header['typ'] ?? 'JWT') !== 'JWT') {
        return $fail('Algoritmo no permitido');
    }

    // Firma: comparación en tiempo constante
    $expected = hash_hmac('sha256', "$h64.$p64", $secret, true);
    if (!hash_equals($expected, $signature)) {
        return $fail('Firma inválida');
    }

    // Claims registrados
    $now = time();
    if (!isset($payload['exp']) || !is_int($payload['exp']) || $payload['exp'] + JWT_LEEWAY < $now) {
        return $fail('Token expirado');
    }
    if (isset($payload['nbf']) && (!is_int($payload['nbf']) || $payload['nbf'] - JWT_LEEWAY > $now)) {
        return $fail('Token aún no válido');
    }
    if (!isset($payload['iat']) || !is_int($payload['iat']) || $payload['iat'] - JWT_LEEWAY > $now) {
        return $fail('Fecha de emisión inválida');
    }
    if (($payload['iss'] ?? null) !== JWT_ISSUER || ($payload['aud'] ?? null) !== JWT_AUDIENCE) {
        return $fail('Emisor o audiencia inválidos');
    }
    if (!isset($payload['sub']) || !isset($payload['rol'])) {
        return $fail('Claims incompletos');
    }

    return ['valid' => true, 'claims' => $payload, 'error' => ''];
}

// ---------------------------------------------------------------
// Utilidades de sesión basada en JWT
// ---------------------------------------------------------------
function jwt_issue_for_user(array $user): string {
    $now = time();
    return jwt_encode([
        'iss'   => JWT_ISSUER,
        'aud'   => JWT_AUDIENCE,
        'sub'   => (int)$user['id_usuario'],
        'rol'   => (string)$user['rol'],
        'email' => (string)$user['email'],
        'iat'   => $now,
        'nbf'   => $now,
        'exp'   => $now + JWT_TTL,
        'jti'   => bin2hex(random_bytes(16)),
    ], jwt_secret());
}

function jwt_is_https(): bool {
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
}

function jwt_set_cookie(string $jwt): void {
    setcookie(JWT_COOKIE_NAME, $jwt, [
        'expires'  => time() + JWT_TTL,
        'path'     => '/',
        'secure'   => jwt_is_https(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
}

function jwt_clear_cookie(): void {
    setcookie(JWT_COOKIE_NAME, '', [
        'expires'  => time() - 3600,
        'path'     => '/',
        'secure'   => jwt_is_https(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    unset($_COOKIE[JWT_COOKIE_NAME]);
}

// Token desde "Authorization: Bearer <jwt>" o desde la cookie HttpOnly
function jwt_from_request(): string {
    $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
    if ($auth !== '' && preg_match('/^Bearer\s+([A-Za-z0-9_\-\.]+)$/', $auth, $m)) {
        return $m[1];
    }
    $cookie = $_COOKIE[JWT_COOKIE_NAME] ?? '';
    return is_string($cookie) ? $cookie : '';
}

// Claims validados de la petición actual (o null). Cacheado por petición.
function jwt_current_claims(): ?array {
    static $cache = false;
    if ($cache !== false) {
        return $cache;
    }
    $token = jwt_from_request();
    if ($token === '') {
        return $cache = null;
    }
    $res = jwt_decode($token, jwt_secret());
    return $cache = ($res['valid'] ? $res['claims'] : null);
}
