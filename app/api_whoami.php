<?php
// Endpoint JSON protegido solo con JWT (cookie auth_token o cabecera Authorization: Bearer).
// Sirve para demostrar y probar la validación del token (firma, expiración, algoritmo).
require_once __DIR__ . '/jwt_helper.php';
require_once __DIR__ . '/security_helper.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

try {
    $token = jwt_from_request();
    $res = $token === '' ? ['valid' => false, 'claims' => null, 'error' => 'Token ausente'] : jwt_decode($token, jwt_secret());
} catch (Throwable $e) {
    error_log('[JWT] ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'Error de configuración']);
    exit;
}

if (!$res['valid']) {
    securityLog('JWT_RECHAZADO', ['motivo' => $res['error']]);
    http_response_code(401);
    echo json_encode(['ok' => false, 'error' => $res['error']]);
    exit;
}

$c = $res['claims'];
$salida = [
    'ok'      => true,
    'sub'     => (int)$c['sub'],
    'email'   => $c['email'] ?? null,
    'rol'     => $c['rol'],
    'emitido' => date('c', $c['iat']),
    'expira'  => date('c', $c['exp']),
    'jti'     => $c['jti'] ?? null,
];

// Diagnóstico de red solo para administradores (verifica qué IP ve la aplicación detrás del WAF)
if ($c['rol'] === 'admin') {
    $salida['red'] = [
        'remote_addr'     => $_SERVER['REMOTE_ADDR'] ?? null,
        'x_forwarded_for' => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? null,
        'ip_detectada'    => clientIp(),
    ];
}

echo json_encode($salida, JSON_UNESCAPED_SLASHES);
