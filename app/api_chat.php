<?php
require_once __DIR__ . '/session_helper.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/security_helper.php';

startSecureSession();
requireAuth();

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'error' => 'Método no permitido.']);
    exit;
}

if (!validateCsrfToken($_POST['csrf_token'] ?? null)) {
    http_response_code(403);
    echo json_encode(['ok' => false, 'error' => 'Token CSRF inválido.']);
    exit;
}

$accion = (string)($_POST['accion'] ?? 'chat');
$rol = (string)($_SESSION['rol'] ?? 'cliente');

if ($accion === 'sincronizar') {
    if (!in_array($rol, ['admin', 'gerente'], true)) {
        http_response_code(403);
        echo json_encode(['ok' => false, 'error' => 'No autorizado.']);
        exit;
    }

    $conn = getConexion('lectura');
    $res = $conn->query("SELECT id_producto, nombre, precio, stock FROM productos");
    $productos = [];
    while ($row = $res->fetch_assoc()) {
        $productos[] = [
            'id_producto' => (int)$row['id_producto'],
            'nombre'      => (string)$row['nombre'],
            'descripcion' => '',
            'precio'      => (float)$row['precio'],
            'stock'       => (int)$row['stock'],
        ];
    }
    $conn->close();

    $resp = internal_service_post('ia', '/indexar', ['productos' => $productos], 60);
    if (!$resp['ok']) {
        http_response_code(502);
        echo json_encode(['ok' => false, 'error' => $resp['error'] ?? 'Error al indexar en ChromaDB.']);
        exit;
    }

    echo json_encode(['ok' => true, 'indexados' => $resp['data']['indexados'] ?? 0]);
    exit;
}

$validacion = validate_plain_text((string)($_POST['mensaje'] ?? ''), 'Mensaje', 400, 2);
if ($validacion['error'] !== '') {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => $validacion['error']]);
    exit;
}

$modo = ((string)($_POST['modo'] ?? 'catalogo') === 'seguridad' && $rol === 'admin')
    ? 'seguridad'
    : 'catalogo';

$contextoSeguridad = '';
if ($modo === 'seguridad') {
    $historial = afb_historial(20);
    $lineas = [];
    foreach ($historial as $h) {
        $estado = ((int)$h['exito'] === 1) ? 'OK' : 'FALLO';
        $lineas[] = "[{$h['fecha']}] {$estado} | email={$h['email']} | ip={$h['ip']} | motivo={$h['motivo']}";
    }
    $contextoSeguridad = implode("\n", $lineas);
}

$resp = internal_service_post('ia', '/chat', [
    'mensaje'            => $validacion['valor'],
    'rol'                => $rol,
    'modo'               => $modo,
    'contexto_seguridad' => $contextoSeguridad,
], 60);

if (!$resp['ok']) {
    http_response_code(502);
    echo json_encode(['ok' => false, 'error' => $resp['error'] ?? 'El servicio de IA no respondió.']);
    exit;
}

echo json_encode([
    'ok'        => true,
    'respuesta' => $resp['data']['respuesta'] ?? '',
]);