<?php
// Verificador de enlaces de proveedores (solo admin/gerente).
// Demuestra la prevención de SSRF: toda petición saliente pasa por ssrf_safe_request().
// Solo se muestran metadatos (estado HTTP, tipo y tamaño), nunca el cuerpo de la respuesta.
require_once __DIR__ . '/session_helper.php';
require_once __DIR__ . '/security_helper.php';
require_once __DIR__ . '/nav.php';

startSecureSession();
requireRole(['admin', 'gerente']);

$resultado = null;
$error = '';
$url = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCsrfToken($_POST['csrf_token'] ?? null)) {
        $error = 'Token CSRF inválido. Recarga la página e intenta nuevamente.';
    } else {
        $url = mb_substr(trim((string)($_POST['url'] ?? '')), 0, 2048);
        $resultado = ssrf_safe_request($url);
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Verificador de URL</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <?php renderNav('verificar_url'); ?>

    <h2>Verificador de enlaces de proveedores</h2>
    <p>Comprueba si una URL pública responde. Se bloquean destinos internos (localhost, redes privadas, metadatos cloud) y esquemas distintos de http/https.</p>

    <?php if ($error): ?>
        <p style="color: #ff6b6b;"><strong><?= h($error) ?></strong></p>
    <?php endif; ?>

    <form method="POST" action="verificar_url.php">
        <input type="hidden" name="csrf_token" value="<?= h(generateCsrfToken()) ?>">
        URL: <input type="text" name="url" size="60" maxlength="2048" value="<?= h($url) ?>" placeholder="https://example.com" required>
        <input type="submit" value="Verificar">
    </form>

    <?php if ($resultado !== null): ?>
        <h3>Resultado</h3>
        <?php if (!empty($resultado['bloqueado'])): ?>
            <p style="color: #ff6b6b;"><strong>BLOQUEADO:</strong> <?= h($resultado['error']) ?></p>
        <?php elseif (!$resultado['ok']): ?>
            <p><strong>Error:</strong> <?= h($resultado['error']) ?></p>
        <?php else: ?>
            <table border="1" cellpadding="6">
                <tr><th>Estado HTTP</th><td><?= (int)$resultado['status'] ?></td></tr>
                <tr><th>Tipo de contenido</th><td><?= h($resultado['content_type']) ?></td></tr>
                <tr><th>Bytes recibidos</th><td><?= (int)$resultado['bytes'] ?></td></tr>
                <tr><th>URL final</th><td><?= h($resultado['url_final']) ?></td></tr>
                <tr><th>Redirecciones</th><td><?= (int)$resultado['redirecciones'] ?></td></tr>
            </table>
        <?php endif; ?>
    <?php endif; ?>
</body>
</html>
