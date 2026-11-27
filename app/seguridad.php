<?php
// Panel de seguridad (solo admin): diagnóstico de conexión/token, bloqueos AFB activos,
// desbloqueo manual de correos e IPs e historial reciente de intentos de login.
require_once __DIR__ . '/session_helper.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/security_helper.php';
require_once __DIR__ . '/nav.php';

startSecureSession();
requireRole(['admin']);

$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCsrfToken($_POST['csrf_token'] ?? null)) {
        $error = 'Token CSRF inválido. Recarga la página e intenta nuevamente.';
    } else {
        try {
            $accion = (string)($_POST['accion'] ?? '');

            if ($accion === 'desbloquear') {
                $tipo  = (string)($_POST['tipo'] ?? '');
                $valor = clean_text((string)($_POST['valor'] ?? ''), 100);

                if (!in_array($tipo, ['email', 'ip'], true) || $valor === '') {
                    $error = 'Solicitud de desbloqueo inválida.';
                } else {
                    $n = afb_desbloquear($tipo, $valor);
                    securityLog('DESBLOQUEO_ADMIN', ['tipo' => $tipo, 'valor' => $valor, 'admin' => $_SESSION['email'] ?? '', 'registros' => $n]);
                    $message = "Se desbloqueó " . ($tipo === 'ip' ? 'la IP' : 'el correo') . " $valor ($n registros de fallos eliminados).";
                }
            } elseif ($accion === 'desbloquear_todo') {
                $n = afb_desbloquear_todo();
                securityLog('DESBLOQUEO_ADMIN_TOTAL', ['admin' => $_SESSION['email'] ?? '', 'registros' => $n]);
                $message = "Se eliminaron todos los bloqueos activos ($n registros de fallos).";
            }
        } catch (Throwable $e) {
            error_log('[SEGURIDAD] ' . $e->getMessage());
            $error = 'No se pudo completar la operación.';
        }
    }
}

$bloqueos = ['email' => [], 'ip' => []];
$historial = [];
try {
    $bloqueos  = afb_bloqueos_activos();
    $historial = afb_historial(30);
} catch (Throwable $e) {
    error_log('[SEGURIDAD] ' . $e->getMessage());
    $error = $error ?: 'No se pudo leer la bitácora de intentos. ¿Ejecutaste fase1_migracion.sql?';
}

$claims = jwt_current_claims();
$csrf = generateCsrfToken();

function formato_tiempo(int $segundos): string {
    return sprintf('%d:%02d min', intdiv($segundos, 60), $segundos % 60);
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Seguridad</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <?php renderNav('seguridad'); ?>

    <h2>Panel de seguridad</h2>

    <?php if ($message): ?><p><strong><?= h($message) ?></strong></p><?php endif; ?>
    <?php if ($error): ?><p style="color: #ff6b6b;"><strong><?= h($error) ?></strong></p><?php endif; ?>

    <h3>Mi conexión y mi token</h3>
    <table class="compacta">
        <tr><th>IP detectada por la aplicación</th><td><code><?= h(clientIp()) ?></code></td></tr>
        <tr><th>REMOTE_ADDR (quién le habla a PHP)</th><td><code><?= h($_SERVER['REMOTE_ADDR'] ?? '-') ?></code></td></tr>
        <tr><th>X-Forwarded-For (lo que añade el WAF)</th><td><code><?= h($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '(vacío)') ?></code></td></tr>
        <tr><th>Usuario / rol</th><td><?= h($_SESSION['email'] ?? '') ?> / <?= h($_SESSION['rol']) ?></td></tr>
        <?php if ($claims): ?>
            <tr><th>Token JWT emitido</th><td><?= h(date('Y-m-d H:i:s', (int)$claims['iat'])) ?></td></tr>
            <tr><th>Token JWT expira</th><td><?= h(date('Y-m-d H:i:s', (int)$claims['exp'])) ?></td></tr>
            <tr><th>Identificador (jti)</th><td><code><?= h((string)($claims['jti'] ?? '')) ?></code></td></tr>
        <?php endif; ?>
        <tr><th>Respuesta JSON del token</th><td><a href="api_whoami.php" target="_blank" rel="noopener">Abrir /api_whoami.php</a></td></tr>
    </table>
    <p style="font-size: 13px; color: #8fa8c7; margin-top: 8px;">
        Si "IP detectada" es la IP real del equipo desde el que entras (o la del gateway de Docker en pruebas locales),
        el WAF está pasando bien la cabecera. Las horas del panel están en UTC (hora del servidor).
    </p>

    <h3 style="margin-top: 30px;">Bloqueos activos (AFB)</h3>
    <p style="font-size: 13px; color: #8fa8c7;">
        Se bloquea un correo tras <?= AFB_MAX_POR_EMAIL ?> fallos y una IP tras <?= AFB_MAX_POR_IP ?> fallos
        dentro de <?= intdiv(AFB_VENTANA, 60) ?> minutos. Los bloqueos del firewall o de Fail2Ban (Fase 3) se administran aparte.
    </p>

    <?php
    $secciones = [
        'ip'    => ['IPs bloqueadas', 'IP'],
        'email' => ['Correos bloqueados', 'Correo'],
    ];
    foreach ($secciones as $tipo => [$titulo, $columna]):
    ?>
        <h3 style="font-size: 15px; margin-top: 15px;"><?= h($titulo) ?></h3>
        <?php if (!$bloqueos[$tipo]): ?>
            <p>Sin bloqueos activos.</p>
        <?php else: ?>
            <table>
                <tr><th><?= h($columna) ?></th><th>Fallos</th><th>Último intento (UTC)</th><th>Se libera en</th><th>Acción</th></tr>
                <?php foreach ($bloqueos[$tipo] as $b): ?>
                    <tr>
                        <td><code><?= h($b['clave']) ?></code></td>
                        <td><?= (int)$b['fallos'] ?></td>
                        <td><?= h($b['ultimo']) ?></td>
                        <td><?= h(formato_tiempo($b['segundos'])) ?></td>
                        <td>
                            <form method="POST" action="seguridad.php">
                                <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                                <input type="hidden" name="accion" value="desbloquear">
                                <input type="hidden" name="tipo" value="<?= h($tipo) ?>">
                                <input type="hidden" name="valor" value="<?= h($b['clave']) ?>">
                                <input type="submit" value="Desbloquear">
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </table>
        <?php endif; ?>
    <?php endforeach; ?>

    <form method="POST" action="seguridad.php" onsubmit="return confirm('¿Eliminar TODOS los bloqueos activos?');" class="en-linea" style="margin-top: 15px;">
        <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
        <input type="hidden" name="accion" value="desbloquear_todo">
        <input type="submit" value="Desbloquear todo">
    </form>

    <h3 style="margin-top: 30px;">Asistente SOC y Base de Conocimiento IA (Ollama + ChromaDB)</h3>
    <p style="font-size: 13px; color: #8fa8c7;">
        Analiza los últimos eventos de inicio de sesión con IA local o sincroniza el catálogo de productos hacia ChromaDB.
    </p>
    <div style="margin-bottom: 12px;">
        <button type="button" id="btn-sync-chroma">Sincronizar catálogo a ChromaDB</button>
        <span id="sync-status" style="margin-left: 10px; font-size: 13px; color: #ffd700;"></span>
    </div>
    <form id="form-soc-ia" style="max-width: 750px;">
        <input type="hidden" id="soc-csrf" value="<?= h($csrf) ?>">
        <input type="text" id="soc-msg" maxlength="400" placeholder="Ej. Analiza los últimos intentos fallidos y dime si hay patrón de ataque" style="width: 72%;" required>
        <button type="submit" id="btn-soc-enviar">Analizar con IA</button>
    </form>
    <pre id="soc-respuesta" style="max-width: 750px; white-space: pre-wrap; background: #11151c; border: 1px solid #2a3340; padding: 12px; border-radius: 4px; margin-top: 10px; min-height: 50px; color: #e6edf3;">Listo para analizar eventos de seguridad...</pre>

    <h3 style="margin-top: 30px;">Últimos intentos de inicio de sesión</h3>
    <?php if (!$historial): ?>
        <p>Aún no hay intentos registrados.</p>
    <?php else: ?>
        <table>
            <tr><th>Fecha (UTC)</th><th>Correo</th><th>IP</th><th>Resultado</th><th>Motivo</th></tr>
            <?php foreach ($historial as $f): ?>
                <tr>
                    <td><?= h($f['fecha']) ?></td>
                    <td><?= h($f['email']) ?></td>
                    <td><code><?= h($f['ip']) ?></code></td>
                    <td><?= (int)$f['exito'] === 1 ? 'Exitoso' : 'Fallido' ?></td>
                    <td><?= h($f['motivo']) ?></td>
                </tr>
            <?php endforeach; ?>
        </table>
    <?php endif; ?>

    <script>
    (function () {
        var csrf = document.getElementById('soc-csrf').value;
        var btnSync = document.getElementById('btn-sync-chroma');
        var syncStatus = document.getElementById('sync-status');

        btnSync.addEventListener('click', async function () {
            btnSync.disabled = true;
            syncStatus.textContent = 'Indexando productos en ChromaDB...';
            try {
                var fd = new FormData();
                fd.append('csrf_token', csrf);
                fd.append('accion', 'sincronizar');
                var r = await fetch('api_chat.php', { method: 'POST', body: fd });
                var d = await r.json();
                syncStatus.textContent = d.ok ? ('Listo: ' + d.indexados + ' documentos indexados en ChromaDB.') : ('Error: ' + (d.error || 'fallo'));
            } catch (e) {
                syncStatus.textContent = 'Error de red al sincronizar.';
            } finally {
                btnSync.disabled = false;
            }
        });

        var form = document.getElementById('form-soc-ia');
        var input = document.getElementById('soc-msg');
        var out = document.getElementById('soc-respuesta');
        var btn = document.getElementById('btn-soc-enviar');

        form.addEventListener('submit', async function (ev) {
            ev.preventDefault();
            var txt = input.value.trim();
            if (!txt) return;
            btn.disabled = true;
            out.textContent = 'Consultando modelo local en Ollama...';
            try {
                var fd = new FormData();
                fd.append('csrf_token', csrf);
                fd.append('accion', 'chat');
                fd.append('modo', 'seguridad');
                fd.append('mensaje', txt);
                var r = await fetch('api_chat.php', { method: 'POST', body: fd });
                var d = await r.json();
                out.textContent = d.ok ? d.respuesta : ('Error: ' + (d.error || 'No se pudo obtener respuesta.'));
            } catch (e) {
                out.textContent = 'Error de comunicación con api_chat.php.';
            } finally {
                btn.disabled = false;
            }
        });
    })();
    </script>
</body>
</html>