<?php
require_once __DIR__ . '/session_helper.php';
require_once __DIR__ . '/totp.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/jwt_helper.php';
require_once __DIR__ . '/security_helper.php';

startSecureSession();

$error = '';
$email_ingresado = '';

// Hash bcrypt de relleno: se verifica aunque el usuario no exista para igualar tiempos de respuesta
const LOGIN_HASH_DUMMY = '$2y$10$WpvN.BlW2c3v2ksBTIqrWeJ899a5xP6GJLOukzHI2ggJTYZMeD/Va';

// Completa el login: nueva sesión + variables de sesión + JWT firmado en cookie HttpOnly
function finalizarLogin(array $u): void {
    regenerateSessionOnLogin();

    $_SESSION['authenticated_user_id'] = (int)$u['id_usuario'];
    $_SESSION['id_usuario']            = (int)$u['id_usuario'];
    $_SESSION['nombre']                = $u['nombre'];
    $_SESSION['email']                 = $u['email'];
    $_SESSION['rol']                   = $u['rol'];

    jwt_set_cookie(jwt_issue_for_user($u));

    afb_limpiar($u['email']);
    afb_registrar($u['email'], clientIp(), true, 'login_ok');

    header('Location: ' . ($u['rol'] === 'admin' ? 'usuarios.php' : 'productos.php'));
    exit;
}

// Aviso si la sesión caducó por inactividad
if (!empty($_SESSION['expired'])) {
    $error = 'Tu sesión expiró por inactividad. Inicia sesión nuevamente.';
    unset($_SESSION['expired']);
}

// Permitir cancelar el paso 2FA para cambiar de usuario
if (isset($_GET['cancelar'])) {
    unset($_SESSION['pending_2fa']);
    header('Location: login.php');
    exit;
}

// Si ya está autenticado, redirigir según su rol
if (isset($_SESSION['authenticated_user_id'], $_SESSION['rol'])) {
    if ($_SESSION['rol'] === 'admin') {
        header('Location: usuarios.php');
    } else {
        header('Location: productos.php');
    }
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf_post = $_POST['csrf_token'] ?? null;
    $ip = clientIp();

    try {
        if (!validateCsrfToken($csrf_post)) {
            $error = 'Token CSRF inválido. Recarga la página e intenta nuevamente.';
        } elseif (isset($_POST['step']) && $_POST['step'] === '2fa') {
            // =========================================================
            // FASE 2: VERIFICACIÓN DEL CÓDIGO TOTP (6 DÍGITOS)
            // =========================================================
            if (!isset($_SESSION['pending_2fa'])) {
                $error = 'La verificación 2FA expiró. Vuelve a ingresar tus credenciales.';
            } else {
                $pending = $_SESSION['pending_2fa'];
                $estado = afb_estado($pending['email'], $ip);

                if ($estado['bloqueado']) {
                    unset($_SESSION['pending_2fa']);
                    $error = afb_mensaje_bloqueo($estado['segundos']);
                } else {
                    $codigo = preg_replace('/\s+/', '', $_POST['totp_code'] ?? '');

                    if (!preg_match('/^\d{6}$/', $codigo)) {
                        $error = 'Ingresa un código numérico válido de 6 dígitos.';
                    } elseif (verifyTotpCode($pending['twofa_secret'], $codigo)) {
                        unset($_SESSION['pending_2fa']);
                        finalizarLogin($pending);
                    } else {
                        // Los códigos TOTP también cuentan como intentos fallidos (6 dígitos son fáciles de adivinar)
                        afb_registrar($pending['email'], $ip, false, 'totp_incorrecto');
                        $estado = afb_estado($pending['email'], $ip);
                        if ($estado['bloqueado']) {
                            unset($_SESSION['pending_2fa']);
                            $error = afb_mensaje_bloqueo($estado['segundos']);
                        } else {
                            $error = 'Código 2FA incorrecto o expirado. Intenta de nuevo.';
                        }
                    }
                }
            }
        } else {
            // =========================================================
            // FASE 1: VALIDACIÓN DE CREDENCIALES (LECTURA EN ESCLAVOS)
            // =========================================================
            $email_ingresado = clean_text((string)($_POST['email'] ?? ''), 100);
            $password = (string)($_POST['password'] ?? '');

            if ($email_ingresado === '' || $password === '') {
                $error = 'Por favor, completa todos los campos.';
            } elseif (strlen($password) > 72 || !filter_var($email_ingresado, FILTER_VALIDATE_EMAIL)) {
                // bcrypt solo procesa 72 bytes; un correo inválido ni siquiera consulta la BD
                afb_registrar($email_ingresado, $ip, false, 'formato_invalido');
                $error = 'Correo o contraseña incorrectos.';
            } else {
                // 1) ¿Está bloqueado este correo o esta IP? (se comprueba ANTES de validar la contraseña)
                $estado = afb_estado($email_ingresado, $ip);

                if ($estado['bloqueado']) {
                    securityLog('LOGIN_BLOQUEADO', ['email' => afb_normalizar_email($email_ingresado), 'segundos' => $estado['segundos']]);
                    $error = afb_mensaje_bloqueo($estado['segundos']);
                } else {
                    // 2) Consulta de credenciales
                    $conn = getConexion('lectura');
                    $stmt = $conn->prepare(
                        "SELECT id_usuario, nombre, email, password, rol, email_verified, twofa_enabled, twofa_secret
                         FROM usuarios
                         WHERE email = ?
                         LIMIT 1"
                    );
                    $stmt->bind_param('s', $email_ingresado);
                    $stmt->execute();
                    $usuario = $stmt->get_result()->fetch_assoc();
                    $stmt->close();
                    $conn->close();

                    $hash = $usuario['password'] ?? LOGIN_HASH_DUMMY;
                    $password_ok = password_verify($password, $hash) && $usuario !== null;

                    if (!$password_ok) {
                        afb_registrar($email_ingresado, $ip, false, $usuario ? 'password_incorrecta' : 'usuario_inexistente');
                        $estado = afb_estado($email_ingresado, $ip);
                        $error = $estado['bloqueado']
                            ? afb_mensaje_bloqueo($estado['segundos'])
                            : 'Correo o contraseña incorrectos.';
                    } elseif ((int)$usuario['email_verified'] !== 1) {
                        $error = 'Tu correo aún no ha sido verificado. Revisa MailHog.';
                    } elseif ((int)$usuario['twofa_enabled'] === 1) {
                        $secreto = $usuario['twofa_secret'] ?? '';
                        $es_primer_registro = false;

                        // Si tiene 2FA activo pero aún no tiene secreto en BD, generarlo y guardarlo en el Maestro
                        if ($secreto === '') {
                            $secreto = generateTotpSecret();
                            $es_primer_registro = true;

                            $connMaster = getConexion('escritura');
                            $stmtUpd = $connMaster->prepare("UPDATE usuarios SET twofa_secret = ? WHERE id_usuario = ?");
                            $uid = (int)$usuario['id_usuario'];
                            $stmtUpd->bind_param('si', $secreto, $uid);
                            $stmtUpd->execute();
                            $stmtUpd->close();
                            $connMaster->close();
                        }

                        $_SESSION['pending_2fa'] = [
                            'id_usuario'   => (int)$usuario['id_usuario'],
                            'nombre'       => $usuario['nombre'],
                            'email'        => $usuario['email'],
                            'rol'          => $usuario['rol'],
                            'twofa_secret' => $secreto,
                            'is_setup'     => $es_primer_registro
                        ];

                        header('Location: login.php');
                        exit;
                    } else {
                        // Usuario sin 2FA activo
                        finalizarLogin($usuario);
                    }
                }
            }
        }
    } catch (Throwable $e) {
        error_log('[LOGIN] ' . $e->getMessage());
        $error = 'Error interno de seguridad. Contacta al administrador.';
    }
}

$csrf_token = generateCsrfToken();
$en_paso_2fa = isset($_SESSION['pending_2fa']);
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $en_paso_2fa ? 'Verificación 2FA' : 'Iniciar Sesión'; ?> - EcommerceLab</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container login-container">
        <div class="card">
            <?php if ($error !== ''): ?>
                <div class="alert alert-error" style="color: #b00020; background: #fdecea; padding: 10px; border-radius: 4px; margin-bottom: 15px;">
                    <?php echo h($error); ?>
                </div>
            <?php endif; ?>

            <?php if ($en_paso_2fa): ?>
                <?php
                    $pending = $_SESSION['pending_2fa'];
                    $otpUri  = getTotpUri($pending['twofa_secret'], $pending['email']);
                ?>
                <h2>Verificación en Dos Pasos (2FA)</h2>
                <p>Ingresa el código de 6 dígitos de tu aplicación autenticadora para <strong><?php echo h($pending['email']); ?></strong>.</p>

                <?php if (!empty($pending['is_setup'])): ?>
                    <div style="background: #f4f6f8; border: 1px solid #d0d7de; padding: 12px; border-radius: 6px; margin-bottom: 15px; text-align: center;">
                        <p style="margin-top: 0; font-size: 0.9rem;"><strong>Configuración inicial de 2FA:</strong> escanea este QR o ingresa la clave secreta manualmente en Google Authenticator / Authy:</p>
                        <img
                            src="https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=<?php echo urlencode($otpUri); ?>"
                            alt="Código QR 2FA"
                            style="margin: 8px auto; display: block;"
                            onerror="this.style.display='none'"
                        >
                        <code style="display: inline-block; background: #fff; padding: 6px 10px; border: 1px solid #ccc; border-radius: 4px; font-size: 1rem; letter-spacing: 1px;">
                            <?php echo h($pending['twofa_secret']); ?>
                        </code>
                    </div>
                <?php endif; ?>

                <form method="POST" action="login.php" autocomplete="off">
                    <input type="hidden" name="csrf_token" value="<?php echo h($csrf_token); ?>">
                    <input type="hidden" name="step" value="2fa">

                    <div class="form-group">
                        <label for="totp_code">Código de 6 dígitos</label>
                        <input
                            type="text"
                            id="totp_code"
                            name="totp_code"
                            inputmode="numeric"
                            pattern="[0-9]{6}"
                            maxlength="6"
                            placeholder="000000"
                            required
                            autofocus
                        >
                    </div>

                    <button type="submit" class="btn">Verificar y Entrar</button>
                </form>

                <p style="margin-top: 15px;">
                    <a href="login.php?cancelar=1">Cancelar y volver al inicio</a>
                </p>

            <?php else: ?>
                <h2>Iniciar Sesión</h2>

                <form method="POST" action="login.php" autocomplete="off">
                    <input type="hidden" name="csrf_token" value="<?php echo h($csrf_token); ?>">

                    <div class="form-group">
                        <label for="email">Correo electrónico</label>
                        <input
                            type="email"
                            id="email"
                            name="email"
                            value="<?php echo h($email_ingresado); ?>"
                            maxlength="100"
                            required
                            autofocus
                        >
                    </div>

                    <div class="form-group">
                        <label for="password">Contraseña</label>
                        <input
                            type="password"
                            id="password"
                            name="password"
                            maxlength="72"
                            required
                        >
                    </div>

                    <button type="submit" class="btn">Ingresar</button>
                </form>

                <p style="margin-top: 15px;">
                    ¿No tienes cuenta? <a href="registro.php">Regístrate aquí</a>
                </p>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
