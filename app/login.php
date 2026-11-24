<?php
require_once __DIR__ . '/session_helper.php';
require_once __DIR__ . '/totp.php';
require_once __DIR__ . '/db.php';

startSecureSession();

$error = '';
$email_ingresado = '';

// Aviso si la sesión caducó por el timeout de 2 minutos en session_helper.php
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

    if (!validateCsrfToken($csrf_post)) {
        $error = 'Token CSRF inválido. Recarga la página e intenta nuevamente.';
    } elseif (isset($_POST['step']) && $_POST['step'] === '2fa') {
        // =========================================================
        // FASE 2: VERIFICACIÓN DEL CÓDIGO TOTP (6 DÍGITOS)
        // =========================================================
        if (!isset($_SESSION['pending_2fa'])) {
            $error = 'La verificación 2FA expiró. Vuelve a ingresar tus credenciales.';
        } else {
            $codigo = preg_replace('/\s+/', '', $_POST['totp_code'] ?? '');
            $pending = $_SESSION['pending_2fa'];

            if (!preg_match('/^\d{6}$/', $codigo)) {
                $error = 'Ingresa un código numérico válido de 6 dígitos.';
            } elseif (verifyTotpCode($pending['twofa_secret'], $codigo)) {
                unset($_SESSION['pending_2fa']);
                regenerateSessionOnLogin();

                $_SESSION['authenticated_user_id'] = (int)$pending['id_usuario'];
                $_SESSION['id_usuario']            = (int)$pending['id_usuario'];
                $_SESSION['nombre']                = $pending['nombre'];
                $_SESSION['email']                 = $pending['email'];
                $_SESSION['rol']                   = $pending['rol'];

                if ($pending['rol'] === 'admin') {
                    header('Location: usuarios.php');
                } else {
                    header('Location: productos.php');
                }
                exit;
            } else {
                $error = 'Código 2FA incorrecto o expirado. Intenta de nuevo.';
            }
        }
    } else {
        // =========================================================
        // FASE 1: VALIDACIÓN DE CREDENCIALES (LECTURA EN ESCLAVOS)
        // =========================================================
        $email_ingresado = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';

        if ($email_ingresado === '' || $password === '') {
            $error = 'Por favor, completa todos los campos.';
        } else {
            $conn = getConexion('lectura');
            $stmt = $conn->prepare(
                "SELECT id_usuario, nombre, email, password, rol, email_verified, twofa_enabled, twofa_secret 
                 FROM usuarios 
                 WHERE email = ? 
                 LIMIT 1"
            );

            if ($stmt) {
                $stmt->bind_param('s', $email_ingresado);
                $stmt->execute();
                $resultado = $stmt->get_result();

                if ($usuario = $resultado->fetch_assoc()) {
                    if (password_verify($password, $usuario['password'])) {
                        if ((int)$usuario['email_verified'] !== 1) {
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
                                if ($stmtUpd) {
                                    $uid = (int)$usuario['id_usuario'];
                                    $stmtUpd->bind_param('si', $secreto, $uid);
                                    $stmtUpd->execute();
                                    $stmtUpd->close();
                                }
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

                            $stmt->close();
                            $conn->close();
                            header('Location: login.php');
                            exit;
                        } else {
                            // Usuario sin 2FA activo
                            regenerateSessionOnLogin();

                            $_SESSION['authenticated_user_id'] = (int)$usuario['id_usuario'];
                            $_SESSION['id_usuario']            = (int)$usuario['id_usuario'];
                            $_SESSION['nombre']                = $usuario['nombre'];
                            $_SESSION['email']                 = $usuario['email'];
                            $_SESSION['rol']                   = $usuario['rol'];

                            $stmt->close();
                            $conn->close();

                            if ($usuario['rol'] === 'admin') {
                                header('Location: usuarios.php');
                            } else {
                                header('Location: productos.php');
                            }
                            exit;
                        }
                    } else {
                        $error = 'Correo o contraseña incorrectos.';
                    }
                } else {
                    $error = 'Correo o contraseña incorrectos.';
                }
                $stmt->close();
            } else {
                $error = 'Error interno al consultar la base de datos.';
            }
            $conn->close();
        }
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
                    <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?>
                </div>
            <?php endif; ?>

            <?php if ($en_paso_2fa): ?>
                <?php 
                    $pending = $_SESSION['pending_2fa'];
                    $otpUri  = getTotpUri($pending['twofa_secret'], $pending['email']);
                ?>
                <h2>Verificación en Dos Pasos (2FA)</h2>
                <p>Ingresa el código de 6 dígitos de tu aplicación autenticadora para <strong><?php echo htmlspecialchars($pending['email'], ENT_QUOTES, 'UTF-8'); ?></strong>.</p>

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
                            <?php echo htmlspecialchars($pending['twofa_secret'], ENT_QUOTES, 'UTF-8'); ?>
                        </code>
                    </div>
                <?php endif; ?>

                <form method="POST" action="login.php" autocomplete="off">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
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
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">

                    <div class="form-group">
                        <label for="email">Correo electrónico</label>
                        <input 
                            type="email" 
                            id="email" 
                            name="email" 
                            value="<?php echo htmlspecialchars($email_ingresado, ENT_QUOTES, 'UTF-8'); ?>" 
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