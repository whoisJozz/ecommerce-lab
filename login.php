<?php
require __DIR__ . '/session_helper.php';
startSecureSession();
require __DIR__ . '/totp.php';

$conn = new mysqli("bd_maestro", "app_login", "apploginpwd123", "ecommerce_db");
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$step = 'login';
$message = '';
$qrUri = '';

if (!empty($_SESSION['expired'])) {
    $message = "Tu sesión expiró por inactividad, inicia sesión de nuevo";
    unset($_SESSION['expired']);
}

if (isset($_POST['email'], $_POST['pass'])) {
    if (!validateCsrfToken($_POST['csrf_token'] ?? null)) {
        die("Token CSRF inválido");
    }

    $email = $_POST['email'];
    $pass = $_POST['pass'];

    $stmt = $conn->prepare("SELECT id_usuario, nombre, password, rol, twofa_secret, twofa_enabled, email_verified FROM usuarios WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result && $result->num_rows > 0) {
        $user = $result->fetch_assoc();

        if (password_verify($pass, $user['password'])) {
            if (!$user['email_verified']) {
                $message = "Debes verificar tu correo antes de iniciar sesión";
            } else {
                $_SESSION['pending_user_id'] = $user['id_usuario'];
                $_SESSION['pending_user_nombre'] = $user['nombre'];
                $_SESSION['pending_user_rol'] = $user['rol'];

                if ($user['twofa_enabled']) {
                    $step = 'verify2fa';
                } else {
                    $secret = generateTotpSecret();
                    $_SESSION['pending_secret'] = $secret;
                    $qrUri = getTotpUri($secret, $email);
                    $step = 'setup2fa';
                }
            }
        } else {
            $message = "Login incorrecto";
        }
    } else {
        $message = "Login incorrecto";
    }
    $stmt->close();
}

if (isset($_POST['enroll_code']) && isset($_SESSION['pending_secret'], $_SESSION['pending_user_id'])) {
    if (!validateCsrfToken($_POST['csrf_token'] ?? null)) {
        die("Token CSRF inválido");
    }

    if (verifyTotpCode($_SESSION['pending_secret'], $_POST['enroll_code'])) {
        $stmt = $conn->prepare("UPDATE usuarios SET twofa_secret = ?, twofa_enabled = 1 WHERE id_usuario = ?");
        $stmt->bind_param("si", $_SESSION['pending_secret'], $_SESSION['pending_user_id']);
        $stmt->execute();
        $stmt->close();

        $uid = $_SESSION['pending_user_id'];
        $nombre = $_SESSION['pending_user_nombre'];
        $rol = $_SESSION['pending_user_rol'];
        session_unset();
        regenerateSessionOnLogin();
        $_SESSION['authenticated_user_id'] = $uid;
        $_SESSION['nombre'] = $nombre;
        $_SESSION['rol'] = $rol;
        $_SESSION['last_activity'] = time();

        header("Location: productos.php");
        exit;
    } else {
        $message = "Código incorrecto, intenta de nuevo";
        $qrUri = getTotpUri($_SESSION['pending_secret'], "usuario");
        $step = 'setup2fa';
    }
}

if (isset($_POST['login_code']) && isset($_SESSION['pending_user_id'])) {
    if (!validateCsrfToken($_POST['csrf_token'] ?? null)) {
        die("Token CSRF inválido");
    }

    $stmt = $conn->prepare("SELECT twofa_secret FROM usuarios WHERE id_usuario = ?");
    $stmt->bind_param("i", $_SESSION['pending_user_id']);
    $stmt->execute();
    $r = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if ($r && verifyTotpCode($r['twofa_secret'], $_POST['login_code'])) {
        $uid = $_SESSION['pending_user_id'];
        $nombre = $_SESSION['pending_user_nombre'];
        $rol = $_SESSION['pending_user_rol'];
        session_unset();
        regenerateSessionOnLogin();
        $_SESSION['authenticated_user_id'] = $uid;
        $_SESSION['nombre'] = $nombre;
        $_SESSION['rol'] = $rol;
        $_SESSION['last_activity'] = time();

        header("Location: productos.php");
        exit;
    } else {
        $message = "Código 2FA incorrecto";
        $step = 'verify2fa';
    }
}

$conn->close();
?>
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Login 2FA</title>
<link rel="stylesheet" href="style.css">
</head>
<body>

<?php if ($message): ?>
    <p><strong><?= htmlspecialchars($message) ?></strong></p>
<?php endif; ?>

<?php if ($step === 'setup2fa' && $qrUri): ?>
    <h3>Configura tu app de autenticación</h3>
    <p>Escanea este código QR con Google Authenticator o Authy:</p>
    <div id="qrcode"></div>
    <p>O ingresa manualmente este secreto: <code><?= htmlspecialchars($_SESSION['pending_secret']) ?></code></p>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
    <script>
        new QRCode(document.getElementById("qrcode"), "<?= htmlspecialchars($qrUri) ?>");
    </script>

    <form method="POST">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCsrfToken()) ?>">
        <input type="text" name="enroll_code" maxlength="6"><br>
        <input type="submit" value="Confirmar y activar 2FA">
    </form>

<?php elseif ($step === 'verify2fa'): ?>
    <h3>Ingresa tu código de 6 dígitos</h3>
    <form method="POST">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCsrfToken()) ?>">
        <input type="text" name="login_code" maxlength="6"><br>
        <input type="submit" value="Verificar">
    </form>

<?php else: ?>
    <h3>Login</h3>
    <form method="POST">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCsrfToken()) ?>">
        Email: <input type="text" name="email"><br>
        Password: <input type="password" name="pass"><br>
        <input type="submit" value="Login">
    </form>
    <p><a href="registro.php">¿No tienes cuenta? Regístrate</a></p>
<?php endif; ?>

</body>
</html>
