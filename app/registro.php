<?php
require_once __DIR__ . '/session_helper.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/security_helper.php';

startSecureSession();

$message = '';
$success = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $password  = (string)($_POST['password'] ?? '');
    $password2 = (string)($_POST['password2'] ?? '');
    $nombre = validate_plain_text((string)($_POST['nombre'] ?? ''), 'El nombre', 100);
    $email  = validate_email_field((string)($_POST['email'] ?? ''));

    if (!validateCsrfToken($_POST['csrf_token'] ?? null)) {
        $message = "Token CSRF inválido. Recarga la página e intenta nuevamente.";
    } elseif ($nombre['error'] !== '') {
        $message = $nombre['error'];
    } elseif ($email['error'] !== '') {
        $message = $email['error'];
    } elseif ($password === '') {
        $message = "Todos los campos son obligatorios";
    } elseif ($password !== $password2) {
        $message = "Las contraseñas no coinciden";
    } elseif (strlen($password) < 8) {
        $message = "La contraseña debe tener al menos 8 caracteres";
    } elseif (strlen($password) > 72) {
        $message = "La contraseña no puede exceder 72 caracteres";
    } else {
        $conn = getConexion('escritura'); // Todo registro va al maestro
        try {
            $check = $conn->prepare("SELECT id_usuario FROM usuarios WHERE email = ?");
            $check->bind_param("s", $email['valor']);
            $check->execute();
            $existe = $check->get_result()->num_rows > 0;
            $check->close();

            if ($existe) {
                $message = "Ese email ya está registrado";
            } else {
                $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
                $token = bin2hex(random_bytes(32));

                // rol y email_verified se fijan en el servidor: nunca provienen del formulario
                $stmt = $conn->prepare(
                    "INSERT INTO usuarios (nombre, email, password, rol, email_verified, verification_token)
                     VALUES (?, ?, ?, 'cliente', 0, ?)"
                );
                $stmt->bind_param("ssss", $nombre['valor'], $email['valor'], $hashedPassword, $token);
                $stmt->execute();
                $stmt->close();

                $verificationLink = "http://localhost:8080/verificar.php?token=" . $token;

                $asunto = "Confirma tu cuenta - Ecommerce Lab";
                $cuerpo = "Hola {$nombre['valor']},\n\nConfirma tu cuenta haciendo clic en el siguiente enlace:\n$verificationLink\n\nSi no creaste esta cuenta, ignora este mensaje.";
                $headers = "From: noreply@ecommercelab.local\r\n";

                // El correo ya fue validado con FILTER_VALIDATE_EMAIL y sin saltos de línea (anti inyección de cabeceras)
                mail($email['valor'], $asunto, $cuerpo, $headers);

                $success = true;
                $message = "Cuenta creada. Revisa tu correo (MailHog) para confirmar tu cuenta.";
            }
        } catch (mysqli_sql_exception $e) {
            error_log('[REGISTRO] ' . $e->getMessage());
            $message = "No se pudo crear la cuenta. Intenta más tarde.";
        }
        $conn->close();
    }
}
?>
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Registro</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<h2>Crear cuenta</h2>

<?php if ($message): ?>
    <p><strong><?= h($message) ?></strong></p>
<?php endif; ?>

<?php if (!$success): ?>
<form method="POST">
    <input type="hidden" name="csrf_token" value="<?= h(generateCsrfToken()) ?>">
    Nombre: <input type="text" name="nombre" maxlength="100" required><br>
    Email: <input type="email" name="email" maxlength="100" required><br>
    Contraseña: <input type="password" name="password" minlength="8" maxlength="72" required><br>
    Confirmar contraseña: <input type="password" name="password2" minlength="8" maxlength="72" required><br>
    <input type="submit" value="Registrarme">
</form>
<?php endif; ?>

<p><a href="index.php">← Ya tengo cuenta, iniciar sesión</a></p>
</body>
</html>
