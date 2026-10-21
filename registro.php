<?php
$conn = new mysqli("bd_maestro", "gerente_db", "gerentepwd123", "ecommerce_db");
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$message = '';
$success = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $nombre = trim($_POST['nombre'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $password2 = $_POST['password2'] ?? '';

    if ($nombre === '' || $email === '' || $password === '') {
        $message = "Todos los campos son obligatorios";
    } elseif ($password !== $password2) {
        $message = "Las contraseñas no coinciden";
    } elseif (strlen($password) < 8) {
        $message = "La contraseña debe tener al menos 8 caracteres";
    } else {
        $check = $conn->prepare("SELECT id_usuario FROM usuarios WHERE email = ?");
        $check->bind_param("s", $email);
        $check->execute();
        if ($check->get_result()->num_rows > 0) {
            $message = "Ese email ya está registrado";
        } else {
            $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
            $token = bin2hex(random_bytes(32));

            $stmt = $conn->prepare("INSERT INTO usuarios (nombre, email, password, verification_token) VALUES (?, ?, ?, ?)");
            $stmt->bind_param("ssss", $nombre, $email, $hashedPassword, $token);
            $stmt->execute();
            $stmt->close();

            $verificationLink = "http://localhost:8080/verificar.php?token=" . $token;

            $asunto = "Confirma tu cuenta - Ecommerce Lab";
            $cuerpo = "Hola $nombre,\n\nConfirma tu cuenta haciendo clic en el siguiente enlace:\n$verificationLink\n\nSi no creaste esta cuenta, ignora este mensaje.";
            $headers = "From: noreply@ecommercelab.local\r\n";

            mail($email, $asunto, $cuerpo, $headers);

            $success = true;
            $message = "Cuenta creada. Revisa tu correo (MailHog) para confirmar tu cuenta.";
        }
        $check->close();
    }
}
$conn->close();
?>
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Registro</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<h2>Crear cuenta</h2>

<?php if ($message): ?>
    <p><strong><?= htmlspecialchars($message) ?></strong></p>
<?php endif; ?>

<?php if (!$success): ?>
<form method="POST">
    Nombre: <input type="text" name="nombre" required><br>
    Email: <input type="email" name="email" required><br>
    Contraseña: <input type="password" name="password" required><br>
    Confirmar contraseña: <input type="password" name="password2" required><br>
    <input type="submit" value="Registrarme">
</form>
<?php endif; ?>

<p><a href="index.php">← Ya tengo cuenta, iniciar sesión</a></p>
</body>
</html>
