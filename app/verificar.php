<?php
$conn = new mysqli("bd_maestro", "admin_db", "admin123", "ecommerce_db");
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$message = "Enlace inválido o expirado";
$ok = false;

$token = $_GET['token'] ?? '';

if ($token !== '') {
    $stmt = $conn->prepare("SELECT id_usuario FROM usuarios WHERE verification_token = ? AND email_verified = 0");
    $stmt->bind_param("s", $token);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        $upd = $conn->prepare("UPDATE usuarios SET email_verified = 1, verification_token = NULL WHERE id_usuario = ?");
        $upd->bind_param("i", $user['id_usuario']);
        $upd->execute();
        $upd->close();
        $ok = true;
        $message = "Correo verificado correctamente. Ya puedes iniciar sesión.";
    }
    $stmt->close();
}
$conn->close();
?>
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Verificación</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<h2>Verificación de correo</h2>
<p><strong><?= htmlspecialchars($message) ?></strong></p>
<p><a href="index.php">Ir al login</a></p>
</body>
</html>
