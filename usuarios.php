<?php
require __DIR__ . '/session_helper.php';
startSecureSession();
requireRole(['admin']);

$conn = new mysqli("bd_maestro", "gerente_db", "gerentepwd123", "ecommerce_db");
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$action = $_POST['action'] ?? $_GET['action'] ?? 'list';
$message = '';

if ($action === 'create' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCsrfToken($_POST['csrf_token'] ?? null)) { die("Token CSRF inválido"); }
    $hashedPassword = password_hash($_POST['password'], PASSWORD_BCRYPT);
    $stmt = $conn->prepare("INSERT INTO usuarios (nombre, email, password, rol) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("ssss", $_POST['nombre'], $_POST['email'], $hashedPassword, $_POST['rol']);
    $stmt->execute();
    $stmt->close();
    $message = "Usuario creado correctamente";
}

if ($action === 'update' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCsrfToken($_POST['csrf_token'] ?? null)) { die("Token CSRF inválido"); }
    $stmt = $conn->prepare("UPDATE usuarios SET nombre = ?, email = ?, rol = ? WHERE id_usuario = ?");
    $stmt->bind_param("sssi", $_POST['nombre'], $_POST['email'], $_POST['rol'], $_POST['id_usuario']);
    $stmt->execute();
    $stmt->close();
    $message = "Usuario actualizado correctamente";
}

if ($action === 'delete' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCsrfToken($_POST['csrf_token'] ?? null)) { die("Token CSRF inválido"); }
    $stmt = $conn->prepare("DELETE FROM usuarios WHERE id_usuario = ?");
    $stmt->bind_param("i", $_POST['id_usuario']);
    $stmt->execute();
    $stmt->close();
    $message = "Usuario eliminado";
}

$editing = null;
if (isset($_GET['edit'])) {
    $stmt = $conn->prepare("SELECT id_usuario, nombre, email, rol FROM usuarios WHERE id_usuario = ?");
    $stmt->bind_param("i", $_GET['edit']);
    $stmt->execute();
    $editing = $stmt->get_result()->fetch_assoc();
    $stmt->close();
}

$usuarios = $conn->query("SELECT id_usuario, nombre, email, rol, fecha_registro FROM usuarios ORDER BY id_usuario DESC");
$conn->close();
?>
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Usuarios</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<p>Sesión: <?= htmlspecialchars($_SESSION['nombre']) ?> (<?= htmlspecialchars($_SESSION['rol']) ?>) | <a href="logout.php">Cerrar sesión</a></p>
<h2>Usuarios</h2>
<?php if ($message): ?><p><strong><?= htmlspecialchars($message) ?></strong></p><?php endif; ?>

<form method="POST" action="?action=<?= $editing ? 'update' : 'create' ?>">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCsrfToken()) ?>">
    <?php if ($editing): ?>
        <input type="hidden" name="id_usuario" value="<?= (int)$editing['id_usuario'] ?>">
    <?php endif; ?>
    Nombre: <input type="text" name="nombre" value="<?= htmlspecialchars($editing['nombre'] ?? '') ?>" required><br>
    Email: <input type="email" name="email" value="<?= htmlspecialchars($editing['email'] ?? '') ?>" required><br>
    <?php if (!$editing): ?>
        Password: <input type="password" name="password" required><br>
    <?php endif; ?>
    Rol:
    <select name="rol">
        <option value="cliente" <?= ($editing['rol'] ?? '') === 'cliente' ? 'selected' : '' ?>>Cliente</option>
        <option value="gerente" <?= ($editing['rol'] ?? '') === 'gerente' ? 'selected' : '' ?>>Gerente</option>
        <option value="admin" <?= ($editing['rol'] ?? '') === 'admin' ? 'selected' : '' ?>>Admin</option>
    </select><br>
    <input type="submit" value="<?= $editing ? 'Actualizar' : 'Crear' ?>">
</form>

<table border="1" cellpadding="6">
<tr><th>ID</th><th>Nombre</th><th>Email</th><th>Rol</th><th>Registro</th><th>Acciones</th></tr>
<?php while ($row = $usuarios->fetch_assoc()): ?>
<tr>
    <td><?= (int)$row['id_usuario'] ?></td>
    <td><?= htmlspecialchars($row['nombre']) ?></td>
    <td><?= htmlspecialchars($row['email']) ?></td>
    <td><?= htmlspecialchars($row['rol']) ?></td>
    <td><?= htmlspecialchars($row['fecha_registro']) ?></td>
    <td>
        <a href="?edit=<?= (int)$row['id_usuario'] ?>">Editar</a>
        <form method="POST" action="?action=delete" style="display:inline" onsubmit="return confirm('¿Eliminar usuario?')">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCsrfToken()) ?>">
            <input type="hidden" name="id_usuario" value="<?= (int)$row['id_usuario'] ?>">
            <input type="submit" value="Eliminar">
        </form>
    </td>
</tr>
<?php endwhile; ?>
</table>

<p><a href="productos.php">← Volver a productos</a></p>
</body>
</html>
