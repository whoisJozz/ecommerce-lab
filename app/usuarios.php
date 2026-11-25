<?php
require_once __DIR__ . '/session_helper.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/security_helper.php';
require_once __DIR__ . '/nav.php';

startSecureSession();
requireRole(['admin']);

$conn = getConexion('escritura'); // Panel administrativo: todo contra el maestro (evita lag de réplica)

const ROLES_VALIDOS = ['cliente', 'gerente', 'admin'];

$action = $_POST['action'] ?? $_GET['action'] ?? 'list';
$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && in_array($action, ['create', 'update', 'delete'], true)) {
    if (!validateCsrfToken($_POST['csrf_token'] ?? null)) {
        die('Token CSRF inválido');
    }

    try {
        if ($action === 'create' || $action === 'update') {
            $nombre = validate_plain_text((string)($_POST['nombre'] ?? ''), 'El nombre', 100);
            $email  = validate_email_field((string)($_POST['email'] ?? ''));
            $rol    = (string)($_POST['rol'] ?? '');

            if ($nombre['error'] !== '') {
                $error = $nombre['error'];
            } elseif ($email['error'] !== '') {
                $error = $email['error'];
            } elseif (!in_array($rol, ROLES_VALIDOS, true)) {
                $error = 'Rol inválido.';
            } elseif ($action === 'create') {
                $password = (string)($_POST['password'] ?? '');
                if (strlen($password) < 8 || strlen($password) > 72) {
                    $error = 'La contraseña debe tener entre 8 y 72 caracteres.';
                } else {
                    $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
                    $stmt = $conn->prepare("INSERT INTO usuarios (nombre, email, password, rol) VALUES (?, ?, ?, ?)");
                    $stmt->bind_param("ssss", $nombre['valor'], $email['valor'], $hashedPassword, $rol);
                    $stmt->execute();
                    $stmt->close();
                    $message = "Usuario creado correctamente";
                }
            } else {
                $id = (int)($_POST['id_usuario'] ?? 0);
                $stmt = $conn->prepare("UPDATE usuarios SET nombre = ?, email = ?, rol = ? WHERE id_usuario = ?");
                $stmt->bind_param("sssi", $nombre['valor'], $email['valor'], $rol, $id);
                $stmt->execute();
                $stmt->close();
                $message = "Usuario actualizado correctamente";
            }
        } else { // delete
            $id = (int)($_POST['id_usuario'] ?? 0);
            if ($id === (int)$_SESSION['authenticated_user_id']) {
                $error = 'No puedes eliminar tu propia cuenta.';
            } else {
                $stmt = $conn->prepare("DELETE FROM usuarios WHERE id_usuario = ?");
                $stmt->bind_param("i", $id);
                $stmt->execute();
                $stmt->close();
                $message = "Usuario eliminado";
            }
        }
    } catch (mysqli_sql_exception $e) {
        error_log('[USUARIOS] ' . $e->getMessage());
        if ($e->getCode() === 1062) {
            $error = 'Ese correo ya está registrado.';
        } elseif ($e->getCode() === 1451) {
            $error = 'No se puede eliminar: el usuario tiene pedidos asociados.';
        } else {
            $error = 'No se pudo completar la operación.';
        }
    }
}

$editing = null;
if (isset($_GET['edit'])) {
    $editId = (int)$_GET['edit'];
    $stmt = $conn->prepare("SELECT id_usuario, nombre, email, rol FROM usuarios WHERE id_usuario = ?");
    $stmt->bind_param("i", $editId);
    $stmt->execute();
    $editing = $stmt->get_result()->fetch_assoc();
    $stmt->close();
}

$usuarios = $conn->query("SELECT id_usuario, nombre, email, rol, fecha_registro FROM usuarios ORDER BY id_usuario DESC");
?>
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Usuarios</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<?php renderNav('usuarios'); ?>
<h2>Usuarios</h2>
<?php if ($message): ?><p><strong><?= h($message) ?></strong></p><?php endif; ?>
<?php if ($error): ?><p style="color: #ff6b6b;"><strong><?= h($error) ?></strong></p><?php endif; ?>

<form method="POST" action="?action=<?= $editing ? 'update' : 'create' ?>">
    <input type="hidden" name="csrf_token" value="<?= h(generateCsrfToken()) ?>">
    <?php if ($editing): ?>
        <input type="hidden" name="id_usuario" value="<?= (int)$editing['id_usuario'] ?>">
    <?php endif; ?>
    Nombre: <input type="text" name="nombre" maxlength="100" value="<?= h($editing['nombre'] ?? '') ?>" required><br>
    Email: <input type="email" name="email" maxlength="100" value="<?= h($editing['email'] ?? '') ?>" required><br>
    <?php if (!$editing): ?>
        Password: <input type="password" name="password" minlength="8" maxlength="72" required><br>
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
    <td><?= h($row['nombre']) ?></td>
    <td><?= h($row['email']) ?></td>
    <td><?= h($row['rol']) ?></td>
    <td><?= h($row['fecha_registro']) ?></td>
    <td>
      <div class="acciones">
        <a href="?edit=<?= (int)$row['id_usuario'] ?>">Editar</a>
        <form method="POST" action="?action=delete" style="display:inline" onsubmit="return confirm('¿Eliminar usuario?')">
            <input type="hidden" name="csrf_token" value="<?= h(generateCsrfToken()) ?>">
            <input type="hidden" name="id_usuario" value="<?= (int)$row['id_usuario'] ?>">
            <input type="submit" value="Eliminar">
        </form>
      </div>
    </td>
</tr>
<?php endwhile; ?>
</table>

</body>
</html>
<?php $conn->close(); ?>
