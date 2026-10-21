<?php
require __DIR__ . '/session_helper.php';
startSecureSession();
requireAuth();

$esAdmin = in_array($_SESSION['rol'], ['admin', 'gerente']);

if (!isset($_SESSION['cart'])) {
    $_SESSION['cart'] = [];
}

$conn = new mysqli("bd_maestro", "gerente_db", "gerentepwd123", "ecommerce_db");
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$action = $_POST['action'] ?? $_GET['action'] ?? 'list';
$message = '';

if ($esAdmin && $action === 'create' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCsrfToken($_POST['csrf_token'] ?? null)) { die("Token CSRF inválido"); }
    $stmt = $conn->prepare("INSERT INTO productos (nombre, precio, stock) VALUES (?, ?, ?)");
    $stmt->bind_param("sdi", $_POST['nombre'], $_POST['precio'], $_POST['stock']);
    $stmt->execute();
    $stmt->close();
    $message = "Producto creado correctamente";
}

if ($esAdmin && $action === 'update' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCsrfToken($_POST['csrf_token'] ?? null)) { die("Token CSRF inválido"); }
    $stmt = $conn->prepare("UPDATE productos SET nombre = ?, precio = ?, stock = ? WHERE id_producto = ?");
    $stmt->bind_param("sdii", $_POST['nombre'], $_POST['precio'], $_POST['stock'], $_POST['id_producto']);
    $stmt->execute();
    $stmt->close();
    $message = "Producto actualizado correctamente";
}

if ($esAdmin && $action === 'delete' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCsrfToken($_POST['csrf_token'] ?? null)) { die("Token CSRF inválido"); }
    $stmt = $conn->prepare("DELETE FROM productos WHERE id_producto = ?");
    $stmt->bind_param("i", $_POST['id_producto']);
    $stmt->execute();
    $stmt->close();
    $message = "Producto eliminado";
}

if ($action === 'add_to_cart' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCsrfToken($_POST['csrf_token'] ?? null)) { die("Token CSRF inválido"); }

    $idProducto = (int)$_POST['id_producto'];
    $cantidad = (int)$_POST['cantidad'];

    if ($cantidad > 0) {
        $_SESSION['cart'][$idProducto] = ($_SESSION['cart'][$idProducto] ?? 0) + $cantidad;
        $message = "Producto agregado al carrito";
    }
}

$editing = null;
if ($esAdmin && isset($_GET['edit'])) {
    $stmt = $conn->prepare("SELECT * FROM productos WHERE id_producto = ?");
    $stmt->bind_param("i", $_GET['edit']);
    $stmt->execute();
    $editing = $stmt->get_result()->fetch_assoc();
    $stmt->close();
}

$productos = $conn->query("SELECT * FROM productos ORDER BY id_producto DESC");
$conn->close();
?>
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Productos</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<p>Sesión: <?= htmlspecialchars($_SESSION['nombre']) ?> (<?= htmlspecialchars($_SESSION['rol']) ?>) |
<a href="carrito.php">Carrito (<?= array_sum($_SESSION['cart']) ?>)</a> |
<a href="logout.php">Cerrar sesión</a></p>
<h2>Productos</h2>
<?php if ($message): ?><p><strong><?= htmlspecialchars($message) ?></strong></p><?php endif; ?>

<?php if ($esAdmin): ?>
<form method="POST" action="?action=<?= $editing ? 'update' : 'create' ?>">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCsrfToken()) ?>">
    <?php if ($editing): ?>
        <input type="hidden" name="id_producto" value="<?= (int)$editing['id_producto'] ?>">
    <?php endif; ?>
    Nombre: <input type="text" name="nombre" value="<?= htmlspecialchars($editing['nombre'] ?? '') ?>" required><br>
    Precio: <input type="number" step="0.01" name="precio" value="<?= htmlspecialchars($editing['precio'] ?? '') ?>" required><br>
    Stock: <input type="number" name="stock" value="<?= htmlspecialchars($editing['stock'] ?? '') ?>" required><br>
    <input type="submit" value="<?= $editing ? 'Actualizar' : 'Crear' ?>">
</form>
<?php endif; ?>

<table border="1" cellpadding="6">
<tr><th>ID</th><th>Nombre</th><th>Precio</th><th>Stock</th><th>Acciones</th></tr>
<?php while ($row = $productos->fetch_assoc()): ?>
<tr>
    <td><?= (int)$row['id_producto'] ?></td>
    <td><?= htmlspecialchars($row['nombre']) ?></td>
    <td><?= htmlspecialchars($row['precio']) ?></td>
    <td><?= (int)$row['stock'] ?></td>
    <td>
        <?php if ($esAdmin): ?>
            <a href="?edit=<?= (int)$row['id_producto'] ?>">Editar</a>
            <form method="POST" action="?action=delete" style="display:inline" onsubmit="return confirm('¿Eliminar producto?')">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCsrfToken()) ?>">
                <input type="hidden" name="id_producto" value="<?= (int)$row['id_producto'] ?>">
                <input type="submit" value="Eliminar">
            </form>
        <?php else: ?>
            <form method="POST" action="?action=add_to_cart" style="display:inline">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCsrfToken()) ?>">
                <input type="hidden" name="id_producto" value="<?= (int)$row['id_producto'] ?>">
                <input type="number" name="cantidad" value="1" min="1" max="<?= (int)$row['stock'] ?>" style="width:60px">
                <input type="submit" value="Agregar al carrito">
            </form>
        <?php endif; ?>
    </td>
</tr>
<?php endwhile; ?>
</table>

<?php if ($esAdmin): ?>
<p><a href="usuarios.php">Gestionar usuarios</a></p>
<?php endif; ?>
</body>
</html>
