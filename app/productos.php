<?php
require_once __DIR__ . '/session_helper.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/security_helper.php';
require_once __DIR__ . '/nav.php';

startSecureSession();
requireAuth();

$rol = $_SESSION['rol'] ?? 'cliente';
$esGestion = in_array($rol, ['admin', 'gerente'], true);

$action = $_POST['action'] ?? $_GET['action'] ?? 'list';
$message = '';
$error = '';

// Operaciones de escritura en bd_maestro (solo admin y gerente)
if ($esGestion && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCsrfToken($_POST['csrf_token'] ?? null)) {
        die('Token CSRF inválido');
    }

    $connWrite = getConexion('escritura');

    if ($action === 'create' || $action === 'update') {
        $nombre = validate_plain_text((string)($_POST['nombre'] ?? ''), 'El nombre del producto', 150);
        $precio = (float)($_POST['precio'] ?? 0);
        $stock  = (int)($_POST['stock'] ?? 0);
        $id_producto = (int)($_POST['id_producto'] ?? 0);

        if ($nombre['error'] !== '') {
            $error = $nombre['error'];
        } elseif ($precio < 0 || $precio > 99999999.99 || $stock < 0 || $stock > 1000000) {
            $error = "Verifica que el precio y el stock sean válidos.";
        } elseif ($action === 'update' && $id_producto <= 0) {
            $error = "Producto inválido.";
        } else {
            try {
                if ($action === 'create') {
                    $stmt = $connWrite->prepare("INSERT INTO productos (nombre, precio, stock) VALUES (?, ?, ?)");
                    $stmt->bind_param("sdi", $nombre['valor'], $precio, $stock);
                    $stmt->execute();
                    $stmt->close();
                    $message = "Producto creado correctamente en el maestro.";
                } else {
                    $stmt = $connWrite->prepare("UPDATE productos SET nombre = ?, precio = ?, stock = ? WHERE id_producto = ?");
                    $stmt->bind_param("sdii", $nombre['valor'], $precio, $stock, $id_producto);
                    $stmt->execute();
                    $stmt->close();
                    $message = "Producto actualizado correctamente.";
                }
            } catch (mysqli_sql_exception $e) {
                error_log('[PRODUCTOS] ' . $e->getMessage());
                $error = "No se pudo guardar el producto.";
            }
        }
    }

    if ($action === 'delete') {
        $id_producto = (int)($_POST['id_producto'] ?? 0);
        if ($id_producto > 0) {
            try {
                $stmt = $connWrite->prepare("DELETE FROM productos WHERE id_producto = ?");
                $stmt->bind_param("i", $id_producto);
                $stmt->execute();
                $stmt->close();
                $message = "Producto eliminado correctamente.";
            } catch (mysqli_sql_exception $e) {
                $error = "No se puede eliminar el producto porque ya tiene pedidos asociados.";
            }
        }
    }

    $connWrite->close();
}

// Consultas de lectura en nodos esclavos
$connRead = getConexion('lectura');

$editing = null;
if ($esGestion && isset($_GET['edit'])) {
    $editId = (int)$_GET['edit'];
    $stmt = $connRead->prepare("SELECT id_producto, nombre, precio, stock FROM productos WHERE id_producto = ?");
    $stmt->bind_param("i", $editId);
    $stmt->execute();
    $editing = $stmt->get_result()->fetch_assoc();
    $stmt->close();
}

$productos = $connRead->query("SELECT id_producto, nombre, precio, stock FROM productos ORDER BY id_producto DESC");
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Gestión de Productos</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <?php renderNav('productos'); ?>

    <h2><?= $esGestion ? 'Gestión de Productos (Inventario)' : 'Catálogo de Productos' ?></h2>

    <?php if ($message): ?>
        <p><strong><?= htmlspecialchars($message) ?></strong></p>
    <?php endif; ?>
    <?php if ($error): ?>
        <p style="color: #ff6b6b;"><strong><?= htmlspecialchars($error) ?></strong></p>
    <?php endif; ?>

    <?php if ($esGestion): ?>
        <form method="POST" action="productos.php?action=<?= $editing ? 'update' : 'create' ?>">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCsrfToken()) ?>">
            <?php if ($editing): ?>
                <input type="hidden" name="id_producto" value="<?= (int)$editing['id_producto'] ?>">
            <?php endif; ?>

            Nombre del producto:
            <input type="text" name="nombre" value="<?= htmlspecialchars($editing['nombre'] ?? '') ?>" required><br>

            Precio ($):
            <input type="number" step="0.01" min="0" name="precio" value="<?= htmlspecialchars((string)($editing['precio'] ?? '')) ?>" required><br>

            Stock:
            <input type="number" min="0" name="stock" value="<?= htmlspecialchars((string)($editing['stock'] ?? '0')) ?>" required><br>

            <input type="submit" value="<?= $editing ? 'Actualizar Producto' : 'Crear Producto' ?>">
            <?php if ($editing): ?>
                <a href="productos.php" style="margin-left: 10px;">Cancelar</a>
            <?php endif; ?>
        </form>
    <?php endif; ?>

    <table border="1" cellpadding="6">
        <tr>
            <th>ID</th>
            <th>Nombre</th>
            <th>Precio</th>
            <th>Stock</th>
            <th>Acciones</th>
        </tr>
        <?php while ($row = $productos->fetch_assoc()): ?>
            <tr>
                <td><?= (int)$row['id_producto'] ?></td>
                <td><?= htmlspecialchars($row['nombre']) ?></td>
                <td>$<?= number_format((float)$row['precio'], 2) ?></td>
                <td><?= (int)$row['stock'] ?></td>
                <td>
                    <?php if ($esGestion): ?>
                        <div class="acciones">
                        <a href="productos.php?edit=<?= (int)$row['id_producto'] ?>">Editar</a>
                        <form method="POST" action="productos.php?action=delete" style="display:inline;" onsubmit="return confirm('¿Eliminar este producto?');">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCsrfToken()) ?>">
                            <input type="hidden" name="id_producto" value="<?= (int)$row['id_producto'] ?>">
                            <input type="submit" value="Eliminar">
                        </form>
                        </div>
                    <?php else: ?>
                        <?php if ((int)$row['stock'] > 0): ?>
                            <form method="POST" action="carrito.php" style="display:inline;">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCsrfToken()) ?>">
                                <input type="hidden" name="action" value="add">
                                <input type="hidden" name="id_producto" value="<?= (int)$row['id_producto'] ?>">
                                <input type="number" name="cantidad" value="1" min="1" max="<?= (int)$row['stock'] ?>" style="width: 60px;">
                                <input type="submit" value="Agregar">
                            </form>
                        <?php else: ?>
                            <span>Agotado</span>
                        <?php endif; ?>
                    <?php endif; ?>
                </td>
            </tr>
        <?php endwhile; ?>
    </table>
</body>
</html>
<?php
$connRead->close();
?>