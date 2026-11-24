<?php
require_once __DIR__ . '/session_helper.php';
require_once __DIR__ . '/db.php';

startSecureSession();
requireRole(['admin', 'gerente']);

$rol = $_SESSION['rol'];
$message = '';

// Actualizar estado de un pedido en bd_maestro
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'update_status') {
    if (!validateCsrfToken($_POST['csrf_token'] ?? null)) {
        die('Token CSRF inválido');
    }

    $id_pedido = (int)($_POST['id_pedido'] ?? 0);
    $nuevo_estado = $_POST['estado'] ?? '';
    $estados_validos = ['Pendiente', 'Pagado', 'Enviado', 'Cancelado'];

    if ($id_pedido > 0 && in_array($nuevo_estado, $estados_validos, true)) {
        $connWrite = getConexion('escritura');
        $stmt = $connWrite->prepare("UPDATE pedidos SET estado = ? WHERE id_pedido = ?");
        $stmt->bind_param("si", $nuevo_estado, $id_pedido);
        if ($stmt->execute()) {
            $message = "Estado del pedido #$id_pedido actualizado a '$nuevo_estado'.";
        }
        $stmt->close();
        $connWrite->close();
    }
}

// Consultas de reporte en nodos esclavos
$connRead = getConexion('lectura');

$resumen = $connRead->query("
    SELECT 
        COUNT(*) AS total_pedidos,
        COALESCE(SUM(CASE WHEN estado IN ('Pagado', 'Enviado') THEN total ELSE 0 END), 0) AS ingresos_confirmados,
        COALESCE(SUM(CASE WHEN estado = 'Pendiente' THEN total ELSE 0 END), 0) AS monto_pendiente
    FROM pedidos
")->fetch_assoc();

$bajoStock = $connRead->query("SELECT COUNT(*) AS total FROM productos WHERE stock <= 5")->fetch_assoc();

$pedidos = $connRead->query("
    SELECT 
        p.id_pedido,
        u.nombre AS cliente,
        u.email,
        p.total,
        p.fecha_pedido,
        p.estado,
        GROUP_CONCAT(CONCAT(pr.nombre, ' (x', dp.cantidad, ')') SEPARATOR ', ') AS detalle_productos
    FROM pedidos p
    INNER JOIN usuarios u ON p.id_usuario = u.id_usuario
    LEFT JOIN detalles_pedido dp ON p.id_pedido = dp.id_pedido
    LEFT JOIN productos pr ON dp.id_producto = pr.id_producto
    GROUP BY p.id_pedido, u.nombre, u.email, p.total, p.fecha_pedido, p.estado
    ORDER BY p.id_pedido DESC
");
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Reportes de Compras</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <p>
        Sesión: <?= htmlspecialchars($_SESSION['nombre'] ?? 'Admin') ?> (<?= htmlspecialchars($rol) ?>)
        <?php if ($rol === 'admin'): ?>
            | <a href="usuarios.php">Usuarios</a>
        <?php endif; ?>
        | <a href="productos.php">Productos</a>
        | <a href="logout.php">Cerrar sesión</a>
    </p>

    <h2>Reportes de Compras y Ventas</h2>

    <?php if ($message): ?>
        <p><strong><?= htmlspecialchars($message) ?></strong></p>
    <?php endif; ?>

    <table border="1" cellpadding="6" style="margin-bottom: 20px;">
        <tr>
            <th>Total de Pedidos</th>
            <th>Ingresos Confirmados (Pagado / Enviado)</th>
            <th>Monto Pendiente</th>
            <th>Productos con Bajo Stock (&le; 5)</th>
        </tr>
        <tr>
            <td><?= (int)$resumen['total_pedidos'] ?></td>
            <td>$<?= number_format((float)$resumen['ingresos_confirmados'], 2) ?></td>
            <td>$<?= number_format((float)$resumen['monto_pendiente'], 2) ?></td>
            <td><?= (int)$bajoStock['total'] ?></td>
        </tr>
    </table>

    <h3>Detalle de Pedidos</h3>
    <table border="1" cellpadding="6">
        <tr>
            <th>ID Pedido</th>
            <th>Cliente</th>
            <th>Email</th>
            <th>Productos Comprados</th>
            <th>Total</th>
            <th>Fecha</th>
            <th>Estado</th>
        </tr>
        <?php while ($row = $pedidos->fetch_assoc()): ?>
            <tr>
                <td>#<?= (int)$row['id_pedido'] ?></td>
                <td><?= htmlspecialchars($row['cliente']) ?></td>
                <td><?= htmlspecialchars($row['email']) ?></td>
                <td><?= htmlspecialchars($row['detalle_productos'] ?? 'Sin detalle') ?></td>
                <td>$<?= number_format((float)$row['total'], 2) ?></td>
                <td><?= htmlspecialchars($row['fecha_pedido']) ?></td>
                <td>
                    <form method="POST" action="reportes.php" style="display:inline;">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCsrfToken()) ?>">
                        <input type="hidden" name="action" value="update_status">
                        <input type="hidden" name="id_pedido" value="<?= (int)$row['id_pedido'] ?>">
                        <select name="estado">
                            <?php foreach (['Pendiente', 'Pagado', 'Enviado', 'Cancelado'] as $est): ?>
                                <option value="<?= $est ?>" <?= $row['estado'] === $est ? 'selected' : '' ?>>
                                    <?= $est ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                        <input type="submit" value="Guardar">
                    </form>
                </td>
            </tr>
        <?php endwhile; ?>
    </table>
</body>
</html>
<?php
$connRead->close();
?>