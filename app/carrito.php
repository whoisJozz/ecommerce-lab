<?php
require __DIR__ . '/session_helper.php';
startSecureSession();
requireAuth();

$conn = new mysqli("bd_maestro", "gerente_db", "gerentepwd123", "ecommerce_db");
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if (!isset($_SESSION['cart'])) {
    $_SESSION['cart'] = [];
}

$message = '';
$action = $_POST['action'] ?? '';

if ($action === 'update_qty' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCsrfToken($_POST['csrf_token'] ?? null)) { die("Token CSRF inválido"); }
    $id = (int)$_POST['id_producto'];
    $qty = (int)$_POST['cantidad'];
    if ($qty <= 0) {
        unset($_SESSION['cart'][$id]);
    } else {
        $_SESSION['cart'][$id] = $qty;
    }
    $message = "Carrito actualizado";
}

if ($action === 'remove' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCsrfToken($_POST['csrf_token'] ?? null)) { die("Token CSRF inválido"); }
    unset($_SESSION['cart'][(int)$_POST['id_producto']]);
    $message = "Producto eliminado del carrito";
}

if ($action === 'checkout' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCsrfToken($_POST['csrf_token'] ?? null)) { die("Token CSRF inválido"); }

    if (empty($_SESSION['cart'])) {
        $message = "Tu carrito está vacío";
    } else {
        $conn->begin_transaction();
        try {
            $total = 0;
            $items = [];

            foreach ($_SESSION['cart'] as $idProducto => $cantidad) {
                $stmt = $conn->prepare("SELECT nombre, precio, stock FROM productos WHERE id_producto = ? FOR UPDATE");
                $stmt->bind_param("i", $idProducto);
                $stmt->execute();
                $producto = $stmt->get_result()->fetch_assoc();
                $stmt->close();

                if (!$producto || $cantidad > $producto['stock']) {
                    throw new Exception("Stock insuficiente para el producto $idProducto");
                }

                $subtotal = $producto['precio'] * $cantidad;
                $total += $subtotal;
                $items[] = [
                    'id' => $idProducto,
                    'nombre' => $producto['nombre'],
                    'cantidad' => $cantidad,
                    'precio' => $producto['precio'],
                    'stock_antes' => $producto['stock'],
                ];
            }

            $stmt = $conn->prepare("INSERT INTO pedidos (id_usuario, total, estado) VALUES (?, ?, 'Pagado')");
            $stmt->bind_param("id", $_SESSION['authenticated_user_id'], $total);
            $stmt->execute();
            $idPedido = $stmt->insert_id;
            $stmt->close();

            foreach ($items as $item) {
                $stmt = $conn->prepare("INSERT INTO detalles_pedido (id_pedido, id_producto, cantidad, precio_unitario) VALUES (?, ?, ?, ?)");
                $stmt->bind_param("iiid", $idPedido, $item['id'], $item['cantidad'], $item['precio']);
                $stmt->execute();
                $stmt->close();

                $stmt = $conn->prepare("UPDATE productos SET stock = stock - ? WHERE id_producto = ?");
                $stmt->bind_param("ii", $item['cantidad'], $item['id']);
                $stmt->execute();
                $stmt->close();
            }

            $stmt = $conn->prepare("SELECT nombre, email FROM usuarios WHERE id_usuario = ?");
            $stmt->bind_param("i", $_SESSION['authenticated_user_id']);
            $stmt->execute();
            $comprador = $stmt->get_result()->fetch_assoc();
            $stmt->close();

            $admins = $conn->query("SELECT email FROM usuarios WHERE rol = 'admin'");

            $cuerpo = "Reporte de nueva compra - Pedido #$idPedido\n\n";
            $cuerpo .= "Cliente: {$comprador['nombre']}\n";
            $cuerpo .= "Correo del cliente: {$comprador['email']}\n";
            $cuerpo .= "Fecha: " . date('Y-m-d H:i:s') . "\n\n";
            $cuerpo .= "Detalle de productos:\n";
            $cuerpo .= str_pad("Producto", 25) . str_pad("Cant.", 8) . str_pad("Precio Unit.", 15) . str_pad("Stock restante", 16) . "\n";
            $cuerpo .= str_repeat("-", 64) . "\n";

            foreach ($items as $item) {
                $stockRestante = $item['stock_antes'] - $item['cantidad'];
                $cuerpo .= str_pad($item['nombre'], 25)
                         . str_pad((string)$item['cantidad'], 8)
                         . str_pad('$' . number_format($item['precio'], 2), 15)
                         . str_pad((string)$stockRestante, 16)
                         . "\n";
            }

            $cuerpo .= str_repeat("-", 64) . "\n";
            $cuerpo .= "Total del pedido: $" . number_format($total, 2) . "\n";

            $asunto = "Reporte de compra - Pedido #$idPedido";
            $headers = "From: noreply@ecommercelab.local\r\n";

            while ($adminRow = $admins->fetch_assoc()) {
                mail($adminRow['email'], $asunto, $cuerpo, $headers);
            }

            $conn->commit();
            $_SESSION['cart'] = [];
            $message = "Compra simulada exitosa. Pedido #$idPedido por $" . number_format($total, 2);
        } catch (Exception $e) {
            $conn->rollback();
            $message = "No se pudo completar la compra: " . $e->getMessage();
        }
    }
}

$cartItems = [];
$total = 0;
if (!empty($_SESSION['cart'])) {
    $ids = array_keys($_SESSION['cart']);
    $placeholders = implode(',', array_fill(0, count($ids), '?'));
    $types = str_repeat('i', count($ids));

    $stmt = $conn->prepare("SELECT id_producto, nombre, precio, stock FROM productos WHERE id_producto IN ($placeholders)");
    $stmt->bind_param($types, ...$ids);
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) {
        $cantidad = $_SESSION['cart'][$row['id_producto']];
        $subtotal = $row['precio'] * $cantidad;
        $total += $subtotal;
        $cartItems[] = array_merge($row, ['cantidad' => $cantidad, 'subtotal' => $subtotal]);
    }
    $stmt->close();
}

$conn->close();
?>
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Carrito</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<p><a href="productos.php">← Seguir comprando</a> | <a href="logout.php">Cerrar sesión</a></p>
<h2>Tu carrito</h2>

<?php if ($message): ?><p><strong><?= htmlspecialchars($message) ?></strong></p><?php endif; ?>

<?php if (empty($cartItems)): ?>
    <p>Tu carrito está vacío.</p>
<?php else: ?>
<table border="1" cellpadding="6">
<tr><th>Producto</th><th>Precio</th><th>Cantidad</th><th>Subtotal</th><th>Acciones</th></tr>
<?php foreach ($cartItems as $item): ?>
<tr>
    <td><?= htmlspecialchars($item['nombre']) ?></td>
    <td>$<?= number_format($item['precio'], 2) ?></td>
    <td>
        <form method="POST" action="?" style="display:inline">
            <input type="hidden" name="action" value="update_qty">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCsrfToken()) ?>">
            <input type="hidden" name="id_producto" value="<?= (int)$item['id_producto'] ?>">
            <input type="number" name="cantidad" value="<?= (int)$item['cantidad'] ?>" min="0" max="<?= (int)$item['stock'] ?>" style="width:60px">
            <input type="submit" value="Actualizar">
        </form>
    </td>
    <td>$<?= number_format($item['subtotal'], 2) ?></td>
    <td>
        <form method="POST" action="?" style="display:inline">
            <input type="hidden" name="action" value="remove">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCsrfToken()) ?>">
            <input type="hidden" name="id_producto" value="<?= (int)$item['id_producto'] ?>">
            <input type="submit" value="Quitar">
        </form>
    </td>
</tr>
<?php endforeach; ?>
</table>

<h3>Total: $<?= number_format($total, 2) ?></h3>

<form method="POST" action="?">
    <input type="hidden" name="action" value="checkout">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCsrfToken()) ?>">
    <input type="submit" value="Confirmar compra (simulada)">
</form>
<?php endif; ?>

</body>
</html>
