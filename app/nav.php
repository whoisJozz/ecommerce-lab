<?php
// app/nav.php - Barra de navegación única para todas las páginas autenticadas.
// Los enlaces mostrados dependen del rol; $activo marca la página actual.
// Incluye su propio CSS para verse bien aunque el navegador tenga style.css en caché.
require_once __DIR__ . '/security_helper.php';
require_once __DIR__ . '/session_helper.php';

function renderNav(string $activo = ''): void {
    $rol = $_SESSION['rol'] ?? '';
    $esGestion = in_array($rol, ['admin', 'gerente'], true);

    $enlaces = [];
    if ($esGestion) {
        $enlaces['productos']  = ['productos.php', 'Productos'];
        if ($rol === 'admin') {
            $enlaces['usuarios'] = ['usuarios.php', 'Usuarios'];
        }
        $enlaces['reportes']   = ['reportes.php', 'Reportes'];
        if ($rol === 'admin') {
            $enlaces['seguridad'] = ['seguridad.php', 'Seguridad'];
        }
        $enlaces['verificar_url'] = ['verificar_url.php', 'Verificar URL'];
    } else {
        $enlaces['productos'] = ['productos.php', 'Catálogo'];
        $enlaces['carrito']   = ['carrito.php', 'Mi carrito'];
    }

    // Segundos de sesión que le quedan al usuario (se reinicia con cada clic)
    $restante = max(0, SESSION_TIMEOUT - (time() - (int)($_SESSION['last_activity'] ?? time())));
    ?>
<style>
.navbar{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px 24px;max-width:950px;margin:0 0 25px 0;padding:10px 16px;background:linear-gradient(145deg,#11151c,#0a0d12);border:1px solid #2a3340;border-bottom:2px solid #ffd700;border-radius:4px;box-shadow:0 0 25px rgba(0,150,255,.08)}
.navbar .navbar-links,.navbar .navbar-user{display:flex;align-items:center;flex-wrap:wrap;gap:8px 22px}
.navbar a{display:inline-block;font-family:'Orbitron',sans-serif;font-size:12px;text-transform:uppercase;letter-spacing:1.5px;padding:6px 2px;border-bottom:2px solid transparent;margin:0}
.navbar a.activo{color:#ffd700;border-bottom-color:#ffd700}
.navbar a.salir{color:#ff8a8a}
.navbar .navbar-user span{font-size:14px;color:#8fa8c7}
.navbar .navbar-user em{color:#ffd700;font-style:normal}
.navbar .sesion-timer{font-family:'Orbitron',sans-serif;font-size:11px;color:#8fa8c7;border:1px solid #2a3340;border-radius:3px;padding:3px 8px}
.navbar .sesion-timer.poco{color:#ff8a8a;border-color:#ff8a8a}
</style>
<nav class="navbar">
    <div class="navbar-links">
<?php foreach ($enlaces as $clave => [$url, $texto]): ?>
        <a href="<?= h($url) ?>"<?= $clave === $activo ? ' class="activo"' : '' ?>><?= h($texto) ?></a>
<?php endforeach; ?>
    </div>
    <div class="navbar-user">
        <span><?= h($_SESSION['nombre'] ?? 'Usuario') ?> <em>(<?= h($rol) ?>)</em></span>
        <span class="sesion-timer" id="sesion-timer" title="Tiempo de inactividad restante">Sesión: --:--</span>
        <a class="salir" href="logout.php">Cerrar sesión</a>
    </div>
</nav>
<script>
(function () {
    var restante = <?= (int)$restante ?>;
    var el = document.getElementById('sesion-timer');
    function pintar() {
        var m = Math.floor(restante / 60), s = restante % 60;
        el.textContent = 'Sesión: ' + m + ':' + (s < 10 ? '0' : '') + s;
        el.className = 'sesion-timer' + (restante <= 30 ? ' poco' : '');
    }
    pintar();
    setInterval(function () {
        restante -= 1;
        if (restante <= 0) { window.location.href = 'index.php'; return; }
        pintar();
    }, 1000);
})();
</script>
<?php
}
