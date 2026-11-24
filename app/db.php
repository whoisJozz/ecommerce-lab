<?php
// app/db.php

function getConexion($tipo = 'lectura') {
    $user = 'root';
    $pass = 'rootpassword';
    $db   = 'ecommerce_db';

    if ($tipo === 'escritura') {
        $host = 'bd_maestro';
    } else {
        $esclavos = ['esclavo_1', 'esclavo_2'];
        $host = $esclavos[array_rand($esclavos)];
    }

    $conn = new mysqli($host, $user, $pass, $db);

    if ($conn->connect_error) {
        die("Error de conexión a la base de datos ($tipo): " . $conn->connect_error);
    }

    $conn->set_charset("utf8mb4");

    return $conn;
}
?>