<?php
// app/db.php
// Principio de menor privilegio:
//   - 'lectura'   -> esclavos con user_db   (solo SELECT)
//   - 'escritura' -> bd_maestro con gerente_db (SELECT, INSERT, UPDATE, DELETE; sin DDL)
// Ya no se usa root en la aplicación.

const DB_NAME = 'ecommerce_db';

const DB_USER_LECTURA   = 'user_db';
const DB_PASS_LECTURA   = 'userpwd123';
const DB_USER_ESCRITURA = 'gerente_db';
const DB_PASS_ESCRITURA = 'gerentepwd123';

const DB_HOST_MAESTRO = 'bd_maestro';
const DB_HOSTS_ESCLAVOS = ['esclavo_1', 'esclavo_2'];

function dbConectar(string $host, string $user, string $pass): mysqli {
    $conn = mysqli_init();
    $conn->options(MYSQLI_OPT_CONNECT_TIMEOUT, 3);
    // Con PHP 8.1+ mysqli lanza mysqli_sql_exception si falla la conexión.
    $conn->real_connect($host, $user, $pass, DB_NAME);
    $conn->set_charset('utf8mb4');
    return $conn;
}

function getConexion($tipo = 'lectura'): mysqli {
    try {
        if ($tipo === 'escritura') {
            return dbConectar(DB_HOST_MAESTRO, DB_USER_ESCRITURA, DB_PASS_ESCRITURA);
        }

        // Lectura: balanceo aleatorio con conmutación por error entre esclavos
        $esclavos = DB_HOSTS_ESCLAVOS;
        shuffle($esclavos);
        $ultimoError = null;
        foreach ($esclavos as $host) {
            try {
                return dbConectar($host, DB_USER_LECTURA, DB_PASS_LECTURA);
            } catch (mysqli_sql_exception $e) {
                $ultimoError = $e;
                error_log("[DB] fallo conexión de lectura a $host: " . $e->getMessage());
            }
        }
        throw $ultimoError ?? new RuntimeException('Sin esclavos disponibles');
    } catch (Throwable $e) {
        // No exponer detalles internos al usuario; el detalle queda en el log del contenedor.
        error_log("[DB] error de conexión ($tipo): " . $e->getMessage());
        http_response_code(503);
        die('Servicio no disponible temporalmente. Intenta más tarde.');
    }
}
