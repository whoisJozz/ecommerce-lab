-- Fase 1: migración (ejecutar UNA vez en bd_maestro con root; se replica a los esclavos)
USE ecommerce_db;

-- 1) Tabla para la protección contra fuerza bruta (AFB)
CREATE TABLE IF NOT EXISTS login_intentos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(100) NOT NULL,
    ip VARCHAR(45) NOT NULL,
    exito TINYINT(1) NOT NULL DEFAULT 0,
    motivo VARCHAR(30) NOT NULL DEFAULT '',
    fecha DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_email_fecha (email, exito, fecha),
    INDEX idx_ip_fecha (ip, exito, fecha)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2) Columna verification_token (la usan registro.php y verificar.php).
--    MySQL 8.0 no soporta ADD COLUMN IF NOT EXISTS, por eso se comprueba antes.
SET @existe := (SELECT COUNT(*) FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA = 'ecommerce_db' AND TABLE_NAME = 'usuarios' AND COLUMN_NAME = 'verification_token');
SET @ddl := IF(@existe = 0,
                'ALTER TABLE usuarios ADD COLUMN verification_token VARCHAR(64) DEFAULT NULL',
                'SELECT "verification_token ya existe" AS aviso');
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 3) Verificación de privilegios mínimos
SHOW GRANTS FOR 'user_db'@'%';
SHOW GRANTS FOR 'gerente_db'@'%';
