CREATE USER IF NOT EXISTS 'replica_user'@'%' IDENTIFIED WITH mysql_native_password BY 'replica_pass';
GRANT REPLICATION SLAVE ON *.* TO 'replica_user'@'%';
FLUSH PRIVILEGES;

DROP DATABASE IF EXISTS ecommerce_db;
CREATE DATABASE ecommerce_db;
USE ecommerce_db;

-- 2. Estructura de Usuarios
CREATE TABLE usuarios (
    id_usuario INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    rol VARCHAR(30) NOT NULL DEFAULT 'cliente',
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 3. Estructura de Productos
CREATE TABLE productos (
    id_producto INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(150) NOT NULL,
    precio DECIMAL(10,2) NOT NULL,
    stock INT NOT NULL DEFAULT 0
) ENGINE=InnoDB;

-- 4. Estructura de Pedidos (Ventas)
CREATE TABLE pedidos (
    id_pedido INT AUTO_INCREMENT PRIMARY KEY,
    id_usuario INT NOT NULL,
    total DECIMAL(10,2) NOT NULL,
    fecha_pedido TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    estado VARCHAR(20) DEFAULT 'Pendiente',
    FOREIGN KEY (id_usuario) REFERENCES usuarios(id_usuario)
) ENGINE=InnoDB;

-- 5. Estructura del Detalle de cada Pedido
CREATE TABLE detalles_pedido (
    id_detalle INT AUTO_INCREMENT PRIMARY KEY,
    id_pedido INT NOT NULL,
    id_producto INT NOT NULL,
    cantidad INT NOT NULL,
    precio_unitario DECIMAL(10,2) NOT NULL,
    FOREIGN KEY (id_pedido) REFERENCES pedidos(id_pedido),
    FOREIGN KEY (id_producto) REFERENCES productos(id_producto)
) ENGINE=InnoDB;

-- 6. Inserción de datos de prueba (Para validar que la replicación funcione)
-- Contraseñas en texto plano: 'admin123' y 'cliente123'
INSERT INTO usuarios (nombre, email, password, rol) VALUES 
('Administrador', 'admin@tienda.com', '$2y$10$WpvN.BlW2c3v2ksBTIqrWeJ899a5xP6GJLOukzHI2ggJTYZMeD/Va', 'admin'), 
('Cliente Frecuente', 'cliente@correo.com', '$2y$10$JfIXVutrlmY/qTKvhE2u6u57DP4Bl8GonmHPd1sBTwCtthDyDh28m', 'cliente');

INSERT INTO productos (nombre, precio, stock) VALUES 
('Laptop Gamer', 1250.50, 15), 
('Audífonos Inalámbricos', 89.99, 50),
('Monitor 180Hz', 299.00, 20);

INSERT INTO pedidos (id_usuario, total, estado) VALUES 
(2, 388.99, 'Pagado');

INSERT INTO detalles_pedido (id_pedido, id_producto, cantidad, precio_unitario) VALUES 
(1, 2, 1, 89.99),
(1, 3, 1, 299.00);

ALTER TABLE usuarios ADD COLUMN twofa_secret VARCHAR(64) DEFAULT NULL;
ALTER TABLE usuarios ADD COLUMN twofa_enabled TINYINT(1) NOT NULL DEFAULT 0;

CREATE USER IF NOT EXISTS 'admin_db'@'%' IDENTIFIED WITH mysql_native_password BY 'admin123';
CREATE USER IF NOT EXISTS 'gerente_db'@'%' IDENTIFIED WITH mysql_native_password BY 'gerentepwd123';
CREATE USER IF NOT EXISTS 'user_db'@'%' IDENTIFIED WITH mysql_native_password BY 'userpwd123';

GRANT ALL PRIVILEGES ON ecommerce_db.* TO 'admin_db'@'%';

GRANT SELECT, INSERT, UPDATE, DELETE ON ecommerce_db.* TO 'gerente_db'@'%';

GRANT SELECT ON ecommerce_db.* TO 'user_db'@'%';

FLUSH PRIVILEGES;