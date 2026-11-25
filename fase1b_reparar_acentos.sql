-- Fase 1b: repara texto con acentos "doblemente codificado" (ej. AudÃ­fonos -> Audífonos)
-- Ejecutar UNA vez en bd_maestro con root (se replica a los esclavos).
-- Solo toca filas que contienen los bytes típicos del doble encoding (C3 83 / C3 82);
-- el texto ya correcto no se modifica.
USE ecommerce_db;

UPDATE productos
SET nombre = CONVERT(CAST(CONVERT(nombre USING latin1) AS BINARY) USING utf8mb4)
WHERE LOCATE(UNHEX('C383'), CAST(nombre AS BINARY)) > 0
   OR LOCATE(UNHEX('C382'), CAST(nombre AS BINARY)) > 0;

UPDATE usuarios
SET nombre = CONVERT(CAST(CONVERT(nombre USING latin1) AS BINARY) USING utf8mb4)
WHERE LOCATE(UNHEX('C383'), CAST(nombre AS BINARY)) > 0
   OR LOCATE(UNHEX('C382'), CAST(nombre AS BINARY)) > 0;

SELECT id_producto, nombre FROM productos;
SELECT id_usuario, nombre FROM usuarios;
