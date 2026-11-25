<?php
// app/security_helper.php
// Utilidades de seguridad en PHP nativo:
//   1) Registro de eventos de seguridad (stderr -> docker logs)
//   2) IP real del cliente (detrás del WAF)
//   3) AFB: protección contra fuerza bruta en el login
//   4) Sanitización de entradas / prevención de SSTI -> RCE
//   5) Prevención de SSRF (validador de URLs + cliente HTTP seguro)
//   6) Cliente para servicios internos autorizados (microservicio de IA, Fase 2)

require_once __DIR__ . '/db.php';

// =====================================================================
// 1) BITÁCORA DE SEGURIDAD
// =====================================================================
function securityLog(string $evento, array $detalle = []): void {
    $registro = [
        'ts'      => date('c'),
        'evento'  => $evento,
        'ip'      => clientIp(),
        'detalle' => $detalle,
    ];
    error_log('[SEC] ' . json_encode($registro, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
}

// =====================================================================
// 2) IP REAL DEL CLIENTE
// =====================================================================
// Si la petición llega desde una IP privada (el WAF dentro de la red Docker), se usa la
// ÚLTIMA entrada de X-Forwarded-For: es la que añadió nuestro propio proxy. Las entradas
// anteriores las puede falsificar el cliente.
function clientIp(): string {
    $remote = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    if (!filter_var($remote, FILTER_VALIDATE_IP)) {
        return '0.0.0.0';
    }
    if (!ip_is_public($remote)) {
        $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
        if ($xff !== '') {
            $partes = array_map('trim', explode(',', $xff));
            $ultima = end($partes);
            if ($ultima !== false && filter_var($ultima, FILTER_VALIDATE_IP)) {
                return $ultima;
            }
        }
    }
    return $remote;
}

// =====================================================================
// 3) AFB - ATAQUES DE FUERZA BRUTA
// =====================================================================
const AFB_MAX_POR_EMAIL = 5;     // fallos permitidos por correo dentro de la ventana
const AFB_MAX_POR_IP    = 15;    // fallos permitidos por IP dentro de la ventana
const AFB_VENTANA       = 900;   // ventana / duración del bloqueo: 15 minutos

function afb_normalizar_email(string $email): string {
    return mb_substr(mb_strtolower(trim($email), 'UTF-8'), 0, 100, 'UTF-8');
}

// Devuelve ['bloqueado' => bool, 'segundos' => int]. Usa SIEMPRE el maestro
// (los esclavos pueden ir con retraso y permitirían saltarse el bloqueo).
function afb_estado(string $email, string $ip): array {
    $email = afb_normalizar_email($email);
    $conn = getConexion('escritura');
    $restante = 0;

    // Los nombres de columna salen de esta lista fija, nunca del usuario.
    $criterios = [
        ['email', $email, AFB_MAX_POR_EMAIL],
        ['ip',    $ip,    AFB_MAX_POR_IP],
    ];

    foreach ($criterios as [$columna, $valor, $max]) {
        $offset = $max - 1;
        $sql = "SELECT TIMESTAMPDIFF(SECOND, fecha, NOW()) AS edad
                FROM login_intentos
                WHERE $columna = ? AND exito = 0
                  AND fecha > (NOW() - INTERVAL " . AFB_VENTANA . " SECOND)
                ORDER BY fecha DESC, id DESC
                LIMIT 1 OFFSET $offset";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param('s', $valor);
        $stmt->execute();
        $fila = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        // Si existe el intento número $max (contando desde el más reciente) hay bloqueo
        // hasta que ese intento salga de la ventana.
        if ($fila) {
            $restante = max($restante, max(1, AFB_VENTANA - (int)$fila['edad']));
        }
    }
    $conn->close();

    return ['bloqueado' => $restante > 0, 'segundos' => $restante];
}

function afb_registrar(string $email, string $ip, bool $exito, string $motivo): void {
    $email = afb_normalizar_email($email);
    $ok = $exito ? 1 : 0;
    $motivo = mb_substr($motivo, 0, 30);
    $conn = getConexion('escritura');

    $stmt = $conn->prepare('INSERT INTO login_intentos (email, ip, exito, motivo) VALUES (?, ?, ?, ?)');
    $stmt->bind_param('ssis', $email, $ip, $ok, $motivo);
    $stmt->execute();
    $stmt->close();

    // Mantenimiento ocasional: borrar registros con más de 7 días
    if (random_int(1, 50) === 1) {
        $conn->query('DELETE FROM login_intentos WHERE fecha < (NOW() - INTERVAL 7 DAY)');
    }
    $conn->close();

    if (!$exito) {
        securityLog('LOGIN_FALLIDO', ['email' => $email, 'motivo' => $motivo]);
    }
}

// Tras un acceso completo y exitoso se reinicia el contador de fallos del correo
function afb_limpiar(string $email): void {
    $email = afb_normalizar_email($email);
    $conn = getConexion('escritura');
    $stmt = $conn->prepare('DELETE FROM login_intentos WHERE email = ? AND exito = 0');
    $stmt->bind_param('s', $email);
    $stmt->execute();
    $stmt->close();
    $conn->close();
}

function afb_mensaje_bloqueo(int $segundos): string {
    $min = (int)ceil($segundos / 60);
    return 'Demasiados intentos fallidos. Por seguridad el acceso está bloqueado temporalmente. '
         . "Intenta de nuevo en $min minuto" . ($min === 1 ? '' : 's') . '.';
}

// =====================================================================
// 4) SANITIZACIÓN DE ENTRADAS Y PREVENCIÓN DE SSTI -> RCE
// =====================================================================
// La aplicación NO usa motor de plantillas, eval(), include dinámico ni unserialize() sobre
// datos del usuario. Esta capa añade defensa en profundidad: ningún campo de texto puede
// contener sintaxis de plantillas (Twig/Jinja/Smarty/Blade/EL/ERB) ni etiquetas PHP.

function h(?string $s): string {
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// Elimina bytes nulos y caracteres de control, normaliza espacios y limita la longitud
function clean_text(string $s, int $max = 100): string {
    $s = str_replace("\0", '', $s);
    $s = preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $s) ?? '';
    $s = trim(preg_replace('/\s+/u', ' ', $s) ?? '');
    return mb_substr($s, 0, $max, 'UTF-8');
}

function has_template_syntax(string $s): bool {
    return (bool)preg_match('/(\{\{|\}\}|\{%|%\}|\{#|#\}|\$\{|#\{|<\?|\?>|<%|%>)/', $s);
}

// Devuelve ['valor' => string, 'error' => string]. error === '' si todo está bien.
function validate_plain_text(string $raw, string $etiqueta, int $max = 100, int $min = 1): array {
    $valor = clean_text($raw, $max + 1);
    if (mb_strlen($valor, 'UTF-8') < $min) {
        return ['valor' => '', 'error' => "$etiqueta es obligatorio."];
    }
    if (mb_strlen($valor, 'UTF-8') > $max) {
        return ['valor' => '', 'error' => "$etiqueta excede $max caracteres."];
    }
    if (has_template_syntax($valor)) {
        securityLog('SSTI_BLOQUEADO', ['campo' => $etiqueta, 'muestra' => mb_substr($valor, 0, 60, 'UTF-8')]);
        return ['valor' => '', 'error' => "$etiqueta contiene caracteres no permitidos."];
    }
    return ['valor' => $valor, 'error' => ''];
}

function validate_email_field(string $raw): array {
    $email = afb_normalizar_email($raw);
    if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || preg_match('/[\r\n]/', $raw)) {
        return ['valor' => '', 'error' => 'Correo electrónico inválido.'];
    }
    return ['valor' => $email, 'error' => ''];
}

// =====================================================================
// 5) PREVENCIÓN DE SSRF
// =====================================================================
const SSRF_PUERTOS_PERMITIDOS = [80, 443];
const SSRF_CIDR_BLOQUEADOS = [
    // IPv4
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15',
    '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
    // IPv6
    '::/128', '::1/128', '64:ff9b::/96', '100::/64', '2001::/32', '2001:db8::/32',
    '2002::/16', 'fc00::/7', 'fe80::/10', 'fec0::/10', 'ff00::/8',
];

function ip_in_cidr(string $ip, string $cidr): bool {
    [$red, $bits] = explode('/', $cidr);
    $ipBin  = inet_pton($ip);
    $redBin = inet_pton($red);
    if ($ipBin === false || $redBin === false || strlen($ipBin) !== strlen($redBin)) {
        return false;
    }
    $bits  = (int)$bits;
    $bytes = intdiv($bits, 8);
    $resto = $bits % 8;
    if ($bytes > 0 && substr($ipBin, 0, $bytes) !== substr($redBin, 0, $bytes)) {
        return false;
    }
    if ($resto === 0) {
        return true;
    }
    $mascara = (0xFF << (8 - $resto)) & 0xFF;
    return (ord($ipBin[$bytes]) & $mascara) === (ord($redBin[$bytes]) & $mascara);
}

// true solo si la IP es enrutable públicamente
function ip_is_public(string $ip): bool {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return false;
    }
    $bin = inet_pton($ip);
    // IPv4 mapeada en IPv6 (::ffff:127.0.0.1) -> se evalúa la IPv4 interna
    if ($bin !== false && strlen($bin) === 16 && str_starts_with($bin, str_repeat("\0", 10) . "\xff\xff")) {
        $ip = inet_ntop(substr($bin, 12));
    }
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return false;
    }
    foreach (SSRF_CIDR_BLOQUEADOS as $cidr) {
        if (ip_in_cidr($ip, $cidr)) {
            return false;
        }
    }
    return true;
}

// Valida una URL antes de hacer una petición saliente.
// Devuelve ['ok'=>bool, 'error'=>string, 'url'=>string, 'host'=>string, 'port'=>int, 'ip'=>string]
function ssrf_validate_url(string $url): array {
    $bad = fn(string $m): array => ['ok' => false, 'error' => $m, 'url' => $url, 'host' => '', 'port' => 0, 'ip' => ''];

    $url = trim($url);
    if ($url === '' || strlen($url) > 2048) {
        return $bad('URL vacía o demasiado larga.');
    }
    if (preg_match('/[\x00-\x20\x7F\\\\]/', $url)) {
        return $bad('La URL contiene caracteres no permitidos.');
    }

    $p = parse_url($url);
    if ($p === false || empty($p['scheme']) || empty($p['host'])) {
        return $bad('URL mal formada.');
    }

    $esquema = strtolower($p['scheme']);
    if (!in_array($esquema, ['http', 'https'], true)) {
        return $bad('Esquema no permitido (solo http y https).');
    }
    if (isset($p['user']) || isset($p['pass'])) {
        return $bad('No se permiten credenciales dentro de la URL.');
    }

    $puerto = $p['port'] ?? ($esquema === 'https' ? 443 : 80);
    if (!in_array($puerto, SSRF_PUERTOS_PERMITIDOS, true)) {
        return $bad('Puerto no permitido.');
    }

    $host = strtolower(trim($p['host'], '[]'));
    $host = rtrim($host, '.');
    if ($host === '') {
        return $bad('Host inválido.');
    }

    $ips = [];
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        $ips = [$host];
    } else {
        // Formas numéricas ofuscadas (2130706433, 0x7f000001, 0177.0.0.1, 127.1) -> rechazar
        if (preg_match('/^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+))*$/i', $host)) {
            return $bad('Formato de dirección IP no permitido.');
        }
        if (!preg_match('/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/', $host)) {
            return $bad('Nombre de host inválido.');
        }
        if ($host === 'localhost' || preg_match('/\.(localhost|local|internal|lan|home|corp|intranet|home\.arpa)$/', $host)) {
            return $bad('Host interno no permitido.');
        }

        $registros = @dns_get_record($host, DNS_A | DNS_AAAA);
        if (is_array($registros)) {
            foreach ($registros as $r) {
                if (!empty($r['ip']))   { $ips[] = $r['ip']; }
                if (!empty($r['ipv6'])) { $ips[] = $r['ipv6']; }
            }
        }
        if (!$ips) {
            $v4 = @gethostbynamel($host);
            if (is_array($v4)) { $ips = $v4; }
        }
        if (!$ips) {
            return $bad('El dominio no resuelve.');
        }
    }

    // TODAS las IPs resueltas deben ser públicas (evita respuestas DNS mixtas)
    foreach ($ips as $ip) {
        if (!ip_is_public($ip)) {
            return $bad('El destino apunta a una red interna o reservada.');
        }
    }

    // Se fija una IPv4 pública validada (anti DNS-rebinding con CURLOPT_RESOLVE)
    $ipFijada = '';
    foreach ($ips as $ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) { $ipFijada = $ip; break; }
    }
    if ($ipFijada === '') {
        return $bad('Solo se admiten destinos con dirección IPv4.');
    }

    $normalizada = $esquema . '://' . $host . ':' . $puerto . ($p['path'] ?? '/')
                 . (isset($p['query']) ? '?' . $p['query'] : '');

    return ['ok' => true, 'error' => '', 'url' => $normalizada, 'host' => $host, 'port' => $puerto, 'ip' => $ipFijada];
}

// Petición HTTP GET saliente segura: valida, fija la IP, revalida cada redirección y limita tamaño.
// No devuelve el cuerpo (evita SSRF "ciego" con lectura de datos internos): solo metadatos.
function ssrf_safe_request(string $url, int $maxRedirecciones = 3, int $maxBytes = 524288): array {
    $actual = $url;

    for ($i = 0; $i <= $maxRedirecciones; $i++) {
        $v = ssrf_validate_url($actual);
        if (!$v['ok']) {
            securityLog('SSRF_BLOQUEADO', ['url' => mb_substr($actual, 0, 200), 'motivo' => $v['error']]);
            return ['ok' => false, 'bloqueado' => true, 'error' => $v['error']];
        }

        $location = '';
        $contentType = '';
        $bytes = 0;

        $ch = curl_init($v['url']);
        curl_setopt_array($ch, [
            CURLOPT_FOLLOWLOCATION  => false,
            CURLOPT_PROTOCOLS       => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_RESOLVE         => [$v['host'] . ':' . $v['port'] . ':' . $v['ip']],
            CURLOPT_IPRESOLVE       => CURL_IPRESOLVE_V4,
            CURLOPT_CONNECTTIMEOUT  => 3,
            CURLOPT_TIMEOUT         => 6,
            CURLOPT_SSL_VERIFYPEER  => true,
            CURLOPT_SSL_VERIFYHOST  => 2,
            CURLOPT_USERAGENT       => 'EcommerceLab-LinkChecker/1.0',
            CURLOPT_PROXY           => '',
            CURLOPT_NOPROXY         => '*',
            CURLOPT_HEADERFUNCTION  => function ($ch, $linea) use (&$location, &$contentType) {
                if (stripos($linea, 'location:') === 0) {
                    $location = trim(substr($linea, 9));
                } elseif (stripos($linea, 'content-type:') === 0) {
                    $contentType = trim(substr($linea, 13));
                }
                return strlen($linea);
            },
            CURLOPT_WRITEFUNCTION   => function ($ch, $datos) use (&$bytes, $maxBytes) {
                $bytes += strlen($datos);
                return $bytes > $maxBytes ? 0 : strlen($datos); // 0 aborta la descarga
            },
        ]);

        curl_exec($ch);
        $errno  = curl_errno($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($status === 0) {
            return ['ok' => false, 'bloqueado' => false, 'error' => "No se pudo conectar con el destino (código $errno)."];
        }

        if (in_array($status, [301, 302, 303, 307, 308], true) && $location !== '') {
            if (preg_match('#^https?://#i', $location)) {
                $actual = $location;
            } elseif (str_starts_with($location, '/')) {
                $actual = parse_url($v['url'], PHP_URL_SCHEME) . '://' . $v['host'] . ':' . $v['port'] . $location;
            } else {
                return ['ok' => false, 'bloqueado' => false, 'error' => 'Redirección no soportada.'];
            }
            continue; // se vuelve a validar el nuevo destino
        }

        return [
            'ok'           => true,
            'bloqueado'    => false,
            'status'       => $status,
            'content_type' => mb_substr($contentType, 0, 100),
            'bytes'        => $bytes,
            'url_final'    => $v['url'],
            'redirecciones'=> $i,
        ];
    }

    return ['ok' => false, 'bloqueado' => false, 'error' => 'Demasiadas redirecciones.'];
}

// =====================================================================
// 6) SERVICIOS INTERNOS AUTORIZADOS (p. ej. microservicio de IA - Fase 2)
// =====================================================================
// El host NUNCA viene del usuario: solo se puede elegir un alias de esta lista cerrada.
// El contenido del usuario viaja únicamente en el cuerpo JSON.
const SERVICIOS_INTERNOS = [
    'ia' => 'http://ia_service:8000',
];

function internal_service_post(string $servicio, string $ruta, array $payload, int $timeout = 60): array {
    if (!isset(SERVICIOS_INTERNOS[$servicio])) {
        securityLog('SERVICIO_INTERNO_NO_AUTORIZADO', ['servicio' => $servicio]);
        return ['ok' => false, 'error' => 'Servicio no autorizado.'];
    }
    if (!preg_match('#^/[a-z0-9_/-]{1,64}$#', $ruta) || str_contains($ruta, '..')) {
        return ['ok' => false, 'error' => 'Ruta no permitida.'];
    }

    $respuesta = '';
    $ch = curl_init(SERVICIOS_INTERNOS[$servicio] . $ruta);
    curl_setopt_array($ch, [
        CURLOPT_POST            => true,
        CURLOPT_POSTFIELDS      => json_encode($payload, JSON_UNESCAPED_UNICODE),
        CURLOPT_HTTPHEADER      => ['Content-Type: application/json', 'Accept: application/json'],
        CURLOPT_FOLLOWLOCATION  => false,
        CURLOPT_PROTOCOLS       => CURLPROTO_HTTP,
        CURLOPT_CONNECTTIMEOUT  => 3,
        CURLOPT_TIMEOUT         => $timeout,
        CURLOPT_PROXY           => '',
        CURLOPT_NOPROXY         => '*',
        CURLOPT_WRITEFUNCTION   => function ($ch, $datos) use (&$respuesta) {
            $respuesta .= $datos;
            return strlen($respuesta) > 1048576 ? 0 : strlen($datos);
        },
    ]);
    curl_exec($ch);
    $errno  = curl_errno($ch);
    $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($errno !== 0 || $status === 0) {
        error_log("[SERVICIO_INTERNO] $servicio$ruta falló (curl $errno)");
        return ['ok' => false, 'error' => 'El servicio no respondió.'];
    }
    $datos = json_decode($respuesta, true);
    if (!is_array($datos)) {
        return ['ok' => false, 'error' => 'Respuesta inválida del servicio.', 'status' => $status];
    }
    return ['ok' => $status >= 200 && $status < 300, 'status' => $status, 'data' => $datos];
}
