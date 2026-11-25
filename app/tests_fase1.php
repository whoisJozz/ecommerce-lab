<?php
// Pruebas automáticas de la Fase 1 (JWT, SSRF, SSTI). SOLO por línea de comandos:
//   docker exec ecommerce_app php /var/www/html/tests_fase1.php
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

putenv('JWT_SECRET=' . str_repeat('k', 48));
require_once __DIR__ . '/jwt_helper.php';
require_once __DIR__ . '/security_helper.php';

$ok = 0; $fail = 0;
function check(string $nombre, bool $cond): void {
    global $ok, $fail;
    if ($cond) { $ok++; echo "  [OK]   $nombre\n"; } else { $fail++; echo "  [FALLA] $nombre\n"; }
}

echo "== JWT ==\n";
$secret = jwt_secret();
$user = ['id_usuario' => 7, 'rol' => 'gerente', 'email' => 'x@y.com'];
$jwt = jwt_issue_for_user($user);
$r = jwt_decode($jwt, $secret);
check('Token válido se acepta', $r['valid'] && $r['claims']['sub'] === 7 && $r['claims']['rol'] === 'gerente');

[$h, $p, $s] = explode('.', $jwt);
$payload = json_decode(base64url_decode($p), true); $payload['rol'] = 'admin';
$forjado = $h . '.' . base64url_encode(json_encode($payload)) . '.' . $s;
check('Payload alterado (rol=admin) se rechaza', !jwt_decode($forjado, $secret)['valid']);

$none = base64url_encode('{"alg":"none","typ":"JWT"}') . '.' . $p . '.';
check('alg=none se rechaza', !jwt_decode($none, $secret)['valid']);

$hs512h = base64url_encode('{"alg":"HS512","typ":"JWT"}');
$firma = base64url_encode(hash_hmac('sha512', "$hs512h.$p", $secret, true));
check('alg=HS512 se rechaza', !jwt_decode("$hs512h.$p.$firma", $secret)['valid']);

check('Firma con otro secreto se rechaza', !jwt_decode($jwt, str_repeat('z', 48))['valid']);

$exp = jwt_encode(['iss'=>JWT_ISSUER,'aud'=>JWT_AUDIENCE,'sub'=>1,'rol'=>'admin','iat'=>time()-100,'exp'=>time()-50], $secret);
check('Token expirado se rechaza', !jwt_decode($exp, $secret)['valid']);

$aud = jwt_encode(['iss'=>JWT_ISSUER,'aud'=>'otro','sub'=>1,'rol'=>'admin','iat'=>time(),'exp'=>time()+60], $secret);
check('Audiencia incorrecta se rechaza', !jwt_decode($aud, $secret)['valid']);

check('Basura se rechaza', !jwt_decode('abc.def', $secret)['valid'] && !jwt_decode('', $secret)['valid']);
check('Base64URL ida y vuelta', base64url_decode(base64url_encode("\xff\xfe\x00abc?>>")) === "\xff\xfe\x00abc?>>");

echo "\n== SSRF: IPs ==\n";
foreach (['127.0.0.1','10.1.2.3','172.16.5.5','172.18.0.2','192.168.1.1','169.254.169.254','0.0.0.0','100.64.0.1','::1','fe80::1','fc00::1','::ffff:127.0.0.1','::ffff:10.0.0.1'] as $ip) {
    check("IP bloqueada: $ip", !ip_is_public($ip));
}
foreach (['8.8.8.8','93.184.216.34','1.1.1.1','2606:4700:4700::1111'] as $ip) {
    check("IP pública permitida: $ip", ip_is_public($ip));
}

echo "\n== SSRF: URLs ==\n";
$bloqueadas = [
    'http://localhost/', 'http://127.0.0.1/', 'http://127.0.0.1:3306/', 'http://[::1]/',
    'http://169.254.169.254/latest/meta-data/', 'http://10.0.0.5/', 'http://172.17.0.1/',
    'http://192.168.0.1/', 'http://2130706433/', 'http://0x7f000001/', 'http://0177.0.0.1/', 'http://127.1/',
    'http://bd_maestro:3306/', 'http://app/', 'http://waf.internal/', 'http://foo.localhost/',
    'file:///etc/passwd', 'gopher://127.0.0.1:6379/_PING', 'ftp://example.com/', 'dict://127.0.0.1:11211/',
    'http://user:pass@93.184.216.34/', 'http://93.184.216.34:22/', 'http://93.184.216.34:6379/',
    'http://[::ffff:127.0.0.1]/', "http://93.184.216.34/\r\nHost: x", 'http://exa mple.com/', 'javascript:alert(1)', '',
];
foreach ($bloqueadas as $u) {
    check('Bloqueada: ' . json_encode($u), !ssrf_validate_url($u)['ok']);
}
foreach (['http://93.184.216.34/', 'https://93.184.216.34/ruta?x=1', 'http://8.8.8.8:80/'] as $u) {
    check("Permitida: $u", ssrf_validate_url($u)['ok']);
}
$r = ssrf_safe_request('http://127.0.0.1:80/');
check('ssrf_safe_request no conecta a loopback', $r['ok'] === false && !empty($r['bloqueado']));

echo "\n== Servicios internos ==\n";
check('Alias no autorizado rechazado', internal_service_post('mysql', '/x', [])['ok'] === false);
check('Ruta con .. rechazada', internal_service_post('ia', '/../etc', [])['ok'] === false);

echo "\n== SSTI / sanitización ==\n";
foreach (['{{7*7}}', '${7*7}', '<?php system("id"); ?>', '{%  import os %}', '#{7*7}', '<%= 7*7 %>', '{#c#}'] as $payload) {
    check('Plantilla/código rechazado: ' . $payload, validate_plain_text($payload, 'Campo')['error'] !== '');
}
check('Texto normal permitido', validate_plain_text('Laptop Gamer 15"', 'Campo', 150)['error'] === '');
check('Acentos permitidos', validate_plain_text('Audífonos Inalámbricos', 'Campo', 150)['valor'] === 'Audífonos Inalámbricos');
check('Bytes nulos/control eliminados', validate_plain_text("Hola\0\x07 mundo", 'Campo')['valor'] === 'Hola mundo');
check('Email con CRLF rechazado', validate_email_field("a@b.com\r\nBcc: x@y.com")['error'] !== '');
check('Email válido', validate_email_field(' Test@Correo.com ')['valor'] === 'test@correo.com');

echo "\nResultado: $ok correctas, $fail con falla\n";
exit($fail === 0 ? 0 : 1);
