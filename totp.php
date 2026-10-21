<?php
function base32_encode(string $data): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $binaryString = '';
    foreach (str_split($data) as $char) {
        $binaryString .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
    }
    $encoded = '';
    foreach (str_split($binaryString, 5) as $chunk) {
        $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
        $encoded .= $alphabet[bindec($chunk)];
    }
    return $encoded;
}

function base32_decode(string $b32): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $b32 = strtoupper($b32);
    $binaryString = '';
    foreach (str_split($b32) as $char) {
        $pos = strpos($alphabet, $char);
        if ($pos === false) continue;
        $binaryString .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
    }
    $bytes = '';
    foreach (str_split($binaryString, 8) as $byte) {
        if (strlen($byte) < 8) continue;
        $bytes .= chr(bindec($byte));
    }
    return $bytes;
}

function generateTotpSecret(): string {
    return base32_encode(random_bytes(20));
}

function getTotpCode(string $secret, ?int $timestamp = null, int $period = 30, int $digits = 6): string {
    $timestamp ??= time();
    $counter = intdiv($timestamp, $period);
    $binCounter = pack('N*', 0) . pack('N*', $counter);

    $key = base32_decode($secret);
    $hash = hash_hmac('sha1', $binCounter, $key, true);

    $offset = ord($hash[strlen($hash) - 1]) & 0x0F;
    $truncated = (
        ((ord($hash[$offset]) & 0x7F) << 24) |
        ((ord($hash[$offset + 1]) & 0xFF) << 16) |
        ((ord($hash[$offset + 2]) & 0xFF) << 8) |
        (ord($hash[$offset + 3]) & 0xFF)
    );

    $code = $truncated % (10 ** $digits);
    return str_pad((string)$code, $digits, '0', STR_PAD_LEFT);
}

function verifyTotpCode(string $secret, string $code, int $window = 1): bool {
    $timestamp = time();
    $period = 30;
    for ($i = -$window; $i <= $window; $i++) {
        if (hash_equals(getTotpCode($secret, $timestamp + ($i * $period)), $code)) {
            return true;
        }
    }
    return false;
}

function getTotpUri(string $secret, string $accountName, string $issuer = 'EcommerceLab'): string {
    $label = rawurlencode($issuer . ':' . $accountName);
    $params = http_build_query([
        'secret' => $secret,
        'issuer' => $issuer,
        'algorithm' => 'SHA1',
        'digits' => 6,
        'period' => 30,
    ]);
    return "otpauth://totp/$label?$params";
}
