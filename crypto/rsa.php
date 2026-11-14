<?php
declare(strict_types=1);

/**
 * RSA-PSS (RFC 8017) - verifikasi tanda tangan digital.
 *
 * CATATAN KOMPATIBILITAS: openssl_verify() milik PHP TIDAK mendukung padding PSS,
 * sedangkan Web Crypto API menandatangani dengan RSA-PSS. Karena itu verifikasi
 * dilakukan manual: operasi RSA publik mentah (openssl_public_decrypt tanpa padding,
 * RSAVP1) lalu pemeriksaan encoding EMSA-PSS-VERIFY (MGF1-SHA256, salt 32 byte).
 * Parameter wajib sama di klien: {name:'RSA-PSS', saltLength:32}, hash SHA-256.
 */
const RSA_MIN_BITS     = 2048;
const RSA_PSS_SALT_LEN = 32;

/** @return OpenSSLAsymmetricKey|false */
function rsa_load_public_key(string $pem)
{
    $pem = trim($pem);
    if ($pem === '' || strlen($pem) > 4096 || !str_contains($pem, 'BEGIN PUBLIC KEY')) {
        return false;
    }
    $key = @openssl_pkey_get_public($pem);
    return $key ?: false;
}

/** Validasi: harus RSA dan minimal 2048-bit. Mengembalikan pesan error atau null jika valid. */
function rsa_validate_public_key(string $pem): ?string
{
    $key = rsa_load_public_key($pem);
    if (!$key) {
        return 'Public key tidak valid (harus format PEM "BEGIN PUBLIC KEY").';
    }
    $d = openssl_pkey_get_details($key);
    if (!$d || ($d['type'] ?? null) !== OPENSSL_KEYTYPE_RSA) {
        return 'Public key harus bertipe RSA.';
    }
    if ((int) $d['bits'] < RSA_MIN_BITS) {
        return 'Ukuran kunci RSA minimal ' . RSA_MIN_BITS . ' bit.';
    }
    return null;
}

function rsa_key_bits(string $pem): ?int
{
    $key = rsa_load_public_key($pem);
    if (!$key) {
        return null;
    }
    $d = openssl_pkey_get_details($key);
    return $d ? (int) $d['bits'] : null;
}

/** PEM kanonik (base64 64 kolom). */
function rsa_normalize_pem(string $pem): ?string
{
    if (!preg_match('/-----BEGIN PUBLIC KEY-----(.+?)-----END PUBLIC KEY-----/s', $pem, $m)) {
        return null;
    }
    $body = preg_replace('/\s+/', '', $m[1]);
    if ($body === '' || base64_decode($body, true) === false) {
        return null;
    }
    return "-----BEGIN PUBLIC KEY-----\n" . chunk_split($body, 64, "\n") . "-----END PUBLIC KEY-----\n";
}

/** SHA-256 (hex) dari DER SPKI. Sama dengan fingerprint di sisi klien. */
function rsa_fingerprint(string $pem): ?string
{
    if (!preg_match('/-----BEGIN PUBLIC KEY-----(.+?)-----END PUBLIC KEY-----/s', $pem, $m)) {
        return null;
    }
    $der = base64_decode(preg_replace('/\s+/', '', $m[1]), true);
    return $der === false ? null : hash('sha256', $der);
}

function rsa_mgf1(string $seed, int $length): string
{
    $out = '';
    $counter = 0;
    while (strlen($out) < $length) {
        $out .= hash('sha256', $seed . pack('N', $counter), true);
        $counter++;
    }
    return substr($out, 0, $length);
}

/**
 * Verifikasi RSASSA-PSS (SHA-256, MGF1-SHA256).
 * @param string $message   pesan asli (byte)
 * @param string $signature tanda tangan biner (panjang = ukuran modulus)
 */
function rsa_pss_verify(string $message, string $signature, string $publicKeyPem, int $saltLen = RSA_PSS_SALT_LEN): bool
{
    $key = rsa_load_public_key($publicKeyPem);
    if (!$key) {
        return false;
    }
    $details = openssl_pkey_get_details($key);
    if (!$details || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA) {
        return false;
    }
    $modBits = (int) $details['bits'];
    if ($modBits < RSA_MIN_BITS) {
        return false;
    }
    $k = intdiv($modBits + 7, 8);
    if (strlen($signature) !== $k) {
        return false;
    }

    // RSAVP1: em = signature^e mod n (tanpa padding)
    $em = '';
    if (!@openssl_public_decrypt($signature, $em, $key, OPENSSL_NO_PADDING)) {
        return false;
    }
    $em = str_pad($em, $k, "\x00", STR_PAD_LEFT);

    $hLen   = 32;
    $emBits = $modBits - 1;
    $emLen  = intdiv($emBits + 7, 8);
    if ($emLen < $k) { // terjadi bila (modBits-1) kelipatan 8; byte awal harus 0
        if ($em[0] !== "\x00") {
            return false;
        }
        $em = substr($em, $k - $emLen);
    }
    if ($emLen < $hLen + $saltLen + 2) {
        return false;
    }
    if ($em[$emLen - 1] !== "\xBC") {
        return false;
    }

    $maskedDb = substr($em, 0, $emLen - $hLen - 1);
    $h        = substr($em, $emLen - $hLen - 1, $hLen);

    $topBits = 8 * $emLen - $emBits;
    $topMask = (0xFF << (8 - $topBits)) & 0xFF;
    if ((ord($maskedDb[0]) & $topMask) !== 0) {
        return false;
    }

    $db = $maskedDb ^ rsa_mgf1($h, strlen($maskedDb));
    $db[0] = chr(ord($db[0]) & (0xFF >> $topBits));

    $psLen = $emLen - $hLen - $saltLen - 2;
    if ($psLen > 0 && substr($db, 0, $psLen) !== str_repeat("\x00", $psLen)) {
        return false;
    }
    if ($db[$psLen] !== "\x01") {
        return false;
    }
    $salt = substr($db, strlen($db) - $saltLen);

    $mHash  = hash('sha256', $message, true);
    $hPrime = hash('sha256', str_repeat("\x00", 8) . $mHash . $salt, true);
    return hash_equals($h, $hPrime);
}

/**
 * Pembuatan pasangan kunci RSA di sisi server (HANYA untuk pengujian/CLI).
 * Pada aplikasi, kunci dibuat di browser agar private key tidak pernah ada di server.
 * @return array{private:string,public:string}
 */
function rsa_generate_keypair(int $bits = 2048): array
{
    $res = openssl_pkey_new(['private_key_bits' => max($bits, RSA_MIN_BITS), 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    if (!$res) {
        throw new RuntimeException('Gagal membuat pasangan kunci RSA. Periksa konfigurasi OpenSSL (openssl.cnf).');
    }
    $private = '';
    openssl_pkey_export($res, $private);
    $details = openssl_pkey_get_details($res);
    return ['private' => $private, 'public' => $details['key']];
}
