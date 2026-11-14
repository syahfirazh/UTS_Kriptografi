<?php
declare(strict_types=1);
/**
 * Self-test kriptografi (CLI):  php tools/selftest.php
 * Menguji AES-256-GCM, deteksi manipulasi, dan verifikasi RSA-PSS terhadap
 * tanda tangan yang dibuat oleh Web Crypto API (JavaScript) - bukti kompatibilitas JS <-> PHP.
 * Tidak memerlukan database.
 */
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}
require_once __DIR__ . '/../crypto/aes.php';
require_once __DIR__ . '/../crypto/rsa.php';

$pass = 0;
$fail = 0;
function check(string $name, bool $ok): void
{
    global $pass, $fail;
    $ok ? $pass++ : $fail++;
    echo ($ok ? '[PASS] ' : '[FAIL] ') . $name . PHP_EOL;
}

echo "PHP " . PHP_VERSION . ' | ' . OPENSSL_VERSION_TEXT . PHP_EOL . PHP_EOL;

// ---------- AES-256-GCM ----------
check('Cipher aes-256-gcm tersedia', in_array('aes-256-gcm', openssl_get_cipher_methods(), true));
$key = random_bytes(32);
$plain = 'Informasi penting dalam sistem.';
$aad = 'SAS|content|1|v1';
$r = aes_encrypt($plain, $key, $aad);
check('Ciphertext berbeda dari plaintext', $r['ciphertext'] !== $plain);
check('Panjang nonce 12 byte dan tag 16 byte', strlen($r['nonce']) === 12 && strlen($r['tag']) === 16);
check('Dekripsi menghasilkan plaintext semula', aes_decrypt($r['ciphertext'], $key, $r['nonce'], $r['tag'], $aad) === $plain);
$r2 = aes_encrypt($plain, $key, $aad);
check('Nonce acak: dua enkripsi plaintext sama -> ciphertext berbeda', $r['ciphertext'] !== $r2['ciphertext'] && $r['nonce'] !== $r2['nonce']);

$expectFail = function (callable $fn): bool {
    try {
        $fn();
        return false;
    } catch (Throwable $e) {
        return true;
    }
};
$bad = $r['ciphertext'];
$bad[0] = chr(ord($bad[0]) ^ 1);
check('Ciphertext diubah 1 bit -> DITOLAK', $expectFail(fn() => aes_decrypt($bad, $key, $r['nonce'], $r['tag'], $aad)));
$badTag = $r['tag'];
$badTag[0] = chr(ord($badTag[0]) ^ 1);
check('Auth tag diubah -> DITOLAK', $expectFail(fn() => aes_decrypt($r['ciphertext'], $key, $r['nonce'], $badTag, $aad)));
check('AAD berbeda (ciphertext dipindah ke baris lain) -> DITOLAK', $expectFail(fn() => aes_decrypt($r['ciphertext'], $key, $r['nonce'], $r['tag'], 'SAS|content|2|v1')));
check('Kunci salah -> DITOLAK', $expectFail(fn() => aes_decrypt($r['ciphertext'], random_bytes(32), $r['nonce'], $r['tag'], $aad)));
check('Kunci bukan 32 byte -> ditolak', $expectFail(fn() => aes_encrypt('x', 'pendek')));

// ---------- RSA-PSS (vektor dibuat oleh Web Crypto di browser/Node) ----------
$pem = <<<'PEM'
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5CcF3ClRqCl/hhgZwy76
g97ZL2+7ZrXLRyK/7PJKXEOppKO8NGmhlM7uvW16VE8aHbDwyWRKI7cgTN7m5e1w
LFifQQE3GIFtfmju/scSImv/V9qsNALNxKEkut1+GdzZpdtZ/W07C2tbtWqJ286t
z5uFUWG40WcUmd+eAmSs3SS26ecpVq99QtNOAqGG2MNTx6bwgfzjPV5io6evI2uV
jwE0iv8Oe/1PUdOSn+q1itYA2f4plU5dLVa+Rywb2E5QFwgdtC2ys7xfLS+cTeu+
0pmnqdk7ZiXfmNYqlwXaYcF7C1uusAnik0WcCsC2STMUonNuvH8qR+JkZrUmhyF+
qQIDAQAB
-----END PUBLIC KEY-----
PEM;
$message = 'SAS-LOGIN-v1:admin:86ae9f85c56f4fd8b0d7eab87d70179fecb805163d526f813978db10c74285b7';
$sig = base64_decode('ECjpsJgfvnXygKff1rxtf5CoMK38gHHGL/E0QwrbGLlHSYnvLjm0jfGSkarbNyOj9Uf1P0g7UC7iW8oAYdruadLm3Jr1dRBP5v6kawaKHFFcPtdkVnHr0UCANvEgxOSnz84tl+EIaHQEfJvHe3ygNL0a8jxcJwNPU7LJd0Hv3h1Ul4DB3Sx3HUiXH5iOC0jhyODEhdI0JBQ4/UdmL/fjjKEhbVfoBw38Y4Wy/+0Wck3iQk8jTbWbYETdbW/x32aUTnECN2t7JediA9F6L9CiDezMW5Bp2pmOIva4Fy5oTKvpPz9WPP9jmB+UcHyO3LsUgEPnr4F//2S834IakIRUzA==', true);
$expectedFp = '73f2d250b536986ef43c0a72766859df5d1cd70bec46f933b671353c107303d4';

check('Public key lolos validasi (RSA >= 2048-bit)', rsa_validate_public_key($pem) === null);
check('Fingerprint SHA-256 sama dengan hasil JavaScript', rsa_fingerprint($pem) === $expectedFp);
check('RSA-PSS: signature Web Crypto VALID di PHP', rsa_pss_verify($message, $sig, $pem));
check('RSA-PSS: pesan diubah -> INVALID', !rsa_pss_verify($message . 'x', $sig, $pem));
$badSig = $sig;
$badSig[10] = chr(ord($badSig[10]) ^ 1);
check('RSA-PSS: signature diubah -> INVALID', !rsa_pss_verify($message, $badSig, $pem));
check('RSA-PSS: signature terpotong -> INVALID', !rsa_pss_verify($message, substr($sig, 0, -1), $pem));
check('RSA-PSS: kunci publik lain -> INVALID', !rsa_pss_verify($message, $sig, rsa_generate_keypair(2048)['public']));

echo PHP_EOL . "Hasil: $pass lulus, $fail gagal" . PHP_EOL;
exit($fail === 0 ? 0 : 1);
