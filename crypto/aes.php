<?php
declare(strict_types=1);

/**
 * AES-256-GCM (AEAD) memakai PHP OpenSSL.
 * - Kunci 32 byte, nonce/IV 12 byte acak PER enkripsi, tag 16 byte.
 * - AAD (additional authenticated data) ikut diautentikasi namun tidak dienkripsi.
 */
const AES_CIPHER    = 'aes-256-gcm';
const AES_KEY_LEN   = 32;
const AES_NONCE_LEN = 12;
const AES_TAG_LEN   = 16;

/** @return array{ciphertext:string,nonce:string,tag:string} (semua biner) */
function aes_encrypt(string $plaintext, string $key, string $aad = ''): array
{
    if (strlen($key) !== AES_KEY_LEN) {
        throw new InvalidArgumentException('Panjang kunci AES harus 32 byte (256-bit).');
    }
    if (!in_array(AES_CIPHER, openssl_get_cipher_methods(), true)) {
        throw new RuntimeException('AES-256-GCM tidak didukung oleh OpenSSL pada server ini.');
    }
    $nonce = random_bytes(AES_NONCE_LEN);
    $tag = '';
    $ciphertext = openssl_encrypt($plaintext, AES_CIPHER, $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad, AES_TAG_LEN);
    if ($ciphertext === false || strlen($tag) !== AES_TAG_LEN) {
        throw new RuntimeException('Enkripsi AES-256-GCM gagal.');
    }
    return ['ciphertext' => $ciphertext, 'nonce' => $nonce, 'tag' => $tag];
}

/**
 * Dekripsi + verifikasi integritas. Melempar RuntimeException bila tag tidak cocok
 * (data/nonce/tag/AAD/kunci berubah).
 */
function aes_decrypt(string $ciphertext, string $key, string $nonce, string $tag, string $aad = ''): string
{
    if (strlen($key) !== AES_KEY_LEN) {
        throw new InvalidArgumentException('Panjang kunci AES harus 32 byte (256-bit).');
    }
    if (strlen($nonce) !== AES_NONCE_LEN || strlen($tag) !== AES_TAG_LEN) {
        throw new RuntimeException('Format nonce atau authentication tag tidak valid.');
    }
    $plain = openssl_decrypt($ciphertext, AES_CIPHER, $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
    if ($plain === false) {
        throw new RuntimeException('Validasi integritas gagal: data telah diubah atau kunci tidak sesuai.');
    }
    return $plain;
}
