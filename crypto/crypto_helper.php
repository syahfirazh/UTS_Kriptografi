<?php
declare(strict_types=1);

require_once __DIR__ . '/aes.php';
require_once __DIR__ . '/rsa.php';

/* ---------- Manajemen master key ---------- */
function current_key_version(): int
{
    return max(1, (int) env('KEY_VERSION', 1));
}

function key_dir(): string
{
    $dir = (string) env('KEY_DIR', '');
    return rtrim($dir !== '' ? $dir : ROOT_PATH . '/storage/keys', '/\\');
}

function master_key_path(int $version): string
{
    return key_dir() . '/master_v' . $version . '.key';
}

function master_key_exists(?int $version = null): bool
{
    return is_readable(master_key_path($version ?? current_key_version()));
}

/** Muat master key (32 byte biner) dari file hex 64 karakter. Tidak ada di source code. */
function load_master_key(?int $version = null): string
{
    $path = master_key_path($version ?? current_key_version());
    if (!is_readable($path)) {
        throw new RuntimeException('Master key belum tersedia. Jalankan tools/setup_admin.php terlebih dahulu.');
    }
    $hex = trim((string) file_get_contents($path));
    if (!preg_match('/^[a-f0-9]{64}$/i', $hex)) {
        throw new RuntimeException('Format master key tidak valid (harus 64 karakter hex).');
    }
    return hex2bin($hex);
}

/** Buat master key baru bila belum ada. Tidak pernah menimpa file yang sudah ada. */
function generate_master_key_file(?int $version = null): bool
{
    $path = master_key_path($version ?? current_key_version());
    if (file_exists($path)) {
        return false;
    }
    if (!is_dir(dirname($path)) && !mkdir(dirname($path), 0700, true)) {
        return false;
    }
    $fh = @fopen($path, 'x');
    if ($fh === false) {
        return false;
    }
    fwrite($fh, bin2hex(random_bytes(32)) . "\n");
    fclose($fh);
    @chmod($path, 0600);
    return true;
}

/** Turunkan sub-key dengan HKDF-SHA256 supaya master key tidak dipakai langsung untuk demo. */
function derive_key(string $master, string $info): string
{
    return hash_hkdf('sha256', $master, 32, $info);
}

/* ---------- Enkripsi konten ---------- */
/** AAD mengikat ciphertext ke ID baris dan versi kunci (mencegah pemindahan ciphertext antar baris). */
function content_aad(int $contentId, int $keyVersion): string
{
    return 'SAS|content|' . $contentId . '|v' . $keyVersion;
}

/** @return array{ciphertext:string,nonce:string,tag:string,key_version:int} */
function content_encrypt(string $plaintext, int $contentId): array
{
    $version = current_key_version();
    $r = aes_encrypt($plaintext, load_master_key($version), content_aad($contentId, $version));
    $r['key_version'] = $version;
    return $r;
}

/** @param array $row baris tabel contents (id, ciphertext, nonce, auth_tag, key_version) */
function content_decrypt(array $row): string
{
    $version = (int) $row['key_version'];
    return aes_decrypt(
        $row['ciphertext'],
        load_master_key($version),
        $row['nonce'],
        $row['auth_tag'],
        content_aad((int) $row['id'], $version)
    );
}

/** Catat operasi kriptografi (TANPA plaintext, kunci, atau passphrase). */
function crypto_log(?int $adminId, ?int $contentId, string $operation, string $algorithm, string $status, ?string $detail = null): void
{
    try {
        $st = db()->prepare(
            'INSERT INTO crypto_logs (admin_id, content_id, operation, algorithm, status, detail, ip_address)
             VALUES (?, ?, ?, ?, ?, ?, ?)'
        );
        $st->execute([$adminId, $contentId, $operation, $algorithm, $status, $detail !== null ? substr($detail, 0, 255) : null, client_ip()]);
    } catch (Throwable $e) {
        error_log('crypto_log gagal: ' . $e->getMessage());
    }
}
