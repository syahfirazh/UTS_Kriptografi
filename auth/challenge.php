<?php
declare(strict_types=1);
require_once __DIR__ . '/../includes/auth.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_response(405, ['ok' => false, 'error' => 'Metode tidak diizinkan.']);
}
csrf_require();

$in = read_json();
$username = trim((string) ($in['username'] ?? ''));
if (!valid_username($username)) {
    json_response(422, ['ok' => false, 'error' => 'Username tidak valid.']);
}

if (login_rate_limited($username)) {
    record_login_attempt(null, $username, false, 'rate_limited');
    json_response(429, ['ok' => false, 'error' => 'Terlalu banyak percobaan. Coba lagi beberapa menit lagi.']);
}

$pdo = db();
$ttl = max(30, (int) get_setting('challenge_ttl_seconds', '120'));

// Bersihkan challenge kedaluwarsa lama
$pdo->exec('DELETE FROM auth_challenges WHERE expires_at < DATE_SUB(NOW(), INTERVAL 1 DAY)');

$challenge = bin2hex(random_bytes(32));

$st = $pdo->prepare('SELECT id, is_active, public_key_pem, (locked_until IS NOT NULL AND locked_until > NOW()) AS is_locked FROM admins WHERE username = ? LIMIT 1');
$st->execute([$username]);
$admin = $st->fetch();

// Tidak membocorkan keberadaan akun: akun tidak ada/nonaktif/terkunci tetap mendapat challenge
// (yang tidak tersimpan) sehingga respons identik; verifikasi akan gagal.
if ($admin && (int) $admin['is_active'] === 1 && !empty($admin['public_key_pem']) && (int) $admin['is_locked'] === 0) {
    $sidHash = hash('sha256', session_id());
    $del = $pdo->prepare('DELETE FROM auth_challenges WHERE admin_id = ? AND session_id_hash = ? AND used_at IS NULL');
    $del->execute([(int) $admin['id'], $sidHash]);

    $ins = $pdo->prepare('INSERT INTO auth_challenges (admin_id, challenge, session_id_hash, ip_address, expires_at) VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND))');
    $ins->execute([(int) $admin['id'], $challenge, $sidHash, client_ip(), $ttl]);
}
record_login_attempt($admin ? (int) $admin['id'] : null, $username, false, 'challenge_issued');

json_response(200, ['ok' => true, 'challenge' => $challenge, 'expires_in' => $ttl]);
