<?php
declare(strict_types=1);
require_once __DIR__ . '/../includes/auth.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_response(405, ['ok' => false, 'error' => 'Metode tidak diizinkan.']);
}
csrf_require();

$generic = 'Autentikasi gagal. Periksa username, file kunci, dan passphrase Anda.';
$in = read_json();
$username  = trim((string) ($in['username'] ?? ''));
$challenge = (string) ($in['challenge'] ?? '');
$sigB64    = (string) ($in['signature'] ?? '');

if (!valid_username($username) || !preg_match('/^[a-f0-9]{64}$/', $challenge) || $sigB64 === '' || strlen($sigB64) > 2048) {
    login_fail($username, null, 'malformed_request', $generic, 422);
}
if (login_rate_limited($username)) {
    login_fail($username, null, 'rate_limited', 'Terlalu banyak percobaan. Coba lagi beberapa menit lagi.', 429);
}

$pdo = db();
$st = $pdo->prepare('SELECT *, (locked_until IS NOT NULL AND locked_until > NOW()) AS is_locked FROM admins WHERE username = ? LIMIT 1');
$st->execute([$username]);
$admin = $st->fetch();

if (!$admin || (int) $admin['is_active'] !== 1 || empty($admin['public_key_pem'])) {
    login_fail($username, null, 'unknown_user', $generic);
}
if ((int) $admin['is_locked'] === 1) {
    login_fail($username, $admin, 'account_locked', 'Akun dikunci sementara karena terlalu banyak percobaan gagal.', 423);
}

// Klaim challenge secara atomik: sekali pakai (anti replay), belum kedaluwarsa, milik admin & session ini.
// Dilakukan SEBELUM verifikasi sehingga challenge hangus walaupun tanda tangan salah.
$claim = $pdo->prepare(
    'UPDATE auth_challenges SET used_at = NOW()
     WHERE challenge = ? AND admin_id = ? AND session_id_hash = ? AND used_at IS NULL AND expires_at > NOW()'
);
$claim->execute([$challenge, (int) $admin['id'], hash('sha256', session_id())]);
if ($claim->rowCount() !== 1) {
    login_fail($username, $admin, 'invalid_challenge', $generic);
}

$signature = base64_decode($sigB64, true);
if ($signature === false) {
    login_fail($username, $admin, 'bad_signature', $generic);
}

$message = 'SAS-LOGIN-v1:' . $username . ':' . $challenge;
if (!rsa_pss_verify($message, $signature, $admin['public_key_pem'])) {
    crypto_log((int) $admin['id'], null, 'rsa_sign_verify', 'RSA-PSS-SHA256', 'failure', 'Verifikasi login gagal');
    login_fail($username, $admin, 'bad_signature', $generic);
}

// Sukses
$up = $pdo->prepare('UPDATE admins SET failed_attempts = 0, locked_until = NULL, last_login_at = NOW(), last_login_ip = ? WHERE id = ?');
$up->execute([client_ip(), (int) $admin['id']]);
record_login_attempt((int) $admin['id'], $username, true, 'login_ok');
establish_admin_session($admin);
audit_log('LOGIN_SUCCESS', 'Login berhasil dengan RSA-PSS', (int) $admin['id'], $admin['username']);
crypto_log((int) $admin['id'], null, 'rsa_sign_verify', 'RSA-PSS-SHA256', 'success', 'Verifikasi login berhasil');

json_response(200, ['ok' => true, 'redirect' => url('admin/dashboard.php')]);
