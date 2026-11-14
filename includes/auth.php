<?php
declare(strict_types=1);

/**
 * Middleware autentikasi + fungsi audit & rate limiting.
 * Halaman admin: require_once file ini lalu panggil require_admin().
 */
require_once __DIR__ . '/../config/security.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../crypto/crypto_helper.php';
require_once __DIR__ . '/helpers.php';

/* ---------- Audit log (tidak menyimpan plaintext/kunci/passphrase) ---------- */
function audit_log(string $action, ?string $description = null, ?int $adminId = null, ?string $usernameSnapshot = null): void
{
    try {
        if ($adminId === null && !empty($_SESSION['admin_id'])) {
            $adminId = (int) $_SESSION['admin_id'];
            $usernameSnapshot = $usernameSnapshot ?? ($_SESSION['admin_username'] ?? null);
        }
        $st = db()->prepare(
            'INSERT INTO audit_logs (admin_id, username_snapshot, action, description, ip_address, user_agent)
             VALUES (?, ?, ?, ?, ?, ?)'
        );
        $st->execute([
            $adminId,
            $usernameSnapshot,
            $action,
            $description !== null ? substr($description, 0, 255) : null,
            client_ip(),
            user_agent(),
        ]);
    } catch (Throwable $e) {
        error_log('audit_log gagal: ' . $e->getMessage());
    }
}

/* ---------- Middleware ---------- */
function require_admin(): array
{
    if (empty($_SESSION['admin_id'])) {
        redirect('auth/login.php');
    }
    $idle = (int) get_setting('session_idle_timeout', '1800');
    if (isset($_SESSION['last_activity']) && (time() - (int) $_SESSION['last_activity']) > $idle) {
        destroy_session();
        redirect('auth/login.php?reason=timeout');
    }
    if (($_SESSION['ua_hash'] ?? '') !== hash('sha256', user_agent())) {
        destroy_session();
        redirect('auth/login.php?reason=session');
    }
    $_SESSION['last_activity'] = time();

    // Rotasi session id berkala (15 menit)
    if (time() - (int) ($_SESSION['created_at'] ?? 0) > 900) {
        session_regenerate_id(true);
        $_SESSION['created_at'] = time();
    }

    $st = db()->prepare('SELECT id, username, full_name, email, public_key_pem, public_key_fingerprint, password_hash, is_active, last_login_at, last_login_ip FROM admins WHERE id = ? LIMIT 1');
    $st->execute([(int) $_SESSION['admin_id']]);
    $admin = $st->fetch();
    if (!$admin || (int) $admin['is_active'] !== 1) {
        destroy_session();
        redirect('auth/login.php?reason=session');
    }
    return $admin;
}

/** Buat session admin setelah verifikasi RSA sukses. */
function establish_admin_session(array $admin): void
{
    session_regenerate_id(true);           // cegah session fixation
    unset($_SESSION['csrf']);              // token CSRF baru setelah login
    $_SESSION['admin_id']       = (int) $admin['id'];
    $_SESSION['admin_username'] = $admin['username'];
    $_SESSION['ua_hash']        = hash('sha256', user_agent());
    $_SESSION['created_at']     = time();
    $_SESSION['last_activity']  = time();
}

/* ---------- Rate limiting berbasis login_attempts ---------- */
function record_login_attempt(?int $adminId, string $username, bool $success, string $reason): void
{
    try {
        $st = db()->prepare('INSERT INTO login_attempts (admin_id, username, ip_address, success, reason) VALUES (?, ?, ?, ?, ?)');
        $st->execute([$adminId, substr($username, 0, 50), client_ip(), $success ? 1 : 0, substr($reason, 0, 60)]);
    } catch (Throwable $e) {
        error_log('record_login_attempt: ' . $e->getMessage());
    }
}

function login_rate_limited(string $username): bool
{
    $window = max(1, (int) get_setting('attempt_window_minutes', '15'));
    $maxIp  = max(1, (int) get_setting('max_attempts_per_ip', '10'));
    $maxUsr = max(1, (int) get_setting('max_attempts_per_user', '5'));
    $pdo = db();

    $st = $pdo->prepare("SELECT COUNT(*) FROM login_attempts WHERE ip_address = ? AND success = 0 AND reason <> 'challenge_issued' AND attempted_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)");
    $st->execute([client_ip(), $window]);
    if ((int) $st->fetchColumn() >= $maxIp) {
        return true;
    }
    $st = $pdo->prepare("SELECT COUNT(*) FROM login_attempts WHERE ip_address = ? AND reason = 'challenge_issued' AND attempted_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)");
    $st->execute([client_ip(), $window]);
    if ((int) $st->fetchColumn() >= $maxIp * 3) {
        return true;
    }
    $st = $pdo->prepare("SELECT COUNT(*) FROM login_attempts WHERE username = ? AND success = 0 AND reason <> 'challenge_issued' AND attempted_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)");
    $st->execute([substr($username, 0, 50), $window]);
    return (int) $st->fetchColumn() >= $maxUsr * 2;
}

/** Catat kegagalan login, kunci akun bila melewati batas, lalu balas JSON. */
function login_fail(string $username, ?array $admin, string $reason, string $message, int $httpCode = 401): never
{
    record_login_attempt($admin['id'] ?? null, $username, false, $reason);
    audit_log('LOGIN_FAILED', 'Login gagal (' . $reason . ')', $admin ? (int) $admin['id'] : null, substr($username, 0, 50));

    if ($admin && in_array($reason, ['bad_signature', 'invalid_challenge'], true)) {
        $max  = max(1, (int) get_setting('max_attempts_per_user', '5'));
        $lock = max(1, (int) get_setting('lockout_minutes', '15'));
        $new  = (int) $admin['failed_attempts'] + 1;
        if ($new >= $max) {
            $st = db()->prepare('UPDATE admins SET failed_attempts = 0, locked_until = DATE_ADD(NOW(), INTERVAL ? MINUTE) WHERE id = ?');
            $st->execute([$lock, (int) $admin['id']]);
        } else {
            $st = db()->prepare('UPDATE admins SET failed_attempts = ? WHERE id = ?');
            $st->execute([$new, (int) $admin['id']]);
        }
    }
    json_response($httpCode, ['ok' => false, 'error' => $message]);
}
