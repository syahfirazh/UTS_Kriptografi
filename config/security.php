<?php
declare(strict_types=1);

/**
 * Bootstrap keamanan: env, konstanta, error handling, session aman,
 * security headers, CSRF, dan helper umum.
 */
if (defined('SAS_BOOTSTRAPPED')) {
    return;
}
define('SAS_BOOTSTRAPPED', true);
define('ROOT_PATH', dirname(__DIR__));

/** Baca konfigurasi dari .env (file di luar jangkauan web via .htaccess). */
function env(string $key, $default = null)
{
    static $vars = null;
    if ($vars === null) {
        $vars = [];
        $file = ROOT_PATH . '/.env';
        if (is_readable($file)) {
            $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
            foreach ($lines as $line) {
                $line = trim($line);
                if ($line === '' || $line[0] === '#') {
                    continue;
                }
                $pos = strpos($line, '=');
                if ($pos === false) {
                    continue;
                }
                $vars[trim(substr($line, 0, $pos))] = trim(trim(substr($line, $pos + 1)), "\"'");
            }
        }
    }
    if (array_key_exists($key, $vars) && $vars[$key] !== '') {
        return $vars[$key];
    }
    return $default;
}

define('APP_NAME', 'SECURE ADMIN SYSTEM');
define('APP_TAGLINE', 'Secure Your Information, Protect Your Data.');
define('APP_DEBUG', strtolower((string) env('APP_DEBUG', 'false')) === 'true');
define('BASE_URL', rtrim((string) env('BASE_URL', '/secure-admin-system'), '/'));

date_default_timezone_set((string) env('APP_TIMEZONE', 'Asia/Jakarta'));

ini_set('display_errors', APP_DEBUG ? '1' : '0');
ini_set('log_errors', '1');
ini_set('error_log', ROOT_PATH . '/storage/php_error.log');
error_reporting(E_ALL);

function is_https(): bool
{
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || ((int) ($_SERVER['SERVER_PORT'] ?? 0) === 443);
}

/* ---------- Session aman ---------- */
if (PHP_SAPI !== 'cli' && session_status() === PHP_SESSION_NONE) {
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.use_trans_sid', '0');
    session_name('SAS_SESSID');
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => BASE_URL . '/',
        'secure'   => is_https(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start();
}

/* ---------- Security headers ---------- */
function send_security_headers(): void
{
    if (headers_sent()) {
        return;
    }
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: same-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header("Content-Security-Policy: default-src 'self'; "
        . "script-src 'self' https://cdn.jsdelivr.net; "
        . "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        . "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com data:; "
        . "img-src 'self' data:; connect-src 'self'; "
        . "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'");
    if (is_https()) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
}
if (PHP_SAPI !== 'cli') {
    send_security_headers();
}

/* ---------- Helper umum ---------- */
function e($value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function url(string $path = ''): string
{
    return BASE_URL . '/' . ltrim($path, '/');
}

function redirect(string $path): never
{
    header('Location: ' . url($path));
    exit;
}

function client_ip(): string
{
    $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
    $proxy = (string) env('TRUSTED_PROXY', '');
    if ($proxy !== '' && $ip === $proxy && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $first = trim(explode(',', (string) $_SERVER['HTTP_X_FORWARDED_FOR'])[0]);
        if (filter_var($first, FILTER_VALIDATE_IP)) {
            return $first;
        }
    }
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
}

function user_agent(): string
{
    return substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 255);
}

function valid_username(string $u): bool
{
    return (bool) preg_match('/^[A-Za-z0-9_.-]{3,50}$/', $u);
}

function json_response(int $status, array $data): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function read_json(): array
{
    $raw = file_get_contents('php://input');
    if ($raw === false || $raw === '' || strlen($raw) > 65536) {
        return [];
    }
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

/* ---------- CSRF ---------- */
function csrf_token(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function csrf_field(): string
{
    return '<input type="hidden" name="csrf_token" value="' . e(csrf_token()) . '">';
}

function csrf_verify($token): bool
{
    return is_string($token) && !empty($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $token);
}

/** Wajib dipanggil pada setiap request yang mengubah state. */
function csrf_require(): void
{
    $token = $_POST['csrf_token'] ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
    if (csrf_verify($token)) {
        return;
    }
    $wantsJson = str_contains((string) ($_SERVER['HTTP_ACCEPT'] ?? ''), 'application/json')
        || str_contains((string) ($_SERVER['CONTENT_TYPE'] ?? ''), 'application/json');
    if ($wantsJson) {
        json_response(419, ['ok' => false, 'error' => 'Sesi tidak valid (CSRF). Muat ulang halaman.']);
    }
    http_response_code(419);
    exit('Token CSRF tidak valid. Muat ulang halaman dan coba lagi.');
}

/* ---------- Flash message ---------- */
function flash(string $type, string $message): void
{
    $_SESSION['flash'][] = ['type' => $type, 'message' => $message];
}

function consume_flashes(): array
{
    $f = $_SESSION['flash'] ?? [];
    unset($_SESSION['flash']);
    return $f;
}

/* ---------- Pengaturan keamanan (tabel security_settings) ---------- */
function get_setting(string $key, $default = null)
{
    static $cache = null;
    if ($cache === null) {
        $cache = [];
        try {
            foreach (db()->query('SELECT setting_key, setting_value FROM security_settings') as $r) {
                $cache[$r['setting_key']] = $r['setting_value'];
            }
        } catch (Throwable $e) {
            error_log('get_setting: ' . $e->getMessage());
        }
    }
    return $cache[$key] ?? $default;
}

function destroy_session(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires' => time() - 42000, 'path' => $p['path'], 'domain' => $p['domain'],
            'secure' => $p['secure'], 'httponly' => true, 'samesite' => 'Strict',
        ]);
    }
    session_destroy();
}
