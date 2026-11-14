<?php
declare(strict_types=1);
require_once __DIR__ . '/../includes/auth.php';
$admin = require_admin();
$pdo = db();

// key => [label, min, max, satuan]
$fields = [
    'challenge_ttl_seconds'  => ['Masa berlaku challenge login', 30, 600, 'detik'],
    'max_attempts_per_ip'    => ['Maks. percobaan gagal per IP', 3, 100, 'kali'],
    'max_attempts_per_user'  => ['Maks. percobaan gagal per akun (sebelum dikunci)', 3, 20, 'kali'],
    'attempt_window_minutes' => ['Jendela waktu rate limiting', 1, 120, 'menit'],
    'lockout_minutes'        => ['Durasi penguncian akun', 1, 1440, 'menit'],
    'session_idle_timeout'   => ['Batas idle session', 300, 14400, 'detik'],
];
$current = [];
foreach ($fields as $k => $f) {
    $current[$k] = (int) get_setting($k, '0');
}
$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_require();
    $input = [];
    foreach ($fields as $k => [$label, $min, $max]) {
        $raw = trim((string) ($_POST[$k] ?? ''));
        if (!ctype_digit($raw) || (int) $raw < $min || (int) $raw > $max) {
            $errors[] = "$label harus berupa angka $min-$max.";
        }
        $input[$k] = (int) $raw;
    }
    // Step-up authentication: konfirmasi password untuk perubahan konfigurasi sensitif
    $pw = (string) ($_POST['confirm_password'] ?? '');
    if (empty($admin['password_hash']) || !password_verify($pw, $admin['password_hash'])) {
        $errors[] = 'Password konfirmasi salah.';
        audit_log('SETTINGS_CHANGE', 'Percobaan ubah pengaturan GAGAL (konfirmasi password salah)');
    }
    if (!$errors) {
        $changes = [];
        $st = $pdo->prepare('INSERT INTO security_settings (setting_key, setting_value, updated_by) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), updated_by = VALUES(updated_by)');
        foreach ($input as $k => $v) {
            if ($v !== $current[$k]) {
                $st->execute([$k, (string) $v, (int) $admin['id']]);
                $changes[] = $k . ': ' . $current[$k] . ' -> ' . $v;
            }
        }
        if ($changes) {
            audit_log('SETTINGS_CHANGE', 'Pengaturan keamanan diubah: ' . implode('; ', $changes));
            flash('success', 'Pengaturan keamanan diperbarui.');
        } else {
            flash('info', 'Tidak ada perubahan.');
        }
        redirect('admin/settings.php');
    }
    $current = $input;
}

$info = [
    'OpenSSL'               => OPENSSL_VERSION_TEXT,
    'PHP'                   => PHP_VERSION,
    'AES-256-GCM'           => in_array(AES_CIPHER, openssl_get_cipher_methods(), true) ? 'Tersedia' : 'TIDAK tersedia',
    'Master key aktif'      => 'v' . current_key_version() . (master_key_exists() ? ' (termuat)' : ' (TIDAK ditemukan)'),
    'Lokasi master key'     => str_starts_with(key_dir(), ROOT_PATH) ? 'Di dalam project (diblokir .htaccess) - disarankan pindah ke luar webroot' : 'Di luar project',
    'HTTPS'                 => is_https() ? 'Ya' : 'Tidak (wajib untuk produksi)',
    'RSA public key admin'  => $admin['public_key_pem'] ? (rsa_key_bits($admin['public_key_pem']) . '-bit, RSA-PSS SHA-256') : 'Belum terdaftar',
    'Fingerprint (SHA-256)' => $admin['public_key_fingerprint'] ?: '-',
];

$pageTitle = 'Pengaturan Keamanan';
$layout = 'admin';
$active = 'settings';
require __DIR__ . '/../includes/header.php';
?>
<div class="row g-3">
  <div class="col-lg-7">
    <form method="post" class="panel" novalidate data-loading-form>
      <?= csrf_field() ?>
      <div class="panel-head"><h2>Parameter Autentikasi &amp; Sesi</h2></div>
      <div class="panel-body">
        <?php if ($errors): ?><div class="alert alert-danger"><ul class="mb-0 ps-3"><?php foreach ($errors as $er): ?><li><?= e($er) ?></li><?php endforeach; ?></ul></div><?php endif; ?>
        <?php foreach ($fields as $k => [$label, $min, $max, $unit]): ?>
          <div class="mb-3">
            <label class="form-label" for="<?= e($k) ?>"><?= e($label) ?></label>
            <div class="input-group">
              <input type="number" class="form-control" id="<?= e($k) ?>" name="<?= e($k) ?>" min="<?= $min ?>" max="<?= $max ?>" required value="<?= (int) $current[$k] ?>">
              <span class="input-group-text"><?= e($unit) ?></span>
            </div>
          </div>
        <?php endforeach; ?>
        <hr>
        <div class="mb-1">
          <label class="form-label" for="confirm_password">Konfirmasi password admin</label>
          <input type="password" class="form-control" id="confirm_password" name="confirm_password" autocomplete="current-password" required>
          <div class="form-text">Perubahan konfigurasi keamanan memerlukan password akun (disimpan sebagai hash).</div>
        </div>
      </div>
      <div class="panel-foot"><button class="btn btn-cyan"><span class="btn-label"><i class="fa-solid fa-floppy-disk me-1"></i>Simpan Pengaturan</span><span class="spinner-border spinner-border-sm d-none"></span></button></div>
    </form>
  </div>
  <div class="col-lg-5">
    <div class="panel">
      <div class="panel-head"><h2>Status Kriptografi</h2></div>
      <div class="panel-body">
        <ul class="status-list">
          <?php foreach ($info as $k => $v): ?>
            <li class="flex-wrap"><span><?= e($k) ?></span><b class="text-break text-end"><?= e($v) ?></b></li>
          <?php endforeach; ?>
        </ul>
      </div>
    </div>
  </div>
</div>
<?php require __DIR__ . '/../includes/footer.php'; ?>
