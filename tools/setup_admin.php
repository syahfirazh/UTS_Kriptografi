<?php
declare(strict_types=1);
/**
 * Pendaftaran ADMIN PERTAMA.
 * - Dilindungi SETUP_TOKEN (di .env). Otomatis terkunci setelah ada admin aktif berkunci RSA.
 * - Pasangan kunci dibuat DI BROWSER; hanya public key yang dikirim ke server.
 * - Membuat master key AES (storage/keys/master_v1.key) bila belum ada.
 */
require_once __DIR__ . '/../includes/auth.php';

$pdo = db();
$hasAdmin = (int) $pdo->query("SELECT COUNT(*) FROM admins WHERE is_active = 1 AND public_key_pem IS NOT NULL")->fetchColumn() > 0;
$setupToken = (string) env('SETUP_TOKEN', '');
$tokenOk = strlen($setupToken) >= 16 && !str_starts_with($setupToken, 'GANTI_');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_require();
    if ($hasAdmin) {
        json_response(403, ['ok' => false, 'error' => 'Setup terkunci: admin sudah terdaftar.']);
    }
    if (!$tokenOk) {
        json_response(500, ['ok' => false, 'error' => 'SETUP_TOKEN pada .env belum diatur (min. 16 karakter).']);
    }
    // Rate limit percobaan token
    if (login_rate_limited('__setup__')) {
        json_response(429, ['ok' => false, 'error' => 'Terlalu banyak percobaan. Coba lagi nanti.']);
    }
    $in = read_json();
    if (!hash_equals($setupToken, (string) ($in['setup_token'] ?? ''))) {
        record_login_attempt(null, '__setup__', false, 'bad_setup_token');
        json_response(403, ['ok' => false, 'error' => 'Setup token salah.']);
    }

    $username = trim((string) ($in['username'] ?? ''));
    $fullName = trim((string) ($in['full_name'] ?? ''));
    $email    = trim((string) ($in['email'] ?? ''));
    $password = (string) ($in['password'] ?? '');
    $pem      = (string) ($in['public_key_pem'] ?? '');

    $errors = [];
    if (!valid_username($username)) {
        $errors[] = 'Username 3-50 karakter (huruf, angka, . _ -).';
    }
    if (mb_strlen($fullName) < 3 || mb_strlen($fullName) > 100) {
        $errors[] = 'Nama lengkap 3-100 karakter.';
    }
    if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Format email tidak valid.';
    }
    if (strlen($password) < 12) {
        $errors[] = 'Password minimal 12 karakter.';
    }
    $keyErr = rsa_validate_public_key($pem);
    if ($keyErr !== null) {
        $errors[] = $keyErr;
    }
    if ($errors) {
        json_response(422, ['ok' => false, 'error' => implode(' ', $errors)]);
    }

    $pem = rsa_normalize_pem($pem);
    $fp = rsa_fingerprint($pem);
    $hash = password_hash($password, PASSWORD_DEFAULT);

    try {
        $pdo->beginTransaction();
        $exists = $pdo->prepare('SELECT id FROM admins WHERE username = ? LIMIT 1');
        $exists->execute([$username]);
        $id = $exists->fetchColumn();
        if ($id === false) {
            // Gunakan akun awal "admin" nonaktif jika ada (hasil seed SQL), selain itu buat baru
            $seed = $pdo->query("SELECT id FROM admins WHERE is_active = 0 AND public_key_pem IS NULL ORDER BY id LIMIT 1")->fetchColumn();
            if ($seed !== false) {
                $id = $seed;
                $pdo->prepare('UPDATE admins SET username = ? WHERE id = ?')->execute([$username, $id]);
            }
        }
        if ($id === false) {
            $pdo->prepare('INSERT INTO admins (username, full_name, email, password_hash, public_key_pem, public_key_fingerprint, is_active) VALUES (?, ?, ?, ?, ?, ?, 1)')
                ->execute([$username, $fullName, $email !== '' ? $email : null, $hash, $pem, $fp]);
            $id = (int) $pdo->lastInsertId();
        } else {
            $pdo->prepare('UPDATE admins SET full_name = ?, email = ?, password_hash = ?, public_key_pem = ?, public_key_fingerprint = ?, is_active = 1, failed_attempts = 0, locked_until = NULL WHERE id = ?')
                ->execute([$fullName, $email !== '' ? $email : null, $hash, $pem, $fp, (int) $id]);
        }
        $pdo->commit();
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log('setup_admin: ' . $e->getMessage());
        json_response(500, ['ok' => false, 'error' => 'Gagal menyimpan admin (username/kunci mungkin sudah dipakai).']);
    }

    $newKey = false;
    try {
        $newKey = generate_master_key_file();
    } catch (Throwable $e) {
        error_log('master key: ' . $e->getMessage());
    }
    audit_log('ADMIN_SETUP', 'Admin pertama didaftarkan: ' . $username . ($newKey ? ' (master key dibuat)' : ''), (int) $id, $username);
    json_response(200, [
        'ok' => true, 'fingerprint' => $fp, 'master_key_created' => $newKey, 'master_key_present' => master_key_exists(),
        'login_url' => url('auth/login.php'),
    ]);
}

$pageTitle = 'Setup Admin Pertama';
$layout = 'auth';
$extraJs = ['public/js/rsa-client.js', 'public/js/setup.js'];
$pageData = ['endpoint' => url('tools/setup_admin.php')];
require __DIR__ . '/../includes/header.php';
?>
<div class="auth-bg">
  <div class="auth-grid"></div>
  <div class="container position-relative">
    <div class="row justify-content-center">
      <div class="col-12 col-md-9 col-lg-7 col-xl-6">
        <div class="auth-card fade-up">
          <div class="text-center mb-4">
            <div class="auth-icon"><i class="fa-solid fa-user-shield"></i></div>
            <h1 class="h4 fw-bold text-white mb-1">Setup Admin Pertama</h1>
            <p class="text-muted-light small mb-0">Kunci RSA dibuat di browser Anda. Server hanya menerima public key.</p>
          </div>

          <?php if ($hasAdmin): ?>
            <div class="alert alert-warning mb-0"><i class="fa-solid fa-lock me-2"></i>Setup terkunci karena admin sudah terdaftar.
              <a href="<?= e(url('auth/login.php')) ?>" class="alert-link">Ke halaman login</a>.</div>
          <?php elseif (!$tokenOk): ?>
            <div class="alert alert-danger mb-0">Atur <code>SETUP_TOKEN</code> (min. 16 karakter acak) di file <code>.env</code> terlebih dahulu.</div>
          <?php else: ?>
            <div class="alert alert-danger d-none" id="setupError"></div>
            <div class="alert alert-success d-none" id="setupDone"></div>
            <form id="setupForm" novalidate>
              <div class="mb-3"><label class="form-label" for="setupToken">Setup Token (dari file .env)</label><input type="password" class="form-control" id="setupToken" autocomplete="off" required></div>
              <div class="row g-3 mb-3">
                <div class="col-md-6"><label class="form-label" for="username">Username</label><input class="form-control" id="username" value="admin" maxlength="50" required></div>
                <div class="col-md-6"><label class="form-label" for="fullName">Nama lengkap</label><input class="form-control" id="fullName" value="Administrator Utama" maxlength="100" required></div>
              </div>
              <div class="mb-3"><label class="form-label" for="email">Email (opsional)</label><input type="email" class="form-control" id="email" maxlength="120"></div>
              <div class="mb-3"><label class="form-label" for="password">Password akun (min. 12 karakter)</label><input type="password" class="form-control" id="password" autocomplete="new-password" required>
                <div class="form-text">Disimpan sebagai hash. Dipakai untuk konfirmasi perubahan pengaturan keamanan.</div></div>
              <hr class="border-secondary">
              <div class="mb-3"><label class="form-label" for="passphrase">Passphrase private key (min. 12 karakter)</label><input type="password" class="form-control" id="passphrase" autocomplete="new-password" required></div>
              <div class="mb-4"><label class="form-label" for="passphrase2">Ulangi passphrase</label><input type="password" class="form-control" id="passphrase2" autocomplete="new-password" required>
                <div class="form-text">Passphrase tidak dapat dipulihkan. Simpan file kunci yang diunduh di tempat aman.</div></div>
              <button class="btn btn-cyan w-100" type="submit" id="setupBtn"><span class="btn-label"><i class="fa-solid fa-key me-2"></i>Buat Kunci RSA &amp; Daftarkan Admin</span><span class="spinner-border spinner-border-sm d-none"></span></button>
            </form>
            <div id="downloadBox" class="d-none mt-3 text-center">
              <button class="btn btn-outline-light" id="btnDownloadAgain"><i class="fa-solid fa-download me-1"></i>Unduh ulang file private key</button>
              <a class="btn btn-cyan ms-2" href="<?= e(url('auth/login.php')) ?>">Ke halaman login</a>
            </div>
          <?php endif; ?>
        </div>
      </div>
    </div>
  </div>
</div>
<?php require __DIR__ . '/../includes/footer.php'; ?>
