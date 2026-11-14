<?php
declare(strict_types=1);
require_once __DIR__ . '/../includes/auth.php';

if (!empty($_SESSION['admin_id'])) {
    redirect('admin/dashboard.php');
}
$reasons = [
    'logout'  => ['success', 'Anda telah logout dengan aman.'],
    'timeout' => ['warning', 'Sesi berakhir karena tidak aktif. Silakan login kembali.'],
    'session' => ['warning', 'Sesi tidak valid. Silakan login kembali.'],
];
$reason = $reasons[$_GET['reason'] ?? ''] ?? null;
if ($reason) {
    flash($reason[0], $reason[1]);
}

$pageTitle = 'Login Admin';
$layout = 'auth';
$extraJs = ['public/js/rsa-client.js', 'public/js/login.js'];
require __DIR__ . '/../includes/header.php';
?>
<div class="auth-bg">
  <div class="auth-grid"></div>
  <div class="container position-relative">
    <div class="row justify-content-center">
      <div class="col-12 col-md-8 col-lg-6 col-xl-5">
        <a href="<?= e(url('index.php')) ?>" class="auth-back"><i class="fa-solid fa-arrow-left me-1"></i> Kembali ke beranda</a>
        <div class="auth-card fade-up">
          <div class="text-center mb-4">
            <div class="auth-icon"><i class="fa-solid fa-fingerprint"></i></div>
            <h1 class="h4 fw-bold text-white mb-1">RSA Digital Signature Login</h1>
            <p class="text-muted-light small mb-0">Autentikasi tanpa password dikirim. Private key tetap di perangkat Anda.</p>
          </div>

          <div class="alert alert-danger d-none" id="loginError" role="alert"></div>

          <form id="loginForm" novalidate
                data-challenge-url="<?= e(url('auth/challenge.php')) ?>"
                data-verify-url="<?= e(url('auth/verify.php')) ?>">
            <div class="mb-3">
              <label for="username" class="form-label">Username</label>
              <div class="input-group">
                <span class="input-group-text"><i class="fa-solid fa-user"></i></span>
                <input type="text" class="form-control" id="username" autocomplete="username" maxlength="50" required>
              </div>
            </div>
            <div class="mb-3">
              <label for="keyFile" class="form-label">File Private Key (.json)</label>
              <input type="file" class="form-control" id="keyFile" accept=".json,application/json" required>
            </div>
            <div class="mb-4">
              <label for="passphrase" class="form-label">Passphrase Private Key</label>
              <div class="input-group">
                <span class="input-group-text"><i class="fa-solid fa-key"></i></span>
                <input type="password" class="form-control" id="passphrase" autocomplete="off" required>
                <button class="btn btn-outline-light" type="button" id="togglePass" aria-label="Tampilkan passphrase"><i class="fa-solid fa-eye"></i></button>
              </div>
            </div>

            <ol class="auth-steps list-unstyled mb-4" id="authSteps">
              <li data-step="1"><i class="fa-regular fa-circle"></i> Membuka private key (lokal di browser)</li>
              <li data-step="2"><i class="fa-regular fa-circle"></i> Meminta challenge dari server</li>
              <li data-step="3"><i class="fa-regular fa-circle"></i> Menandatangani challenge (RSA-PSS, SHA-256)</li>
              <li data-step="4"><i class="fa-regular fa-circle"></i> Server memverifikasi signature</li>
            </ol>

            <button type="submit" class="btn btn-cyan w-100 py-2" id="loginBtn">
              <span class="btn-label"><i class="fa-solid fa-shield-halved me-2"></i>Autentikasi dengan RSA</span>
              <span class="spinner-border spinner-border-sm d-none" role="status"></span>
            </button>
          </form>
          <p class="text-center text-muted-light small mt-4 mb-0">
    Belum punya kunci? Admin pertama dibuat melalui 
    <a href="http://localhost/secure-admin-system/tools/setup_admin.php" class="text-reset text-decoration-underline"><br><code>Buat di Sini</code></a>.
</p>
        </div>
      </div>
    </div>
  </div>
</div>
<?php require __DIR__ . '/../includes/footer.php'; ?>
