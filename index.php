<?php
declare(strict_types=1);
require_once __DIR__ . '/config/security.php';

$pageTitle = 'Secure Information Management System';
$layout = 'public';
require __DIR__ . '/includes/header.php';
?>
<header class="hero">
  <div class="hero-grid"></div>
  <div class="container position-relative">
    <div class="row align-items-center g-5">
      <div class="col-lg-7 fade-up">
        <span class="eyebrow"><i class="fa-solid fa-shield-halved me-2"></i>AES-256-GCM &middot; RSA-PSS &middot; SHA-256</span>
        <h1 class="hero-title">Secure Information <span class="text-gradient">Management System</span></h1>
        <p class="hero-lead">SECURE ADMIN SYSTEM adalah sistem informasi manajemen konten yang mengamankan akses administrator dengan tanda tangan digital RSA dan melindungi isi data dengan enkripsi AES-256-GCM.</p>
        <p class="hero-tag"><i class="fa-solid fa-quote-left me-2"></i><?= e(APP_TAGLINE) ?></p>
        <div class="d-flex flex-wrap gap-3 mt-4">
          <a href="#fitur" class="btn btn-outline-light btn-lg px-4">Pelajari Fitur</a>
        </div>
      </div>
      <div class="col-lg-5 fade-up delay-1">
        <div class="terminal">
          <div class="terminal-bar"><span></span><span></span><span></span><em>auth-handshake.log</em></div>
          <pre class="terminal-body"><span class="t-dim">// 1. server &rarr; browser</span>
challenge = random_bytes(32)
<span class="t-dim">// 2. browser (lokal, private key tidak keluar)</span>
sig = RSA-PSS.sign(challenge)
<span class="t-dim">// 3. browser &rarr; server</span>
verify(sig, publicKey)  <span class="t-ok">&rarr; VALID</span>
<span class="t-dim">// 4. data tersimpan</span>
AES-256-GCM(nonce, tag)  <span class="t-ok">&rarr; OK</span></pre>
        </div>
      </div>
    </div>
  </div>
</header>

<section id="fitur" class="section">
  <div class="container">
    <div class="section-head text-center">
      <span class="eyebrow">Fitur Keamanan</span>
      <h2>Keamanan berlapis, dari login hingga penyimpanan</h2>
    </div>
    <div class="row g-4">
      <?php
      $features = [
          ['fa-fingerprint', 'Login Tanda Tangan Digital', 'Admin membuktikan identitas dengan menandatangani challenge menggunakan private key RSA, tanpa mengirim password atau kunci rahasia.'],
          ['fa-database', 'Konten Terenkripsi', 'Isi konten dienkripsi AES-256-GCM sebelum masuk database. Yang tersimpan hanya ciphertext, nonce, dan authentication tag.'],
          ['fa-rotate', 'Anti Replay Attack', 'Challenge acak, berumur pendek, terikat ke sesi, dan hanya dapat dipakai satu kali.'],
          ['fa-gauge-simple-high', 'Rate Limiting', 'Pembatasan percobaan login per IP dan per akun, plus penguncian sementara akun.'],
          ['fa-clipboard-list', 'Audit Log Lengkap', 'Setiap login, perubahan konten, dan operasi kriptografi tercatat tanpa menyimpan data sensitif.'],
          ['fa-user-lock', 'Sesi & Header Aman', 'Cookie HttpOnly + SameSite, regenerasi session, proteksi CSRF, XSS, dan SQL injection.'],
      ];
      foreach ($features as $i => [$icon, $title, $text]): ?>
        <div class="col-md-6 col-lg-4">
          <div class="feature-card">
            <div class="feature-icon"><i class="fa-solid <?= $icon ?>"></i></div>
            <h3><?= e($title) ?></h3>
            <p><?= e($text) ?></p>
          </div>
        </div>
      <?php endforeach; ?>
    </div>
  </div>
</section>

<section id="aes" class="section section-alt">
  <div class="container">
    <div class="row align-items-center g-5">
      <div class="col-lg-6">
        <span class="eyebrow">Kriptografi Simetris</span>
        <h2>AES-256-GCM</h2>
        <p class="text-muted-light">AES dalam mode Galois/Counter (GCM) adalah enkripsi terautentikasi (AEAD): menjaga <strong>kerahasiaan</strong> sekaligus <strong>integritas</strong>. Jika satu bit ciphertext diubah, dekripsi ditolak.</p>
        <ul class="check-list">
          <li>Kunci 256-bit dikelola di luar source code</li>
          <li>Nonce 96-bit acak untuk setiap enkripsi</li>
          <li>Authentication tag 128-bit memvalidasi keaslian data</li>
          <li>AAD mengikat ciphertext ke ID konten dan versi kunci</li>
        </ul>
      </div>
      <div class="col-lg-6">
        <div class="flow-card">
          <div class="flow-step"><i class="fa-solid fa-file-lines"></i><span>Plaintext</span></div>
          <i class="fa-solid fa-arrow-down flow-arrow"></i>
          <div class="flow-step accent"><i class="fa-solid fa-lock"></i><span>AES-256-GCM + nonce acak</span></div>
          <i class="fa-solid fa-arrow-down flow-arrow"></i>
          <div class="flow-step"><i class="fa-solid fa-database"></i><span>Ciphertext + Nonce + Tag &rarr; Database</span></div>
        </div>
      </div>
    </div>
  </div>
</section>

<section id="rsa" class="section">
  <div class="container">
    <div class="row align-items-center g-5 flex-lg-row-reverse">
      <div class="col-lg-6">
        <span class="eyebrow">Kriptografi Asimetris</span>
        <h2>RSA-PSS Digital Signature</h2>
        <p class="text-muted-light">RSA-PSS (RSASSA-PSS, RFC 8017) adalah skema tanda tangan probabilistik dengan bukti keamanan yang lebih kuat daripada PKCS#1 v1.5. Server hanya menyimpan <em>public key</em>; <em>private key</em> tetap terenkripsi di perangkat admin.</p>
        <ul class="check-list">
          <li>RSA 2048-bit, hash SHA-256, MGF1, salt 32 byte</li>
          <li>Challenge-response sekali pakai</li>
          <li>Private key dibuka lokal dengan passphrase (PBKDF2 + AES-GCM)</li>
          <li>Kompatibel Web Crypto API &harr; PHP OpenSSL</li>
        </ul>
      </div>
      <div class="col-lg-6">
        <div class="flow-card">
          <div class="flow-step"><i class="fa-solid fa-server"></i><span>Server: challenge acak</span></div>
          <i class="fa-solid fa-arrow-down flow-arrow"></i>
          <div class="flow-step accent"><i class="fa-solid fa-pen-nib"></i><span>Browser: tanda tangan RSA-PSS</span></div>
          <i class="fa-solid fa-arrow-down flow-arrow"></i>
          <div class="flow-step"><i class="fa-solid fa-circle-check"></i><span>Server: verifikasi dengan public key</span></div>
        </div>
      </div>
    </div>
  </div>
</section>

<section id="keunggulan" class="section section-alt">
  <div class="container">
    <div class="section-head text-center">
      <span class="eyebrow">Keunggulan Sistem</span>
      <h2>Dirancang untuk pembelajaran dan praktik nyata</h2>
    </div>
    <div class="row g-4 text-center">
      <?php foreach ([
          ['fa-code', 'PHP Native', 'Tanpa framework dan tanpa Composer; kode mudah ditelusuri.'],
          ['fa-layer-group', 'Sistem Informasi Utuh', 'CRUD konten, kategori, dashboard, dan audit.'],
          ['fa-flask', 'Demonstrasi Kriptografi', 'Uji enkripsi, dekripsi, dan verifikasi tanda tangan secara nyata.'],
          ['fa-mobile-screen', 'Responsif', 'Tampil optimal di desktop, tablet, dan ponsel.'],
      ] as [$icon, $t, $d]): ?>
        <div class="col-6 col-lg-3"><div class="adv"><i class="fa-solid <?= $icon ?>"></i><h3><?= e($t) ?></h3><p><?= e($d) ?></p></div></div>
      <?php endforeach; ?>
    </div>

  </div>
</section>

<footer class="site-footer">
  <div class="container d-flex flex-column flex-md-row justify-content-between align-items-center gap-2">
    
<a href="<?= e(url('auth/login.php')) ?>"
   class="d-flex align-items-center gap-2 text-decoration-none text-reset"
   title="Admin Access">

  <span class="brand-mark sm">
    <i class="fa-solid fa-shield-halved"></i>
  </span>

  <strong><?= e(APP_NAME) ?></strong>

</a>

    <small><?= e(APP_TAGLINE) ?></small>
    <small>&copy; <?= date('Y') ?> Proyek akademik kriptografi</small>
  </div>
</footer>
<?php require __DIR__ . '/includes/footer.php'; ?>
