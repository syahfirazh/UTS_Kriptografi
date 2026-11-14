<?php /* Navbar halaman publik (landing, login) */ ?>
<nav class="navbar navbar-expand-lg navbar-dark sas-navbar fixed-top">
  <div class="container">
    <a class="navbar-brand d-flex align-items-center gap-2" href="<?= e(url('index.php')) ?>">
      <span class="brand-mark"><i class="fa-solid fa-shield-halved"></i></span>
      <span class="brand-text">SECURE <span>ADMIN</span> SYSTEM</span>
    </a>
    <button class="navbar-toggler border-0" type="button" data-bs-toggle="collapse" data-bs-target="#publicNav" aria-controls="publicNav" aria-expanded="false" aria-label="Menu">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="publicNav">
      <ul class="navbar-nav ms-auto align-items-lg-center gap-lg-2">
        <li class="nav-item"><a class="nav-link" href="<?= e(url('index.php#fitur')) ?>">Fitur</a></li>
        <li class="nav-item"><a class="nav-link" href="<?= e(url('index.php#aes')) ?>">AES-256-GCM</a></li>
        <li class="nav-item"><a class="nav-link" href="<?= e(url('index.php#rsa')) ?>">RSA-PSS</a></li>
        <li class="nav-item"><a class="nav-link" href="<?= e(url('index.php#keunggulan')) ?>">Keunggulan</a></li>
      </ul>
    </div>
  </div>
</nav>
