<?php
/* Sidebar admin. Variabel: $active (kunci menu aktif). */
$menu = [
    'dashboard'  => ['admin/dashboard.php',        'fa-gauge-high',       'Dashboard'],
    'contents'   => ['admin/contents/index.php',   'fa-file-lines',       'Manajemen Konten'],
    'categories' => ['admin/categories/index.php', 'fa-tags',             'Kategori Konten'],
    'encryption' => ['admin/encryption.php',       'fa-key',              'Enkripsi & Dekripsi'],
    'audit'      => ['admin/audit.php',            'fa-clipboard-list',   'Audit Log'],
    'settings'   => ['admin/settings.php',         'fa-sliders',          'Pengaturan Keamanan'],
];
?>
<aside class="sidebar" id="sidebar">
  <div class="sidebar-brand">
    <span class="brand-mark"><i class="fa-solid fa-shield-halved"></i></span>
    <span class="sidebar-label brand-text">SECURE <span>ADMIN</span></span>
  </div>
  <nav class="sidebar-nav">
    <?php foreach ($menu as $key => [$path, $icon, $label]): ?>
      <a href="<?= e(url($path)) ?>" class="sidebar-link<?= ($active ?? '') === $key ? ' active' : '' ?>" title="<?= e($label) ?>">
        <i class="fa-solid <?= e($icon) ?>"></i><span class="sidebar-label"><?= e($label) ?></span>
      </a>
    <?php endforeach; ?>
  </nav>
  <form method="post" action="<?= e(url('auth/logout.php')) ?>" class="sidebar-footer">
    <?= csrf_field() ?>
    <button type="submit" class="sidebar-link w-100 border-0 text-start" title="Logout">
      <i class="fa-solid fa-right-from-bracket"></i><span class="sidebar-label">Logout</span>
    </button>
  </form>
</aside>
