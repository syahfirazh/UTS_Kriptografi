<?php
declare(strict_types=1);
require_once __DIR__ . '/../includes/auth.php';
$admin = require_admin();
$pdo = db();

$totalContents  = (int) $pdo->query('SELECT COUNT(*) FROM contents')->fetchColumn();
$totalEncrypted = (int) $pdo->query("SELECT COUNT(*) FROM contents WHERE LENGTH(ciphertext) > 0 AND LENGTH(nonce) = 12 AND LENGTH(auth_tag) = 16")->fetchColumn();
$totalCategories = (int) $pdo->query('SELECT COUNT(*) FROM categories')->fetchColumn();
$activity24h = (int) $pdo->query('SELECT COUNT(*) FROM audit_logs WHERE created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)')->fetchColumn();

// Grafik 7 hari
$rows = $pdo->query('SELECT DATE(created_at) AS d, COUNT(*) AS c FROM audit_logs WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 6 DAY) GROUP BY DATE(created_at)')->fetchAll();
$byDay = [];
foreach ($rows as $r) {
    $byDay[$r['d']] = (int) $r['c'];
}
$chart = ['labels' => [], 'values' => []];
for ($i = 6; $i >= 0; $i--) {
    $d = date('Y-m-d', strtotime("-$i day"));
    $chart['labels'][] = date('d M', strtotime($d));
    $chart['values'][] = $byDay[$d] ?? 0;
}

$recent = $pdo->query('SELECT action, description, username_snapshot, ip_address, created_at FROM audit_logs ORDER BY id DESC LIMIT 8')->fetchAll();

// Status enkripsi & RSA
$gcmOk   = in_array(AES_CIPHER, openssl_get_cipher_methods(), true);
$keyOk   = master_key_exists();
$keyVer  = current_key_version();
$rsaBits = $admin['public_key_pem'] ? rsa_key_bits($admin['public_key_pem']) : null;

$pageTitle = 'Dashboard';
$layout = 'admin';
$active = 'dashboard';
$pageData = ['chart' => $chart];
$extraJs = ['public/js/dashboard.js'];
require __DIR__ . '/../includes/header.php';
?>
<div class="row g-3 mb-4">
  <?php
  $cards = [
      ['Total Konten', $totalContents, 'fa-file-lines', 'cyan'],
      ['Konten Terenkripsi', $totalEncrypted, 'fa-lock', 'green'],
      ['Total Kategori', $totalCategories, 'fa-tags', 'blue'],
      ['Aktivitas 24 Jam', $activity24h, 'fa-bolt', 'amber'],
  ];
  foreach ($cards as [$label, $val, $icon, $tone]): ?>
    <div class="col-6 col-xl-3">
      <div class="stat-card tone-<?= $tone ?>">
        <div class="stat-icon"><i class="fa-solid <?= $icon ?>"></i></div>
        <div>
          <div class="stat-value"><?= number_format($val) ?></div>
          <div class="stat-label"><?= e($label) ?></div>
        </div>
      </div>
    </div>
  <?php endforeach; ?>
</div>

<div class="row g-3 mb-4">
  <div class="col-lg-8">
    <div class="panel h-100">
      <div class="panel-head"><h2>Grafik Aktivitas Admin (7 hari)</h2></div>
      <div class="panel-body"><canvas id="activityChart" height="110" aria-label="Grafik aktivitas"></canvas></div>
    </div>
  </div>
  <div class="col-lg-4">
    <div class="panel h-100">
      <div class="panel-head"><h2>Status Keamanan</h2></div>
      <div class="panel-body">
        <ul class="status-list">
          <li><span>AES-256-GCM (OpenSSL)</span><?= $gcmOk ? '<b class="ok">Aktif</b>' : '<b class="bad">Tidak tersedia</b>' ?></li>
          <li><span>Master key v<?= (int) $keyVer ?></span><?= $keyOk ? '<b class="ok">Termuat</b>' : '<b class="bad">Tidak ditemukan</b>' ?></li>
          <li><span>Autentikasi RSA-PSS</span><?= $rsaBits ? '<b class="ok">' . (int) $rsaBits . '-bit</b>' : '<b class="bad">Belum ada kunci</b>' ?></li>
          <li><span>Koneksi HTTPS</span><?= is_https() ? '<b class="ok">Ya</b>' : '<b class="warn">Tidak (dev)</b>' ?></li>
          <li><span>Login terakhir</span><b><?= e(format_dt($admin['last_login_at'])) ?></b></li>
        </ul>
        <?php if ($admin['public_key_fingerprint']): ?>
          <div class="fp-box"><small>Fingerprint public key (SHA-256)</small><code><?= e(chunk_split(substr($admin['public_key_fingerprint'], 0, 32), 4, ' ')) ?>…</code></div>
        <?php endif; ?>
      </div>
    </div>
  </div>
</div>

<div class="panel">
  <div class="panel-head d-flex justify-content-between align-items-center">
    <h2>Aktivitas Terbaru</h2>
    <a href="<?= e(url('admin/audit.php')) ?>" class="btn btn-sm btn-outline-cyan">Lihat semua</a>
  </div>
  <div class="table-responsive">
    <table class="table table-sas align-middle mb-0">
      <thead><tr><th>Waktu</th><th>Admin</th><th>Aktivitas</th><th>Keterangan</th><th>IP</th></tr></thead>
      <tbody>
      <?php if (!$recent): ?>
        <tr><td colspan="5"><div class="empty-state"><i class="fa-regular fa-folder-open"></i><p>Belum ada aktivitas.</p></div></td></tr>
      <?php endif; ?>
      <?php foreach ($recent as $r): ?>
        <tr>
          <td class="text-nowrap"><?= e(format_dt($r['created_at'])) ?></td>
          <td><?= e($r['username_snapshot'] ?? '-') ?></td>
          <td><?= action_badge($r['action']) ?></td>
          <td class="text-truncate-cell"><?= e($r['description'] ?? '') ?></td>
          <td><code><?= e($r['ip_address']) ?></code></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>
</div>
<?php require __DIR__ . '/../includes/footer.php'; ?>
