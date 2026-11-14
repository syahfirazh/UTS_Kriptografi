<?php
declare(strict_types=1);
require_once __DIR__ . '/../../includes/auth.php';
$admin = require_admin();
$pdo = db();

$id = (int) ($_GET['id'] ?? 0);
$st = $pdo->prepare(
    'SELECT c.*, cat.name AS category_name, a.username FROM contents c
     JOIN categories cat ON cat.id = c.category_id JOIN admins a ON a.id = c.created_by
     WHERE c.id = ? LIMIT 1'
);
$st->execute([$id]);
$row = $st->fetch();
if (!$row) {
    flash('danger', 'Konten tidak ditemukan.');
    redirect('admin/contents/index.php');
}

$plain = null;
$integrityError = null;
try {
    $plain = content_decrypt($row);   // GCM: tag diverifikasi di sini
    audit_log('CONTENT_DECRYPT', 'Konten #' . $id . ' didekripsi untuk dilihat');
    crypto_log((int) $admin['id'], $id, 'decrypt', 'AES-256-GCM', 'success', 'Integritas valid');
} catch (Throwable $e) {
    $integrityError = $e->getMessage();
    audit_log('CONTENT_DECRYPT', 'GAGAL mendekripsi konten #' . $id . ' (integritas)');
    crypto_log((int) $admin['id'], $id, 'decrypt', 'AES-256-GCM', 'failure', 'Validasi integritas gagal');
}

$pageTitle = 'Detail Konten';
$layout = 'admin';
$active = 'contents';
require __DIR__ . '/../../includes/header.php';
?>
<div class="panel">
  <div class="panel-head d-flex flex-wrap justify-content-between align-items-center gap-2">
    <h2 class="mb-0"><?= e($row['title']) ?></h2>
    <div class="d-flex gap-2">
      <a href="<?= e(url('admin/contents/edit.php?id=' . $id)) ?>" class="btn btn-sm btn-outline-cyan"><i class="fa-solid fa-pen me-1"></i>Edit</a>
      <a href="<?= e(url('admin/contents/index.php')) ?>" class="btn btn-sm btn-outline-secondary">Kembali</a>
    </div>
  </div>
  <div class="panel-body">
    <div class="meta-grid mb-3">
      <div><small>Kategori</small><span><?= e($row['category_name']) ?></span></div>
      <div><small>Status</small><span><?= status_badge($row['status']) ?></span></div>
      <div><small>Dibuat oleh</small><span><?= e($row['username']) ?></span></div>
      <div><small>Dibuat</small><span><?= e(format_dt($row['created_at'])) ?></span></div>
      <div><small>Diperbarui</small><span><?= e(format_dt($row['updated_at'])) ?></span></div>
      <div><small>Kunci</small><span>AES-256-GCM v<?= (int) $row['key_version'] ?></span></div>
    </div>
    <?php if ($integrityError !== null): ?>
      <div class="alert alert-danger"><i class="fa-solid fa-triangle-exclamation me-2"></i><strong>Validasi integritas gagal.</strong> <?= e($integrityError) ?></div>
    <?php else: ?>
      <div class="alert alert-success py-2"><i class="fa-solid fa-circle-check me-2"></i>Authentication tag valid. Integritas data terverifikasi.</div>
      <div class="content-body"><?= nl2br(e($plain)) ?></div>
    <?php endif; ?>
  </div>
</div>
<?php require __DIR__ . '/../../includes/footer.php'; ?>
