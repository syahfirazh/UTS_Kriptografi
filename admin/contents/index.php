<?php
declare(strict_types=1);
require_once __DIR__ . '/../../includes/auth.php';
$admin = require_admin();
$pdo = db();

$q      = trim((string) ($_GET['q'] ?? ''));
$cat    = (int) ($_GET['category'] ?? 0);
$status = (string) ($_GET['status'] ?? '');
$page   = max(1, (int) ($_GET['page'] ?? 1));
$per    = 10;

$where = [];
$params = [];
if ($q !== '') {
    $where[] = 'c.title LIKE ?';
    $params[] = '%' . addcslashes($q, '%_\\') . '%';
}
if ($cat > 0) {
    $where[] = 'c.category_id = ?';
    $params[] = $cat;
}
if (in_array($status, ['draft', 'published', 'archived'], true)) {
    $where[] = 'c.status = ?';
    $params[] = $status;
}
$whereSql = $where ? 'WHERE ' . implode(' AND ', $where) : '';

$st = $pdo->prepare("SELECT COUNT(*) FROM contents c $whereSql");
$st->execute($params);
$total = (int) $st->fetchColumn();
$offset = ($page - 1) * $per;

$st = $pdo->prepare(
    "SELECT c.id, c.title, c.status, c.key_version, c.created_at, c.updated_at, cat.name AS category_name, a.username
     FROM contents c
     JOIN categories cat ON cat.id = c.category_id
     JOIN admins a ON a.id = c.created_by
     $whereSql ORDER BY c.id DESC LIMIT ? OFFSET ?"
);
$i = 1;
foreach ($params as $p) {
    $st->bindValue($i++, $p);
}
$st->bindValue($i++, $per, PDO::PARAM_INT);
$st->bindValue($i, $offset, PDO::PARAM_INT);
$st->execute();
$rows = $st->fetchAll();
$categories = $pdo->query('SELECT id, name FROM categories ORDER BY name')->fetchAll();

$pageTitle = 'Manajemen Konten';
$layout = 'admin';
$active = 'contents';
require __DIR__ . '/../../includes/header.php';
?>
<div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-3">
  <form class="filter-bar" method="get">
    <input type="search" name="q" class="form-control form-control-sm" placeholder="Cari judul…" value="<?= e($q) ?>">
    <select name="category" class="form-select form-select-sm">
      <option value="0">Semua kategori</option>
      <?php foreach ($categories as $c): ?>
        <option value="<?= (int) $c['id'] ?>"<?= $cat === (int) $c['id'] ? ' selected' : '' ?>><?= e($c['name']) ?></option>
      <?php endforeach; ?>
    </select>
    <select name="status" class="form-select form-select-sm">
      <option value="">Semua status</option>
      <?php foreach (['draft', 'published', 'archived'] as $s): ?>
        <option value="<?= $s ?>"<?= $status === $s ? ' selected' : '' ?>><?= ucfirst($s) ?></option>
      <?php endforeach; ?>
    </select>
    <button class="btn btn-sm btn-outline-cyan"><i class="fa-solid fa-magnifying-glass"></i></button>
  </form>
  <a href="<?= e(url('admin/contents/create.php')) ?>" class="btn btn-cyan btn-sm"><i class="fa-solid fa-plus me-1"></i>Tambah Konten</a>
</div>

<div class="panel">
  <div class="table-responsive">
    <table class="table table-sas align-middle mb-0">
      <thead><tr><th>ID</th><th>Judul</th><th>Kategori</th><th>Status</th><th>Enkripsi</th><th>Diperbarui</th><th class="text-end">Aksi</th></tr></thead>
      <tbody>
      <?php if (!$rows): ?>
        <tr><td colspan="7"><div class="empty-state"><i class="fa-regular fa-folder-open"></i><p>Tidak ada konten ditemukan.</p></div></td></tr>
      <?php endif; ?>
      <?php foreach ($rows as $r): ?>
        <tr>
          <td>#<?= (int) $r['id'] ?></td>
          <td class="fw-medium"><?= e($r['title']) ?></td>
          <td><?= e($r['category_name']) ?></td>
          <td><?= status_badge($r['status']) ?></td>
          <td><span class="badge badge-secure"><i class="fa-solid fa-lock me-1"></i>AES-GCM v<?= (int) $r['key_version'] ?></span></td>
          <td class="text-nowrap"><?= e(format_dt($r['updated_at'])) ?></td>
          <td class="text-end text-nowrap">
            <a href="<?= e(url('admin/contents/view.php?id=' . (int) $r['id'])) ?>" class="btn btn-icon btn-sm" title="Lihat"><i class="fa-solid fa-eye"></i></a>
            <a href="<?= e(url('admin/contents/edit.php?id=' . (int) $r['id'])) ?>" class="btn btn-icon btn-sm" title="Edit"><i class="fa-solid fa-pen"></i></a>
            <button type="button" class="btn btn-icon btn-sm text-danger" title="Hapus" data-bs-toggle="modal" data-bs-target="#deleteModal"
                    data-delete-action="<?= e(url('admin/contents/delete.php')) ?>" data-delete-id="<?= (int) $r['id'] ?>" data-delete-name="<?= e($r['title']) ?>"><i class="fa-solid fa-trash"></i></button>
          </td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>
  <div class="panel-foot d-flex justify-content-between align-items-center">
    <small class="text-muted">Total <?= number_format($total) ?> konten</small>
    <?= render_pagination($total, $page, $per, ['q' => $q, 'category' => $cat, 'status' => $status]) ?>
  </div>
</div>
<?php require __DIR__ . '/../../includes/footer.php'; ?>
