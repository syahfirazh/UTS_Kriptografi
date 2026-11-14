<?php
declare(strict_types=1);
require_once __DIR__ . '/../../includes/auth.php';
$admin = require_admin();
$pdo = db();
$errors = [];
$name = '';
$desc = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_require();
    $name = trim((string) ($_POST['name'] ?? ''));
    $desc = trim((string) ($_POST['description'] ?? ''));
    if (mb_strlen($name) < 2 || mb_strlen($name) > 80) {
        $errors[] = 'Nama kategori harus 2-80 karakter.';
    }
    if (mb_strlen($desc) > 255) {
        $errors[] = 'Deskripsi maksimal 255 karakter.';
    }
    if (!$errors) {
        $slug = slugify($name);
        $dup = $pdo->prepare('SELECT COUNT(*) FROM categories WHERE name = ? OR slug = ?');
        $dup->execute([$name, $slug]);
        if ((int) $dup->fetchColumn() > 0) {
            $errors[] = 'Kategori dengan nama tersebut sudah ada.';
        } else {
            $pdo->prepare('INSERT INTO categories (name, slug, description) VALUES (?, ?, ?)')->execute([$name, $slug, $desc !== '' ? $desc : null]);
            audit_log('CATEGORY_CREATE', 'Kategori dibuat: ' . $name);
            flash('success', 'Kategori ditambahkan.');
            redirect('admin/categories/index.php');
        }
    }
}

$rows = $pdo->query('SELECT cat.*, (SELECT COUNT(*) FROM contents c WHERE c.category_id = cat.id) AS total FROM categories cat ORDER BY cat.name')->fetchAll();

$pageTitle = 'Kategori Konten';
$layout = 'admin';
$active = 'categories';
require __DIR__ . '/../../includes/header.php';
?>
<div class="row g-3">
  <div class="col-lg-4">
    <form method="post" class="panel" novalidate data-loading-form>
      <?= csrf_field() ?>
      <div class="panel-head"><h2>Tambah Kategori</h2></div>
      <div class="panel-body">
        <?php if ($errors): ?><div class="alert alert-danger"><ul class="mb-0 ps-3"><?php foreach ($errors as $er): ?><li><?= e($er) ?></li><?php endforeach; ?></ul></div><?php endif; ?>
        <div class="mb-3"><label class="form-label" for="name">Nama</label><input class="form-control" id="name" name="name" maxlength="80" required value="<?= e($name) ?>"></div>
        <div class="mb-3"><label class="form-label" for="description">Deskripsi</label><textarea class="form-control" id="description" name="description" rows="3" maxlength="255"><?= e($desc) ?></textarea></div>
        <button class="btn btn-cyan w-100"><span class="btn-label"><i class="fa-solid fa-plus me-1"></i>Tambah</span><span class="spinner-border spinner-border-sm d-none"></span></button>
      </div>
    </form>
  </div>
  <div class="col-lg-8">
    <div class="panel">
      <div class="table-responsive">
        <table class="table table-sas align-middle mb-0">
          <thead><tr><th>Nama</th><th>Deskripsi</th><th>Konten</th><th class="text-end">Aksi</th></tr></thead>
          <tbody>
          <?php if (!$rows): ?><tr><td colspan="4"><div class="empty-state"><i class="fa-regular fa-folder-open"></i><p>Belum ada kategori.</p></div></td></tr><?php endif; ?>
          <?php foreach ($rows as $r): ?>
            <tr>
              <td class="fw-medium"><?= e($r['name']) ?><br><small class="text-muted"><?= e($r['slug']) ?></small></td>
              <td class="text-truncate-cell"><?= e($r['description'] ?? '') ?></td>
              <td><span class="badge text-bg-secondary"><?= (int) $r['total'] ?></span></td>
              <td class="text-end text-nowrap">
                <a href="<?= e(url('admin/categories/edit.php?id=' . (int) $r['id'])) ?>" class="btn btn-icon btn-sm" title="Edit"><i class="fa-solid fa-pen"></i></a>
                <button type="button" class="btn btn-icon btn-sm text-danger" title="Hapus" data-bs-toggle="modal" data-bs-target="#deleteModal"
                        data-delete-action="<?= e(url('admin/categories/delete.php')) ?>" data-delete-id="<?= (int) $r['id'] ?>" data-delete-name="<?= e($r['name']) ?>"><i class="fa-solid fa-trash"></i></button>
              </td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div>
<?php require __DIR__ . '/../../includes/footer.php'; ?>
