<?php
declare(strict_types=1);
require_once __DIR__ . '/../../includes/auth.php';
$admin = require_admin();
$pdo = db();

$id = (int) ($_GET['id'] ?? 0);
$st = $pdo->prepare('SELECT * FROM categories WHERE id = ?');
$st->execute([$id]);
$cat = $st->fetch();
if (!$cat) {
    flash('danger', 'Kategori tidak ditemukan.');
    redirect('admin/categories/index.php');
}
$errors = [];
$name = $cat['name'];
$desc = (string) $cat['description'];

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
        $dup = $pdo->prepare('SELECT COUNT(*) FROM categories WHERE (name = ? OR slug = ?) AND id <> ?');
        $dup->execute([$name, $slug, $id]);
        if ((int) $dup->fetchColumn() > 0) {
            $errors[] = 'Kategori dengan nama tersebut sudah ada.';
        } else {
            $pdo->prepare('UPDATE categories SET name = ?, slug = ?, description = ? WHERE id = ?')->execute([$name, $slug, $desc !== '' ? $desc : null, $id]);
            audit_log('CATEGORY_UPDATE', 'Kategori #' . $id . ' diperbarui');
            flash('success', 'Kategori diperbarui.');
            redirect('admin/categories/index.php');
        }
    }
}

$pageTitle = 'Edit Kategori';
$layout = 'admin';
$active = 'categories';
require __DIR__ . '/../../includes/header.php';
?>
<form method="post" class="panel" style="max-width:620px" novalidate data-loading-form>
  <?= csrf_field() ?>
  <div class="panel-body">
    <?php if ($errors): ?><div class="alert alert-danger"><ul class="mb-0 ps-3"><?php foreach ($errors as $er): ?><li><?= e($er) ?></li><?php endforeach; ?></ul></div><?php endif; ?>
    <div class="mb-3"><label class="form-label" for="name">Nama</label><input class="form-control" id="name" name="name" maxlength="80" required value="<?= e($name) ?>"></div>
    <div class="mb-3"><label class="form-label" for="description">Deskripsi</label><textarea class="form-control" id="description" name="description" rows="3" maxlength="255"><?= e($desc) ?></textarea></div>
  </div>
  <div class="panel-foot d-flex gap-2">
    <button class="btn btn-cyan"><span class="btn-label"><i class="fa-solid fa-floppy-disk me-1"></i>Simpan</span><span class="spinner-border spinner-border-sm d-none"></span></button>
    <a class="btn btn-outline-secondary" href="<?= e(url('admin/categories/index.php')) ?>">Batal</a>
  </div>
</form>
<?php require __DIR__ . '/../../includes/footer.php'; ?>
