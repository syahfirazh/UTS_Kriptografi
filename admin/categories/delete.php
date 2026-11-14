<?php
declare(strict_types=1);
require_once __DIR__ . '/../../includes/auth.php';
$admin = require_admin();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    redirect('admin/categories/index.php');
}
csrf_require();

$id = (int) ($_POST['id'] ?? 0);
$pdo = db();
$st = $pdo->prepare('SELECT name, (SELECT COUNT(*) FROM contents WHERE category_id = categories.id) AS total FROM categories WHERE id = ?');
$st->execute([$id]);
$cat = $st->fetch();
if (!$cat) {
    flash('danger', 'Kategori tidak ditemukan.');
} elseif ((int) $cat['total'] > 0) {
    flash('danger', 'Kategori tidak dapat dihapus karena masih dipakai oleh ' . (int) $cat['total'] . ' konten.');
} else {
    $pdo->prepare('DELETE FROM categories WHERE id = ?')->execute([$id]);
    audit_log('CATEGORY_DELETE', 'Kategori dihapus: ' . $cat['name']);
    flash('success', 'Kategori dihapus.');
}
redirect('admin/categories/index.php');
