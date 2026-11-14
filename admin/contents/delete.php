<?php
declare(strict_types=1);
require_once __DIR__ . '/../../includes/auth.php';
$admin = require_admin();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    redirect('admin/contents/index.php');
}
csrf_require();

$id = (int) ($_POST['id'] ?? 0);
$pdo = db();
$st = $pdo->prepare('SELECT title FROM contents WHERE id = ?');
$st->execute([$id]);
$title = $st->fetchColumn();
if ($title === false) {
    flash('danger', 'Konten tidak ditemukan.');
    redirect('admin/contents/index.php');
}
$pdo->prepare('DELETE FROM contents WHERE id = ?')->execute([$id]);
audit_log('CONTENT_DELETE', 'Konten #' . $id . ' dihapus (judul: ' . mb_substr((string) $title, 0, 80) . ')');
flash('success', 'Konten berhasil dihapus.');
redirect('admin/contents/index.php');
