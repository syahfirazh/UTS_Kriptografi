<?php
declare(strict_types=1);
require_once __DIR__ . '/../../includes/auth.php';
$admin = require_admin();
$pdo = db();

$id = (int) ($_GET['id'] ?? 0);
$st = $pdo->prepare('SELECT * FROM contents WHERE id = ? LIMIT 1');
$st->execute([$id]);
$row = $st->fetch();
if (!$row) {
    flash('danger', 'Konten tidak ditemukan.');
    redirect('admin/contents/index.php');
}

$categories = $pdo->query('SELECT id, name FROM categories ORDER BY name')->fetchAll();
$errors = [];
$values = ['title' => $row['title'], 'category_id' => (int) $row['category_id'], 'status' => $row['status'], 'body' => ''];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_require();
    $values = [
        'title'       => trim((string) ($_POST['title'] ?? '')),
        'category_id' => (int) ($_POST['category_id'] ?? 0),
        'status'      => (string) ($_POST['status'] ?? 'draft'),
        'body'        => str_replace("\r\n", "\n", (string) ($_POST['body'] ?? '')),
    ];
    $len = mb_strlen($values['title']);
    if ($len < 3 || $len > 200) {
        $errors[] = 'Judul harus 3-200 karakter.';
    }
    $chk = $pdo->prepare('SELECT COUNT(*) FROM categories WHERE id = ?');
    $chk->execute([$values['category_id']]);
    if ((int) $chk->fetchColumn() !== 1) {
        $errors[] = 'Kategori tidak valid.';
    }
    if (!in_array($values['status'], ['draft', 'published', 'archived'], true)) {
        $errors[] = 'Status tidak valid.';
    }
    if (trim($values['body']) === '' || mb_strlen($values['body']) > 100000) {
        $errors[] = 'Isi konten wajib diisi (maksimal 100.000 karakter).';
    }
    if (!$errors) {
        try {
            // Nonce baru pada setiap enkripsi ulang (nonce tidak boleh dipakai ulang dengan kunci yang sama)
            $enc = content_encrypt($values['body'], $id);
            $upd = $pdo->prepare('UPDATE contents SET category_id = ?, title = ?, status = ?, ciphertext = ?, nonce = ?, auth_tag = ?, key_version = ? WHERE id = ?');
            $upd->bindValue(1, $values['category_id'], PDO::PARAM_INT);
            $upd->bindValue(2, $values['title']);
            $upd->bindValue(3, $values['status']);
            $upd->bindValue(4, $enc['ciphertext'], PDO::PARAM_LOB);
            $upd->bindValue(5, $enc['nonce'], PDO::PARAM_LOB);
            $upd->bindValue(6, $enc['tag'], PDO::PARAM_LOB);
            $upd->bindValue(7, $enc['key_version'], PDO::PARAM_INT);
            $upd->bindValue(8, $id, PDO::PARAM_INT);
            $upd->execute();
            audit_log('CONTENT_UPDATE', 'Konten #' . $id . ' diperbarui');
            audit_log('CONTENT_ENCRYPT', 'Konten #' . $id . ' dienkripsi ulang AES-256-GCM (key v' . $enc['key_version'] . ')');
            crypto_log((int) $admin['id'], $id, 'encrypt', 'AES-256-GCM', 'success', 'Enkripsi ulang saat edit');
            flash('success', 'Konten berhasil diperbarui.');
            redirect('admin/contents/index.php');
        } catch (Throwable $e) {
            error_log('edit content: ' . $e->getMessage());
            $errors[] = 'Gagal menyimpan perubahan. Periksa log server.';
        }
    }
} else {
    // GET: dekripsi + validasi integritas sebelum ditampilkan di form
    try {
        $values['body'] = content_decrypt($row);
        audit_log('CONTENT_DECRYPT', 'Konten #' . $id . ' didekripsi untuk edit');
        crypto_log((int) $admin['id'], $id, 'decrypt', 'AES-256-GCM', 'success', 'Dekripsi untuk edit');
    } catch (Throwable $e) {
        crypto_log((int) $admin['id'], $id, 'decrypt', 'AES-256-GCM', 'failure', 'Integritas/kunci gagal');
        audit_log('CONTENT_DECRYPT', 'GAGAL mendekripsi konten #' . $id . ' (integritas)');
        flash('danger', 'Konten tidak dapat didekripsi: ' . $e->getMessage());
        redirect('admin/contents/index.php');
    }
}

$pageTitle = 'Edit Konten #' . $id;
$layout = 'admin';
$active = 'contents';
$formAction = url('admin/contents/edit.php?id=' . $id);
$submitLabel = 'Perbarui & Enkripsi Ulang';
require __DIR__ . '/../../includes/header.php';
require __DIR__ . '/_form.php';
require __DIR__ . '/../../includes/footer.php';
