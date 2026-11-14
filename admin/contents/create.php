<?php
declare(strict_types=1);
require_once __DIR__ . '/../../includes/auth.php';
$admin = require_admin();
$pdo = db();

$categories = $pdo->query('SELECT id, name FROM categories ORDER BY name')->fetchAll();
$values = ['title' => '', 'category_id' => 0, 'status' => 'draft', 'body' => ''];
$errors = [];

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
            $pdo->beginTransaction();
            // Sisipkan baris dulu agar ID tersedia sebagai bagian dari AAD
            $ins = $pdo->prepare("INSERT INTO contents (category_id, created_by, title, status, ciphertext, nonce, auth_tag, key_version) VALUES (?, ?, ?, ?, '', ?, ?, 1)");
            $ins->bindValue(1, $values['category_id'], PDO::PARAM_INT);
            $ins->bindValue(2, (int) $admin['id'], PDO::PARAM_INT);
            $ins->bindValue(3, $values['title']);
            $ins->bindValue(4, $values['status']);
            $ins->bindValue(5, str_repeat("\0", 12), PDO::PARAM_LOB);
            $ins->bindValue(6, str_repeat("\0", 16), PDO::PARAM_LOB);
            $ins->execute();
            $id = (int) $pdo->lastInsertId();

            $enc = content_encrypt($values['body'], $id);
            $upd = $pdo->prepare('UPDATE contents SET ciphertext = ?, nonce = ?, auth_tag = ?, key_version = ? WHERE id = ?');
            $upd->bindValue(1, $enc['ciphertext'], PDO::PARAM_LOB);
            $upd->bindValue(2, $enc['nonce'], PDO::PARAM_LOB);
            $upd->bindValue(3, $enc['tag'], PDO::PARAM_LOB);
            $upd->bindValue(4, $enc['key_version'], PDO::PARAM_INT);
            $upd->bindValue(5, $id, PDO::PARAM_INT);
            $upd->execute();
            $pdo->commit();

            audit_log('CONTENT_CREATE', 'Konten #' . $id . ' dibuat');
            audit_log('CONTENT_ENCRYPT', 'Konten #' . $id . ' dienkripsi AES-256-GCM (key v' . $enc['key_version'] . ')');
            crypto_log((int) $admin['id'], $id, 'encrypt', 'AES-256-GCM', 'success', 'Panjang plaintext ' . strlen($values['body']) . ' byte');
            flash('success', 'Konten berhasil disimpan dan dienkripsi.');
            redirect('admin/contents/index.php');
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            error_log('create content: ' . $e->getMessage());
            $errors[] = 'Gagal menyimpan konten. ' . (str_contains($e->getMessage(), 'Master key') ? $e->getMessage() : 'Periksa log server.');
        }
    }
}

$pageTitle = 'Tambah Konten';
$layout = 'admin';
$active = 'contents';
$formAction = url('admin/contents/create.php');
$submitLabel = 'Simpan & Enkripsi';
require __DIR__ . '/../../includes/header.php';
require __DIR__ . '/_form.php';
require __DIR__ . '/../../includes/footer.php';
