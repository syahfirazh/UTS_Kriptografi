<?php
/** Partial form konten. Variabel: $values, $errors, $categories, $formAction, $submitLabel */
$statuses = ['draft' => 'Draft', 'published' => 'Published', 'archived' => 'Archived'];
?>
<form method="post" action="<?= e($formAction) ?>" class="panel" novalidate data-loading-form>
  <?= csrf_field() ?>
  <div class="panel-body">
    <?php if (!empty($errors)): ?>
      <div class="alert alert-danger"><ul class="mb-0 ps-3"><?php foreach ($errors as $err): ?><li><?= e($err) ?></li><?php endforeach; ?></ul></div>
    <?php endif; ?>
    <div class="row g-3">
      <div class="col-12">
        <label class="form-label" for="title">Judul <small class="text-muted">(tidak terenkripsi, dipakai untuk pencarian)</small></label>
        <input type="text" class="form-control" id="title" name="title" maxlength="200" required value="<?= e($values['title']) ?>">
      </div>
      <div class="col-md-6">
        <label class="form-label" for="category_id">Kategori</label>
        <select class="form-select" id="category_id" name="category_id" required>
          <option value="">- pilih kategori -</option>
          <?php foreach ($categories as $c): ?>
            <option value="<?= (int) $c['id'] ?>"<?= (int) $values['category_id'] === (int) $c['id'] ? ' selected' : '' ?>><?= e($c['name']) ?></option>
          <?php endforeach; ?>
        </select>
      </div>
      <div class="col-md-6">
        <label class="form-label" for="status">Status</label>
        <select class="form-select" id="status" name="status">
          <?php foreach ($statuses as $k => $label): ?>
            <option value="<?= e($k) ?>"<?= $values['status'] === $k ? ' selected' : '' ?>><?= e($label) ?></option>
          <?php endforeach; ?>
        </select>
      </div>
      <div class="col-12">
        <label class="form-label" for="body">Isi Konten <span class="badge badge-secure ms-1"><i class="fa-solid fa-lock me-1"></i>dienkripsi AES-256-GCM</span></label>
        <textarea class="form-control" id="body" name="body" rows="10" maxlength="100000" required><?= e($values['body']) ?></textarea>
      </div>
    </div>
  </div>
  <div class="panel-foot d-flex gap-2">
    <button type="submit" class="btn btn-cyan"><span class="btn-label"><i class="fa-solid fa-floppy-disk me-1"></i><?= e($submitLabel) ?></span><span class="spinner-border spinner-border-sm d-none"></span></button>
    <a href="<?= e(url('admin/contents/index.php')) ?>" class="btn btn-outline-secondary">Batal</a>
  </div>
</form>
