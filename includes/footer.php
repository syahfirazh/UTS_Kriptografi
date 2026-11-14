<?php
/** Layout penutup. Variabel opsional: $extraJs (array path relatif), $pageData (array -> JSON). */
$layout  = $layout ?? 'public';
$extraJs = $extraJs ?? [];
$flashes = consume_flashes();
$jsonFlags = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE;
?>
<?php if ($layout === 'admin'): ?>
      </main>
      <footer class="content-footer">
        <span>&copy; <?= date('Y') ?> <?= e(APP_NAME) ?> &middot; AES-256-GCM &amp; RSA-PSS</span>
      </footer>
    </div>
  </div>

  <!-- Modal konfirmasi hapus (dipakai bersama) -->
  <div class="modal fade" id="deleteModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
      <form class="modal-content" method="post" id="deleteForm" action="">
        <?= csrf_field() ?>
        <input type="hidden" name="id" id="deleteId" value="">
        <div class="modal-header">
          <h5 class="modal-title"><i class="fa-solid fa-triangle-exclamation text-danger me-2"></i>Konfirmasi Hapus</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Tutup"></button>
        </div>
        <div class="modal-body">Anda yakin ingin menghapus <strong id="deleteName"></strong>? Tindakan ini tidak dapat dibatalkan.</div>
        <div class="modal-footer">
          <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Batal</button>
          <button type="submit" class="btn btn-danger"><i class="fa-solid fa-trash me-1"></i>Hapus</button>
        </div>
      </form>
    </div>
  </div>
<?php endif; ?>

<?php if ($layout !== 'public'): ?>
  <div class="toast-container position-fixed top-0 end-0 p-3" id="toastContainer"></div>
<?php endif; ?>
<?php if ($layout === 'public'): ?>
  <div class="toast-container position-fixed top-0 end-0 p-3" id="toastContainer"></div>
<?php endif; ?>

<script type="application/json" id="flash-data"><?= json_encode($flashes, $jsonFlags) ?></script>
<?php if (isset($pageData)): ?>
<script type="application/json" id="page-data"><?= json_encode($pageData, $jsonFlags) ?></script>
<?php endif; ?>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="<?= e(url('public/js/app.js')) ?>"></script>
<?php foreach ($extraJs as $js): ?>
<script src="<?= e(url($js)) ?>"></script>
<?php endforeach; ?>
</body>
</html>
