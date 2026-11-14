<?php
declare(strict_types=1);
require_once __DIR__ . '/../includes/auth.php';
$admin = require_admin();
$pdo = db();

$tab    = ($_GET['tab'] ?? 'audit') === 'crypto' ? 'crypto' : 'audit';
$page   = max(1, (int) ($_GET['page'] ?? 1));
$per    = 20;
$offset = ($page - 1) * $per;
$q      = trim((string) ($_GET['q'] ?? ''));
$action = trim((string) ($_GET['action'] ?? ''));

if ($tab === 'audit') {
    $where = [];
    $params = [];
    if ($q !== '') {
        $where[] = '(description LIKE ? OR username_snapshot LIKE ? OR ip_address LIKE ?)';
        $like = '%' . addcslashes($q, '%_\\') . '%';
        array_push($params, $like, $like, $like);
    }
    if ($action !== '') {
        $where[] = 'action = ?';
        $params[] = $action;
    }
    $w = $where ? 'WHERE ' . implode(' AND ', $where) : '';
    $st = $pdo->prepare("SELECT COUNT(*) FROM audit_logs $w");
    $st->execute($params);
    $total = (int) $st->fetchColumn();
    $st = $pdo->prepare("SELECT * FROM audit_logs $w ORDER BY id DESC LIMIT ? OFFSET ?");
    $i = 1;
    foreach ($params as $p) {
        $st->bindValue($i++, $p);
    }
    $st->bindValue($i++, $per, PDO::PARAM_INT);
    $st->bindValue($i, $offset, PDO::PARAM_INT);
    $st->execute();
    $rows = $st->fetchAll();
    $actions = $pdo->query('SELECT DISTINCT action FROM audit_logs ORDER BY action')->fetchAll(PDO::FETCH_COLUMN);
} else {
    $total = (int) $pdo->query('SELECT COUNT(*) FROM crypto_logs')->fetchColumn();
    $st = $pdo->prepare('SELECT cl.*, a.username FROM crypto_logs cl LEFT JOIN admins a ON a.id = cl.admin_id ORDER BY cl.id DESC LIMIT ? OFFSET ?');
    $st->bindValue(1, $per, PDO::PARAM_INT);
    $st->bindValue(2, $offset, PDO::PARAM_INT);
    $st->execute();
    $rows = $st->fetchAll();
    $actions = [];
}

$pageTitle = 'Audit Log';
$layout = 'admin';
$active = 'audit';
require __DIR__ . '/../includes/header.php';
?>
<ul class="nav nav-tabs-sas mb-3">
  <li class="nav-item"><a class="nav-link<?= $tab === 'audit' ? ' active' : '' ?>" href="?tab=audit">Aktivitas Admin</a></li>
  <li class="nav-item"><a class="nav-link<?= $tab === 'crypto' ? ' active' : '' ?>" href="?tab=crypto">Operasi Kriptografi</a></li>
</ul>

<?php if ($tab === 'audit'): ?>
<form method="get" class="filter-bar mb-3">
  <input type="hidden" name="tab" value="audit">
  <input type="search" name="q" class="form-control form-control-sm" placeholder="Cari keterangan / user / IP" value="<?= e($q) ?>">
  <select name="action" class="form-select form-select-sm">
    <option value="">Semua aktivitas</option>
    <?php foreach ($actions as $a): ?><option value="<?= e($a) ?>"<?= $action === $a ? ' selected' : '' ?>><?= e($a) ?></option><?php endforeach; ?>
  </select>
  <button class="btn btn-sm btn-outline-cyan"><i class="fa-solid fa-magnifying-glass"></i></button>
</form>
<?php endif; ?>

<div class="panel">
  <div class="table-responsive">
    <table class="table table-sas align-middle mb-0">
      <?php if ($tab === 'audit'): ?>
      <thead><tr><th>ID</th><th>Admin</th><th>Aktivitas</th><th>Keterangan</th><th>IP Address</th><th>Timestamp</th></tr></thead>
      <tbody>
        <?php if (!$rows): ?><tr><td colspan="6"><div class="empty-state"><i class="fa-regular fa-folder-open"></i><p>Tidak ada log.</p></div></td></tr><?php endif; ?>
        <?php foreach ($rows as $r): ?>
          <tr>
            <td>#<?= (int) $r['id'] ?></td>
            <td><?= e($r['username_snapshot'] ?? '-') ?></td>
            <td><?= action_badge($r['action']) ?></td>
            <td><?= e($r['description'] ?? '') ?></td>
            <td><code><?= e($r['ip_address']) ?></code></td>
            <td class="text-nowrap"><?= e(format_dt($r['created_at'])) ?></td>
          </tr>
        <?php endforeach; ?>
      </tbody>
      <?php else: ?>
      <thead><tr><th>ID</th><th>Admin</th><th>Operasi</th><th>Algoritma</th><th>Status</th><th>Detail</th><th>Timestamp</th></tr></thead>
      <tbody>
        <?php if (!$rows): ?><tr><td colspan="7"><div class="empty-state"><i class="fa-regular fa-folder-open"></i><p>Belum ada operasi kriptografi.</p></div></td></tr><?php endif; ?>
        <?php foreach ($rows as $r): ?>
          <tr>
            <td>#<?= (int) $r['id'] ?></td>
            <td><?= e($r['username'] ?? '-') ?></td>
            <td><span class="badge text-bg-info"><?= e($r['operation']) ?></span><?= $r['content_id'] ? ' <small class="text-muted">konten #' . (int) $r['content_id'] . '</small>' : '' ?></td>
            <td><?= e($r['algorithm']) ?></td>
            <td><?= $r['status'] === 'success' ? '<span class="badge text-bg-success">success</span>' : '<span class="badge text-bg-danger">failure</span>' ?></td>
            <td><?= e($r['detail'] ?? '') ?></td>
            <td class="text-nowrap"><?= e(format_dt($r['created_at'])) ?></td>
          </tr>
        <?php endforeach; ?>
      </tbody>
      <?php endif; ?>
    </table>
  </div>
  <div class="panel-foot d-flex justify-content-between align-items-center">
    <small class="text-muted">Total <?= number_format($total) ?> catatan</small>
    <?= render_pagination($total, $page, $per, ['tab' => $tab, 'q' => $q, 'action' => $action]) ?>
  </div>
</div>
<?php require __DIR__ . '/../includes/footer.php'; ?>
