<?php
/**
 * Layout pembuka. Variabel yang dapat diset sebelum include:
 *   $pageTitle, $layout ('public'|'auth'|'admin'), $active, $admin (untuk layout admin)
 */
$pageTitle = $pageTitle ?? APP_NAME;
$layout    = $layout ?? 'public';
?>
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="csrf-token" content="<?= e(csrf_token()) ?>">
  <meta name="robots" content="<?= $layout === 'public' ? 'index,follow' : 'noindex,nofollow' ?>">
  <title><?= e($pageTitle) ?> | <?= e(APP_NAME) ?></title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
  <link href="<?= e(url('public/css/style.css')) ?>" rel="stylesheet">
</head>
<body class="layout-<?= e($layout) ?>" data-base-url="<?= e(BASE_URL) ?>">
<?php if ($layout === 'public'): ?>
  <?php require __DIR__ . '/navbar.php'; ?>
<?php elseif ($layout === 'admin'): ?>
  <div class="app-shell" id="appShell">
    <?php require __DIR__ . '/sidebar.php'; ?>
    <div class="main-wrapper">
      <header class="topbar">
        <button class="btn btn-icon" id="sidebarToggle" type="button" aria-label="Toggle sidebar"><i class="fa-solid fa-bars"></i></button>
        <h1 class="topbar-title"><?= e($pageTitle) ?></h1>
        <div class="ms-auto d-flex align-items-center gap-3">
          <span class="badge badge-secure d-none d-md-inline-flex"><i class="fa-solid fa-lock me-1"></i> RSA-PSS Session</span>
          <div class="admin-chip">
            <span class="avatar"><?= e(strtoupper(substr($admin['username'] ?? 'A', 0, 1))) ?></span>
            <span class="d-none d-sm-inline"><?= e($admin['full_name'] ?? 'Admin') ?></span>
          </div>
        </div>
      </header>
      <main class="content">
<?php endif; ?>
