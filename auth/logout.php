<?php
declare(strict_types=1);
require_once __DIR__ . '/../includes/auth.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    redirect(empty($_SESSION['admin_id']) ? 'auth/login.php' : 'admin/dashboard.php');
}
csrf_require();

if (!empty($_SESSION['admin_id'])) {
    audit_log('LOGOUT', 'Admin logout');
}
destroy_session();
redirect('auth/login.php?reason=logout');
