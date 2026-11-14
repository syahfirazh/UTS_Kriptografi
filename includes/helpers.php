<?php
declare(strict_types=1);

/** Helper tampilan: pagination, badge, format tanggal. */

function format_dt(?string $dt): string
{
    if (!$dt) {
        return '-';
    }
    $ts = strtotime($dt);
    return $ts ? date('d M Y, H:i', $ts) : e($dt);
}

function status_badge(string $status): string
{
    $map = [
        'draft'     => ['secondary', 'Draft'],
        'published' => ['success', 'Published'],
        'archived'  => ['warning', 'Archived'],
    ];
    [$cls, $label] = $map[$status] ?? ['secondary', $status];
    return '<span class="badge text-bg-' . $cls . '">' . e($label) . '</span>';
}

function action_badge(string $action): string
{
    $cls = 'info';
    if (str_contains($action, 'FAILED') || str_contains($action, 'DELETE')) {
        $cls = 'danger';
    } elseif (str_contains($action, 'SUCCESS') || str_contains($action, 'CREATE')) {
        $cls = 'success';
    } elseif (str_contains($action, 'SETTINGS') || str_contains($action, 'UPDATE')) {
        $cls = 'warning';
    }
    return '<span class="badge text-bg-' . $cls . '">' . e($action) . '</span>';
}

/** Render pagination Bootstrap. $query = parameter GET yang dipertahankan. */
function render_pagination(int $total, int $page, int $perPage, array $query = []): string
{
    $pages = (int) ceil($total / max(1, $perPage));
    if ($pages <= 1) {
        return '';
    }
    unset($query['page']);
    $link = function (int $p, string $label, bool $disabled = false, bool $active = false) use ($query): string {
        $href = '?' . http_build_query($query + ['page' => $p]);
        $cls = 'page-item' . ($disabled ? ' disabled' : '') . ($active ? ' active' : '');
        return '<li class="' . $cls . '"><a class="page-link" href="' . e($href) . '">' . $label . '</a></li>';
    };
    $html = '<nav aria-label="Pagination"><ul class="pagination pagination-sm mb-0">';
    $html .= $link(max(1, $page - 1), '&laquo;', $page <= 1);
    $start = max(1, $page - 2);
    $end = min($pages, $page + 2);
    for ($i = $start; $i <= $end; $i++) {
        $html .= $link($i, (string) $i, false, $i === $page);
    }
    $html .= $link(min($pages, $page + 1), '&raquo;', $page >= $pages);
    return $html . '</ul></nav>';
}

function slugify(string $text): string
{
    $text = strtolower(trim($text));
    $text = preg_replace('/[^a-z0-9]+/', '-', $text) ?? '';
    $text = trim($text, '-');
    return $text !== '' ? substr($text, 0, 100) : 'kategori';
}
