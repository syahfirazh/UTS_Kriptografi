/* Perilaku UI umum: sidebar, toast, modal hapus, loading state, toggle password. */
(function () {
  'use strict';
  var $ = function (s, r) { return (r || document).querySelector(s); };

  /* Sidebar collapsible (state disimpan di localStorage, hanya preferensi UI) */
  var shell = $('#appShell');
  var toggle = $('#sidebarToggle');
  if (shell && toggle) {
    try { if (localStorage.getItem('sas_sidebar') === '1') shell.classList.add('collapsed'); } catch (e) {}
    toggle.addEventListener('click', function () {
      if (window.matchMedia('(max-width: 991.98px)').matches) {
        shell.classList.toggle('open');
      } else {
        shell.classList.toggle('collapsed');
        try { localStorage.setItem('sas_sidebar', shell.classList.contains('collapsed') ? '1' : '0'); } catch (e) {}
      }
    });
    document.addEventListener('click', function (ev) {
      if (shell.classList.contains('open') && !ev.target.closest('.sidebar') && !ev.target.closest('#sidebarToggle')) {
        shell.classList.remove('open');
      }
    });
  }

  /* Toast */
  var icons = { success: 'fa-circle-check', danger: 'fa-circle-xmark', warning: 'fa-triangle-exclamation', info: 'fa-circle-info' };
  window.showToast = function (type, message) {
    var box = $('#toastContainer');
    if (!box || !window.bootstrap) return;
    type = icons[type] ? type : 'info';
    var el = document.createElement('div');
    el.className = 'toast align-items-center text-bg-' + type + ' border-0';
    el.setAttribute('role', 'alert');
    var body = document.createElement('div');
    body.className = 'd-flex';
    var msg = document.createElement('div');
    msg.className = 'toast-body';
    var i = document.createElement('i');
    i.className = 'fa-solid ' + icons[type] + ' me-2';
    msg.appendChild(i);
    msg.appendChild(document.createTextNode(message)); // textContent: aman dari XSS
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn-close btn-close-white me-2 m-auto';
    btn.setAttribute('data-bs-dismiss', 'toast');
    body.appendChild(msg);
    body.appendChild(btn);
    el.appendChild(body);
    box.appendChild(el);
    var t = new bootstrap.Toast(el, { delay: 5000 });
    el.addEventListener('hidden.bs.toast', function () { el.remove(); });
    t.show();
  };

  var flashEl = $('#flash-data');
  if (flashEl) {
    try { JSON.parse(flashEl.textContent || '[]').forEach(function (f) { window.showToast(f.type, f.message); }); } catch (e) {}
  }

  /* Data halaman (JSON non-eksekusi) */
  window.getPageData = function () {
    var el = $('#page-data');
    try { return el ? JSON.parse(el.textContent) : {}; } catch (e) { return {}; }
  };
  window.csrfToken = function () {
    var m = $('meta[name="csrf-token"]');
    return m ? m.content : '';
  };
  window.postJson = async function (url, body) {
    var res = await fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': window.csrfToken() },
      body: JSON.stringify(body)
    });
    var data;
    try { data = await res.json(); } catch (e) { throw new Error('Respons server tidak valid (' + res.status + ').'); }
    return { status: res.status, data: data };
  };

  /* Modal hapus bersama */
  var delModal = $('#deleteModal');
  if (delModal) {
    delModal.addEventListener('show.bs.modal', function (ev) {
      var b = ev.relatedTarget;
      if (!b) return;
      $('#deleteForm').action = b.getAttribute('data-delete-action');
      $('#deleteId').value = b.getAttribute('data-delete-id');
      $('#deleteName').textContent = b.getAttribute('data-delete-name');
    });
  }

  /* Loading state pada form */
  document.querySelectorAll('form[data-loading-form]').forEach(function (f) {
    f.addEventListener('submit', function () {
      var btn = f.querySelector('button[type="submit"], button:not([type])');
      if (!btn) return;
      setTimeout(function () {
        btn.disabled = true;
        var l = btn.querySelector('.btn-label'), s = btn.querySelector('.spinner-border');
        if (l) l.classList.add('d-none');
        if (s) s.classList.remove('d-none');
      }, 0);
    });
  });

  /* Tampilkan/sembunyikan passphrase */
  var tp = $('#togglePass');
  if (tp) {
    tp.addEventListener('click', function () {
      var inp = $('#passphrase');
      var show = inp.type === 'password';
      inp.type = show ? 'text' : 'password';
      tp.innerHTML = '<i class="fa-solid ' + (show ? 'fa-eye-slash' : 'fa-eye') + '"></i>';
    });
  }
})();
