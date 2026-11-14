/* Demonstrasi AES-256-GCM (server) dan RSA-PSS (browser -> server). */
(function () {
  'use strict';
  var endpoint = (window.getPageData() || {}).endpoint;
  var $ = function (id) { return document.getElementById(id); };
  if (!$('btnEncrypt')) return;

  function result(el, ok, html) {
    el.className = 'result-box mt-3 ' + (ok ? 'result-ok' : 'result-bad');
    el.innerHTML = html;               // hanya string statis + nilai yang sudah di-escape lewat esc()
  }
  function esc(s) { var d = document.createElement('div'); d.textContent = String(s); return d.innerHTML; }

  /* ---------- AES ---------- */
  $('btnEncrypt').addEventListener('click', async function () {
    var plain = $('demoPlain').value;
    try {
      var r = await postJson(endpoint, { action: 'encrypt', plaintext: plain });
      if (!r.data.ok) return window.showToast('danger', r.data.error || 'Gagal.');
      $('outCipher').value = r.data.ciphertext_hex;
      $('outNonce').value = r.data.nonce_hex;
      $('outTag').value = r.data.tag_hex;
      $('outB64').value = r.data.ciphertext_b64;
      $('encOut').classList.remove('d-none');
      $('decOut').classList.add('d-none');
      window.showToast('success', 'Terenkripsi: ' + r.data.plaintext_bytes + ' byte -> ' + r.data.ciphertext_bytes + ' byte ciphertext.');
    } catch (e) { window.showToast('danger', e.message); }
  });

  $('btnDecrypt').addEventListener('click', async function () {
    var out = $('decOut');
    out.classList.remove('d-none');
    try {
      var r = await postJson(endpoint, { action: 'decrypt', ciphertext_hex: $('outCipher').value.trim(), nonce_hex: $('outNonce').value.trim(), tag_hex: $('outTag').value.trim() });
      if (r.data.ok) {
        result(out, true, '<strong><i class="fa-solid fa-circle-check me-1"></i>Integritas valid.</strong><div class="mt-1">Plaintext: <code>' + esc(r.data.plaintext) + '</code></div>');
      } else {
        result(out, false, '<strong><i class="fa-solid fa-triangle-exclamation me-1"></i>Integritas TIDAK valid.</strong><div class="mt-1">' + esc(r.data.error || 'Gagal.') + '</div>');
      }
    } catch (e) { result(out, false, esc(e.message)); }
  });

  $('btnTamper').addEventListener('click', function () {
    var c = $('outCipher').value;
    if (!c) return;
    var ch = c.charAt(0) === '0' ? '1' : '0';
    $('outCipher').value = ch + c.slice(1);
    window.showToast('warning', 'Karakter pertama ciphertext diubah. Klik Decrypt untuk melihat deteksi manipulasi.');
  });

  /* ---------- RSA-PSS ---------- */
  var rsa = { publicPem: null, signature: null, message: null };
  $('btnSign').addEventListener('click', async function () {
    var btn = this;
    btn.disabled = true;
    try {
      var msg = $('rsaMsg').value;
      if (!msg) { window.showToast('warning', 'Pesan tidak boleh kosong.'); return; }
      var pair = await SASCrypto.generateKeyPair();
      rsa.publicPem = await SASCrypto.exportPublicPem(pair.publicKey);
      rsa.signature = await SASCrypto.sign(pair.privateKey, msg);   // kunci sementara, tidak disimpan
      rsa.message = msg;
      $('rsaPub').value = rsa.publicPem;
      $('rsaSig').value = rsa.signature;
      $('rsaOut').classList.remove('d-none');
      $('rsaResult').classList.add('d-none');
    } catch (e) { window.showToast('danger', e.message); }
    finally { btn.disabled = false; }
  });

  $('btnRsaVerify').addEventListener('click', async function () {
    var out = $('rsaResult');
    out.classList.remove('d-none');
    var message = rsa.message + ($('rsaTamper').checked ? ' (dimanipulasi)' : '');
    try {
      var r = await postJson(endpoint, { action: 'rsa_verify', public_key_pem: rsa.publicPem, message: message, signature: rsa.signature });
      if (!r.data.ok) return result(out, false, esc(r.data.error || 'Gagal.'));
      var info = '<div class="mt-1 small">RSA ' + esc(r.data.bits) + '-bit &middot; fingerprint ' + esc((r.data.fingerprint || '').slice(0, 16)) + '…</div>';
      if (r.data.valid) result(out, true, '<strong><i class="fa-solid fa-circle-check me-1"></i>Signature VALID</strong>' + info);
      else result(out, false, '<strong><i class="fa-solid fa-circle-xmark me-1"></i>Signature INVALID</strong>' + info);
    } catch (e) { result(out, false, esc(e.message)); }
  });
})();
