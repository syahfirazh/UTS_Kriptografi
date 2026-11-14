/* Setup admin pertama: buat kunci RSA di browser, unduh private key terenkripsi, kirim public key. */
(function () {
  'use strict';
  var form = document.getElementById('setupForm');
  if (!form) return;
  var errBox = document.getElementById('setupError');
  var doneBox = document.getElementById('setupDone');
  var btn = document.getElementById('setupBtn');
  var dlBox = document.getElementById('downloadBox');
  var keyFileObj = null, keyFileName = 'sas-private-key.json';
  var endpoint = (window.getPageData() || {}).endpoint;

  function busy(on) {
    btn.disabled = on;
    btn.querySelector('.btn-label').classList.toggle('d-none', on);
    btn.querySelector('.spinner-border').classList.toggle('d-none', !on);
  }
  function fail(m) { errBox.textContent = m; errBox.classList.remove('d-none'); busy(false); }
  var val = function (id) { return document.getElementById(id).value; };

  form.addEventListener('submit', async function (ev) {
    ev.preventDefault();
    errBox.classList.add('d-none');
    var pass = val('passphrase');
    if (pass.length < 12) return fail('Passphrase minimal 12 karakter.');
    if (pass !== val('passphrase2')) return fail('Konfirmasi passphrase tidak sama.');
    if (val('password').length < 12) return fail('Password akun minimal 12 karakter.');
    var username = val('username').trim();

    busy(true);
    try {
      var pair = await SASCrypto.generateKeyPair();
      var pem = await SASCrypto.exportPublicPem(pair.publicKey);
      var fp = await SASCrypto.publicKeyFingerprint(pair.publicKey);
      keyFileObj = await SASCrypto.exportEncryptedPrivateKey(pair.privateKey, pass, { username: username, fingerprint: fp, created: new Date().toISOString() });
      keyFileName = 'sas-private-key-' + username + '.json';

      var r = await postJson(endpoint, {
        setup_token: val('setupToken'), username: username, full_name: val('fullName').trim(),
        email: val('email').trim(), password: val('password'), public_key_pem: pem
      });
      if (!r.data.ok) return fail(r.data.error || 'Setup gagal.');

      SASCrypto.downloadJson(keyFileObj, keyFileName);   // unduh setelah server menerima public key
      form.classList.add('d-none');
      doneBox.textContent = 'Admin terdaftar. Fingerprint: ' + r.data.fingerprint.slice(0, 32) + '… File private key diunduh. Simpan di tempat aman; passphrase tidak dapat dipulihkan.';
      doneBox.classList.remove('d-none');
      dlBox.classList.remove('d-none');
    } catch (e) {
      fail(e && e.message ? e.message : 'Terjadi kesalahan.');
    }
  });

  var again = document.getElementById('btnDownloadAgain');
  if (again) again.addEventListener('click', function () { if (keyFileObj) SASCrypto.downloadJson(keyFileObj, keyFileName); });
})();
