/* Alur login RSA: buka private key (lokal) -> minta challenge -> tanda tangan -> verifikasi. */
(function () {
  'use strict';
  var form = document.getElementById('loginForm');
  if (!form) return;
  var errBox = document.getElementById('loginError');
  var btn = document.getElementById('loginBtn');
  var steps = document.querySelectorAll('#authSteps li');

  function setStep(n, state) {
    steps.forEach(function (li) {
      var s = Number(li.getAttribute('data-step'));
      li.className = '';
      var icon = li.querySelector('i');
      if (s < n || (s === n && state === 'done')) { li.classList.add('done'); icon.className = 'fa-solid fa-circle-check'; }
      else if (s === n && state === 'active') { li.classList.add('active'); icon.className = 'fa-solid fa-spinner fa-spin'; }
      else if (s === n && state === 'error') { li.classList.add('error'); icon.className = 'fa-solid fa-circle-xmark'; }
      else { icon.className = 'fa-regular fa-circle'; }
    });
  }
  function fail(msg, step) {
    if (step) setStep(step, 'error');
    errBox.textContent = msg;
    errBox.classList.remove('d-none');
    busy(false);
  }
  function busy(on) {
    btn.disabled = on;
    btn.querySelector('.btn-label').classList.toggle('d-none', on);
    btn.querySelector('.spinner-border').classList.toggle('d-none', !on);
  }

  form.addEventListener('submit', async function (ev) {
    ev.preventDefault();
    errBox.classList.add('d-none');
    var username = document.getElementById('username').value.trim();
    var file = document.getElementById('keyFile').files[0];
    var passphrase = document.getElementById('passphrase').value;

    if (!/^[A-Za-z0-9_.-]{3,50}$/.test(username)) return fail('Username tidak valid.');
    if (!file) return fail('Pilih file private key (.json).');
    if (!passphrase) return fail('Passphrase wajib diisi.');
    if (file.size > 20000) return fail('File kunci tidak valid (terlalu besar).');

    busy(true);
    try {
      // 1. Buka private key secara lokal. Dilakukan SEBELUM meminta challenge agar passphrase salah
      //    tidak menghabiskan challenge atau menambah hitungan percobaan di server.
      setStep(1, 'active');
      var keyFile;
      try { keyFile = JSON.parse(await file.text()); } catch (e) { return fail('File kunci bukan JSON yang valid.', 1); }
      var privateKey;
      try { privateKey = await SASCrypto.importEncryptedPrivateKey(keyFile, passphrase); }
      catch (e) { return fail(e.message, 1); }

      // 2. Minta challenge
      setStep(2, 'active');
      var c = await postJson(form.dataset.challengeUrl, { username: username });
      if (!c.data.ok) return fail(c.data.error || 'Gagal meminta challenge.', 2);

      // 3. Tanda tangan challenge
      setStep(3, 'active');
      var signature = await SASCrypto.sign(privateKey, SASCrypto.loginMessage(username, c.data.challenge));

      // 4. Verifikasi di server
      setStep(4, 'active');
      var v = await postJson(form.dataset.verifyUrl, { username: username, challenge: c.data.challenge, signature: signature });
      if (!v.data.ok) return fail(v.data.error || 'Autentikasi gagal.', 4);

      setStep(4, 'done');
      document.getElementById('passphrase').value = '';
      window.location.href = v.data.redirect;
    } catch (e) {
      fail(e && e.message ? e.message : 'Terjadi kesalahan tak terduga.');
    }
  });
})();
