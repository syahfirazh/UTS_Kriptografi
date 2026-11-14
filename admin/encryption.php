<?php
declare(strict_types=1);
require_once __DIR__ . '/../includes/auth.php';
$admin = require_admin();

/* ---------- Endpoint AJAX demonstrasi ---------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_require();
    $in = read_json();
    $action = (string) ($in['action'] ?? '');
    $adminId = (int) $admin['id'];
    $demoAad = 'SAS|demo|v1';

    $demoKey = null;
    if (in_array($action, ['encrypt', 'decrypt'], true)) {
        try {
            $demoKey = derive_key(load_master_key(), 'SAS-DEMO-v1'); // sub-key khusus demo; master key tidak dipakai langsung
        } catch (Throwable $e) {
            json_response(500, ['ok' => false, 'error' => $e->getMessage()]);
        }
    }

    if ($action === 'encrypt') {
        $plain = (string) ($in['plaintext'] ?? '');
        if ($plain === '' || strlen($plain) > 5000) {
            json_response(422, ['ok' => false, 'error' => 'Plaintext wajib diisi (maksimal 5000 byte).']);
        }
        $r = aes_encrypt($plain, $demoKey, $demoAad);
        crypto_log($adminId, null, 'demo_encrypt', 'AES-256-GCM', 'success', 'Demo, ' . strlen($plain) . ' byte');
        json_response(200, ['ok' => true,
            'algorithm' => 'AES-256-GCM', 'key_bits' => 256, 'nonce_bits' => 96, 'tag_bits' => 128,
            'nonce_hex' => bin2hex($r['nonce']), 'tag_hex' => bin2hex($r['tag']),
            'ciphertext_hex' => bin2hex($r['ciphertext']), 'ciphertext_b64' => base64_encode($r['ciphertext']),
            'plaintext_bytes' => strlen($plain), 'ciphertext_bytes' => strlen($r['ciphertext'])]);
    }

    if ($action === 'decrypt') {
        $ct = (string) ($in['ciphertext_hex'] ?? '');
        $nonce = (string) ($in['nonce_hex'] ?? '');
        $tag = (string) ($in['tag_hex'] ?? '');
        foreach ([$ct, $nonce, $tag] as $h) {
            if ($h === '' || strlen($h) % 2 !== 0 || !ctype_xdigit($h) || strlen($h) > 12000) {
                json_response(422, ['ok' => false, 'error' => 'Input harus berupa hex yang valid.']);
            }
        }
        try {
            $plain = aes_decrypt(hex2bin($ct), $demoKey, hex2bin($nonce), hex2bin($tag), $demoAad);
            crypto_log($adminId, null, 'demo_decrypt', 'AES-256-GCM', 'success', 'Integritas valid');
            json_response(200, ['ok' => true, 'plaintext' => $plain, 'integrity' => 'valid']);
        } catch (Throwable $e) {
            crypto_log($adminId, null, 'demo_decrypt', 'AES-256-GCM', 'failure', 'Validasi integritas gagal');
            json_response(200, ['ok' => false, 'integrity' => 'invalid', 'error' => $e->getMessage()]);
        }
    }

    if ($action === 'rsa_verify') {
        $pem = (string) ($in['public_key_pem'] ?? '');
        $msg = (string) ($in['message'] ?? '');
        $sig = base64_decode((string) ($in['signature'] ?? ''), true);
        $err = rsa_validate_public_key($pem);
        if ($err !== null || $sig === false || $msg === '' || strlen($msg) > 2000) {
            json_response(422, ['ok' => false, 'error' => $err ?? 'Input tidak valid.']);
        }
        $valid = rsa_pss_verify($msg, $sig, $pem);
        crypto_log($adminId, null, 'rsa_sign_verify', 'RSA-PSS-SHA256', $valid ? 'success' : 'failure', 'Demo verifikasi: ' . ($valid ? 'valid' : 'invalid'));
        json_response(200, ['ok' => true, 'valid' => $valid, 'bits' => rsa_key_bits($pem), 'fingerprint' => rsa_fingerprint($pem)]);
    }

    json_response(400, ['ok' => false, 'error' => 'Aksi tidak dikenal.']);
}

$pageTitle = 'Enkripsi & Dekripsi';
$layout = 'admin';
$active = 'encryption';
$pageData = ['endpoint' => url('admin/encryption.php')];
$extraJs = ['public/js/rsa-client.js', 'public/js/demo.js'];
require __DIR__ . '/../includes/header.php';
?>
<div class="row g-3">
  <div class="col-xl-6">
    <div class="panel h-100">
      <div class="panel-head"><h2><i class="fa-solid fa-lock me-2 text-cyan"></i>Demonstrasi AES-256-GCM</h2></div>
      <div class="panel-body">
        <p class="small text-muted">Proses nyata di server memakai <code>openssl_encrypt()</code> dengan nonce acak 96-bit. Base64 hanyalah pengkodean, bukan enkripsi.</p>
        <label class="form-label" for="demoPlain">Plaintext</label>
        <textarea id="demoPlain" class="form-control mb-2" rows="3" maxlength="5000">Informasi penting dalam sistem.</textarea>
        <button class="btn btn-cyan btn-sm mb-3" id="btnEncrypt"><i class="fa-solid fa-lock me-1"></i>Encrypt</button>

        <div id="encOut" class="d-none">
          <div class="algo-info mb-3">
            <span>Algoritma: <b>AES-256-GCM</b></span><span>Kunci: <b>256-bit</b></span><span>Nonce: <b>96-bit acak</b></span><span>Tag: <b>128-bit</b></span>
          </div>
          <label class="form-label">Ciphertext (hex)</label>
          <textarea id="outCipher" class="form-control mono mb-2" rows="3"></textarea>
          <div class="row g-2 mb-2">
            <div class="col-md-6"><label class="form-label">Nonce (hex)</label><input id="outNonce" class="form-control mono"></div>
            <div class="col-md-6"><label class="form-label">Authentication tag (hex)</label><input id="outTag" class="form-control mono"></div>
          </div>
          <label class="form-label">Ciphertext (Base64, hanya tampilan)</label>
          <input id="outB64" class="form-control mono mb-3" readonly>
          <div class="d-flex flex-wrap gap-2">
            <button class="btn btn-outline-cyan btn-sm" id="btnDecrypt"><i class="fa-solid fa-lock-open me-1"></i>Decrypt</button>
            <button class="btn btn-outline-warning btn-sm" id="btnTamper"><i class="fa-solid fa-bug me-1"></i>Ubah 1 karakter ciphertext</button>
          </div>
        </div>
        <div id="decOut" class="mt-3 d-none"></div>
      </div>
    </div>
  </div>

  <div class="col-xl-6">
    <div class="panel h-100">
      <div class="panel-head"><h2><i class="fa-solid fa-signature me-2 text-cyan"></i>Demonstrasi RSA-PSS</h2></div>
      <div class="panel-body">
        <p class="small text-muted">Browser membuat pasangan kunci sementara (tidak disimpan) dan menandatangani challenge. Server memverifikasi dengan public key, membuktikan kompatibilitas Web Crypto &harr; PHP.</p>
        <label class="form-label" for="rsaMsg">Challenge / pesan</label>
        <input id="rsaMsg" class="form-control mb-2" maxlength="500" value="SAS-DEMO-challenge-12345">
        <div class="d-flex flex-wrap gap-2 mb-3">
          <button class="btn btn-cyan btn-sm" id="btnSign"><i class="fa-solid fa-pen-nib me-1"></i>Generate key &amp; Sign</button>
        </div>
        <div id="rsaOut" class="d-none">
          <label class="form-label">Public key (SPKI PEM)</label>
          <textarea id="rsaPub" class="form-control mono mb-2" rows="4" readonly></textarea>
          <label class="form-label">Signature (Base64)</label>
          <textarea id="rsaSig" class="form-control mono mb-2" rows="3" readonly></textarea>
          <div class="form-check mb-3">
            <input class="form-check-input" type="checkbox" id="rsaTamper">
            <label class="form-check-label" for="rsaTamper">Ubah pesan sebelum verifikasi (simulasi pemalsuan)</label>
          </div>
          <button class="btn btn-outline-cyan btn-sm" id="btnRsaVerify"><i class="fa-solid fa-shield-halved me-1"></i>Verifikasi di server</button>
        </div>
        <div id="rsaResult" class="mt-3 d-none"></div>
      </div>
    </div>
  </div>
</div>
<?php require __DIR__ . '/../includes/footer.php'; ?>
