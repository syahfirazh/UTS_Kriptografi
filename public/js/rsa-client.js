/**
 * SASCrypto - kriptografi sisi klien (Web Crypto API).
 * - Pembuatan kunci RSA-PSS 2048-bit (SHA-256)
 * - Private key diekspor PKCS#8 lalu DIENKRIPSI dengan passphrase:
 *   PBKDF2-SHA256 (310.000 iterasi) + AES-256-GCM  -> file .json lokal
 * - Tanda tangan RSA-PSS (saltLength 32) kompatibel dengan verifikasi PHP (crypto/rsa.php)
 * Private key TIDAK pernah dikirim ke server.
 * Catatan: Web Crypto hanya tersedia pada secure context (HTTPS atau http://localhost).
 */
(function (root) {
  'use strict';

  const subtle = root.crypto && root.crypto.subtle;
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const PBKDF2_ITERATIONS = 310000;
  const KEYFILE_AAD = enc.encode('SAS-PRIVATE-KEY-v1');
  const PSS_SALT_LENGTH = 32;

  function requireSubtle() {
    if (!subtle) {
      throw new Error('Web Crypto tidak tersedia. Gunakan HTTPS atau http://localhost.');
    }
  }

  function b64e(buf) {
    const bytes = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  function b64d(str) {
    const s = atob(str);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }

  function toHex(buf) {
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async function generateKeyPair() {
    requireSubtle();
    return subtle.generateKey(
      { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['sign', 'verify']
    );
  }

  async function exportPublicPem(publicKey) {
    const spki = await subtle.exportKey('spki', publicKey);
    const lines = b64e(spki).match(/.{1,64}/g).join('\n');
    return '-----BEGIN PUBLIC KEY-----\n' + lines + '\n-----END PUBLIC KEY-----\n';
  }

  /** SHA-256 hex dari DER SPKI (sama dengan rsa_fingerprint() di PHP). */
  async function publicKeyFingerprint(publicKey) {
    const spki = await subtle.exportKey('spki', publicKey);
    return toHex(await subtle.digest('SHA-256', spki));
  }

  async function deriveWrapKey(passphrase, salt, iterations) {
    const base = await subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    return subtle.deriveKey(
      { name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /** Ekspor private key terenkripsi passphrase -> objek JSON (disimpan sebagai file oleh pengguna). */
  async function exportEncryptedPrivateKey(privateKey, passphrase, meta) {
    requireSubtle();
    const pkcs8 = await subtle.exportKey('pkcs8', privateKey);
    const salt = root.crypto.getRandomValues(new Uint8Array(16));
    const iv = root.crypto.getRandomValues(new Uint8Array(12));
    const wrapKey = await deriveWrapKey(passphrase, salt, PBKDF2_ITERATIONS);
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: KEYFILE_AAD }, wrapKey, pkcs8);
    return Object.assign({
      format: 'SAS-PRIVATE-KEY',
      version: 1,
      kdf: 'PBKDF2-SHA256',
      iterations: PBKDF2_ITERATIONS,
      cipher: 'AES-256-GCM',
      salt: b64e(salt),
      iv: b64e(iv),
      data: b64e(ct)
    }, meta || {});
  }

  /** Buka file private key dengan passphrase -> CryptoKey (non-extractable, hanya untuk sign). */
  async function importEncryptedPrivateKey(keyFile, passphrase) {
    requireSubtle();
    if (!keyFile || keyFile.format !== 'SAS-PRIVATE-KEY' || keyFile.version !== 1 || !keyFile.salt || !keyFile.iv || !keyFile.data) {
      throw new Error('Format file private key tidak dikenali.');
    }
    const iterations = Number(keyFile.iterations);
    if (!Number.isInteger(iterations) || iterations < 100000 || iterations > 2000000) {
      throw new Error('Parameter KDF pada file kunci tidak valid.');
    }
    let pkcs8;
    try {
      const wrapKey = await deriveWrapKey(passphrase, b64d(keyFile.salt), iterations);
      pkcs8 = await subtle.decrypt({ name: 'AES-GCM', iv: b64d(keyFile.iv), additionalData: KEYFILE_AAD }, wrapKey, b64d(keyFile.data));
    } catch (e) {
      throw new Error('Passphrase salah atau file kunci rusak.');
    }
    return subtle.importKey('pkcs8', pkcs8, { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['sign']);
  }

  /** Tanda tangan RSA-PSS (SHA-256, salt 32). Mengembalikan Base64. */
  async function sign(privateKey, message) {
    requireSubtle();
    const sig = await subtle.sign({ name: 'RSA-PSS', saltLength: PSS_SALT_LENGTH }, privateKey, enc.encode(message));
    return b64e(sig);
  }

  async function verify(publicKey, message, signatureB64) {
    return subtle.verify({ name: 'RSA-PSS', saltLength: PSS_SALT_LENGTH }, publicKey, b64d(signatureB64), enc.encode(message));
  }

  /** Pesan yang ditandatangani saat login (harus identik dengan verify.php). */
  function loginMessage(username, challenge) {
    return 'SAS-LOGIN-v1:' + username + ':' + challenge;
  }

  function downloadJson(obj, filename) {
    const blob = new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 2000);
  }

  const api = {
    generateKeyPair, exportPublicPem, publicKeyFingerprint,
    exportEncryptedPrivateKey, importEncryptedPrivateKey,
    sign, verify, loginMessage, downloadJson, b64e, b64d, toHex
  };
  root.SASCrypto = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : window);
