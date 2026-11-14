# SECURE ADMIN SYSTEM

> *Secure Your Information, Protect Your Data.*

Sistem informasi manajemen konten berbasis **PHP Native 8.2+** (tanpa framework/Composer) yang menerapkan **AES-256-GCM** (kriptografi simetris) untuk melindungi isi konten dan **RSA-PSS** (kriptografi asimetris) untuk autentikasi admin berbasis tanda tangan digital. Dibuat untuk proyek akademik.

Dokumen lain: [`ARCHITECTURE.md`](ARCHITECTURE.md) (arsitektur, keputusan teknis, batasan desain).

---

## 1. Fitur

| Area | Fitur |
|---|---|
| Publik | Landing page responsif (hero, fitur, penjelasan AES/RSA, keunggulan) |
| Autentikasi | Login RSA-PSS challenge-response, anti replay, rate limiting, penguncian akun, regenerasi session, logout, log percobaan login |
| Dashboard | Statistik, grafik aktivitas 7 hari, status enkripsi & RSA, aktivitas terbaru, sidebar collapsible |
| Konten | CRUD, pencarian judul, filter kategori/status, pagination, isi dienkripsi AES-256-GCM |
| Kategori | CRUD (kategori yang masih dipakai tidak dapat dihapus) |
| Kriptografi | Halaman demo AES (encrypt/decrypt/deteksi manipulasi) dan RSA-PSS (sign di browser, verifikasi di server) |
| Audit | Audit log aktivitas admin + log operasi kriptografi |
| Pengaturan | Parameter rate limit, TTL challenge, idle timeout (butuh konfirmasi password) + status kripto |

## 2. Struktur Folder

```
secure-admin-system/
├── index.php                  landing page
├── .htaccess  .env  .env.example
├── config/      database.php, security.php        (bootstrap, session, header, CSRF)
├── includes/    header, footer, navbar, sidebar, auth (middleware), helpers
├── auth/        login, challenge, verify, logout
├── admin/       dashboard, contents/*, categories/*, encryption, audit, settings
├── crypto/      aes.php, rsa.php, crypto_helper.php
├── public/      css/ js/ images/
├── tools/       setup_admin.php (admin pertama), selftest.php (uji kripto CLI)
├── database/    secure_admin_system.sql
└── storage/keys/   master key AES (diblokir dari web)
```

## 3. Instalasi di XAMPP (Windows)

1. Instal **XAMPP dengan PHP 8.2 atau lebih baru** (apachefriends.org). Jalankan *Apache* dan *MySQL* dari XAMPP Control Panel.
2. Salin folder `secure-admin-system` ke `C:\xampp\htdocs\`.
3. Impor database: buka `http://localhost/phpmyadmin` → **Import** → pilih `database/secure_admin_system.sql` → **Go**.
   (atau CLI: `C:\xampp\mysql\bin\mysql -u root < database\secure_admin_system.sql`)
4. Periksa `.env` (sudah berisi default XAMPP: user `root`, password kosong, `BASE_URL=/secure-admin-system`). Ubah bila perlu.
5. Pastikan `mod_rewrite` tidak wajib, tetapi **`AllowOverride All`** harus aktif untuk `htdocs` agar `.htaccess` berlaku (default XAMPP sudah aktif).
6. Folder `storage/` harus dapat ditulis oleh Apache (default XAMPP Windows: ya; Linux: `chmod 775 storage storage/keys` dan pemilik `www-data`).

## 4. Konfigurasi PHP OpenSSL

Di `C:\xampp\php\php.ini` pastikan baris berikut **tidak diawali `;`**:

```ini
extension=openssl
extension=pdo_mysql
extension=mbstring
```

Restart Apache, lalu verifikasi dari terminal:

```
C:\xampp\php\php.exe -m | findstr /i "openssl pdo_mysql mbstring"
C:\xampp\php\php.exe -r "var_dump(in_array('aes-256-gcm', openssl_get_cipher_methods()));"   # harus bool(true)
```

Bila `openssl_pkey_new()` gagal di Windows (hanya dipakai `selftest.php`), set variabel lingkungan `OPENSSL_CONF=C:\xampp\apache\conf\openssl.cnf`.

> Web Crypto API di browser hanya aktif pada **secure context**: `http://localhost` atau HTTPS. Mengakses lewat `http://192.168.x.x` **tidak akan bisa login/setup** tanpa HTTPS.

## 5. Membuat Admin Pertama

1. Buka `http://localhost/secure-admin-system/tools/setup_admin.php`.
2. Isi **Setup Token** = nilai `SETUP_TOKEN` pada file `.env` (token acak sudah dibuat untuk Anda; ganti bila perlu).
3. Isi username, nama, password akun (≥ 12 karakter, disimpan sebagai hash; dipakai untuk konfirmasi pengaturan keamanan), lalu **passphrase private key** (≥ 12 karakter).
4. Klik **Buat Kunci RSA & Daftarkan Admin**. Browser akan:
   - membuat pasangan kunci RSA-2048 (RSA-PSS/SHA-256),
   - mengenkripsi private key dengan passphrase (PBKDF2 310.000 iterasi + AES-256-GCM),
   - mengirim **hanya public key** ke server, lalu mengunduh `sas-private-key-<username>.json`.
5. **Simpan file `.json` dan passphrase di tempat aman.** Keduanya tidak dapat dipulihkan oleh server.
6. Server otomatis membuat master key AES di `storage/keys/master_v1.key` (jika belum ada). **Backup file ini**: tanpa master key, konten terenkripsi tidak dapat dibuka.
7. Halaman setup terkunci otomatis setelah admin aktif terdaftar.

**Pemulihan (kunci/passphrase hilang):** jalankan SQL `UPDATE admins SET is_active=0, public_key_pem=NULL, public_key_fingerprint=NULL WHERE username='admin';` lalu ulangi langkah setup.

## 6. Menjalankan Aplikasi

- Landing page: `http://localhost/secure-admin-system/`
- Login: `http://localhost/secure-admin-system/auth/login.php` → isi username, pilih file `.json`, isi passphrase → **Autentikasi dengan RSA**.

Alur login: (1) private key dibuka lokal → (2) minta challenge → (3) tanda tangan RSA-PSS → (4) server memverifikasi, menandai challenge terpakai, membuat session baru.

## 7. Panduan Pengujian Kriptografi

### a. Self-test otomatis (CLI, tanpa database)
```
C:\xampp\php\php.exe tools\selftest.php
```
Menguji: round-trip AES-256-GCM, nonce acak, penolakan ciphertext/tag/AAD/kunci yang diubah, serta **verifikasi RSA-PSS terhadap signature buatan Web Crypto (JavaScript)**. Semua baris harus `[PASS]`.

### b. Demo di dashboard (menu *Enkripsi & Dekripsi*)
1. **AES**: isi plaintext → *Encrypt* (lihat ciphertext, nonce, tag) → *Decrypt* (integritas valid).
2. Klik *Ubah 1 karakter ciphertext* → *Decrypt* → harus **Integritas TIDAK valid**.
3. **RSA-PSS**: *Generate key & Sign* → *Verifikasi di server* → **VALID**. Centang "Ubah pesan" → **INVALID**.

### c. Bukti data terenkripsi di database
Tambah konten lalu jalankan:
```sql
SELECT id, title, HEX(nonce), HEX(auth_tag), LEFT(HEX(ciphertext),64) FROM contents;
```
Isi konten tidak terbaca; yang tersimpan hanya ciphertext + nonce + tag + `key_version`.

### d. Pengujian keamanan manual
| Uji | Cara | Hasil yang diharapkan |
|---|---|---|
| Replay | Tangkap request `verify.php` (DevTools) lalu kirim ulang | Ditolak (challenge sudah dipakai) |
| Challenge kedaluwarsa | Tunggu > TTL (default 120 dtk) sebelum verify | Ditolak |
| Passphrase salah | Login dengan passphrase salah | Ditolak lokal di browser; tidak ada percobaan tercatat di server |
| Rate limiting | Kirim banyak tanda tangan salah | HTTP 429 / akun terkunci sementara |
| CSRF | POST ke `contents/delete.php` tanpa token | HTTP 419 |
| Akses tanpa login | Buka `admin/dashboard.php` di sesi baru | Redirect ke login |
| Manipulasi data | Ubah 1 byte `ciphertext` di DB lalu buka konten | "Validasi integritas gagal" + tercatat di audit & crypto log |
| File sensitif | Buka `/.env`, `/storage/keys/master_v1.key`, `/config/security.php` | 403 Forbidden |

## 8. Deployment (produksi)

1. **HTTPS wajib** (Let's Encrypt). Aplikasi otomatis memakai cookie `Secure` dan HSTS bila HTTPS terdeteksi.
2. Set `APP_DEBUG=false`, buat user database khusus (hak minimal: SELECT/INSERT/UPDATE/DELETE pada `secure_admin_system`), jangan pakai `root`.
3. **Pindahkan master key ke luar document root**: buat mis. `/etc/sas-keys/` (chmod 700, pemilik user web), pindahkan `master_v1.key` (chmod 600), lalu isi `KEY_DIR=/etc/sas-keys` pada `.env`.
4. Idealnya letakkan seluruh project di luar webroot dan hanya expose `index.php`, `auth/`, `admin/`, `public/`, `tools/` (atau hapus `tools/` setelah setup). Minimal: **hapus/blokir `tools/setup_admin.php`** setelah admin terdaftar dan ganti `SETUP_TOKEN`.
5. Apache: `AllowOverride All` (agar `.htaccess` aktif) atau salin aturan `Require all denied` ke konfigurasi vhost untuk `config/ includes/ crypto/ database/ storage/ .env`. Nginx: tambahkan `location ~ ^/(config|includes|crypto|database|storage)/ { deny all; }` dan `location ~ /\. { deny all; }`.
6. Backup terjadwal: database **dan** master key (disimpan terpisah).
7. Opsional hardening: self-host Bootstrap/Font Awesome/Fonts (hilangkan dependensi CDN) lalu perketat CSP; aktifkan `session.save_path` khusus; batasi akses `/auth/` per IP bila memungkinkan.

## 9. Ringkasan Keamanan yang Diterapkan

- PDO prepared statements (native, `EMULATE_PREPARES=false`); semua output di-escape (`htmlspecialchars`); validasi input server-side.
- CSRF token pada semua request yang mengubah state (form & fetch via header `X-CSRF-Token`).
- Session: `HttpOnly`, `SameSite=Strict`, `Secure` (HTTPS), strict mode, regenerasi saat login dan berkala, idle timeout, pengikatan ke User-Agent.
- Header: CSP, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, HSTS (HTTPS), `Cache-Control: no-store`.
- Login: challenge acak 256-bit (`random_bytes`), sekali pakai (klaim atomik `UPDATE … WHERE used_at IS NULL`), TTL, terikat session & admin, respons seragam (tidak membocorkan keberadaan akun), rate limit per IP/akun + lockout.
- AES-256-GCM: nonce 96-bit acak per enkripsi, tag 128-bit, AAD = ID konten + versi kunci. Master key dari file di luar source code; demo memakai sub-key HKDF.
- Audit/crypto log tidak menyimpan plaintext, private key, passphrase, maupun master key.

## 10. Keterbatasan yang Perlu Dicatat (untuk laporan)

- **Metadata tidak terenkripsi**: judul, kategori, status, tanggal tersimpan plaintext agar dapat dicari/difilter. Isi konten tidak dapat dicari lewat SQL.
- Keamanan AES bergantung pada kerahasiaan master key; jika key file dan database bocor bersamaan, data terbuka.
- **Kompatibilitas RSA-PSS**: `openssl_verify()` PHP tidak mendukung PSS, sehingga verifikasi diimplementasikan manual (RSAVP1 + EMSA-PSS-VERIFY, RFC 8017) di `crypto/rsa.php`. Parameter harus sama dengan klien: SHA-256, MGF1-SHA256, salt 32 byte.
- Penguncian akun dapat dipakai penyerang untuk menunda login admin sah (DoS terbatas); rate limit per IP dan jendela waktu singkat memitigasi hal ini.
- Satu peran (admin). Tidak ada manajemen multi-admin/rotasi master key otomatis (kolom `key_version` disiapkan untuk pengembangan lanjutan).
- Kehilangan file private key/passphrase memerlukan prosedur pemulihan manual (lihat bagian 5).

## 11. Pemecahan Masalah

| Gejala | Penyebab / solusi |
|---|---|
| "Koneksi database gagal" | Periksa `.env`, MySQL berjalan, database sudah diimpor |
| Halaman tanpa gaya | `BASE_URL` di `.env` tidak sesuai nama folder; atau tidak ada internet untuk CDN |
| "Web Crypto tidak tersedia" | Akses lewat `http://localhost` atau HTTPS |
| "Master key belum tersedia" | Jalankan setup admin, atau pastikan `storage/keys/` dapat ditulis |
| Setup: "Setup terkunci" | Admin sudah terdaftar; lihat prosedur pemulihan |
| Verifikasi selalu gagal | Jalankan `tools/selftest.php`; pastikan OpenSSL aktif dan waktu server benar |
| Log galat PHP | `storage/php_error.log` |
#   U T S _ K r i p t o g r a f i  
 