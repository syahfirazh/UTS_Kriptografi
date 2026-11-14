# SECURE ADMIN SYSTEM — Arsitektur (Tahap 1)

## 1. Gambaran Arsitektur

```
 BROWSER                                   SERVER (PHP Native + MySQL)
 ───────                                   ──────────────────────────
 Landing page (publik)  ───────────────►   index.php

 Login RSA
 1. kirim username      ───────────────►   auth/challenge.php
                                            - cek admin aktif, rate limit
                                            - random_bytes(32) -> auth_challenges
 2. terima challenge    ◄───────────────      (expires_at, used_at=NULL)
 3. buka file private key
    (dekripsi lokal dgn passphrase:
     PBKDF2 + AES-GCM, Web Crypto)
 4. sign challenge (RSA-PSS, SHA-256,
    salt 32 byte)
 5. kirim signature     ───────────────►   auth/verify.php
                                            - challenge valid, belum expired, belum used
                                            - verifikasi RSA-PSS dgn public key admin
                                            - tandai used_at (atomik) -> anti replay
                                            - session_regenerate_id(true)
 6. redirect            ◄───────────────   admin/dashboard.php

 Admin Panel            ───────────────►   admin/* (middleware includes/auth.php)
                                            └─ crypto/aes.php  (AES-256-GCM, master key dari env)
                                            └─ crypto/rsa.php  (verifikasi RSA-PSS)
                                            └─ audit_logs / crypto_logs
```

Prinsip utama:
- **Private key tidak pernah menyentuh server.** Pasangan kunci dibuat di browser (Web Crypto), private key disimpan sebagai file lokal terenkripsi passphrase, hanya public key (SPKI PEM) dikirim ke server.
- **AES master key tidak ada di source code.** Dibaca dari file `.env` / `storage/keys/` yang diblokir dari akses web (idealnya di luar document root).
- **Challenge sekali pakai**, berumur pendek, terikat ke session pra-login dan IP.

## 2. Keputusan Teknis Penting (kompatibilitas JS ↔ PHP)

| Isu | Keputusan |
|---|---|
| `openssl_verify()` PHP **tidak mendukung padding PSS** | Verifikasi RSA-PSS diimplementasikan manual di `crypto/rsa.php`: `openssl_public_decrypt()` dengan `OPENSSL_NO_PADDING` lalu pengecekan EMSA-PSS (RFC 8017 §9.1.2: MGF1-SHA256, salt 32 byte, trailer 0xBC). Tanpa Composer/phpseclib sesuai larangan. |
| Parameter RSA-PSS Web Crypto | `{name:"RSA-PSS", saltLength:32}`, hash SHA-256, modulus 2048-bit, e=65537. Server memakai parameter identik. |
| Format kunci | Public key: SPKI PEM (`exportKey("spki")`, base64 + header PEM, cocok untuk `openssl_pkey_get_public`). |
| Penyimpanan private key di klien | Export PKCS#8, dienkripsi dengan AES-GCM, kunci dari passphrase via PBKDF2-SHA256 (≥310.000 iterasi) + salt acak; disimpan sebagai file `.json` yang diunduh pengguna. |
| Web Crypto butuh secure context | Jalan di `http://localhost`; di deployment wajib HTTPS. |
| AES-GCM di PHP | `openssl_encrypt($pt,'aes-256-gcm',$key,OPENSSL_RAW_DATA,$iv,$tag,$aad,16)`; IV 12 byte acak per enkripsi; tag 16 byte. |
| AAD | Berisi `content_id` dan `key_version` agar ciphertext tidak bisa dipindah antar baris. Alur simpan: INSERT lalu enkripsi dan UPDATE dalam satu transaksi. |

## 3. Batasan Desain (untuk dokumentasi akademik)

- `title`, `category_id`, `status`, dan tanggal **tidak terenkripsi** supaya dapat dicari/difilter. Konsekuensinya, DBA atau penyerang yang membaca database dapat melihat metadata tersebut. Isi konten terlindungi.
- Isi konten **tidak dapat dicari** lewat SQL karena berbentuk ciphertext.
- Keamanan AES bergantung pada kerahasiaan master key. Jika `.env`/key file bocor bersama database, data terbuka.
- Rate limiting berbasis IP dapat dilewati penyerang yang memakai banyak IP, sehingga ada juga pembatasan per username dan penguncian akun.
- Kehilangan file private key atau passphrase = kehilangan akses; perlu prosedur pemulihan (daftarkan public key baru lewat skrip setup/CLI).

## 4. Struktur Folder

```
secure-admin-system/
├── index.php                      # landing page publik
├── .htaccess                      # security headers, blokir file sensitif
├── .env.example                   # APP_ENV, DB_*, path master key
├── config/
│   ├── database.php               # koneksi PDO (prepared statements, ERRMODE_EXCEPTION)
│   └── security.php               # session, header, helper CSRF, konstanta kripto
├── includes/
│   ├── header.php  footer.php  navbar.php  sidebar.php
│   └── auth.php                   # middleware: wajib login, idle timeout, CSRF
├── public/
│   ├── css/  js/  images/
│   └── js/rsa-client.js           # Web Crypto: keygen, enkripsi key file, sign
├── auth/
│   ├── login.php  challenge.php  verify.php  logout.php
├── admin/
│   ├── dashboard.php
│   ├── contents/    (index, create, edit, view, delete)
│   ├── categories/  (index, create, edit, delete)
│   ├── encryption.php             # demo AES & RSA-PSS
│   ├── audit.php
│   └── settings.php
├── crypto/
│   ├── aes.php                    # AES-256-GCM
│   ├── rsa.php                    # verifikasi RSA-PSS (manual EMSA-PSS)
│   └── crypto_helper.php          # load master key, versi kunci, logging
├── tools/
│   └── setup_admin.php            # pendaftaran admin pertama (hapus/kunci setelah dipakai)
├── database/
│   └── secure_admin_system.sql
├── storage/
│   ├── .htaccess                  # Require all denied
│   └── keys/                      # master.key (chmod 600), tidak di-commit
└── README.md
```

Tambahan di luar daftar awal: `.htaccess`, `.env.example`, `public/js/rsa-client.js`, `tools/setup_admin.php`. Semuanya diperlukan agar alur RSA dan perlindungan file berfungsi.

## 5. Skema Database (ringkas)

```
admins 1──* contents *──1 categories
admins 1──* audit_logs        admins 1──* crypto_logs *──0..1 contents
admins 1──* login_attempts    admins 1──* auth_challenges
admins 1──* security_settings (updated_by)
```

Aturan FK: `contents → categories/admins` **RESTRICT** (kategori yang masih dipakai tidak bisa dihapus). Log memakai **SET NULL** agar jejak audit bertahan. `auth_challenges` memakai **CASCADE**.

Tabel tambahan: `security_settings`, untuk menyimpan konfigurasi yang diubah di halaman Pengaturan Keamanan.

## 6. Admin Awal

SQL memasukkan akun `admin` dalam keadaan **nonaktif** tanpa public key dan password. Kunci RSA harus dibuat pemiliknya di browser, dan hash password tidak boleh di-hardcode. Aktivasi dilakukan lewat `tools/setup_admin.php` di Tahap 3.

## 7. Uji Tahap 1

1. Jalankan Apache + MySQL di XAMPP.
2. Buka phpMyAdmin → Import → `database/secure_admin_system.sql`.
3. Verifikasi: database `secure_admin_system` berisi 8 tabel; `SELECT * FROM categories;` → 5 baris; `SELECT * FROM admins;` → 1 baris nonaktif.
4. Cek FK: `DELETE FROM categories WHERE id=1;` boleh jika belum dipakai; setelah ada konten harus ditolak (RESTRICT).
