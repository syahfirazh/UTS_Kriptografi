-- =====================================================================
-- SECURE ADMIN SYSTEM — Skema Database (Tahap 1)
-- Kompatibel: MySQL 5.7+/8.x dan MariaDB 10.4+ (XAMPP)
-- Import: phpMyAdmin > Import, atau: mysql -u root -p < secure_admin_system.sql
-- =====================================================================

CREATE DATABASE IF NOT EXISTS `secure_admin_system`
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE `secure_admin_system`;

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS `auth_challenges`;
DROP TABLE IF EXISTS `login_attempts`;
DROP TABLE IF EXISTS `audit_logs`;
DROP TABLE IF EXISTS `crypto_logs`;
DROP TABLE IF EXISTS `contents`;
DROP TABLE IF EXISTS `categories`;
DROP TABLE IF EXISTS `security_settings`;
DROP TABLE IF EXISTS `admins`;

SET FOREIGN_KEY_CHECKS = 1;

-- ---------------------------------------------------------------------
-- 1. admins
--    Autentikasi utama = RSA-PSS (public_key_pem). Private key TIDAK
--    pernah disimpan di server. password_hash dipakai hanya untuk
--    re-autentikasi aksi sensitif (mis. ubah pengaturan keamanan).
-- ---------------------------------------------------------------------
CREATE TABLE `admins` (
  `id`                     INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `username`               VARCHAR(50)  NOT NULL,
  `full_name`              VARCHAR(100) NOT NULL,
  `email`                  VARCHAR(120) NULL,
  `password_hash`          VARCHAR(255) NULL COMMENT 'password_hash() bcrypt/argon2; untuk step-up auth',
  `public_key_pem`         TEXT         NULL COMMENT 'RSA public key (SPKI PEM), min 2048-bit',
  `public_key_fingerprint` CHAR(64)     NULL COMMENT 'SHA-256 hex dari DER public key',
  `is_active`              TINYINT(1)   NOT NULL DEFAULT 0,
  `failed_attempts`        SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  `locked_until`           DATETIME     NULL,
  `last_login_at`          DATETIME     NULL,
  `last_login_ip`          VARCHAR(45)  NULL,
  `created_at`             TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`             TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_admins_username` (`username`),
  UNIQUE KEY `uq_admins_fingerprint` (`public_key_fingerprint`),
  KEY `idx_admins_active` (`is_active`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- 2. categories
-- ---------------------------------------------------------------------
CREATE TABLE `categories` (
  `id`          INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `name`        VARCHAR(80)  NOT NULL,
  `slug`        VARCHAR(100) NOT NULL,
  `description` VARCHAR(255) NULL,
  `created_at`  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_categories_name` (`name`),
  UNIQUE KEY `uq_categories_slug` (`slug`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- 3. contents
--    title & category_id = metadata TIDAK terenkripsi (untuk pencarian/filter).
--    Isi konten disimpan sebagai ciphertext AES-256-GCM:
--      ciphertext + nonce (IV 12 byte) + auth_tag (16 byte) + key_version.
--    Plaintext TIDAK pernah disimpan di kolom mana pun.
-- ---------------------------------------------------------------------
CREATE TABLE `contents` (
  `id`          INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `category_id` INT UNSIGNED NOT NULL,
  `created_by`  INT UNSIGNED NOT NULL,
  `title`       VARCHAR(200) NOT NULL,
  `status`      ENUM('draft','published','archived') NOT NULL DEFAULT 'draft',
  `ciphertext`  LONGBLOB     NOT NULL,
  `nonce`       VARBINARY(12) NOT NULL COMMENT 'IV/nonce acak 96-bit, unik per enkripsi',
  `auth_tag`    VARBINARY(16) NOT NULL COMMENT 'GCM authentication tag 128-bit',
  `key_version` SMALLINT UNSIGNED NOT NULL DEFAULT 1 COMMENT 'versi master key (rotasi kunci)',
  `created_at`  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_contents_category` (`category_id`),
  KEY `idx_contents_created_by` (`created_by`),
  KEY `idx_contents_status` (`status`),
  KEY `idx_contents_created_at` (`created_at`),
  KEY `idx_contents_title` (`title`),
  CONSTRAINT `fk_contents_category`
    FOREIGN KEY (`category_id`) REFERENCES `categories` (`id`)
    ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT `fk_contents_admin`
    FOREIGN KEY (`created_by`) REFERENCES `admins` (`id`)
    ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- 4. crypto_logs — jejak operasi kriptografi (tanpa plaintext/kunci)
-- ---------------------------------------------------------------------
CREATE TABLE `crypto_logs` (
  `id`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `admin_id`   INT UNSIGNED NULL,
  `content_id` INT UNSIGNED NULL,
  `operation`  ENUM('encrypt','decrypt','demo_encrypt','demo_decrypt','rsa_sign_verify') NOT NULL,
  `algorithm`  VARCHAR(30)  NOT NULL COMMENT 'mis. AES-256-GCM, RSA-PSS-SHA256',
  `status`     ENUM('success','failure') NOT NULL,
  `detail`     VARCHAR(255) NULL COMMENT 'mis. panjang data, alasan gagal (integritas), TANPA data sensitif',
  `ip_address` VARCHAR(45)  NULL,
  `created_at` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_crypto_admin` (`admin_id`),
  KEY `idx_crypto_content` (`content_id`),
  KEY `idx_crypto_operation` (`operation`, `created_at`),
  CONSTRAINT `fk_crypto_admin`
    FOREIGN KEY (`admin_id`) REFERENCES `admins` (`id`)
    ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `fk_crypto_content`
    FOREIGN KEY (`content_id`) REFERENCES `contents` (`id`)
    ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- 5. audit_logs — aktivitas admin (append-only secara aplikasi)
--    username_snapshot menjaga jejak walau akun admin dihapus.
-- ---------------------------------------------------------------------
CREATE TABLE `audit_logs` (
  `id`                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `admin_id`          INT UNSIGNED NULL,
  `username_snapshot` VARCHAR(50)  NULL,
  `action`            VARCHAR(40)  NOT NULL COMMENT 'LOGIN_SUCCESS, LOGIN_FAILED, LOGOUT, CONTENT_CREATE, CONTENT_UPDATE, CONTENT_DELETE, CONTENT_ENCRYPT, CONTENT_DECRYPT, SETTINGS_CHANGE, ...',
  `description`       VARCHAR(255) NULL,
  `ip_address`        VARCHAR(45)  NULL,
  `user_agent`        VARCHAR(255) NULL,
  `created_at`        TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_audit_admin` (`admin_id`),
  KEY `idx_audit_action` (`action`),
  KEY `idx_audit_created_at` (`created_at`),
  CONSTRAINT `fk_audit_admin`
    FOREIGN KEY (`admin_id`) REFERENCES `admins` (`id`)
    ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- 6. login_attempts — dasar rate limiting (per IP dan per username)
-- ---------------------------------------------------------------------
CREATE TABLE `login_attempts` (
  `id`           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `admin_id`     INT UNSIGNED NULL,
  `username`     VARCHAR(50)  NOT NULL,
  `ip_address`   VARCHAR(45)  NOT NULL,
  `success`      TINYINT(1)   NOT NULL DEFAULT 0,
  `reason`       VARCHAR(60)  NULL COMMENT 'mis. unknown_user, bad_signature, expired_challenge, rate_limited',
  `attempted_at` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_attempts_ip_time` (`ip_address`, `attempted_at`),
  KEY `idx_attempts_user_time` (`username`, `attempted_at`),
  KEY `idx_attempts_admin` (`admin_id`),
  CONSTRAINT `fk_attempts_admin`
    FOREIGN KEY (`admin_id`) REFERENCES `admins` (`id`)
    ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- 7. auth_challenges — challenge sekali pakai (anti replay)
-- ---------------------------------------------------------------------
CREATE TABLE `auth_challenges` (
  `id`                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `admin_id`          INT UNSIGNED NOT NULL,
  `challenge`         CHAR(64)     NOT NULL COMMENT 'bin2hex(random_bytes(32))',
  `session_id_hash`   CHAR(64)     NOT NULL COMMENT 'SHA-256 dari session id pra-login (mengikat challenge ke browser)',
  `ip_address`        VARCHAR(45)  NOT NULL,
  `expires_at`        DATETIME     NOT NULL,
  `used_at`           DATETIME     NULL COMMENT 'NULL = belum dipakai',
  `created_at`        TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_challenge` (`challenge`),
  KEY `idx_challenge_admin` (`admin_id`),
  KEY `idx_challenge_expires` (`expires_at`),
  CONSTRAINT `fk_challenge_admin`
    FOREIGN KEY (`admin_id`) REFERENCES `admins` (`id`)
    ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- 8. security_settings (tabel tambahan di luar 7 tabel wajib)
--    Dibutuhkan agar "Pengaturan Keamanan" & audit perubahan konfigurasi
--    punya penyimpanan. Tidak menyimpan rahasia apa pun.
-- ---------------------------------------------------------------------
CREATE TABLE `security_settings` (
  `setting_key`   VARCHAR(60)  NOT NULL,
  `setting_value` VARCHAR(255) NOT NULL,
  `description`   VARCHAR(255) NULL,
  `updated_by`    INT UNSIGNED NULL,
  `updated_at`    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`setting_key`),
  CONSTRAINT `fk_settings_admin`
    FOREIGN KEY (`updated_by`) REFERENCES `admins` (`id`)
    ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================================
-- DATA AWAL
-- =====================================================================

-- Kategori awal
INSERT INTO `categories` (`name`, `slug`, `description`) VALUES
  ('Umum',              'umum',              'Informasi umum organisasi'),
  ('Keuangan',          'keuangan',          'Data dan catatan keuangan'),
  ('Kebijakan',         'kebijakan',         'Kebijakan dan prosedur'),
  ('Dokumen Internal',  'dokumen-internal',  'Dokumen rahasia internal'),
  ('Laporan',           'laporan',           'Laporan berkala');

-- Pengaturan keamanan awal
INSERT INTO `security_settings` (`setting_key`, `setting_value`, `description`) VALUES
  ('challenge_ttl_seconds',   '120', 'Masa berlaku challenge login (detik)'),
  ('max_attempts_per_ip',     '10',  'Maks percobaan login per IP dalam jendela waktu'),
  ('max_attempts_per_user',   '5',   'Maks percobaan gagal per username dalam jendela waktu'),
  ('attempt_window_minutes',  '15',  'Jendela waktu rate limiting (menit)'),
  ('lockout_minutes',         '15',  'Durasi penguncian akun setelah melebihi batas'),
  ('session_idle_timeout',    '1800','Batas idle session (detik)');

-- Admin awal.
-- CATATAN: public key RSA & password_hash TIDAK bisa di-hardcode di SQL
-- (kunci harus dibuat oleh pemilik akun; private key tidak boleh dibuat
-- server). Akun ini dibuat NONAKTIF dan diaktifkan lewat skrip setup
-- pada Tahap 3 (setup_admin.php), yang menerima public key hasil
-- generate di browser dan mengisi password_hash via password_hash().
INSERT INTO `admins`
  (`username`, `full_name`, `email`, `password_hash`, `public_key_pem`, `public_key_fingerprint`, `is_active`)
VALUES
  ('admin', 'Administrator Utama', 'admin@localhost', NULL, NULL, NULL, 0);
