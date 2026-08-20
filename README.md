<div align="center">

# 🔒 HYCLEUS

**Encrypted Secure File Vault for Windows**

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![PySide6](https://img.shields.io/badge/PySide6-6.x-41CD52?style=for-the-badge&logo=qt&logoColor=white)](https://doc.qt.io/qtforpython/)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D4?style=for-the-badge&logo=windows&logoColor=white)](https://microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.2.0.dev-red?style=for-the-badge)](#)
[![Security](https://img.shields.io/badge/Encryption-AES--256--GCM-success?style=for-the-badge&logo=shield&logoColor=white)](#security-architecture)

*Hardware-presence + PIN dual-factor encrypted file vault with USB HWID authentication, TOTP 2FA, and Shamir Secret Sharing.*

</div>

---

## 🇬🇧 English

### What is HYCLEUS?

HYCLEUS is a Windows desktop application that encrypts and manages sensitive files inside a hardware-bound vault. Every file is encrypted with **AES-256-GCM** before hitting disk. The master key is split via **Shamir 2-of-3 Secret Sharing** — any two of the three shares reconstruct it. share_1 lives in a local vault file (`.hclv`) encrypted with an Argon2id PIN-derived KEK; share_2 lives in the **OS credential store** (Windows Credential Manager / macOS Keychain / Linux Secret Service) under `HYCLEUS` / `share_2:<hwid>`. The TOTP secret is stored the same way. If the credential store is unreachable, HYCLEUS refuses to start rather than falling back to plaintext. Reconstructing the master key requires both the correct PIN and the registered USB device to be physically present.

---

> **Lost your USB, PIN, or recovery slip?** Read
> **[docs/kullanici-rehberi.md](docs/kullanici-rehberi.md)** first — a
> step-by-step guide written for non-technical users, in Turkish. It
> starts with the one command you must never run.

---

### ✨ Features

| Category | Feature |
|----------|---------|
| **Encryption** | AES-256-GCM per-file, unique nonce, AAD-bound to file metadata |
| **Key Splitting** | Shamir 2-of-3 SSS — share_1 in Argon2id-encrypted vault file, share_2 in OS credential store, share_3 printed as an offline recovery share |
| **Secret Storage** | `keyring` — Windows DPAPI / macOS Keychain / Linux Secret Service; no plaintext secrets on disk |
| **Authentication** | Argon2id PIN hash + TOTP (Google Authenticator / Aegis) |
| **Hardware Lock** | USB HWID binding — vault locks instantly on USB removal (in-app control; see Security Notes) |
| **Idle Auto-Lock** | Session locks after N minutes of inactivity even with the USB inserted; PIN required to resume (default 10 min, configurable) |
| **SafeZone** | Temporary decrypted copies never touch the system temp directory — shredded on exit, and leftovers from a crash are shredded at startup |
| **Transparent Access** | Open a document in its default application; edits are re-encrypted automatically with a fresh nonce and the plaintext copy is shredded — no manual re-encrypt step |
| **Encrypted Backup** | Copy the vault to external media; database metadata is encrypted, never plaintext. Backups verify **without the key** and restore refuses to run on a corrupt one — verify from the menu (**Yedek Doğrula…**) or the CLI (`backup_cli.py --verify`); restore stays CLI-only |
| **Brute-force Defence** | Login rate limit — 5 failures → 30s, escalating to 300s; counter persisted in DB |
| **Access Control** | RBAC: Administrator / Standard / Read-only roles |
| **Malware Scan** | Every uploaded file — Windows Defender (`MpCmdRun.exe`) on Windows, ClamAV (`clamdscan`/`clamscan`) elsewhere |
| **File Labels** | General · Critical · Quarantine · Destruction Room |
| **Destruction TTL** | Configurable auto-delete timer (1 / 6 / 12 / 24 / 48 h) |
| **Bulk Operations** | Multi-select, bulk tag, bulk move, bulk download with progress |
| **Parallel Upload** | QThreadPool (max 6 workers) — process 150 files without UI freeze |
| **Folder Hierarchy** | Drag-and-drop folder support, recursive vault creation |
| **Tags** | Color-coded tags, private (admin-only) tags, bulk assignment |
| **Audit Log** | Every action recorded with user, timestamp, and detail; entries form a SHA-256 hash chain anchored outside the database |
| **Integrity Sweep** | Weekly background verification of every `.hcl` GCM tag — verification only, plaintext is never assembled |
| **Trusted Timestamp** | Optional RFC 3161 timestamp over the plaintext hash; verified **fully offline** from the certificate chain inside the token — from the CLI (`--verify-timestamp`) or from the file context menu (**Damgayı Doğrula**) |
| **Dark / Light UI** | Full theme support, readable in both modes |

---

### 🛡 Security Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      LOGIN FLOW                         │
│                                                         │
│  PIN ──► Argon2id KEK ──► Decrypt vault file            │
│                                └─► share_1              │
│                                        │                │
│  USB HWID verified ──► OS keyring ──► share_2           │
│                                        │                │
│                   Shamir Reconstruct(share_1, share_2)  │
│                                        │                │
│                                  AES-256 master_key     │
│                                        │                │
│  TOTP (RFC 6238) ──► 6-digit verify    │                │
│                                        ▼                │
│                              Vault Unlocked             │
│                                                         │
│  ⚠ share_1 is protected by Argon2id KEK (requires PIN).│
│    share_2: OS credential store, keyed to HWID.         │
│    The HWID check is an in-app control only — it does   │
│    not stop an attacker who reads the disk directly.    │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                    FILE ENCRYPTION                      │
│  Plain file ──► AES-256-GCM ──► .hcl (vault format)    │
│                     │                                   │
│              AAD: filename + hwid + timestamp           │
│              Unique 12-byte nonce per file              │
│              SHA-256 integrity check (original + vault) │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                   USB LOCK MECHANISM                    │
│  USB removed ──► centralWidget.setEnabled(False)        │
│               ──► Blur overlay raised                   │
│               ──► All interactions blocked              │
│  USB inserted ──► HWID re-verified ──► Unlock           │
└─────────────────────────────────────────────────────────┘
```

**Cryptographic stack:**
- `cryptography` — AES-256-GCM, HKDF
- `argon2-cffi` — Argon2id PIN hashing
- `pyotp` — TOTP (RFC 6238)
- `secrets` / `os.urandom` — nonce and key material generation
- `sqlite3` — WAL-mode database, foreign keys enforced

---

### 📋 Requirements

- **Python** 3.11 or higher
- **Windows** 10 / 11 (64-bit)
- **USB drive** (registered during first-run setup)
- **Authenticator app** — Google Authenticator, Aegis, or any TOTP-compatible app

---

### 🚀 Installation

#### 1. Clone the repository

```bash
git clone https://github.com/yubin-dev/HYCLEUS.git
cd HYCLEUS
```

#### 2. Create virtual environment and install dependencies

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

#### 3. (Optional) Enable development mode — no physical USB required

```bash
set DEV_MODE=true
python main.py
```

> **Production use:** Never run with `DEV_MODE=true`. A real registered USB token is required.

#### 4. Build a distributable

```bash
pip install -r requirements-build.txt
```

**Windows — single-file EXE**

```powershell
.\packaging\windowsuild-exe.ps1
.\packaging\windows\smoke-test.ps1
# Output: dist\HYCLEUS.exe  (single file, no console)
```

`build-exe.ps1` wraps `pyinstaller HYCLEUS.spec` with the two checks whose
absence produced B-024: the clean-tree precondition (`-TemizAgac`) and the
"was an EXE actually produced" postcondition.

**Linux — AppImage**

```bash
./packaging/linux/build-appimage.sh --test
# Output: dist/HYCLEUS-<version>-x86_64.AppImage
```

PyInstaller does **not** cross-compile: each platform's build must run on
that platform. The AppImage is produced on every push by the `appimage` job
in `.github/workflows/ci.yml` and uploaded as an artifact.

Inside an AppImage the mount is read-only, so the vault lives under
`$XDG_DATA_HOME/HYCLEUS` (default `~/.local/share/HYCLEUS`) instead of next
to the binary — see `CORE/paths.py`.

**Verifying a build without a GUI**

```bash
HYCLEUS --version     # version string only
HYCLEUS --selftest    # imports every module, reports what is missing
# Expected: "SELFTEST OK" with loaded == attempted
#           (57 on Windows — 53 plus the wmi/pywin32 group)
```

**This is automated.** Both builds are produced on every push and both are
smoke-tested — `appimage` on ubuntu-latest, `exe` on windows-latest — and a
missing module fails the job. Run it by hand only when building outside CI.

`--selftest` is what caught B-024: ten modules were missing from the
packaged app while the app itself started up and looked fine.

---

### 🖥 First Run — Setup Wizard

When launched for the first time, the setup wizard guides you through:

1. **Select role**

   | Role | Permissions |
   |------|-------------|
   | Administrator | Full access — all features enabled |
   | Standard | File management, Critical tab visible |
   | Read-only | View only — drag-drop and Critical tab disabled |

2. **Set PIN** — Minimum 6 characters, confirmed twice; stored as Argon2id hash

3. **Configure TOTP** — Scan the QR code with your authenticator app, then enter the 6-digit code to verify

4. **"Verify & Save"** — Settings written securely to `data/`

---

### 📖 Usage

#### Uploading Files

Drag and drop any file or folder onto the main window. Each file is:
1. Encrypted with AES-256-GCM → saved as `.hcl` in the vault
2. Registered in the SQLite database with SHA-256 integrity hashes
3. Scanned by the platform's antivirus engine in a background thread

A progress banner shows **"X / N processed"** during batch uploads. A notification appears when all files complete.

#### File Labels

| Label | Description |
|-------|-------------|
| **General** | Standard encrypted files |
| **Critical** | High-priority; hidden from Read-only users |
| **Quarantine** | Flagged for review; antivirus scan status visible |
| **Destruction Room** | Scheduled for permanent deletion (configurable TTL) |

#### Multi-Selection & Bulk Actions

Hold `Ctrl` or `Shift` to select multiple rows, then right-click for:

- **Assign Tags** — bulk tag assignment (intersection pre-check)
- **Move to Critical** — skips already-Critical files
- **Send to Destruction Room** — applies configured TTL
- **Download** — single TOTP verification, QProgressDialog with cancellation
- **Release from Quarantine** — bulk approve

#### USB Lock

Removing the USB token instantly blurs the window and blocks all input. Re-inserting the registered USB resumes the session automatically.

#### Admin Panel

Administrators have access to:
- **Pending Registrations** — approve or reject new user registrations
- **USB Management** — register, view, and blacklist USB tokens
- **Settings** — configure Destruction Room TTL (1 / 6 / 12 / 24 / 48 hours)
- **Audit Log** — full action history with timestamps

---

### 📁 Project Structure

```
HYCLEUS/
├── main.py                   # Entry point
├── requirements.txt
├── requirements-dev.txt      # pytest, ruff, mypy, bandit
├── requirements-security.txt # semgrep (separate — 57 MB wheel)
├── requirements-build.txt    # PyInstaller (packaging only)
├── pyproject.toml            # ruff / mypy / bandit config
├── HYCLEUS.spec              # PyInstaller spec — Windows EXE
├── HYCLEUS-linux.spec        # PyInstaller spec — Linux (AppImage)
├── packaging/linux/          # AppRun, .desktop, icon, build + smoke test
├── packaging/windows/        # EXE build + smoke test (PowerShell)
├── .semgrep/hycleus.yml      # Project-specific semgrep rules
├── .github/workflows/
│   ├── ci.yml                # Tests, ruff, mypy, bandit, semgrep, AppImage, EXE
│   └── fuzz.yml              # atheris fuzzing — manually triggered
├── tests/
│   ├── fuzz/                 # Fuzz targets (crypto container, Shamir)
│   └── canary_semgrep/       # Deliberately unsafe — proves rules fire
├── CORE/
│   ├── version.py            # Single source of the version string
│   ├── crypto.py             # AES-256-GCM encryption (.hcl format)
│   ├── paths.py              # data_dir() — EXE-aware path resolution
│   ├── scanner.py            # Antivirus scan flow (engine-independent)
│   ├── scanner_backends.py   # Defender / ClamAV backends
│   ├── scheduler.py          # APScheduler — expired file cleanup
│   ├── setup_usb.py          # CLI USB registration tool
│   ├── backup.py             # Encrypted backup + verifiable restore
│   ├── backup_cli.py         # CLI: --verify / --restore (restore is CLI-only)
│   ├── checkout.py           # Transparent access (open → edit → re-encrypt)
│   ├── hwid_probe.py         # PROTOTYPE: cross-platform USB id (not wired in)
│   ├── timestamp.py          # RFC 3161 trusted timestamps (.hcl trailer)
│   ├── timestamp_verify.py   # Offline timestamp verification (no network)
│   ├── timestamp_report.py   # Verification result → plain language (UI)
│   ├── verify_timestamp_cli.py  # CLI: --verify-timestamp <file>
│   ├── usb_manager.py        # USB HWID detection (WMI)
│   └── vault_manager.py      # Shamir SSS + key reconstruction
├── DB/
│   ├── db_manager.py         # SQLite3 singleton, schema bootstrap
│   └── migrations.py         # Numbered schema-migration ledger (1..21 + future)
├── UI/
│   ├── main_window.py        # Main window, QThreadPool, USB lock overlay
│   ├── dialog_kit.py         # Shared plumbing for report dialogs
│   ├── login_dialog.py       # Login / first-run setup (Argon2id + TOTP)
│   ├── AdminPanel.py         # Admin: registrations, USB mgmt, settings
│   ├── RegisterDialog.py     # New user registration dialog
│   ├── TagDialog.py          # Tag assignment (single + bulk mode)
│   └── ContactDialog.py      # Support / contact dialog
└── data/                     # Not committed — runtime data only
    ├── hycleus.db            # SQLite database (WAL mode)
    ├── usb_ids.json          # Registered USB HWID map
    └── vaults/               # AES-256-GCM encrypted .hcl files
```

---

### 🔐 Security Notes

- PIN is stored as an **Argon2id** hash under `data/` — never written in plaintext
- The TOTP secret and `share_2` live in the **OS credential store** (service `HYCLEUS`): Windows Credential Manager / DPAPI, macOS Keychain, Linux Secret Service. `share_2` is keyed per device as `share_2:<hwid>`, so each registered USB has its own share
- Legacy installs are migrated automatically on first launch: `data/totp_secret.json` and the `share_2` column in the DB are overwritten with random bytes and then removed (`CORE/secret_migration.py`)
- If the credential store is unreachable (headless Linux, no Secret Service), the app refuses to start — it never falls back to plaintext
- Encrypted files (`.hcl`) and the contents of `data/` are excluded from the repository
- Login attempts are rate limited: 5 failures lock the login for 30s, then 60s / 120s / 300s (capped). The counter lives in the database, not in memory, so restarting the app does not clear it (`CORE/rate_limit.py`)
- The key is split **2-of-3**: any two of `share_1` (vault), `share_2` (credential store) and `share_3` (recovery share) reconstruct it. Export the recovery share with `python CORE/recover_vault.py --export` and store it **on paper, physically** — never digitally. It is never written to disk by HYCLEUS. See SECURITY.md §4.4 for why it must be treated as equivalent to the master key
- The audit log records every action with user identity, timestamp and detail

**What these controls do _not_ cover.** The USB HWID check and the login rate limit are **application-level controls**. They constrain what can be done *through the HYCLEUS interface*; they do not constrain an attacker who can read or write the files directly:

- The HWID check does not protect `share_2` — the OS credential store does. Removing the USB, or editing the `usb_tokens` row, does not make the stored share readable
- An attacker with filesystem access can delete the `login_attempts` table or rewind `locked_until`, defeating the rate limit
- An attacker who copies the vault file (`.hclv`) can brute-force it offline without ever running this code. The only defence there is the Argon2id cost (time=3, memory=64 MB, parallelism=4)
- Secure-erase during migration overwrites in place; on SSDs (wear levelling), copy-on-write filesystems and snapshots that assumption does not hold

Full-disk encryption is the control that covers the offline-attacker case. HYCLEUS does not replace it.

> The full threat model — trust boundaries, known weaknesses, and how to report a vulnerability — is in **[SECURITY.md](SECURITY.md)**. This section is the summary.

---

### 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---
---

## 🇹🇷 Türkçe

### HYCLEUS Nedir?

HYCLEUS, hassas dosyaları donanıma bağlı şifreli bir kasada yönetmek için geliştirilmiş bir Windows masaüstü uygulamasıdır. Her dosya diske yazılmadan önce **AES-256-GCM** ile şifrelenir. Ana anahtar **Shamir 2-of-3 Gizli Paylaşımı** ile üçe bölünür — üç paydan herhangi ikisi anahtarı geri getirir. share_1, Argon2id PIN-türevli KEK ile şifreli yerel kasa dosyasında (`.hclv`) saklanır; share_2 ise **işletim sistemi anahtar kasasında** (Windows Credential Manager / macOS Keychain / Linux Secret Service) `HYCLEUS` / `share_2:<hwid>` adıyla tutulur. TOTP sırrı da aynı şekilde saklanır. Anahtar kasasına erişilemezse HYCLEUS düz metne geri dönmek yerine açılmayı reddeder. Ana anahtarı yeniden oluşturmak için hem doğru PIN hem de kayıtlı USB cihazının fiziksel olarak mevcut olması zorunludur.

---

> **USB'nizi, PIN'inizi ya da kurtarma kâğıdınızı mı kaybettiniz?** Önce
> **[docs/kullanici-rehberi.md](docs/kullanici-rehberi.md)** dosyasını okuyun —
> teknik bilgi gerektirmeyen, adım adım bir rehber. Asla çalıştırmamanız
> gereken tek komutla başlıyor.

---

### ✨ Özellikler

| Kategori | Özellik |
|----------|---------|
| **Şifreleme** | AES-256-GCM, dosya başına benzersiz nonce, metadata'ya bağlı AAD |
| **Anahtar Bölme** | Shamir 2-of-3 SSS — share_1 Argon2id şifreli kasa dosyasında, share_2 OS anahtar kasasında, share_3 çevrimdışı kurtarma parçası olarak basılır |
| **Sır Saklama** | `keyring` — Windows DPAPI / macOS Keychain / Linux Secret Service; diskte düz metin sır yok |
| **Kimlik Doğrulama** | Argon2id PIN hash + TOTP (Google Authenticator / Aegis) |
| **Donanım Kilidi** | USB HWID bağlama — USB çekilince kasa anında kilitlenir (arayüz seviyesi kontrol; bkz. Güvenlik Notları) |
| **Hareketsizlik Kilidi** | USB takılı olsa bile N dakika hareketsizlikte oturum kilitlenir; devam için PIN gerekir (varsayılan 10 dk, yapılandırılabilir) |
| **SafeZone** | Geçici çözülmüş kopyalar sistem TEMP'ine hiç yazılmaz — çıkışta imha edilir, çökme sonrası artıklar açılışta temizlenir |
| **Şeffaf Erişim** | Belgeyi varsayılan uygulamasında açın; düzenleme yeni bir nonce ile otomatik geri şifrelenir ve düz metin kopya güvenli silinir — elle yeniden şifreleme adımı yok |
| **Şifreli Yedekleme** | Kasayı harici medyaya kopyalayın; veritabanı metadata'sı şifreli gider, düz metin asla. Yedekler **anahtarsız** doğrulanabilir ve bozuk bir yedek geri yüklenmez — doğrulama menüden (**Yedek Doğrula…**) ya da komut satırından (`backup_cli.py --verify`); geri yükleme yalnızca komut satırında |
| **Kaba Kuvvet Savunması** | Giriş sınırlaması — 5 hatada 30 sn, 300 sn'ye kadar artan; sayaç DB'de kalıcı |
| **Erişim Kontrolü** | RBAC: Yönetici / Standart / Salt Okunur rolleri |
| **Zararlı Tarama** | Her yüklenen dosyaya: Windows'ta Windows Defender (`MpCmdRun.exe`), diğer platformlarda ClamAV (`clamdscan`/`clamscan`) |
| **Dosya Etiketleri** | Genel · Kritik · Karantina · İmha Odası |
| **İmha TTL** | Yapılandırılabilir otomatik silme süresi (1 / 6 / 12 / 24 / 48 saat) |
| **Toplu İşlemler** | Çoklu seçim, toplu etiket, toplu taşıma, progress'li toplu indirme |
| **Paralel Yükleme** | QThreadPool (max 6 worker) — 150 dosyayı UI donmadan işler |
| **Klasör Hiyerarşisi** | Drag-and-drop klasör desteği, özyinelemeli kasa oluşturma |
| **Etiket Sistemi** | Renkli etiketler, gizli (sadece Yönetici) etiketler, toplu atama |
| **Denetim Kaydı** | Her işlem kullanıcı, zaman ve detayla kayıt altına alınır; kayıtlar veritabanı dışına çıpalanan bir SHA-256 hash zinciri oluşturur |
| **Bütünlük Taraması** | Haftalık arka plan taraması her `.hcl` dosyasının GCM tag'ini doğrular — yalnızca doğrulama, düz metin hiç birleştirilmez |
| **Güvenilir Zaman Damgası** | Düz metin özeti üzerinde opsiyonel RFC 3161 damgası; token'ın içindeki sertifika zinciriyle **tamamen çevrimdışı** doğrulanır — komut satırından (`--verify-timestamp`) ya da dosya sağ tık menüsünden (**Damgayı Doğrula**) |
| **Karanlık / Açık Tema** | Tam tema desteği, her iki modda da okunabilir |

---

### 🛡 Güvenlik Mimarisi

```
┌─────────────────────────────────────────────────────────┐
│                     GİRİŞ AKIŞI                         │
│                                                         │
│  PIN ──► Argon2id KEK ──► Kasa dosyasını çöz           │
│                                └─► share_1              │
│                                        │                │
│  USB HWID doğrulandı ──► OS kasası ──► share_2          │
│                                        │                │
│                 Shamir Birleştirme(share_1, share_2)    │
│                                        │                │
│                               AES-256 master_key        │
│                                        │                │
│  TOTP (RFC 6238) ──► 6 haneli doğrula  │                │
│                                        ▼                │
│                              Kasa Açıldı                │
│                                                         │
│  ⚠ share_1, Argon2id KEK ile korunur (PIN gerekli).    │
│    share_2, OS anahtar kasasında HWID'e bağlı tutulur.  │
│    HWID kontrolü yalnızca uygulama arayüzü seviyesinde  │
│    çalışır; diski doğrudan okuyan saldırganı durdurmaz. │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                   DOSYA ŞİFRELEME                       │
│  Düz dosya ──► AES-256-GCM ──► .hcl (kasa formatı)     │
│                     │                                   │
│              AAD: dosya adı + hwid + zaman damgası      │
│              Dosya başına benzersiz 12 byte nonce        │
│              SHA-256 bütünlük kontrolü (orijinal + kasa) │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                   USB KİLİT MEKANİZMASI                 │
│  USB çekildi ──► centralWidget.setEnabled(False)        │
│               ──► Bulanıklaştırma overlay'i açıldı      │
│               ──► Tüm etkileşimler engellendi           │
│  USB takıldı ──► HWID yeniden doğrulandı ──► Kilit açık │
└─────────────────────────────────────────────────────────┘
```

**Kriptografi yığını:**
- `cryptography` — AES-256-GCM, HKDF
- `argon2-cffi` — Argon2id PIN hashleme
- `pyotp` — TOTP (RFC 6238)
- `secrets` / `os.urandom` — nonce ve anahtar materyali üretimi
- `sqlite3` — WAL modu, foreign key zorlaması

---

### 📋 Gereksinimler

- **Python** 3.11 veya üzeri
- **Windows** 10 / 11 (64-bit)
- **USB sürücü** (ilk çalıştırmada kayıt edilir)
- **Authenticator uygulaması** — Google Authenticator, Aegis veya TOTP uyumlu herhangi bir uygulama

---

### 🚀 Kurulum

#### 1. Depoyu klonlayın

```bash
git clone https://github.com/yubin-dev/HYCLEUS.git
cd HYCLEUS
```

#### 2. Sanal ortam oluşturun ve bağımlılıkları yükleyin

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

#### 3. (Opsiyonel) Geliştirici modu — fiziksel USB gerekmez

```bash
set DEV_MODE=true
python main.py
```

> **Üretim kullanımı:** `DEV_MODE=true` ile asla çalıştırmayın. Gerçek kayıtlı USB token zorunludur.

#### 4. Dağıtılabilir yapı üretme

```bash
pip install -r requirements-build.txt
```

**Windows — tek dosya EXE**

```powershell
.\packaging\windowsuild-exe.ps1
.\packaging\windows\smoke-test.ps1
# Çıktı: dist\HYCLEUS.exe  (tek dosya, konsol yok)
```

`build-exe.ps1`, `pyinstaller HYCLEUS.spec` çağrısını B-024'ün yokluğunda
oluştuğu iki denetimle sarıyor: temiz ağaç ön koşulu (`-TemizAgac`) ve
"EXE gerçekten üretildi mi" son koşulu.

**Linux — AppImage**

```bash
./packaging/linux/build-appimage.sh --test
# Çıktı: dist/HYCLEUS-<sürüm>-x86_64.AppImage
```

PyInstaller **çapraz derleme yapmaz**: her platformun yapısı o platformda
üretilmek zorunda. AppImage her push'ta `.github/workflows/ci.yml`
içindeki `appimage` işi tarafından üretiliyor ve artifact olarak yükleniyor.

AppImage içinde bağlama noktası salt okunur olduğu için kasa, ikilinin
yanında değil `$XDG_DATA_HOME/HYCLEUS` altında duruyor (varsayılan
`~/.local/share/HYCLEUS`) — bkz. `CORE/paths.py`.

**Yapıyı GUI açmadan doğrulama**

```bash
HYCLEUS --version     # yalnızca sürüm dizesi
HYCLEUS --selftest    # her modülü içe aktarır, eksikleri raporlar
# Beklenen: "SELFTEST OK" ve yüklenen == denenen
#           (Windows'ta 57 — 53 artı wmi/pywin32 grubu)
```

**Bu artık otomatik.** İki yapı da her push'ta üretiliyor ve ikisi de duman
testinden geçiyor — `appimage` ubuntu-latest'te, `exe` windows-latest'te — ve
eksik bir modül işi kırıyor. Elle çalıştırmak yalnızca CI dışında yapı
alırken gerekli.

B-024'ü bulan `--selftest` idi: paketlenmiş uygulamada on modül eksikti ve
uygulama yine de açılıp normal görünüyordu.

---

### 🖥 İlk Çalıştırma — Kurulum Sihirbazı

İlk açılışta kurulum sihirbazı sizi adım adım yönlendirir:

1. **Rol seçin**

   | Rol | Yetkiler |
   |-----|----------|
   | Yönetici | Tam erişim — tüm özellikler aktif |
   | Standart | Dosya yönetimi, Kritik sekme görünür |
   | Salt Okunur | Yalnızca görüntüleme — drag-drop ve Kritik sekme devre dışı |

2. **PIN belirleyin** — En az 6 karakter, iki kez girilir; Argon2id hash olarak saklanır

3. **TOTP ayarlayın** — Authenticator uygulamasıyla QR kodu tarayın, ardından üretilen 6 haneli kodu doğrulama alanına girin

4. **"Doğrula ve Kaydet"** — Ayarlar `data/` klasörüne güvenli biçimde yazılır

---

### 📖 Kullanım

#### Dosya Yükleme

Herhangi bir dosyayı veya klasörü ana pencereye sürükleyip bırakın. Her dosya:
1. AES-256-GCM ile şifrelenir → `.hcl` formatında kasaya kaydedilir
2. SHA-256 bütünlük hash'leriyle SQLite veritabanına işlenir
3. Arka plan thread'inde platformun antivirüs motoruyla taranır

Toplu yükleme sırasında **"X / N işlendi"** banner'ı görünür. Tüm dosyalar tamamlandığında bildirim çıkar.

#### Dosya Etiketleri

| Etiket | Açıklama |
|--------|----------|
| **Genel** | Standart şifreli dosyalar |
| **Kritik** | Yüksek öncelikli; Salt Okunur kullanıcılardan gizlenir |
| **Karantina** | İnceleme için işaretlenmiş; antivirüs tarama durumu görünür |
| **İmha Odası** | Kalıcı silme için zamanlanmış (yapılandırılabilir TTL) |

#### Çoklu Seçim ve Toplu İşlemler

Birden fazla satır seçmek için `Ctrl` veya `Shift` tuşuna basılı tutun, ardından sağ tıklayın:

- **Etiket Ata** — toplu etiket atama (ortak etiket kesişim kontrolüyle)
- **Kritik'e Taşı** — zaten Kritik olan dosyaları atlar
- **İmha Odasına At** — yapılandırılmış TTL uygular
- **İndir** — tek TOTP doğrulaması, iptal destekli QProgressDialog
- **Karantinadan Çıkar** — toplu onaylama

#### USB Kilidi

USB token çekildiğinde pencere anında bulanıklaşır ve tüm girişler bloke edilir. Kayıtlı USB yeniden takıldığında oturum otomatik olarak devam eder.

#### Yönetici Paneli

Yöneticiler şu özelliklere erişebilir:

- **Bekleyen Kayıtlar** — yeni kullanıcı kayıt taleplerini onayla veya reddet
- **USB Yönetimi** — USB token kaydet, görüntüle ve kara listeye al
- **Ayarlar** — İmha Odası TTL'ini yapılandır (1 / 6 / 12 / 24 / 48 saat)
- **Denetim Kaydı** — zaman damgalı tam işlem geçmişi

---

### 📁 Proje Yapısı

```
HYCLEUS/
├── main.py                   # Giriş noktası
├── requirements.txt
├── requirements-dev.txt      # pytest, ruff, mypy, bandit
├── requirements-security.txt # semgrep (ayrı — 57 MB tekerlek)
├── pyproject.toml            # ruff / mypy / bandit yapılandırması
├── .semgrep/hycleus.yml      # Projeye özel semgrep kuralları
├── .github/workflows/
│   ├── ci.yml                # Testler, ruff, mypy, bandit, semgrep, AppImage, EXE
│   └── fuzz.yml              # atheris fuzzing — elle tetiklenir
├── tests/
│   ├── fuzz/                 # Fuzz hedefleri (kripto kabı, Shamir)
│   └── canary_semgrep/       # Bilerek güvensiz — kuralların canlı kanıtı
├── HYCLEUS.spec              # PyInstaller spec — Windows EXE
├── HYCLEUS-linux.spec        # PyInstaller spec — Linux (AppImage)
├── packaging/linux/          # AppRun, .desktop, simge, yapı + duman testi
├── packaging/windows/        # EXE yapısı + duman testi (PowerShell)
├── requirements-build.txt    # PyInstaller (yalnızca paketleme)
├── CORE/
│   ├── version.py            # Sürüm dizesinin tek kaynağı
│   ├── crypto.py             # AES-256-GCM şifreleme (.hcl formatı)
│   ├── paths.py              # data_dir() — EXE-duyarlı yol çözümü
│   ├── scanner.py            # Antivirüs tarama akışı (motordan bağımsız)
│   ├── scanner_backends.py   # Defender / ClamAV arka uçları
│   ├── scheduler.py          # APScheduler — süresi dolmuş dosya temizliği
│   ├── setup_usb.py          # CLI USB kayıt aracı
│   ├── backup.py             # Şifreli yedekleme + doğrulanabilir geri yükleme
│   ├── backup_cli.py         # CLI: --verify / --restore (geri yükleme yalnızca CLI)
│   ├── checkout.py           # Şeffaf erişim (aç → düzenle → geri şifrele)
│   ├── hwid_probe.py         # PROTOTİP: çapraz platform USB kimliği (bağlı değil)
│   ├── timestamp.py          # RFC 3161 zaman damgası (.hcl fragmanı)
│   ├── timestamp_verify.py   # Çevrimdışı damga doğrulama (ağ gerekmez)
│   ├── timestamp_report.py   # Doğrulama sonucu → sade Türkçe (arayüz)
│   ├── verify_timestamp_cli.py  # CLI: --verify-timestamp <dosya>
│   ├── usb_manager.py        # USB HWID tespiti (WMI)
│   └── vault_manager.py      # Shamir SSS + anahtar birleştirme
├── DB/
│   ├── db_manager.py         # SQLite3 singleton, şema kurulumu
│   └── migrations.py         # Numaralı göç kayıt defteri (1..21 + gelecek)
├── UI/
│   ├── main_window.py        # Ana pencere, QThreadPool, USB kilit overlay
│   ├── dialog_kit.py         # Rapor diyaloglarının ortak tesisatı
│   ├── login_dialog.py       # Giriş / ilk kurulum (Argon2id + TOTP)
│   ├── AdminPanel.py         # Yönetici: kayıtlar, USB yönetimi, ayarlar
│   ├── RegisterDialog.py     # Yeni kullanıcı kayıt diyaloğu
│   ├── TagDialog.py          # Etiket atama (tekli + toplu mod)
│   └── ContactDialog.py      # Destek / iletişim diyaloğu
└── data/                     # Git'e gitmez — çalışma zamanı verileri
    ├── hycleus.db            # SQLite veritabanı (WAL modu)
    ├── usb_ids.json          # Kayıtlı USB HWID haritası
    └── vaults/               # AES-256-GCM şifreli .hcl dosyaları
```

---

### 🔐 Güvenlik Notları

- PIN `data/` içinde **Argon2id** ile hashlenerek saklanır — düz metin asla yazılmaz
- TOTP sırrı ve `share_2` **işletim sistemi anahtar kasasındadır** (`HYCLEUS` servisi): Windows Credential Manager / DPAPI, macOS Keychain, Linux Secret Service. `share_2` cihaz başına `share_2:<hwid>` adıyla saklanır — her kayıtlı USB'nin kendi payı vardır
- Eski kurulumlardan gelen `data/totp_secret.json` ve DB'deki `share_2` sütunu, ilk açılışta otomatik olarak kasaya taşınır; eski kopyaların üzerine rastgele veri yazılıp silinir (`CORE/secret_migration.py`)
- Anahtar kasasına erişilemezse (başsız Linux, servis yok) uygulama açılmaz — sessizce düz metne geri dönmez
- Şifreli dosyalar (`.hcl`) ve `data/` içeriği depoya dahil edilmez
- USB token çekilince tüm widget etkileşimleri `setEnabled(False)` ile bloke edilir
- Giriş denemeleri sınırlıdır: 5 hatada 30 sn kilit, sonra 60 / 120 / 300 sn (tavan). Sayaç bellekte değil veritabanındadır — uygulamayı yeniden başlatmak kilidi kaldırmaz (`CORE/rate_limit.py`)
- Anahtar **2-of-3** bölünür: `share_1` (vault), `share_2` (anahtar kasası) ve `share_3` (kurtarma parçası) — herhangi ikisi anahtarı geri getirir. Kurtarma parçasını `python CORE/recover_vault.py --export` ile alın ve **kâğıda basıp fiziksel olarak** saklayın, asla dijital olarak değil. HYCLEUS bu parçayı hiçbir zaman diske yazmaz. Neden master key'e denk muamele görmesi gerektiği: SECURITY.md §4.4
- Denetim kaydı her işlemi kullanıcı kimliği, zaman damgası ve detayla saklar

**Bu kontrollerin kapsamadıkları.** USB HWID kontrolü ve giriş sınırlaması **uygulama arayüzü seviyesinde** kontrollerdir. *HYCLEUS arayüzü üzerinden* yapılabilecekleri sınırlarlar; dosyaları doğrudan okuyup yazabilen bir saldırganı sınırlamazlar:

- HWID kontrolü `share_2`'yi korumaz — onu koruyan işletim sistemi anahtar kasasıdır. USB'yi çıkarmak veya `usb_tokens` satırını düzenlemek kasadaki payı okunabilir hâle getirmez
- Dosya sistemine erişimi olan bir saldırgan `login_attempts` tablosunu silebilir veya `locked_until` alanını geriye çekerek giriş sınırlamasını aşabilir
- Vault dosyasını (`.hclv`) kopyalayan bir saldırgan bu koddan hiç geçmeden çevrimdışı kaba kuvvet uygulayabilir. Oradaki tek savunma Argon2id maliyetidir (time=3, bellek=64 MB, paralellik=4)
- Migration sırasındaki güvenli silme yerinde üzerine yazar; SSD (wear levelling), kopyala-yaz dosya sistemleri ve snapshot'larda bu varsayım geçerli değildir

Çevrimdışı saldırgan senaryosunu kapatan kontrol tam disk şifrelemesidir. HYCLEUS onun yerine geçmez.

> Tam tehdit modeli — güven sınırları, bilinen zayıflıklar ve açık bildirimi — **[SECURITY.md](SECURITY.md)** dosyasındadır. Bu bölüm özettir.

---

### 📜 Lisans

MIT Lisansı — ayrıntılar için [LICENSE](LICENSE) dosyasına bakın.
