# Security Policy — HYCLEUS

**Applies to:** v2.1.0 · Last reviewed: 2026-08-13

This document describes what HYCLEUS actually protects, what it does not, and
the weaknesses we already know about. It is deliberately blunt: a security
document that only lists strengths is marketing, not security.

🇹🇷 [Türkçe sürüm aşağıda](#güvenlik-politikası--hycleus)

---

## 1. Trust boundaries

```
┌───────────────────────────────────────────────────────────────┐
│  OUTSIDE THE BOUNDARY — assumed hostile                       │
│                                                               │
│   · Anyone who can read data/ from disk or a backup           │
│   · Anyone who can copy the vault file (.hclv)                │
│   · Anyone who can write to data/hycleus.db                   │
│   · Malware running as the logged-in user                     │
│   · A stolen laptop without full-disk encryption              │
├───────────────────────────────────────────────────────────────┤
│  THE BOUNDARY                                                 │
│                                                               │
│   Secrets:  OS credential store (DPAPI / Keychain / Secret    │
│             Service) — bound to the OS user account           │
│   Content:  AES-256-GCM, key = Shamir(share_1, share_2)       │
│   share_1:  vault file, sealed with Argon2id(PIN) KEK         │
│   share_2:  OS credential store, key "share_2:<hwid>"         │
├───────────────────────────────────────────────────────────────┤
│  INSIDE THE BOUNDARY — trusted, not defended against          │
│                                                               │
│   · The logged-in OS user (the credential store answers them) │
│   · Anyone holding the PIN + the registered USB               │
│   · The running HYCLEUS process and its memory                │
└───────────────────────────────────────────────────────────────┘
```

The single most important consequence: **HYCLEUS defends the contents of
files, not the machine.** Once an attacker is the logged-in OS user, the
credential store will hand them `share_2` on request. The remaining barrier
is the PIN alone.

---

## 2. What HYCLEUS protects against

| Scenario | Protected? | By what |
|---|---|---|
| Encrypted file (`.hcl`) copied off the machine | ✅ | AES-256-GCM; key never stored whole |
| One byte of ciphertext or the GCM tag modified | ✅ | GCM authentication — `AuthenticationError`, never silent wrong plaintext |
| File metadata (filename, user_id, hwid, SHA-256) edited in the header | ✅ | Metadata is the GCM AAD; any edit fails authentication |
| Same key reused across files | ✅ | Fresh 12-byte `os.urandom` nonce per encryption |
| Vault file (`.hclv`) copied, PIN unknown | ✅ | Argon2id KEK (time=3, mem=64 MB, para=4) + GCM |
| `share_2` read out of the database | ✅ | It is no longer there — it lives in the OS credential store |
| Only one Shamir share obtained | ✅ | 2-of-2 is information-theoretically secure; one share reveals nothing |
| Brute-forcing the PIN through the app UI | ⚠️ Slowed | Rate limit: 5 failures → 30s, escalating to 300s, counter persisted in DB |
| Someone tampering with the DB to hide their tracks | ⚠️ Partial | Audit log records every action — but see §3 |

---

## 3. What HYCLEUS does **not** protect against

These are not bugs. They are the boundaries of the design.

**An attacker who can read the disk.** The SQLite database
(`data/hycleus.db`) is **not encrypted**. Filenames, user records, roles,
HWIDs and the entire audit log are plaintext on disk. `sqlcipher3` is a
planned migration, not a shipped feature. Encrypted file *contents* stay
protected; everything around them does not.

**An attacker who can write to the disk.** The audit log is an ordinary
table in that same unencrypted database. Anyone who can write to the file
can delete entries, and nothing detects it. The audit log is an operational
record, not tamper-evident evidence.

**Offline brute force of the vault.** Copy `.hclv` and attack it at leisure;
this codebase never runs. The only cost imposed is Argon2id
(time=3, memory=64 MB, parallelism=4). The login rate limit is irrelevant
here — it lives in the application, and the attacker is not using the
application.

**Rate-limit removal.** The counter is stored in `login_attempts` in the
unencrypted database. `DELETE FROM login_attempts` removes the lockout.
It cannot be encrypted — the application must be able to read its own
lockout. Rolling the system clock back also drops the lock early;
`locked_until` is an absolute timestamp, because a monotonic clock would
reset on restart and lose the property that matters most.

**A compromised OS user account.** The credential store releases `share_2`
to the logged-in user. Malware running as that user can ask for it the same
way HYCLEUS does.

**Memory.** Decrypted content lives in Python `bytes` objects. Intermediate
buffers are zeroed with `ctypes.memset`, but Python may have already copied
the data, and the returned `bytes` is immutable and cannot be wiped. A
memory dump or swap file can contain plaintext.

**Secure-erase guarantees.** Migration overwrites the old secret in place
before deleting it. That assumes the write lands on the same physical
sector — false on SSDs (wear levelling), copy-on-write filesystems (btrfs,
ReFS), snapshots and VM images. It is best-effort at the logical layer, not
a wipe.

**Metadata confidentiality.** In a `.hcl` file the AAD block — original
filename, SHA-256 of the plaintext, timestamps, `user_id`, `hwid` — is
authenticated but **not encrypted**. It is readable in the file header. The
SHA-256 also permits confirming a suspected file without decrypting it.

> The control that covers the offline-attacker cases is **full-disk
> encryption**. HYCLEUS is not a substitute for it.

---

## 4. Known weaknesses we are not hiding

### 4.1 Blacklisting a USB does not revoke anything

`blacklist_usb()` sets `blacklisted = 1` in `usb_tokens`. Both entry paths —
`authenticate_usb()` (USB re-insertion) and `open_vault()` (PIN login) —
now enforce it through the same helper, `_reject_if_blacklisted()`, so a
blacklisted device is refused on either route. Access is blocked. But:

- **It revokes no key material.** `share_1` stays in the vault file and
  `share_2` stays in the credential store under `share_2:<hwid>`. The
  master key remains reconstructible by anything that does not go through
  these two functions.
- **It is one DB write.** `UPDATE usb_tokens SET blacklisted = 0` undoes
  it, and the flag lives in the unencrypted database. The application
  offers this legitimately; an attacker with file access does it directly.

Treat the blacklist as an **administrative marker, not a revocation
mechanism** — and `open_vault()` now enforces that marker too, so it is at
least enforced consistently. Real revocation requires deleting the
credential-store entry (`delete_usb_token()`) and re-keying the vault.

> Until v2.1.0 the login path did **not** check the flag: a blacklisted USB
> with a valid PIN could still open the vault, because the login screen
> calls `open_vault()` directly and only `authenticate_usb()` consulted the
> blacklist. Fixed after this document first reported it.

### 4.2 The vault HMAC key is derived from a non-secret

The vault's HMAC-SHA256 signing key is `HKDF(hwid)` — and the HWID is a USB
serial number, not a secret. It is stored in `data/usb_ids.json`, in the DB,
and can be read from the device itself. **Anyone who knows the HWID can
forge a valid vault HMAC.**

The HMAC therefore provides tamper-*evidence* against someone who does not
know the HWID, which is a weak assumption. Confidentiality does not rest on
it: the ciphertext is protected by AES-256-GCM under the Argon2id/PIN-derived
KEK, with the HWID as AAD. The HMAC is a second, weaker layer — not the one
holding the door.

### 4.3 DEV_MODE derives the file key from the HWID alone

When `DEV_MODE` is set (and only when not running as a frozen executable),
the file-encryption key is `PBKDF2-HMAC-SHA256(hwid, fixed salt, 100 000)` —
**no PIN involved**. Anyone who knows the HWID can decrypt every file. This
is a development convenience and is force-disabled in built executables
(`sys.frozen`), but never enable it on a machine holding real data.

### 4.4 Application-level controls are labelled as such

The USB HWID check and the login rate limit constrain what can be done
*through the HYCLEUS interface*. Neither constrains someone operating on the
files directly. We say this here because the earlier README claimed
`share_2` was "guarded by HWID check" — it was not, and the claim has been
corrected.

---

## 5. Cryptographic details

| Layer | Construction |
|---|---|
| File contents | AES-256-GCM, 12-byte random nonce, 16-byte tag, 64 KB streaming |
| File metadata | GCM AAD — JSON, authenticated, **not encrypted** |
| Integrity of plaintext | SHA-256 computed before encryption, bound into the AAD |
| Vault KEK | Argon2id(PIN, 16-byte salt), time=3, memory=64 MB, parallelism=4, 32-byte output |
| Vault sealing | AES-256-GCM, AAD = HWID (device binding) |
| Vault signature | HMAC-SHA256, key = HKDF-SHA256(HWID) — see §4.2 |
| Key splitting | Shamir 2-of-2 over GF(p), p = 2²⁵⁶ + 297; `f(x) = s + a₁x`, `a₁ ← [1, p−1]` |
| PIN storage | Argon2id hash (never plaintext); minimum 6 characters for new PINs |
| Secret storage | OS credential store, service `HYCLEUS`, usernames `share_2:<hwid>` and `totp_secret` |
| Second factor | TOTP (RFC 6238), 6 digits, ±1 window |

**Randomness** comes from `os.urandom` and `secrets` throughout — nonces,
salts, master keys and the Shamir polynomial coefficient.

**Supported version:** only the latest release (currently v2.1.0) receives
security fixes.

---

## 6. Reporting a vulnerability

Please **do not open a public issue** for security problems.

Use GitHub's private reporting: **Security → Report a vulnerability** on
[this repository](https://github.com/yubin-dev/HYCLEUS/security/advisories/new).
It creates a private advisory visible only to the maintainer.

<!-- Maintainer: add a contact email here if you want one as an alternative
     channel. Left blank deliberately — publishing a personal address is
     your call, not something this document should assume. -->

**What helps:** affected version or commit, what an attacker gains, the
steps to reproduce, and the environment (OS, Python version). A proof of
concept is welcome but not required.

**What to expect:** acknowledgement within 7 days, an assessment within 30
days. HYCLEUS is maintained by one person as a non-commercial project —
there is no bounty programme and no formal SLA. Fixes land in a release with
credit, unless you prefer otherwise.

**Please avoid** while testing: attacking machines that are not yours,
accessing other people's data, and public disclosure before a fix ships.

**Already known?** Everything in §3 and §4 is documented on purpose. A report
that restates one of those will be closed as known — unless you can show it
is worse than described here, which is genuinely useful.

---
---

# Güvenlik Politikası — HYCLEUS

**Kapsam:** v2.1.0 · Son gözden geçirme: 2026-08-13

Bu belge HYCLEUS'un neyi koruduğunu, neyi korumadığını ve halihazırda
bildiğimiz zayıflıkları anlatır. Bilinçli olarak açık sözlüdür: yalnızca
güçlü yanları sıralayan bir güvenlik belgesi güvenlik değil, pazarlamadır.

## 1. Güven sınırları

```
┌───────────────────────────────────────────────────────────────┐
│  SINIRIN DIŞI — düşman kabul edilir                           │
│                                                               │
│   · data/ dizinini diskten veya yedekten okuyabilen herkes    │
│   · Vault dosyasını (.hclv) kopyalayabilen herkes             │
│   · data/hycleus.db dosyasına yazabilen herkes                │
│   · Oturum açmış kullanıcı olarak çalışan zararlı yazılım     │
│   · Tam disk şifrelemesi olmayan çalınmış bir dizüstü         │
├───────────────────────────────────────────────────────────────┤
│  SINIR                                                        │
│                                                               │
│   Sırlar : OS anahtar kasası (DPAPI / Keychain / Secret       │
│            Service) — OS kullanıcı hesabına bağlı             │
│   İçerik : AES-256-GCM, anahtar = Shamir(share_1, share_2)    │
│   share_1: vault dosyası, Argon2id(PIN) KEK ile mühürlü       │
│   share_2: OS anahtar kasası, ad "share_2:<hwid>"             │
├───────────────────────────────────────────────────────────────┤
│  SINIRIN İÇİ — güvenilir, savunulmaz                          │
│                                                               │
│   · Oturum açmış OS kullanıcısı (kasa ona cevap verir)        │
│   · PIN + kayıtlı USB'ye sahip olan herkes                    │
│   · Çalışan HYCLEUS süreci ve belleği                         │
└───────────────────────────────────────────────────────────────┘
```

En önemli sonuç: **HYCLEUS dosyaların içeriğini korur, makineyi değil.**
Saldırgan oturum açmış OS kullanıcısı hâline geldiğinde anahtar kasası
`share_2`'yi istediğinde verir. Geriye kalan tek engel PIN'dir.

## 2. HYCLEUS'un koruduğu senaryolar

| Senaryo | Korunuyor mu | Neyle |
|---|---|---|
| Şifreli dosya (`.hcl`) makineden kopyalandı | ✅ | AES-256-GCM; anahtar hiçbir yerde bütün durmuyor |
| Ciphertext veya GCM tag'inde tek byte değişti | ✅ | GCM doğrulaması — `AuthenticationError`, asla sessizce yanlış veri |
| Başlıktaki metadata (dosya adı, user_id, hwid, SHA-256) düzenlendi | ✅ | Metadata GCM AAD'sidir; her değişiklik doğrulamayı düşürür |
| Aynı anahtar dosyalar arasında yeniden kullanıldı | ✅ | Her şifrelemede taze 12 byte `os.urandom` nonce |
| Vault dosyası (`.hclv`) kopyalandı, PIN bilinmiyor | ✅ | Argon2id KEK (time=3, bellek=64 MB, para=4) + GCM |
| `share_2` veritabanından okundu | ✅ | Artık orada değil — OS anahtar kasasında |
| Yalnızca bir Shamir payı ele geçirildi | ✅ | 2-of-2 bilgi-teorik olarak güvenli; tek pay hiçbir şey sızdırmaz |
| Arayüz üzerinden PIN kaba kuvveti | ⚠️ Yavaşlatılır | 5 hatada 30 sn, 300 sn'ye tırmanır, sayaç DB'de kalıcı |
| Saldırganın izlerini silmek için DB'yi kurcalaması | ⚠️ Kısmen | Denetim kaydı her işlemi tutar — ama bkz. §3 |

## 3. HYCLEUS'un **korumadığı** senaryolar

Bunlar hata değil, tasarımın sınırlarıdır.

**Diski okuyabilen saldırgan.** SQLite veritabanı (`data/hycleus.db`)
**şifreli değildir.** Dosya adları, kullanıcı kayıtları, roller, HWID'ler ve
denetim kaydının tamamı diskte düz metindir. `sqlcipher3` planlanmış bir
geçiştir, mevcut bir özellik değil. Şifreli dosya *içerikleri* korunmaya
devam eder; etraflarındaki her şey korunmaz.

**Diske yazabilen saldırgan.** Denetim kaydı, aynı şifresiz veritabanında
sıradan bir tablodur. Dosyaya yazabilen kayıtları silebilir ve bunu hiçbir
şey tespit etmez. Denetim kaydı operasyonel bir kayıttır, kurcalanamaz bir
delil değil.

**Vault'un çevrimdışı kaba kuvvetle kırılması.** `.hclv` kopyalanıp rahatça
saldırıya uğrayabilir; bu kod hiç çalışmaz. Dayatılan tek maliyet
Argon2id'dir (time=3, bellek=64 MB, paralellik=4). Giriş sınırlaması burada
anlamsızdır — o uygulamanın içindedir, saldırgan ise uygulamayı kullanmıyor.

**Giriş sınırlamasının kaldırılması.** Sayaç, şifresiz veritabanındaki
`login_attempts` tablosundadır. `DELETE FROM login_attempts` kilidi kaldırır.
Şifrelenemez — uygulamanın kendi kilidini okuyabilmesi gerekir. Sistem
saatini geri almak da kilidi erken düşürür; `locked_until` mutlak zaman
damgasıdır, çünkü monotonik saat yeniden başlatmada sıfırlanır ve en çok
önemsediğimiz özelliği kaybettirirdi.

**Ele geçirilmiş OS kullanıcı hesabı.** Anahtar kasası `share_2`'yi oturum
açmış kullanıcıya verir. O kullanıcı olarak çalışan zararlı yazılım da
HYCLEUS'un istediği gibi isteyebilir.

**Bellek.** Çözülmüş içerik Python `bytes` nesnelerinde durur. Ara tamponlar
`ctypes.memset` ile sıfırlanır, ama Python veriyi çoktan kopyalamış olabilir
ve döndürülen `bytes` değiştirilemez olduğu için silinemez. Bellek dökümü ya
da takas dosyası düz metin içerebilir.

**Güvenli silme garantisi.** Migration eski sırrı silmeden önce üzerine
yazar. Bu, yazmanın aynı fiziksel sektöre indiğini varsayar — SSD'de (wear
levelling), kopyala-yaz dosya sistemlerinde (btrfs, ReFS), snapshot'larda ve
VM imajlarında bu yanlıştır. Mantıksal katmanda elden gelenin en iyisidir,
bir silme değil.

**Metadata gizliliği.** `.hcl` dosyasındaki AAD bloğu — orijinal dosya adı,
düz metnin SHA-256'sı, zaman damgaları, `user_id`, `hwid` — doğrulanır ama
**şifrelenmez.** Dosya başlığında okunabilir. SHA-256 ayrıca şüphelenilen bir
dosyanın şifresi çözülmeden doğrulanmasına imkân verir.

> Çevrimdışı saldırgan senaryolarını kapatan kontrol **tam disk
> şifrelemesidir.** HYCLEUS onun yerine geçmez.

## 4. Sakladığımız zayıflıklar yok — bilinenler

### 4.1 USB'yi kara listeye almak hiçbir şeyi iptal etmez

`blacklist_usb()` `usb_tokens` tablosunda `blacklisted = 1` yapar. Her iki
giriş yolu da — `authenticate_usb()` (USB yeniden takma) ve `open_vault()`
(PIN girişi) — artık aynı yardımcı üzerinden (`_reject_if_blacklisted()`)
bu bayrağı uygular; kara listedeki cihaz iki yolda da reddedilir. Erişim
engellenir. Ama:

- **Hiçbir anahtar materyalini iptal etmez.** `share_1` vault dosyasında,
  `share_2` anahtar kasasında `share_2:<hwid>` adıyla durmaya devam eder.
  Bu iki fonksiyondan geçmeyen her şey için master key hâlâ yeniden
  oluşturulabilir.
- **Tek bir DB yazması.** `UPDATE usb_tokens SET blacklisted = 0` geri alır
  ve bayrak şifresiz veritabanında durur. Uygulama bunu meşru olarak
  sunuyor; dosya erişimi olan saldırgan doğrudan yapar.

Kara listeyi **idari bir işaret olarak görün, iptal mekanizması olarak
değil** — ve `open_vault()` artık bu işareti o da uyguluyor, yani en azından
tutarlı biçimde uygulanıyor. Gerçek iptal, kasadaki kaydın silinmesini
(`delete_usb_token()`) ve vault'un yeniden anahtarlanmasını gerektirir.

> v2.1.0'a kadar giriş yolu bayrağı **kontrol etmiyordu**: kara listedeki bir
> USB, geçerli PIN'le vault'u yine de açabiliyordu, çünkü giriş ekranı
> `open_vault()`'u doğrudan çağırıyor ve kara listeye yalnızca
> `authenticate_usb()` bakıyordu. Bu belge sorunu ilk raporladıktan sonra
> düzeltildi.

### 4.2 Vault HMAC anahtarı sır olmayan bir şeyden türetiliyor

Vault'un HMAC-SHA256 imza anahtarı `HKDF(hwid)`'dir — ve HWID bir USB seri
numarasıdır, sır değil. `data/usb_ids.json` içinde, veritabanında saklanır ve
cihazın kendisinden okunabilir. **HWID'i bilen herkes geçerli bir vault HMAC'ı
üretebilir.**

Dolayısıyla HMAC yalnızca HWID'i bilmeyen birine karşı kurcalama *kanıtı*
sağlar ki bu zayıf bir varsayımdır. Gizlilik buna dayanmıyor: ciphertext,
Argon2id/PIN türevli KEK altında AES-256-GCM ile korunuyor ve HWID AAD olarak
bağlanıyor. HMAC ikinci, daha zayıf bir katmandır — kapıyı tutan o değildir.

### 4.3 DEV_MODE dosya anahtarını yalnızca HWID'den türetir

`DEV_MODE` açıkken (ve yalnızca donmuş çalıştırılabilir olarak çalışmıyorken)
dosya şifreleme anahtarı `PBKDF2-HMAC-SHA256(hwid, sabit tuz, 100 000)`
olur — **PIN hiç işin içinde değildir.** HWID'i bilen herkes tüm dosyaların
şifresini çözebilir. Bu bir geliştirme kolaylığıdır ve derlenmiş
çalıştırılabilirlerde zorla kapatılır (`sys.frozen`), ama gerçek veri tutan
bir makinede asla açmayın.

### 4.4 Uygulama seviyesi kontroller böyle etiketlenmiştir

USB HWID kontrolü ve giriş sınırlaması *HYCLEUS arayüzü üzerinden*
yapılabilecekleri sınırlar. İkisi de dosyalar üzerinde doğrudan çalışan
birini sınırlamaz. Bunu burada söylüyoruz çünkü README daha önce `share_2`'nin
"HWID kontrolüyle korunduğunu" iddia ediyordu — korumuyordu ve iddia
düzeltildi.

## 5. Kriptografik ayrıntılar

| Katman | Yapı |
|---|---|
| Dosya içeriği | AES-256-GCM, 12 byte rastgele nonce, 16 byte tag, 64 KB akış |
| Dosya metadata | GCM AAD — JSON, doğrulanır, **şifrelenmez** |
| Düz metin bütünlüğü | Şifrelemeden önce hesaplanan SHA-256, AAD'a bağlanır |
| Vault KEK | Argon2id(PIN, 16 byte tuz), time=3, bellek=64 MB, paralellik=4, 32 byte |
| Vault mühürleme | AES-256-GCM, AAD = HWID (cihaz bağlama) |
| Vault imzası | HMAC-SHA256, anahtar = HKDF-SHA256(HWID) — bkz. §4.2 |
| Anahtar bölme | GF(p) üzerinde Shamir 2-of-2, p = 2²⁵⁶ + 297; `f(x) = s + a₁x`, `a₁ ← [1, p−1]` |
| PIN saklama | Argon2id hash (asla düz metin); yeni PIN'ler için en az 6 karakter |
| Sır saklama | OS anahtar kasası, servis `HYCLEUS`, adlar `share_2:<hwid>` ve `totp_secret` |
| İkinci faktör | TOTP (RFC 6238), 6 hane, ±1 pencere |

**Rastgelelik** baştan sona `os.urandom` ve `secrets`'tan gelir — nonce'lar,
tuzlar, master key'ler ve Shamir polinom katsayısı.

**Desteklenen sürüm:** yalnızca en son sürüm (şu an v2.1.0) güvenlik
düzeltmesi alır.

## 6. Güvenlik açığı bildirimi

Güvenlik sorunları için lütfen **herkese açık issue açmayın.**

GitHub'ın özel bildirim yolunu kullanın: **Security → Report a vulnerability**
([bu depoda](https://github.com/yubin-dev/HYCLEUS/security/advisories/new)).
Yalnızca geliştiricinin görebileceği özel bir danışma kaydı oluşturur.

**İşe yarayanlar:** etkilenen sürüm veya commit, saldırganın ne kazandığı,
yeniden üretme adımları ve ortam (işletim sistemi, Python sürümü). Kavram
kanıtı memnuniyetle karşılanır ama zorunlu değildir.

**Beklenecekler:** 7 gün içinde alındı bildirimi, 30 gün içinde
değerlendirme. HYCLEUS ticari olmayan, tek kişilik bir projedir — ödül
programı ve resmî bir SLA yoktur. Düzeltmeler, aksini tercih etmediğiniz
sürece adınıza atıfla bir sürümde yayınlanır.

**Test ederken lütfen kaçının:** size ait olmayan makinelere saldırmaktan,
başkalarının verilerine erişmekten ve düzeltme yayınlanmadan kamuya
açıklamaktan.

**Zaten biliniyor mu?** §3 ve §4'teki her şey bilerek belgelenmiştir. Bunlardan
birini yineleyen bir bildirim "bilinen" olarak kapatılır — burada
anlatılandan daha kötü olduğunu gösterebiliyorsanız o başka, o gerçekten
değerlidir.
