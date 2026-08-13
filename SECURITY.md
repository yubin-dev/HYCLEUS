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
| Only one Shamir share obtained | ✅ | 2-of-3 is information-theoretically secure; one share reveals nothing |
| Brute-forcing the PIN through the app UI | ⚠️ Slowed | Rate limit: 5 failures → 30s, escalating to 300s, counter persisted in DB |
| An audit entry edited or deleted from the middle of the log | ⚠️ Detected, not prevented | SHA-256 hash chain; `verify_audit_chain()` names the exact record — see §4.6 |
| The newest audit entries deleted (log truncated) | ⚠️ Detected only via the anchor | The chain head is written outside the database to `data/audit_anchor.log` — see §4.6 |
| The whole audit chain recomputed after an edit | ⚠️ Detected only via the anchor | The hash is unkeyed; only the external anchor disagrees — see §4.6 |
| A `.hcl` file silently corrupted on disk (bit rot, bad copy, tampering) | ✅ Found without opening it | Weekly integrity sweep verifies every GCM tag; result in `files.integrity_status` — see §4.7 |
| Someone reaching an unattended, still-unlocked session | ⚠️ Time-limited | Idle auto-lock: session locks after N minutes of no input even with the USB inserted; unlock requires the PIN — see §4.8 |
| Decrypted copies left in the system temp directory | ✅ Not written there | Temporary plaintext goes to `data/safezone/`, shredded on exit and on next startup — see §4.8 |

---

## 3. What HYCLEUS does **not** protect against

These are not bugs. They are the boundaries of the design.

**An attacker who can read the disk.** The SQLite database
(`data/hycleus.db`) is **not encrypted**. Filenames, user records, roles,
HWIDs and the entire audit log are plaintext on disk. `sqlcipher3` is a
planned migration, not a shipped feature. Encrypted file *contents* stay
protected; everything around them does not.

**An attacker who can write to the disk.** The audit log is an ordinary
table in that same unencrypted database, and nothing stops anyone with write
access from editing or deleting rows. Since v2.2 those edits are *detectable*
— the log is a hash chain anchored outside the database — but detection is
not prevention, the chain covers only entries written after the upgrade, and
one of the two detection mechanisms can be defeated by an attacker who is
thorough. Read §4.6 before relying on it.

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

### 4.4 The recovery share is a third path to the key

Since v2.1.2 the master key is split 2-of-3. The third share — the **recovery
share** — is never stored by HYCLEUS: it is displayed once and kept
physically by the user. That is a deliberate trade, and it cuts both ways:

- **It removes a failure mode.** Losing the USB or the credential store no
  longer means losing every file.
- **It adds an attack path.** Anyone holding the printed recovery share
  *and* one live share reconstructs the master key. Combined with disk
  access (which yields `share_2` from the credential store as the logged-in
  user), the recovery share alone is enough — **the PIN is not required on
  that path.**

So the recovery share must be treated as equivalent to the master key, and
stored somewhere the machine's attacker cannot reach: a safe, a deposit box,
a different building. A recovery share photographed onto a phone, stored in
a password manager or left in a cloud note reduces the scheme to 1-of-2.

The recovery share is **derivable, not random**: it is `f(3)` of the same
polynomial, so anyone holding the other two shares can reproduce it at any
time. Re-exporting does not rotate it. Rotating it means re-splitting, which
means re-keying the vault.

**Recovery preserves the key and the polynomial — deliberately.**
`recover_vault.py --recover` re-provisions through `reprovision_vault()`,
which reuses the recovered `master_key` *and* anchors the polynomial on the
recovery share. So after recovery:

- existing `.hcl` files still decrypt (the master key did not change), and
- the printed recovery share stays valid (`f(1)`, `f(2)`, `f(3)` are unchanged).

The trade-off is that **nothing is rotated**. If an old `share_2` leaked
before the loss, it remains a valid share. Rotating would mean re-splitting,
which invalidates the paper the user is holding — and a paper that silently
stops working is worse than a share that might have leaked, because the user
only finds out at the next loss, when it is too late. If you *do* want
rotation, re-key deliberately and export a fresh recovery share immediately.

> ⚠️ `setup_usb.py --reset` is **not** a recovery path. It generates a new
> master key, which makes every existing `.hcl` file permanently
> undecryptable and invalidates the recovery share. It now requires typing
> `SIFIRLA` to confirm and points at `--recover` instead.

### 4.5 Application-level controls are labelled as such

The USB HWID check and the login rate limit constrain what can be done
*through the HYCLEUS interface*. Neither constrains someone operating on the
files directly. We say this here because the earlier README claimed
`share_2` was "guarded by HWID check" — it was not, and the claim has been
corrected.

### 4.6 The audit chain is tamper-evident, and only from v2.2 onward

Since v2.2 every audit entry carries the hash of the one before it
(`CORE/audit_chain.py`):

```
hash_n = SHA256( hash_(n-1) || canonical(entry_n) )
```

`hash_0` is 32 zero bytes. `canonical()` is a fixed-order, length-prefixed
byte encoding of every `audit_log` column except the hash itself — `id`,
`timestamp`, `user_id`, `action`, `target_type`, `target_id`, `detail`. The
length prefix is what makes it unambiguous: without it, an attacker could
write a separator and a field name into `detail` and forge the byte image of
a different record. Verification is `verify_audit_chain()`, which walks the
chain and reports the exact record where it breaks.

**The chain starts at the upgrade, and the boundary is marked, not hidden.**
Entries written before v2.2 cannot be chained: there was no "previous hash"
when they were written, so no hash can be computed for them after the fact.
Computing one now would produce a region that *looks* protected and is not —
the worst possible outcome. Instead:

- a real audit entry with `action = 'audit_chain_genesis'` is written as the
  first link, and its `detail` records how many unchained rows existed and
  the last unchained `id`;
- its id is also stored in `settings.audit_chain_start_id`;
- `verify_audit_chain()` refuses to verify anything before that id and
  reports the count as `unchained_before`.

**Everything before that marker is out of scope.** Pre-v2.2 entries can be
edited or deleted with no trace whatsoever, exactly as before. If those
entries matter, export them and store the export outside the machine.

**What the chain does not do:**

- **It is unkeyed.** SHA-256, not HMAC. Anyone who can write to the database
  can edit a record and recompute every hash after it; the result verifies
  perfectly. A keyed MAC would not fix this, because the key would have to
  live on the same machine (the same problem as the vault HMAC, §4.2).
- **It does not detect truncation.** Deleting the newest N entries leaves no
  gap and no mismatch — the remainder verifies cleanly.
- **It says nothing about events that were never logged.** The chain shows
  that written entries are intact, not that the record is complete.

**The anchor is what covers those two gaps.** The head of the chain — the
last hash — is periodically written outside the database, to an append-only
`data/audit_anchor.log`. Storing it in the database would add nothing: same
file, same attacker, same single write. With the anchor, rewriting the log
means keeping *two* files consistent, and one of them is a plain-text file
that can be copied off the machine. It is written unconditionally at
shutdown, and at most once per UTC day otherwise — at startup and hourly
from the scheduler, so a machine left running for weeks still gets a daily
mark. At startup `verify_against_anchor()` compares the newest anchor
against the database and HYCLEUS warns if they disagree; the warning does
not block login, because the audit log is a record, not an access control.

Two honest caveats about the anchor. "Append-only" is a discipline of this
code, **not an OS guarantee** — whoever can write the file can truncate it.
Each line therefore carries the SHA-256 of the previous line
(`verify_anchor_file()`), so editing a line in the middle is caught, but
cutting the end is not. And an anchor sitting in `data/` next to the database
shares much of its attack surface: it raises the cost of a rewrite, it does
not close it. **The anchor is only as good as where it is kept.** Point
`HYCLEUS_AUDIT_ANCHOR` at a USB stick, a network share or a read-only
location to move it into a genuinely different trust domain — that is where
the property becomes real rather than merely inconvenient for an attacker.

A remote append-only log would be stronger still. HYCLEUS is deliberately
offline, so that option was not taken; the trade is stated here rather than
papered over.

### 4.7 The integrity sweep finds corruption, but its verdict lives in the DB

A weekly background sweep (`CORE/integrity.py`) verifies the GCM tag of
every registered `.hcl` and the vault's HMAC, writing the result to
`files.integrity_status` and `files.integrity_checked_at`. Unlike the audit
chain, this check is **keyed**: the GCM tag is computed under the AES-256
master key, so nobody without the key can alter a file and produce a tag
that still verifies. On that specific point it is strong.

The limits:

- **The verdict is stored in the unencrypted database.** `UPDATE files SET
  integrity_status = 'ok'` erases the finding. The *file* cannot be forged;
  the *report about it* can. The audit-log entry for the same finding is
  harder to erase — it is in the hash chain (§4.6) — which is why the sweep
  writes to both.
- **Only files with a database row are checked.** Delete the row and the
  `.hcl` becomes invisible to the sweep. Orphaned files on disk are not
  reported.
- **The sweep runs weekly, not continuously.** Worst case, corruption sits
  undetected for a week plus however long the application stays closed.
- **A wrong key looks exactly like mass corruption.** GCM cannot tell them
  apart. If *every* file fails the tag check the sweep refuses to mark
  anything, logs `integrity_sweep_aborted` and reports
  `suspected_wrong_key`. The trade is deliberate: a genuinely
  fully-corrupted vault also lands in this branch and is reported as a
  suspected key problem instead of as corruption. Marking every file
  corrupt on a wrong key would be worse — the user would lose the ability
  to spot a real single-file failure.

The sweep never reconstructs plaintext. It streams each file through the
same GCM primitives as decryption but discards every block into a single
reused buffer that is zeroed on exit, so verification costs constant memory
regardless of file size. Plaintext still exists transiently per 64 KB block
— GCM produces it while advancing — so the honest claim is "never
accumulated, returned, or written", not "never produced". See
`CORE.crypto.verify_file()`.

### 4.8 Idle lock and SafeZone close two gaps, neither completely

**Idle auto-lock.** The hardware lock only fires when the USB is *removed*,
but someone who walks away from their desk usually leaves it plugged in. The
session now also locks after N minutes without mouse or keyboard input
(default 10, configurable in the admin panel, `0` disables it and that
disabling is audited under its own action). Unlocking requires the vault
PIN — deliberately not "any mouse movement", which would make it a
screensaver rather than a control.

It is one overlay with two triggers and a set of lock *reasons*: if the USB
is reinserted while the session is idle-locked, the session stays locked.
The two triggers have different exit conditions, not different widgets.

What it does not do: it constrains the **application window only**. It does
not lock the workstation, and it does nothing about a machine left logged in
with other applications open. The OS screen lock is the control for that;
this one is narrower on purpose. The setting also lives in the unencrypted
database, so `UPDATE settings SET value='0'` disables it — with the same
caveat as every other application-level control (§4.5).

**SafeZone.** When decrypted content has to reach disk it goes to
`data/safezone/`, never the system temp directory. Temp is the wrong place
for three reasons: its cleanup is on the OS's schedule and uses `unlink`
rather than overwriting, its contents are indexed and backed up by tools we
do not control, and it may sit on a different volume than the one
`shred_file()`'s assumptions were written for. SafeZone files are shredded
(random overwrite → fsync → truncate → unlink) when the work finishes, again
at shutdown, and anything found at startup is treated as evidence of a crash,
shredded, and logged under `safezone_orphans_purged`.

Two honest notes. The overwrite carries exactly the same limits as
everywhere else in this codebase — SSD wear levelling, copy-on-write
filesystems and snapshots can leave the original blocks intact (§3). And on
Windows the directory inherits `data/`'s ACL rather than getting owner-only
permissions, so what protects SafeZone there is the protection on `data/`,
not this code.

As of this version **no flow writes plaintext to disk at all** — downloads
stream straight to the path the user picks. SafeZone is infrastructure
placed ahead of the open/preview flow, on the reasoning that whoever writes
that flow will reach for `tempfile` if the safe path is not already there.

### 4.9 Timestamps are stored, not yet verified — and can be stripped

A `.hcl` file can now carry an RFC 3161 timestamp token, obtained by having
a Timestamp Authority sign the **plaintext SHA-256** already recorded in the
AAD (`original_sha256`). Because the hash is taken from the header, stamping
needs **no key and never touches plaintext**. What the token proves is
narrow but real: this content existed no later than the time the TSA signed.

Three limits, all deliberate at this stage:

**The signature is not checked yet.** This step obtains the token and
validates its *shape* — status, message imprint, nonce, hash algorithm — but
does not verify that the TSA's signature is genuine or that its certificate
chains anywhere. Right now HYCLEUS **stores** what the TSA returned; it does
not vouch for it. Offline verification is the next step, and until it lands
a timestamp should be read as a record, not as proof.

**The trailer is outside the GCM tag.** The tag covers the AAD and the
ciphertext only — not the magic, the version byte, or the timestamp trailer.
So a timestamp can be **deleted**: strip the trailer and the file still
decrypts cleanly, simply looking unstamped. "Never stamped" and "stamp
removed" are indistinguishable from the file alone. A timestamp cannot be
*forged* — the token is bound to a specific plaintext hash — but it can be
made to disappear. Defending against that requires recording stamps
somewhere other than the file they describe, which is the same argument the
audit anchor makes in §4.6.

**Without a key, the stamped hash is unverified.** `original_sha256` sits in
the AAD, which GCM protects — but checking that protection requires the key.
Stamping without one takes the header's word for it. `timestamp_file()`
accepts an optional key and runs `verify_file()` first when given one; the
caller decides which trade it wants.

Container versioning: files written before this change are version `0x01`
and are still read unchanged. New files are `0x02`, and `0x02` **without** a
trailer is entirely valid — the stamp is optional and added later. Version
`0x01` files are never scanned for a trailer, since the format did not
define one.

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
| Key splitting | Shamir 2-of-3 over GF(p), p = 2²⁵⁶ + 297 (verified prime); `f(x) = s + a₁x`, `a₁ ← [1, p−1]`; shares at x = 1, 2, 3 |
| Audit log integrity | SHA-256 hash chain, `hash_n = SHA256(hash_(n-1) ‖ canonical(entry_n))`, `hash_0` = 32 zero bytes; unkeyed — see §4.6 |
| Audit record encoding | Fixed field order, length-prefixed UTF-8, `NULL` distinct from `""` — deterministic and library-independent |
| Audit anchor | Chain head appended to `data/audit_anchor.log` (JSON Lines, each line carries SHA-256 of the previous); path overridable via `HYCLEUS_AUDIT_ANCHOR` |
| Integrity sweep | Weekly GCM tag verification of every `.hcl` + vault HMAC; streaming, constant memory, no plaintext returned — see §4.7 |
| PIN storage | Argon2id hash (never plaintext); minimum 6 characters for new PINs |
| Secret storage | OS credential store, service `HYCLEUS`, usernames `share_2:<hwid>` and `totp_secret` |
| Second factor | TOTP (RFC 6238), 6 digits, ±1 window |
| Trusted timestamp | RFC 3161, SHA-256 message imprint over the **plaintext** hash, nonce + `certReq`; token stored in an optional file trailer outside the GCM tag — signature not verified yet, see §4.9 |

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
| Yalnızca bir Shamir payı ele geçirildi | ✅ | 2-of-3 bilgi-teorik olarak güvenli; tek pay hiçbir şey sızdırmaz |
| Arayüz üzerinden PIN kaba kuvveti | ⚠️ Yavaşlatılır | 5 hatada 30 sn, 300 sn'ye tırmanır, sayaç DB'de kalıcı |
| Denetim kaydının ORTASINDAN bir satırın değiştirilmesi/silinmesi | ⚠️ Tespit edilir, engellenmez | SHA-256 hash zinciri; `verify_audit_chain()` tam olarak hangi kayıt olduğunu söyler — bkz. §4.6 |
| En yeni denetim kayıtlarının silinmesi (kuyruğun kesilmesi) | ⚠️ Yalnızca çıpayla tespit edilir | Zincirin ucu veritabanının dışına, `data/audit_anchor.log`'a yazılır — bkz. §4.6 |
| Değişiklikten sonra tüm zincirin yeniden hesaplanması | ⚠️ Yalnızca çıpayla tespit edilir | Hash anahtarsızdır; yalnızca dıştaki çıpa itiraz eder — bkz. §4.6 |
| Bir `.hcl` dosyasının diskte sessizce bozulması (bit çürümesi, yarım kopyalama, müdahale) | ✅ Dosya açılmadan bulunur | Haftalık bütünlük taraması her GCM tag'ini doğrular; sonuç `files.integrity_status` içinde — bkz. §4.7 |
| Başında kimse olmayan, açık kalmış bir oturuma erişilmesi | ⚠️ Süreyle sınırlı | Hareketsizlik kilidi: USB takılı olsa bile N dakika giriş olmazsa oturum kilitlenir, açmak PIN ister — bkz. §4.8 |
| Çözülmüş kopyaların sistem TEMP dizininde kalması | ✅ Oraya hiç yazılmaz | Geçici düz metin `data/safezone/`'a gider; çıkışta ve sonraki açılışta imha edilir — bkz. §4.8 |

## 3. HYCLEUS'un **korumadığı** senaryolar

Bunlar hata değil, tasarımın sınırlarıdır.

**Diski okuyabilen saldırgan.** SQLite veritabanı (`data/hycleus.db`)
**şifreli değildir.** Dosya adları, kullanıcı kayıtları, roller, HWID'ler ve
denetim kaydının tamamı diskte düz metindir. `sqlcipher3` planlanmış bir
geçiştir, mevcut bir özellik değil. Şifreli dosya *içerikleri* korunmaya
devam eder; etraflarındaki her şey korunmaz.

**Diske yazabilen saldırgan.** Denetim kaydı, aynı şifresiz veritabanında
sıradan bir tablodur ve dosyaya yazabilen birinin satır değiştirmesini ya da
silmesini hiçbir şey engellemez. v2.2'den itibaren bu müdahaleler *fark
edilebilir* — kayıt, ucu veritabanının dışına çıpalanan bir hash zinciridir.
Ama fark etmek engellemek değildir, zincir yalnızca yükseltmeden SONRAKİ
kayıtları kapsar ve iki tespit mekanizmasından biri yeterince titiz bir
saldırgan tarafından aşılabilir. Buna güvenmeden önce §4.6'yı okuyun.

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

### 4.4 Kurtarma parçası anahtara giden üçüncü yoldur

v2.1.2'den itibaren master key 2-of-3 bölünüyor. Üçüncü pay — **kurtarma
parçası** — HYCLEUS tarafından hiçbir zaman saklanmıyor: bir kez gösterilip
kullanıcı tarafından fiziksel olarak saklanıyor. Bu bilinçli bir takas ve
iki yönü var:

- **Bir arıza modunu ortadan kaldırıyor.** USB'yi ya da anahtar kasasını
  kaybetmek artık tüm dosyaları kaybetmek anlamına gelmiyor.
- **Bir saldırı yolu ekliyor.** Basılı kurtarma parçasını *ve* canlı
  paylardan birini elinde tutan master key'i yeniden oluşturur. Disk
  erişimiyle birlikte (oturum açmış kullanıcı olarak anahtar kasasından
  `share_2` alınabilir), kurtarma parçası tek başına yeterlidir — **o yolda
  PIN gerekmez.**

Dolayısıyla kurtarma parçası master key'e denk muamele görmeli ve makinenin
saldırganının ulaşamayacağı bir yerde saklanmalıdır: kasa, kiralık kasa,
başka bir bina. Telefona fotoğraflanmış, parola yöneticisine konmuş ya da
bulut notunda bırakılmış bir kurtarma parçası şemayı 1-of-2'ye düşürür.

Kurtarma parçası **rastgele değil, türetilebilirdir**: aynı polinomun
`f(3)`'ü olduğu için diğer iki paya sahip olan onu her an yeniden
üretebilir. Yeniden dışa aktarmak parçayı DEĞİŞTİRMEZ. Değiştirmek yeniden
bölmeyi, o da vault'un yeniden anahtarlanmasını gerektirir.

**Kurtarma anahtarı ve polinomu bilerek korur.**
`recover_vault.py --recover`, `reprovision_vault()` üzerinden yeniden
kurulum yapar: kurtarılan `master_key`'i tekrar kullanır *ve* polinomu
kurtarma parçasına çıpalar. Böylece kurtarma sonrasında:

- mevcut `.hcl` dosyaları açılmaya devam eder (master key değişmedi), ve
- basılı kurtarma parçası geçerli kalır (`f(1)`, `f(2)`, `f(3)` aynı).

Takas şu: **hiçbir şey döndürülmez (rotate edilmez).** Kayıptan önce bir
`share_2` kopyası sızmışsa geçerli kalmaya devam eder. Döndürmek yeniden
bölme demek, o da kullanıcının elindeki kâğıdı geçersizleştirir — sessizce
çalışmayı bırakan bir kâğıt, sızmış olabilecek bir paydan daha kötüdür,
çünkü kullanıcı bunu ancak bir sonraki kayıpta, iş işten geçtikten sonra
öğrenir. Döndürme istiyorsanız bilinçli olarak yeniden anahtarlayın ve
hemen ardından yeni kurtarma parçasını dışa aktarın.

> ⚠️ `setup_usb.py --reset` bir kurtarma yolu **değildir**. Yeni bir master
> key üretir; bu da mevcut tüm `.hcl` dosyalarını kalıcı olarak açılamaz
> hâle getirir ve kurtarma parçasını geçersizleştirir. Artık onay için
> `SIFIRLA` yazılmasını istiyor ve kullanıcıyı `--recover`'a yönlendiriyor.

### 4.5 Uygulama seviyesi kontroller böyle etiketlenmiştir

USB HWID kontrolü ve giriş sınırlaması *HYCLEUS arayüzü üzerinden*
yapılabilecekleri sınırlar. İkisi de dosyalar üzerinde doğrudan çalışan
birini sınırlamaz. Bunu burada söylüyoruz çünkü README daha önce `share_2`'nin
"HWID kontrolüyle korunduğunu" iddia ediyordu — korumuyordu ve iddia
düzeltildi.

### 4.6 Denetim zinciri kurcalama KANITIDIR ve yalnızca v2.2'den itibaren geçerlidir

v2.2'den itibaren her denetim kaydı bir öncekinin hash'ini taşır
(`CORE/audit_chain.py`):

```
hash_n = SHA256( hash_(n-1) || kanonik(kayıt_n) )
```

`hash_0` 32 sıfır byte'tır. `kanonik()`, `audit_log`'un hash dışındaki bütün
sütunlarının — `id`, `timestamp`, `user_id`, `action`, `target_type`,
`target_id`, `detail` — sabit sıralı, uzunluk önekli byte kodlamasıdır.
Kodlamayı tek anlamlı kılan şey uzunluk önekidir: o olmasaydı saldırgan
`detail` alanına bir ayraç ve alan adı yazarak başka bir kaydın byte
görüntüsünü taklit edebilirdi. Doğrulama `verify_audit_chain()` ile yapılır;
zinciri baştan sona gezer ve tam olarak hangi kayıtta kırıldığını söyler.

**Zincir yükseltmeyle başlar ve bu sınır gizlenmez, işaretlenir.** v2.2
öncesinde yazılmış kayıtlar zincire alınamaz: o kayıtlar yazılırken "önceki
hash" diye bir şey yoktu, dolayısıyla geriye dönük hesaplanamaz. Şimdi
hesaplansaydı ortaya korunuyormuş *gibi görünen* ama korunmayan bir bölge
çıkardı — olabilecek en kötü sonuç. Bunun yerine:

- zincirin ilk halkası olarak `action = 'audit_chain_genesis'` adlı gerçek
  bir denetim kaydı yazılır; `detail` alanı o an kaç zincirlenmemiş satır
  olduğunu ve son zincirlenmemiş `id`'yi tutar;
- kaydın id'si ayrıca `settings.audit_chain_start_id` içine yazılır;
- `verify_audit_chain()` bu id'den öncesini doğrulamayı reddeder ve sayıyı
  `unchained_before` olarak raporlar.

**Bu işaretten öncesi tamamen kapsam dışıdır.** v2.2 öncesi kayıtlar
eskisi gibi hiçbir iz bırakmadan değiştirilebilir ya da silinebilir. O
kayıtlar önemliyse dışa aktarın ve dışa aktarımı makinenin dışında saklayın.

**Zincirin YAPMADIKLARI:**

- **Anahtarsızdır.** HMAC değil, SHA-256. Veritabanına yazabilen biri bir
  kaydı değiştirip ondan sonraki bütün hash'leri yeniden hesaplayabilir;
  sonuç kusursuz doğrulanır. Anahtarlı bir MAC bunu çözmezdi, çünkü anahtar
  aynı makinede durmak zorunda olurdu (vault HMAC'ıyla aynı sorun, §4.2).
- **Kuyruğun kesilmesini yakalamaz.** En yeni N kaydı silmek ne boşluk ne
  uyuşmazlık bırakır — kalan kısım temiz doğrulanır.
- **Hiç yazılmamış olay hakkında bir şey söylemez.** Zincir yazılanların
  bütünlüğünü gösterir, kaydın eksiksizliğini değil.

**Bu iki boşluğu kapatan şey çıpadır.** Zincirin ucu — son hash — düzenli
olarak veritabanının dışına, append-only bir `data/audit_anchor.log`
dosyasına yazılır. Veritabanında saklamak hiçbir şey eklemezdi: aynı dosya,
aynı saldırgan, aynı tek yazma. Çıpayla birlikte kaydı yeniden yazmak *iki*
dosyayı tutarlı tutmayı gerektirir ve bunlardan biri makinenin dışına
kopyalanabilir bir düz metin dosyasıdır. Çıpa kapanışta koşulsuz, bunun
dışında günde en fazla bir kez (UTC) yazılır — açılışta ve zamanlayıcıdan
saatlik, böylece haftalarca açık bırakılan bir makinede de günlük bir iz
kalır. Açılışta `verify_against_anchor()` en son çıpayı veritabanıyla
karşılaştırır ve uyuşmazlık varsa HYCLEUS uyarır; uyarı girişi ENGELLEMEZ,
çünkü denetim kaydı bir erişim kontrolü değil, bir kayıttır.

Çıpa hakkında iki dürüst çekince. "Append-only" bu kodun disiplinidir,
**işletim sisteminin garantisi değil** — dosyaya yazabilen onu kesebilir de.
Bu yüzden her satır bir öncekinin SHA-256'sını taşır
(`verify_anchor_file()`); araya girip bir satırı değiştirmek yakalanır, ama
sonundan kesmek yakalanmaz. Ayrıca veritabanının yanında, `data/` içinde
duran bir çıpa onun saldırı yüzeyinin büyük kısmını paylaşır: yeniden yazma
maliyetini artırır, kapatmaz. **Çıpa ancak tutulduğu yer kadar iyidir.**
`HYCLEUS_AUDIT_ANCHOR` ile bir USB belleğe, ağ paylaşımına ya da salt-okunur
bir konuma yönlendirin — gerçekten farklı bir güven alanına taşınması, bu
özelliğin saldırgan için sadece zahmetli olmaktan çıkıp gerçek olduğu yerdir.

Uzak, yalnızca-ekleme yapılan bir günlük daha da güçlü olurdu. HYCLEUS
bilinçli olarak çevrimdışıdır, bu yüzden o yol seçilmedi; takas üstü
örtülmek yerine burada yazılıdır.

### 4.7 Bütünlük taraması bozulmayı bulur, ama kararı veritabanında durur

Haftalık arka plan taraması (`CORE/integrity.py`) kayıtlı her `.hcl`
dosyasının GCM tag'ini ve vault'un HMAC'ını doğrular; sonucu
`files.integrity_status` ve `files.integrity_checked_at` alanlarına yazar.
Denetim zincirinin aksine bu kontrol **anahtarlıdır**: GCM tag'i AES-256
master key altında hesaplanıyor, yani anahtarı olmayan biri dosyayı
değiştirip hâlâ doğrulanan bir tag üretemez. Tam olarak bu noktada güçlüdür.

Sınırlar:

- **Karar şifresiz veritabanında saklanıyor.** `UPDATE files SET
  integrity_status = 'ok'` bulguyu siler. *Dosya* taklit edilemez; *onun
  hakkındaki rapor* edilebilir. Aynı bulgunun denetim kaydındaki karşılığını
  silmek daha zordur — o hash zincirinin içinde (§4.6) — tarama bu yüzden
  ikisine birden yazıyor.
- **Yalnızca veritabanı kaydı olan dosyalar kontrol edilir.** Kaydı silinen
  bir `.hcl` tarama için görünmez olur. Diskte öksüz kalmış dosyalar
  raporlanmaz.
- **Tarama haftalık, sürekli değil.** En kötü durumda bozulma bir hafta artı
  uygulamanın kapalı kaldığı süre boyunca fark edilmez.
- **Yanlış anahtar, toplu bozulmayla birebir aynı görünür.** GCM ikisini
  ayırt edemez. *Tüm* dosyalar tag kontrolünü geçemezse tarama hiçbir şeyi
  işaretlemeyi reddeder, `integrity_sweep_aborted` kaydı düşer ve
  `suspected_wrong_key` raporlanır. Takas bilinçli: gerçekten tamamı
  bozulmuş bir kasa da bu dala düşer ve bozulma yerine anahtar şüphesi
  olarak raporlanır. Yanlış anahtarda her dosyayı bozuk işaretlemek daha
  kötü olurdu — kullanıcı gerçek bir tek-dosya arızasını fark edemez hâle
  gelirdi.

Tarama düz metni hiçbir zaman yeniden oluşturmaz. Her dosyayı şifre
çözmeyle aynı GCM ilkelleri üzerinden akıtır ama her bloğu yeniden
kullanılan tek bir tampona atar ve çıkışta sıfırlar; böylece doğrulamanın
bellek maliyeti dosya boyutundan bağımsız, sabittir. Düz metin yine de her
64 KB'lık blokta kısa süreliğine oluşur — GCM ilerlerken üretiyor — yani
dürüst iddia "biriktirilmez, döndürülmez, yazılmaz"dır, "hiç üretilmez"
değil. Bkz. `CORE.crypto.verify_file()`.

### 4.8 Hareketsizlik kilidi ve SafeZone iki boşluğu kapatıyor, ikisini de tam değil

**Hareketsizlik kilidi.** Donanım kilidi yalnızca USB ÇEKİLDİĞİNDE devreye
giriyor, ama masasından kalkan biri USB'yi genellikle takılı bırakır. Artık
oturum, N dakika fare/klavye girdisi olmazsa da kilitleniyor (varsayılan 10
dakika, yönetici panelinden yapılandırılabilir; `0` kapatır ve bu kapatma
kendi action'ıyla denetime düşer). Kilidi açmak vault PIN'i istiyor —
bilerek "herhangi bir fare hareketi" değil; öyle olsaydı bu bir ekran
koruyucu olurdu, güvenlik kontrolü değil.

Tek örtü, iki tetikleyici ve bir kilit NEDENLERİ kümesi: oturum
hareketsizlikten kilitliyken USB geri takılırsa oturum KİLİTLİ KALIR. İki
tetikleyicinin farkı görünüm değil, çıkış koşulu.

Yapmadığı şey: yalnızca UYGULAMA PENCERESİNİ sınırlar. İş istasyonunu
kilitlemez ve başka uygulamaları açık bırakılmış bir makine için hiçbir şey
yapmaz. Onun kontrolü işletim sisteminin ekran kilidi; bu bilerek daha dar.
Ayar da şifresiz veritabanında duruyor, yani `UPDATE settings SET
value='0'` onu kapatır — her uygulama seviyesi kontrolle aynı çekince
(§4.5).

**SafeZone.** Çözülmüş içeriğin diske inmesi gerektiğinde hedef
`data/safezone/`, asla sistem TEMP'i değil. TEMP üç nedenle yanlış yer:
temizliği işletim sisteminin takvimine bağlı ve üzerine yazarak değil
`unlink` ile yapılıyor, içeriği bizim kontrol etmediğimiz araçlarca
indeksleniyor ve yedekleniyor, ayrıca `shred_file()`'ın varsayımlarının
yazıldığı birimden başka bir birimde olabilir. SafeZone dosyaları iş
bitince, kapanışta ve açılışta imha ediliyor (rastgele üzerine yazma →
fsync → truncate → unlink); açılışta bulunan her şey bir ÇÖKME kanıtı
sayılıp `safezone_orphans_purged` olarak kaydediliyor.

İki dürüst not. Üzerine yazma, bu kod tabanının her yerindeki aynı sınırları
taşıyor — SSD wear leveling, kopyala-yaz dosya sistemleri ve snapshot'lar
orijinal blokları yerinde bırakabilir (§3). Windows'ta ise dizin,
sahibe-özel izinler yerine `data/`'nın ACL'ini devralıyor; yani SafeZone'u
orada koruyan şey `data/` üzerindeki koruma, bu kod değil.

Bu sürüm itibarıyla **hiçbir akış düz metni diske yazmıyor** — indirmeler
doğrudan kullanıcının seçtiği yola akıyor. SafeZone, aç/önizle akışından
ÖNCE konmuş bir altyapı; gerekçesi basit: o akışı yazan kişi, güvenli yol
hazır değilse `tempfile`'a uzanacaktır.

### 4.9 Zaman damgaları saklanıyor, henüz doğrulanmıyor — ve silinebilir

Bir `.hcl` dosyası artık RFC 3161 zaman damgası taşıyabiliyor: AAD'de zaten
kayıtlı olan **düz metin SHA-256**'sı (`original_sha256`) bir Zaman Damgası
Otoritesi'ne imzalatılıyor. Özet başlıktan okunduğu için damgalama
**anahtar istemiyor ve düz metne hiç dokunmuyor**. Kanıtladığı şey dar ama
gerçek: bu içerik, TSA'nın imzaladığı tarihte zaten vardı.

Bu aşamada bilinçli üç sınır var:

**İmza henüz doğrulanmıyor.** Bu adım token'ı alıyor ve *biçimini* kontrol
ediyor — status, message imprint, nonce, özet algoritması. Ama TSA'nın
imzasının gerçek olduğunu ya da sertifikasının bir yere zincirlendiğini
doğrulamıyor. HYCLEUS şu an TSA'nın verdiğini **saklıyor**, ona kefil
olmuyor. Çevrimdışı doğrulama sonraki adım; o gelene kadar bir zaman
damgası kanıt değil, kayıt olarak okunmalı.

**Fragman GCM tag'inin dışında.** Tag yalnızca AAD ile ciphertext'i
kapsıyor; magic, sürüm byte'ı ve zaman damgası fragmanı kapsam dışı. Yani
bir damga **silinebilir**: fragman kırpılırsa dosya sorunsuz çözülür,
yalnızca damgasız görünür. "Hiç damgalanmadı" ile "damgası silindi" dosyaya
bakarak ayırt EDİLEMEZ. Damga *uydurulamaz* — token belirli bir düz metin
özetine bağlı — ama yok edilebilir. Buna karşı korunmak, damga kaydının
tarif ettiği dosyadan başka bir yerde de tutulmasını gerektirir; §4.6'daki
denetim çıpasının gerekçesiyle birebir aynı argüman.

**Anahtarsız damgalamada özet doğrulanmamıştır.** `original_sha256` AAD'de
duruyor ve GCM onu koruyor, ama bu korumayı kontrol etmek anahtar ister.
Anahtarsız damgalama başlığın sözüne güvenir. `timestamp_file()` opsiyonel
bir anahtar alıyor ve verilirse önce `verify_file()` çalıştırıyor; hangi
takası istediğine çağıran karar veriyor.

Kap sürümü: bu değişiklikten önce yazılan dosyalar `0x01` ve aynen okunmaya
devam ediyor. Yeni dosyalar `0x02` ve fragmanı **olmayan** bir `0x02` de
tamamen geçerli — damga opsiyonel ve sonradan ekleniyor. `0x01` dosyalarda
fragman hiç aranmıyor, çünkü o formatta böyle bir şey tanımlı değildi.

## 5. Kriptografik ayrıntılar

| Katman | Yapı |
|---|---|
| Dosya içeriği | AES-256-GCM, 12 byte rastgele nonce, 16 byte tag, 64 KB akış |
| Dosya metadata | GCM AAD — JSON, doğrulanır, **şifrelenmez** |
| Düz metin bütünlüğü | Şifrelemeden önce hesaplanan SHA-256, AAD'a bağlanır |
| Vault KEK | Argon2id(PIN, 16 byte tuz), time=3, bellek=64 MB, paralellik=4, 32 byte |
| Vault mühürleme | AES-256-GCM, AAD = HWID (cihaz bağlama) |
| Vault imzası | HMAC-SHA256, anahtar = HKDF-SHA256(HWID) — bkz. §4.2 |
| Anahtar bölme | GF(p) üzerinde Shamir 2-of-3, p = 2²⁵⁶ + 297 (asallığı doğrulandı); `f(x) = s + a₁x`, `a₁ ← [1, p−1]`; paylar x = 1, 2, 3 |
| Denetim kaydı bütünlüğü | SHA-256 hash zinciri, `hash_n = SHA256(hash_(n-1) ‖ kanonik(kayıt_n))`, `hash_0` = 32 sıfır byte; anahtarsız — bkz. §4.6 |
| Denetim kaydı kodlaması | Sabit alan sırası, uzunluk önekli UTF-8, `NULL` ile `""` ayrı — deterministik ve kütüphaneden bağımsız |
| Denetim çıpası | Zincirin ucu `data/audit_anchor.log`'a eklenir (JSON Lines, her satır bir öncekinin SHA-256'sını taşır); yol `HYCLEUS_AUDIT_ANCHOR` ile değiştirilebilir |
| Bütünlük taraması | Haftalık GCM tag doğrulaması (her `.hcl`) + vault HMAC; akış hâlinde, sabit bellek, düz metin döndürülmez — bkz. §4.7 |
| PIN saklama | Argon2id hash (asla düz metin); yeni PIN'ler için en az 6 karakter |
| Sır saklama | OS anahtar kasası, servis `HYCLEUS`, adlar `share_2:<hwid>` ve `totp_secret` |
| İkinci faktör | TOTP (RFC 6238), 6 hane, ±1 pencere |
| Güvenilir zaman damgası | RFC 3161, **düz metin** özeti üzerinden SHA-256 message imprint, nonce + `certReq`; token GCM tag'inin dışındaki opsiyonel dosya fragmanında — imza henüz doğrulanmıyor, bkz. §4.9 |

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
