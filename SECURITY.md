# Security Policy — HYCLEUS

**Applies to:** v2.2.0.dev (development tree) · Last reviewed: 2026-08-16

This document describes what HYCLEUS actually protects, what it does not, and
the weaknesses we already know about. It is deliberately blunt: a security
document that only lists strengths is marketing, not security.

🇹🇷 [Türkçe sürüm aşağıda](#güvenlik-politikası--hycleus)

---

## How to read this document

It is long because the honest answers are long. Nobody needs all of it at
once. Find your row, start there, and follow the cross-references — every
claim in §2 points at the §4 entry that qualifies it.

| If you are | Start here | Then |
|---|---|---|
| **An auditor or reviewer** | §1.1 — the three attacker models | §1.2 (which layer holds against which model) → §1.3 (the gaps we know about) → §4 (every weakness, in our own words) |
| **A developer working on HYCLEUS** | §1.2 — the layer matrix | §5 (constructions and parameters) → the §4 entry covering whatever you are changing |
| **A user or an administrator** | §2 — what is actually protected | §3 (what is not) → `docs/kullanici-rehberi.md` for step-by-step recovery, written without command-line assumptions |
| **About to report something** | §6.7 — is it already known? | §6.2 (scope) → §6.3 (what helps) → §6.1 (how to reach us) |

And by question:

| Question | Section |
|---|---|
| Who is HYCLEUS defending against — and who is it not? | §1.1 |
| Which layer stops which attacker, and where does each one stop? | §1.2 |
| What is deliberately outside the design? | §1.3, then §3 |
| What is protected, concretely, scenario by scenario? | §2 |
| Where is it weak, and how badly? | §4.1 – §4.12 |
| Which algorithms, which parameters? | §5 |
| How do I report a finding, and what happens next? | §6 |
| I lost my USB / forgot my PIN / my files look corrupt | `docs/kullanici-rehberi.md` |

Two conventions used throughout. **M1 / M2 / M3** name the attacker models
defined in §1.1; every scenario in §2, every limit in §3 and every weakness
in §4 is tagged with the models it applies to. And a claim tagged M2 is not
automatically true for M3 — the whole point of the tags is that most of
them are not.

---

## 1. Trust boundaries and attacker models

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

### 1.1 Three attacker models

The diagram above says where the boundary is. These three say who is
standing at it. They are named M1, M2 and M3 throughout this document.

| | Model | Has | Does not have |
|---|---|---|---|
| **M1** | **Remote — over the network** | Only what HYCLEUS reaches out to or is handed: a timestamp-authority response, a dependency, a document the user was sent | Any local presence. No file, no account, no process on the machine |
| **M2** | **Holds a copy of the data, not the machine** | `data/`, the `.hcl` files, a `.hclv`, a backup set — a stolen laptop without full-disk encryption, a lost backup disk, an old drive, a synced folder | The PIN, the OS account password, a usable credential store, a running session |
| **M3** | **On the machine, as the logged-in OS user** | Everything M2 has, plus `share_2` from the credential store on request, the running process and its memory, and write access to the database | The PIN, and the printed recovery share |

**Capability grows M1 → M2 → M3, and the containment is real: anything that
fails against M2 also fails against M3.** So a control is only worth
describing at the weakest model it survives. The containment holds for
*controls*, not for *holdings*: an M2 with old media can be carrying material
the live machine no longer has — see §1.3, and §4.4 on why nothing is
rotated.

How the real world maps onto them:

| Situation | Model |
|---|---|
| A laptop stolen while powered off, no full-disk encryption | M2 |
| The same laptop after the OS account password is cracked | M3, offline and unhurried |
| A backup disk lost in transit; an old drive sold on | M2 |
| Malware running as the logged-in user; an unlocked desk; a remote-support session | M3 |
| A powered-off machine with full-disk encryption and no password | outside all three |
| Someone holding the printed recovery share | see §4.4 — a share, not a model |

The last row is deliberate. The recovery share is not an attacker model
because it is not a position an attacker occupies; it is key material that
can end up in any of the three hands, and §4.4 is where that is worked out.

### 1.2 Which layer holds, and against whom

✅ holds · ⚠️ raises the cost, does not close it · ❌ does not apply ·
— out of reach for that model.

| Layer | M1 | M2 | M3 |
|---|---|---|---|
| AES-256-GCM over file contents | — | ✅ | ⚠️ as strong as the PIN — or as short as one unlocked session (§1.3) |
| GCM tag / AAD authentication (tamper detection) | — | ✅ | ⚠️ keyed, so unforgeable — until M3 catches the key in an unlocked session (§1.3) |
| AAD *confidentiality* (filename, plaintext SHA-256, ids) | — | ❌ readable in the header (§3) | ❌ |
| Argon2id PIN → KEK → `share_1` | — | ✅ | ⚠️ offline brute force, no rate limit (§3) |
| Shamir 2-of-3 | — | ✅ the vault yields one share, and one share is nothing | ❌ `share_2` is already theirs |
| OS credential store holding `share_2` | — | ⚠️ the blob travels with the disk; the OS account password opens it — unless the record is TPM-sealed | ❌ it answers them |
| TPM 2.0 sealing of stored secrets (Windows only) | — | ✅ where present: the blob is useless without that chip (§4.13) | ❌ the TPM answers them too |
| Vault HMAC, key = HKDF(HWID) | — | ❌ the HWID is not a secret (§4.2) | ❌ |
| Device binding via the HWID | — | ❌ see §1.3 | ❌ |
| Login rate limit / lockout | — | ❌ they are not using the application (§4.5) | ⚠️ one `DELETE` removes it (§3) |
| TOTP second factor | — | ❌ not in the path they take | ❌ the secret is in the store that answers them |
| USB blacklist | — | ❌ | ❌ one database write (§4.1) |
| Audit hash chain + external anchor | — | — | ⚠️ detection, never prevention (§4.6) |
| Weekly integrity sweep | — | — | ⚠️ the file cannot be forged while the session is locked, the verdict can be at any time (§4.7) |
| Idle auto-lock | — | — | ⚠️ the application window only (§4.8) |
| SafeZone shredding | — | ⚠️ best-effort at the logical layer (§3) | ⚠️ plaintext is on disk while a document is open (§4.10) |
| RFC 3161 timestamp | ⚠️ a hostile authority still produces a valid-looking token (§4.9) | ⚠️ the trailer is outside the GCM tag and can be stripped (§4.9) | ⚠️ |
| Backup encryption of the database export | — | ✅ (§4.11) | ✅ the key is still required |

Rows tagged M3 also cover the causes that have no attacker at all — bit rot,
a bad copy, a crash mid-write. The integrity sweep does not distinguish
them, and does not need to.

### 1.3 What each model gets, and what is out of scope

**M1 — what holds.** HYCLEUS opens no port, runs no server and exposes no
network-facing account system — the roles in §4.5 are enforced inside the
application, not across a wire. There is exactly one outbound path in the
shipped application: the RFC 3161 request in `CORE/timestamp.py`, opt-in per
file. It carries a nonce that is checked against the response, the response
size is capped, the configured URL is restricted to `http`/`https` so a setting
cannot turn stamping into a local file reader, and the resulting token is
verified with no network access at all (§4.9).

**M1 — what does not.** That one request sends the **plaintext SHA-256** to
a third party. §3 already concedes that this hash lets someone confirm a
suspected file without decrypting it; stamping hands that capability to the
timestamp authority, and to anyone on the path if the configured URL is
plain `http`. And a hostile or impersonated authority can return a token
that verifies perfectly, because the trust anchor travels inside the token —
only an externally supplied root (`--trusted-root`) closes that (§4.9).

**M1 — out of scope.** The supply chain. Dependencies are scanned on every
push (`pip-audit` in `.github/workflows/ci.yml`), which is reporting, not a
control. Third-party engines HYCLEUS invokes — the platform antivirus — have
their own network behaviour, and this project does not govern it.

**M2 — what holds.** This is the model HYCLEUS is built for, and it is where
the design is strongest. File contents are AES-256-GCM and the key is never
stored whole. The vault file yields `share_1` and nothing else, sealed under
Argon2id — so **even a cracked PIN leaves the attacker with one share, which
is information-theoretically nothing** (§4.4). `share_2` is not in the
database of a current installation and is never written to a backup at all
(`usb_tokens` is excluded, §4.11). Corruption and tampering are detectable
against a key M2 does not have.

One exception, and it is the reason §4.4 insists that nothing is rotated:
`share_2` lived in `usb_tokens.share_2` in plaintext **before the migration
to the OS credential store**. A raw copy of `data/` taken before that upgrade
still carries it, and combined with a cracked PIN it *does* reconstruct the
master key. Migration overwrites and purges the live copy; it cannot reach a
copy that already left the machine.

**M2 — what does not.** Everything in §3's first paragraph: the database is
plaintext on disk, so filenames, user records, roles, HWIDs and the whole
audit log are readable, and the AAD in each `.hcl` header is readable too.
The vault HMAC is forgeable by anyone who knows the HWID (§4.2). Every
application-level control — rate limit, blacklist, idle lock, TOTP — is
simply absent, because M2 is not running the application (§4.5).

**M2 — out of scope, and both cases are real.** First, **the HWID is not a
hardware secret and on some devices is not hardware-derived at all.** When
the storage stack reports an unusable serial, `get_usb_hwid()` falls back to
a UUID persisted in `data/usb_ids.json` — measured on a real device, and
recorded as **B-025** in `BACKLOG.md`. On that device class, anyone holding
a copy of `data/` reproduces the device identity **without the USB**. The
HWID was never a secret (§4.2), so no confidentiality is lost, but "bound to
this device" is weaker than it sounds and the boundary diagram above should
be read with that in mind. Second, `DEV_MODE` installations (§4.3): there
the file key is derived from the HWID alone, so M2 decrypts everything. It
is force-disabled in built executables.

**M3 — what holds.** Very little, and §1's lead paragraph says so plainly.
Two things survive. The GCM tag is **keyed**, so M3 can destroy a file but
cannot alter one and leave it verifying (§4.7) — with one condition that
§4.7 does not state: it holds only while M3 never catches the master key in
an **unlocked** session, because at that moment the key is in process memory
(§3, "Memory") and everything keyed falls with it. And the PIN is still
required to reach that state from cold: M3 holds `share_2` and needs a
second share, which means the vault's Argon2id seal or the printed paper.
That is the barrier §1 names.

**M3 — what does not.** The credential store answers them. Every
application-level control is a database write away (§4.1, §4.5, §4.8). The
lockout counter can be deleted (§3). Plaintext sits in `data/safezone/` for
as long as a document is open (§4.10) and in process memory while the
session is unlocked (§3). A timestamp trailer can be stripped without
breaking the file (§4.9).

**M3 — out of scope, by design.** §6.2 already declares attacks that assume
an already-compromised machine out of scope for reports, and that is not
evasion: M3 *is* the boundary, not something inside it. What HYCLEUS buys
against M3 is **evidence rather than prevention** — the audit chain, the
external anchor and the integrity sweep exist to make an M3 attacker's
presence visible afterwards. Whether that works at all depends on the anchor
living somewhere M3 cannot reach; see the `HYCLEUS_AUDIT_ANCHOR` discussion
in §4.6, which is the difference between a real property and an
inconvenience.

---

## 2. What HYCLEUS protects against

The **Model** column says which attacker the verdict is claimed against
(§1.1). It is a scope, not a decoration: a row marked M2 makes **no claim
about M3**, and several of these verdicts genuinely change once the attacker
is the logged-in OS user. §1.2 shows where each one lands.

| Scenario | Model | Protected? | By what |
|---|---|---|---|
| Encrypted file (`.hcl`) copied off the machine | M2 | ✅ | AES-256-GCM; key never stored whole |
| One byte of ciphertext or the GCM tag modified | M2 | ✅ | GCM authentication — `AuthenticationError`, never silent wrong plaintext |
| File metadata (filename, user_id, hwid, SHA-256) edited in the header | M2 | ✅ | Metadata is the GCM AAD; any edit fails authentication |
| Same key reused across files | M2 · M3 | ✅ | Fresh 12-byte `os.urandom` nonce per encryption |
| Vault file (`.hclv`) copied, PIN unknown | M2 | ✅ | Argon2id KEK (time=3, mem=64 MB, para=4) + GCM |
| `share_2` read out of the database | M2 | ✅ in a current installation | It is no longer there — it lives in the OS credential store. A raw `data/` copy taken **before** that migration still carries it in plaintext; the exception is worked out in §1.3 |
| Only one Shamir share obtained | M2 | ✅ | 2-of-3 is information-theoretically secure; one share reveals nothing |
| Brute-forcing the PIN through the app UI | M3 | ⚠️ Slowed | Rate limit: 5 failures → 30s, escalating to 300s, counter persisted in DB |
| An audit entry edited or deleted from the middle of the log | M3 | ⚠️ Detected, not prevented | SHA-256 hash chain; `verify_audit_chain()` names the exact record — see §4.6 |
| The newest audit entries deleted (log truncated) | M3 | ⚠️ Detected only via the anchor | The chain head is written outside the database to `data/audit_anchor.log` — see §4.6 |
| The whole audit chain recomputed after an edit | M3 | ⚠️ Detected only via the anchor | The hash is unkeyed; only the external anchor disagrees — see §4.6 |
| A `.hcl` file silently corrupted on disk (bit rot, bad copy, tampering) | M3 | ⚠️ Found, but the verdict is erasable | Weekly integrity sweep verifies every GCM tag without opening the file; the file itself cannot be forged, the verdict in `files.integrity_status` can — conditions and reasoning in §4.7 |
| Someone reaching an unattended, still-unlocked session | M3 | ⚠️ Time-limited | Idle auto-lock: session locks after N minutes of no input even with the USB inserted; unlock requires the PIN — see §4.8 |
| Decrypted copies left in the system temp directory | M2 · M3 | ✅ Not written there | Temporary plaintext goes to `data/safezone/`, shredded on exit and on next startup — see §4.8 |

---

## 3. What HYCLEUS does **not** protect against

These are not bugs. They are the boundaries of the design. Each is tagged
with the attacker models it belongs to (§1.1).

**An attacker who can read the disk.** *(M2 · M3)* The SQLite database
(`data/hycleus.db`) is **not encrypted**. Filenames, user records, roles,
HWIDs and the entire audit log are plaintext on disk. `sqlcipher3` is a
planned migration, not a shipped feature. Encrypted file *contents* stay
protected; everything around them does not.

**An attacker who can write to the disk.** *(M3)* The audit log is an ordinary
table in that same unencrypted database, and nothing stops anyone with write
access from editing or deleting rows. Since v2.2 those edits are *detectable*
— the log is a hash chain anchored outside the database — but detection is
not prevention, the chain covers only entries written after the upgrade, and
one of the two detection mechanisms can be defeated by an attacker who is
thorough. Read §4.6 before relying on it.

**Offline brute force of the vault.** *(M2)* Copy `.hclv` and attack it at leisure;
this codebase never runs. The only cost imposed is Argon2id
(time=3, memory=64 MB, parallelism=4). The login rate limit is irrelevant
here — it lives in the application, and the attacker is not using the
application.

**Rate-limit removal.** *(M3)* The counter is stored in `login_attempts` in the
unencrypted database. `DELETE FROM login_attempts` removes the lockout.
It cannot be encrypted — the application must be able to read its own
lockout. Rolling the system clock back also drops the lock early;
`locked_until` is an absolute timestamp, because a monotonic clock would
reset on restart and lose the property that matters most.

**A compromised OS user account.** *(M3)* The credential store releases `share_2`
to the logged-in user. Malware running as that user can ask for it the same
way HYCLEUS does.

**Memory.** *(M3)* Decrypted content lives in Python `bytes` objects. Intermediate
buffers are zeroed with `ctypes.memset`, but Python may have already copied
the data, and the returned `bytes` is immutable and cannot be wiped. A
memory dump or swap file can contain plaintext.

**Secure-erase guarantees.** *(M2)* Migration overwrites the old secret in place
before deleting it. That assumes the write lands on the same physical
sector — false on SSDs (wear levelling), copy-on-write filesystems (btrfs,
ReFS), snapshots and VM images. It is best-effort at the logical layer, not
a wipe.

**Metadata confidentiality.** *(M2 · M3)* In a `.hcl` file the AAD block — original
filename, SHA-256 of the plaintext, timestamps, `user_id`, `hwid` — is
authenticated but **not encrypted**. It is readable in the file header. The
SHA-256 also permits confirming a suspected file without decrypting it.

> The control that covers the offline-attacker cases is **full-disk
> encryption**. HYCLEUS is not a substitute for it.

---

## 4. Known weaknesses we are not hiding

Each entry opens with the attacker models it concerns (§1.1). A weakness
that only M3 can reach is a different thing from one M2 can reach with a
copied disk, and reading them as equivalent is the mistake this tagging
exists to prevent.

### 4.1 Blacklisting a USB does not revoke anything

> **Attacker models:** M3

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

> **Attacker models:** M2 · M3

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

> **Attacker models:** M2 · M3

When `DEV_MODE` is set (and only when not running as a frozen executable),
the file-encryption key is `PBKDF2-HMAC-SHA256(hwid, fixed salt, 100 000)` —
**no PIN involved**. Anyone who knows the HWID can decrypt every file. This
is a development convenience and is force-disabled in built executables
(`sys.frozen`), but never enable it on a machine holding real data.

### 4.4 The recovery share is a third path to the key

> **Attacker models:** M2 · M3

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

> **Attacker models:** M2 · M3

The USB HWID check and the login rate limit constrain what can be done
*through the HYCLEUS interface*. Neither constrains someone operating on the
files directly. We say this here because the earlier README claimed
`share_2` was "guarded by HWID check" — it was not, and the claim has been
corrected.

### 4.6 The audit chain is tamper-evident, and only from v2.2 onward

> **Attacker models:** M3

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

> **Attacker models:** M3

A weekly background sweep (`CORE/integrity.py`) verifies the GCM tag of
every registered `.hcl` and the vault's HMAC, writing the result to
`files.integrity_status` and `files.integrity_checked_at`. Unlike the audit
chain, this check is **keyed**: the GCM tag is computed under the AES-256
master key, so nobody without the key can alter a file and produce a tag
that still verifies. On that specific point it is strong.

**"Without the key" is a condition, and it is the session lock.** While the
session is *locked* the master key is not in reach and the sentence above
holds as written. In an *unlocked* session it is in process memory, and §3
already concedes that a memory dump can reach it — an M3 attacker who does
holds the key, and every keyed check in this document falls with it, this
one included. The strength is real; it is the strength of the lock.

The limits:

- **The verdict is stored in the unencrypted database.** `UPDATE files SET
  integrity_status = 'ok'` erases the finding. The *file* cannot be forged
  under the condition above; the *report about it* can be, under no condition
  at all. The audit-log entry for the same finding is
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

> **Attacker models:** M2 · M3

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

SafeZone was introduced ahead of the flow that needed it. That flow now
exists — transparent access, §4.10 — and it is the only thing that writes
plaintext to disk. Downloads still stream straight to the path the user
picks and never touch SafeZone.

### 4.9 Timestamps are verifiable offline — but the trust anchor comes from the file

> **Attacker models:** M1 · M2 · M3

A `.hcl` file can carry an RFC 3161 timestamp token, obtained by having a
Timestamp Authority sign the **plaintext SHA-256** already recorded in the
AAD (`original_sha256`). Because the hash is taken from the header, stamping
needs **no key and never touches plaintext**. What the token proves is
narrow but real: this content existed no later than the time the TSA signed.

`verify_timestamp()` now checks that claim cryptographically, **with no
network access at all** — the signing certificate and its chain travel
inside the token (`certReq=True`), so verification uses nothing but the file
itself. Ten checks run in order: the token parses and carries exactly one
signer; the signer's certificate is embedded; the `message-digest` and
`content-type` signed attributes match; the signature verifies against that
certificate's public key; the certificate carries the `timeStamping` EKU
(RFC 3161 §2.3); it was valid **at `genTime`**, not today; each certificate
in the chain is signed by the next; and the stamped digest equals the file's
`original_sha256`. There is a CLI for it:

```
python CORE/verify_timestamp_cli.py --verify-timestamp <file.hcl> [--trusted-root ca.pem]
```

A timestamp is therefore no longer merely a record. Three limits remain, and
the first is the one that matters:

**The trust anchor comes from the artifact being verified.** What is proven
is the chain's *internal consistency*, not that its root deserves trust — the
root travels in the same file as the token. Anyone who can rewrite the
trailer can mint their own CA, issue their own TSA certificate, sign a token
saying whatever time they like, and this code will call it valid, because
mathematically it is. Real trust requires comparing the root against a store
held **outside** the file: `verify_timestamp(trusted_roots=...)`, or
`--trusted-root` on the CLI. Without it the result carries
`anchor_trusted=False` and the CLI prints an explicit warning every time —
the default never quietly implies trust. This is the same shape of limit as
the audit anchor in §4.6: evidence and the means of checking it must not
live in the same place.

**The trailer is outside the GCM tag.** The tag covers the AAD and the
ciphertext only — not the magic, the version byte, or the timestamp trailer.
So a timestamp can be **deleted**: strip the trailer and the file still
decrypts cleanly, simply looking unstamped. "Never stamped" and "stamp
removed" are indistinguishable from the file alone. A timestamp cannot be
*forged onto other content* — the digest is cross-checked against the AAD,
and another file's token is rejected — but it can be made to disappear.

**Without a key, the stamped hash is unverified.** `original_sha256` sits in
the AAD, which GCM protects — but checking that protection requires the key.
Both stamping and verification read it without one, so they answer "was the
hash the header claims actually timestamped?" The companion question — "does
the content actually hash to that?" — is `verify_file()`'s job, and needs the
key. `timestamp_file()` accepts an optional key and runs `verify_file()`
first when given one.

**What is not checked:** certificate revocation (no OCSP or CRL — both need
network, and this is deliberately offline), and the self-signature of a
self-signed root, which is not a trust statement.

Container versioning: files written before this feature are version `0x01`
and are still read unchanged. New files are `0x02`, and `0x02` **without** a
trailer is entirely valid — the stamp is optional and added later. Version
`0x01` files are never scanned for a trailer, since the format did not
define one. The trailer format stayed at version `0x01`: the certificate
chain lives inside the token, so no second copy was added — two lists that
could disagree would be worse than one.

### 4.10 Transparent access puts plaintext on disk for as long as you edit

> **Attacker models:** M2 · M3

"Open" decrypts a document into SafeZone, launches it in the default
application, writes any edit back re-encrypted with a fresh nonce, and
shreds the temporary copy. It closes a real gap — previously a user had to
download, remember to re-encrypt, and remember to delete — but it does so
by putting a plaintext copy on disk, which is a trade worth stating plainly.

**There is no "closed" event.** `os.startfile()` returns immediately with no
handle, and on Windows most applications launch a shim that hands off to an
already-running instance and exits — "process ended" does not mean "document
closed". So the model is check-out / check-in, like version control: the
document stays registered as open until a change is detected and settles,
the user clicks Finish, the app shuts down, or the session locks. Locking is
included on purpose: a lock screen that leaves plaintext on disk would guard
the front door and leave a window open. The window title bar shows how many
documents are open, because "I forgot to close it" must not be a silent state.

**Correctness does not depend on the file watcher.** Word, Excel and many
editors save by writing a new file and renaming it over the original, which
drops a `QFileSystemWatcher` path watch — the event never arrives. So the
watcher is an optimisation, layered over a 5-second poll, layered over a
check-in at shutdown. All three ask the same question: does the plaintext
SHA-256 differ from the last encrypted state? Even if every watcher event is
missed, the change is caught before the copy is shredded. `mtime` alone was
not enough: some applications preserve it while writing, some tools touch a
file without changing it.

**Write-back is atomic.** The re-encrypted file goes to a temporary path and
is moved into place with `os.replace()`. A crash mid-write leaves the
original `.hcl` untouched — the same pattern, and the same reasoning, as the
timestamp trailer in §4.9: a half-written `.hcl` fails GCM verification, and
the weekly integrity sweep would report a healthy document as corrupt.

**The exposure window is the editing session.** While a document is open its
plaintext sits in `data/safezone/` and every limit in §3 applies to it: an
attacker who can read the disk can read it, and the shred that follows is
best-effort at the logical layer (SSD wear levelling, copy-on-write
filesystems, snapshots). Opening a document is audited (`file_opened`) —
that entry marks the moment plaintext reached the disk. A full virtual drive
(Dokan/WinFsp), which would keep plaintext out of the filesystem entirely,
is out of scope; this is the interim answer.

### 4.11 A backup takes the vault off the machine — the database goes with it, encrypted

> **Attacker models:** M2

Shamir recovery (§4.4) covers a lost *key*. It does nothing for a lost
*disk*. Backup closes that gap, and the two stay deliberately separate:

    backup → media loss        Shamir → key loss

**`.hcl` files are copied verbatim, not re-wrapped.** They are already
AES-256-GCM with a per-file nonce. A second layer would buy no
confidentiality — the AAD (original filename, plaintext SHA-256,
timestamps, `user_id`, `hwid`) is readable in the header *on the source
machine too* (§3), so wrapping would hide in the backup what is already
open in the vault. Fixing AAD exposure is a format change, not a backup
feature. The honest consequence: backup filenames leak exactly what the
vault leaks, no more.

**The database is the real exposure, and it is encrypted.** §3 concedes
that SQLite is plaintext on disk: filenames, user records, roles, HWIDs and
the whole audit log. Copying that to external media would write the entire
inventory in the clear onto something designed to leave the building. So
the needed tables are exported to canonical JSON and encrypted with
`encrypt_file()` — same primitive, same key, no new crypto. The temporary
plaintext dump is shredded before the backup is finished.

**The key file is not backed up.** `.hclv` holds Argon2id-protected
`share_1`. On external media it would be a ready-made offline brute-force
target, and external media is exactly what goes missing. Losing the key is
Shamir's problem. The consequence, stated plainly: **restoring from this
backup requires a working key.** If the key is gone too, recover it first
(§4.4), then restore.

**The audit log is backed up but never restored.** It is worth keeping for
compliance, but writing it into another database would create a second
chain claiming the same history and disagreeing with the anchor (§4.6).
Restore writes it to a separate file: readable, and out of the live chain.
`users`, `usb_tokens` and `settings` are not backed up at all.

**Verification runs before restore, and works without the key.** The
manifest carries the SHA-256 of each *ciphertext*, so corruption,
truncation and missing files are caught with no key at all — a scheduled
script can check a backup without opening the vault. With the key,
`verify_backup()` additionally runs the GCM tag check through
`verify_file()` (no plaintext assembled) and compares the plaintext
manifest against an encrypted copy of the same list, which is what makes a
rewritten manifest detectable. Restore refuses to run if verification
fails, and refuses a non-empty destination unless overwrite is explicit —
it never writes into the live vault or database.

---

### 4.12 Shamir shares are validated at the parser, and this is hardening — not a fix for a hole

> **Attacker models:** none — this entry is about error reporting, not
> about a control. The reasoning is below and it is the point of the section.

An external reviewer asked (issue #1) whether the recovery-share decoder
checks that the decoded value is in canonical form **and** below the field
prime. The honest answer at the time was: the length was checked, the range
was checked **nowhere** — not by the decoder, not by the caller.

**This was not a vulnerability, and it is important to say why.** Lagrange
interpolation already runs `mod p`, so a share `y` and the same share
`y + p` reconstruct the *identical* key. A non-canonical share gave nobody
access to anything they could not already reach: to exploit it you must
already hold a valid share, and holding a valid share is the whole secret.
No confidentiality was lost and the 2-of-3 threshold never dropped.

What it did cost was **error reporting**, and we measured how much:

| | |
|---|---|
| Canonical shares as a fraction of the 33-byte payload space | **1 in 255** (0.39%) |
| First byte of a canonical share | always `0x00` |
| Single-character typos that land on `y >= p` | **4.6%** — silently accepted before |
| Single-character typos that stay in range | 95.3% — indistinguishable from a legitimate different share, uncatchable by any check |

So the range check converts 4.6% of typos from "wrong key, failure later,
unclear message" into "your recovery share has a typo". That is the whole
benefit. It is worth having; it is not a security fix.

**The check lives in `_parse_share()`, not in the decoder.** The decoder is
one of three entrances — the other two are the vault file and the OS
keyring — and `reconstruct_key()` is a public, documented API that a future
CLI or third-party integration could call directly, bypassing the decoder
entirely. Putting the validation at the chokepoint closes that gap.
`recover_master_key()` additionally now requires index 3; passing share 1 or
2 was never a bypass (both are valid shares held by whoever passes them) but
it worked silently and logged the wrong event.

**Two smaller things stay as they are.** Base32 leaves one slack bit in a
53-character body, so every share has two textual encodings that decode
identically (Python's `b32decode` does not validate trailing bits). And a
value of exactly `0` is now rejected as degenerate, which would also reject
a legitimate zero share — probability ~2^-256, far below hardware failure.

**Backward compatibility:** printed recovery shares are unaffected.
`_fmt_share()` has always written `(...) % p` zero-padded to 66 hex
characters, and that format has not changed since v1.5 (`cdce520`) — the
2-of-2 era code used the same constant. Every share HYCLEUS has ever
produced is already canonical, and the test suite proves it on generated
shares and on a real vault round-trip.

---

### 4.13 TPM sealing raises the floor for M2 only — and binds the secret to one chip

> **Attacker models:** M2 · M3

On Windows with a TPM 2.0, secrets are sealed to the TPM before they are
written to the credential store (`CORE/tpm_sealing.py`). The unsealing key is
generated inside the chip and cannot leave it — measured, `NCryptExportKey`
returns `NTE_NOT_SUPPORTED`. Records written this way carry a `TPM1:` prefix;
records without it are unsealed and still read normally.

**What it buys, precisely: M2 and nothing else.** §1.2 says the credential
store blob travels with the disk and the OS account password opens it. For a
sealed record that stops being true — the blob is useless without that
specific chip. **M3 is unaffected**: the TPM answers the logged-in user
exactly as the credential store does. This raises the floor under a stolen
disk; it does not defend a compromised session.

**It applies to Windows only.** Linux and macOS fall back to the credential
store as before, and so does any Windows machine without a TPM. That
fallback is *never silent* — it lands in the audit log every session
(`tpm_sealing_unavailable`), in `--selftest`, and in Help → About. This is
B-025's lesson applied deliberately: a layer that switches itself off
quietly is worse than one that was never built, because the document keeps
claiming it.

**The cost is real and it is data loss.** Clearing the TPM (BIOS "Clear
TPM", a mainboard swap, some firmware updates) destroys the key, and every
sealed value becomes **permanently unopenable**. For `share_2` the way out
is the printed recovery share (§4.4) — this is exactly the failure Shamir
2-of-3 exists for. For the TOTP secret the way out is re-enrolling the
second factor. Unsealing failure is never reported as "no record": that
would read as *not configured* and push the caller into re-provisioning,
which is how a recoverable vault becomes an unrecoverable one.

**Existing records are not sealed retroactively.** A record written before
this feature stays unsealed until something rewrites it — for `share_2`,
that means re-provisioning. So an established installation on a TPM machine
gets no benefit until then, and no part of the UI currently says so. Tracked
as **B-042** in `BACKLOG.md`.

**What was measured and what was not.** The path was exercised on real
hardware (AMD fTPM 2.0, rev 1.59): seal 1.2 ms, unseal 38 ms, one-time key
generation 1.33 s. Not measured: any other TPM vendor, and CI — no runner
has a TPM, so those tests skip there and the path's health rests on one
developer machine. Same caveat as ClamAV in B-023, stated for the same
reason.

---

### 4.14 The `.hclx` delivery package expires by policy, not by mathematics

> **Attacker models:** M2 · M3

A `.hclx` carries documents out of the vault with a validity window
(`CORE/hclx.py`). It is for **user data only** — it never carries code, and
an application update is a separate format that this one deliberately does
not resemble: the magic bytes differ so that feeding one to the other stops
at the first byte.

**Expiry: the package stops opening. It is not deleted.** Both behaviours
were available and this one was chosen, so the guarantee is stated plainly
rather than implied:

- Deleting would advertise something untrue. If the recipient opened the
  package inside the window they already hold the plaintext and may have
  saved, printed or copied it. Destroying the container afterwards does not
  recall the content.
- Deletion is best-effort anyway — every limit in §3 applies (SSD wear
  levelling, copy-on-write filesystems, snapshots).
- The file belongs to the recipient's machine. HYCLEUS erasing it without
  asking would be a destructive act on someone else's disk, and it
  contradicts the repository's existing rule: expiry means deletion is
  *permitted*, not *required*, and a human decides (`CORE/disposal.py`).

**So the window is an application-level control, exactly the class §4.5
describes — not a cryptographic one.** Two consequences, both real:

- The recipient necessarily holds the key (otherwise they could never open
  it), so a modified client can ignore the window entirely.
- The check reads the **local clock**. Setting it back reopens the package.
  §3 already concedes the same for the login lockout; there is no trusted
  "now" in a deliberately offline application.

What the window does buy: on an honest recipient's machine the document
does not stay open forever, and **every attempt — successful or refused —
lands in the audit log** (`hclx_opened` / `hclx_rejected`), with who, when,
and whether it was inside the window.

**The signature is the GCM tag, and its reach is the vault.** No new scheme
was invented: the body is sealed with `encrypt_file()`, the same primitive
and the same key as everything else. That gives real integrity — one
changed byte and it will not open. It gives origin authentication **at
vault granularity only**: a package can only be produced by someone holding
this vault's master key. It cannot prove *which* user, because everyone
with vault access shares that key. The `sender_user_id` in the manifest is
tamper-proof but self-declared. User-level origin needs an asymmetric
identity, which this project does not have; the boundary is written down
instead of blurred.

**The manifest is readable without the key, and that is deliberate.** A
recipient must be able to see the window and sender before attempting to
open, and a refusal must be loggable by someone who cannot decrypt. Being
plaintext, it is editable — so the same manifest is stored *inside* the
encrypted body and the two are compared byte for byte on open. Editing the
outer copy to extend a window is caught there. This is the pattern §4.11
already uses for backup manifests.

**Creation time is self-declared.** `created_at` comes from the producing
machine and can say anything. An RFC 3161 stamp (§4.9) would turn it into a
trustworthy lower bound; that was not done in this version — see B-035.

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
| PIN storage | Argon2id hash (never plaintext); minimum 6 characters for new PINs — but during the transition window the login screen still accepts an existing 4–5 character PIN (`LOGIN_MIN_LEN = 4`), so "minimum 6" is not yet true of every account. Bridge, removal criterion and window in `BACKLOG.md` / B-040 |
| Secret storage | OS credential store, service `HYCLEUS`, usernames `share_2:<hwid>` and `totp_secret` |
| Secret sealing | Windows + TPM 2.0 only: random 32-byte DEK, AES-256-GCM over the secret with the keyring username as AAD, DEK wrapped by a non-exportable TPM RSA-2048 key via CNG (PKCS#1 v1.5 — OAEP is rejected by the Platform Crypto Provider, measured); `TPM1:` prefix, falls back loudly — see §4.13 |
| Second factor | TOTP (RFC 6238), 6 digits, ±1 window |
| Backup | `.hcl` files copied verbatim (already GCM); DB tables exported to canonical JSON and encrypted with the same primitive; manifest carries ciphertext SHA-256 so integrity is checkable without the key — `.hclv` deliberately excluded, see §4.11 |
| Delivery package (`.hclx`) | Header + plaintext manifest + a complete `.hcl` body; signature = that body's GCM tag under the vault master key, so origin is proven at vault granularity, not per user; the manifest is duplicated inside the body and compared byte for byte; validity window enforced by the application against the local clock — see §4.14 |
| Trusted timestamp | RFC 3161, SHA-256 message imprint over the **plaintext** hash, nonce + `certReq`; token in an optional file trailer outside the GCM tag |
| Timestamp verification | Offline, no network: CMS signature over `signedAttrs` (ECDSA / RSA PKCS#1 v1.5 / PSS) against the embedded signer certificate, `timeStamping` EKU, validity at `genTime`, chain walked among embedded certs, digest cross-checked against the AAD — trust anchor must be supplied externally, see §4.9 |

**Randomness** comes from `os.urandom` and `secrets` throughout — nonces,
salts, master keys and the Shamir polynomial coefficient.

**Supported version:** only the latest release (currently **v2.1.2**)
receives security fixes. The version you are running is shown in
**Help → About**; both strings come from `CORE/version.py`, so if they
disagree with this document, the document is the one that is stale.

---

## 6. Reporting a vulnerability

Please **do not open a public issue** for security problems.

> 🔍 **HYCLEUS has never had an external security review and is asking for
> one.** If you would rather *review* than report, the scope and the open
> invitation are in
> [issue #1](https://github.com/yubin-dev/HYCLEUS/issues/1) — that is the
> right place to coordinate. Findings still go through §6.1.

### 6.1 How to reach us

Use GitHub's private reporting: **Security → Report a vulnerability** on
[this repository](https://github.com/yubin-dev/HYCLEUS/security/advisories/new).
It creates a private advisory visible only to the maintainer.

> **If that link gives you a 404**, private vulnerability reporting has not
> been switched on in the repository settings — the feature is off by default
> and this document cannot turn it on. In that case open a **public issue that
> contains no technical detail** ("I would like to report a security issue,
> please enable private reporting") and wait for a private channel. Do not
> paste the finding into it.

<!-- Maintainer: two things.
     1. Enable Settings → Code security → Private vulnerability reporting.
        Until you do, the advisory link above 404s and the fallback path
        above is what reporters will actually hit.
     2. Add a contact email here if you want a second channel. Left blank
        deliberately — publishing a personal address is your call, not
        something this document should assume. -->

### 6.2 What is in scope

| In scope | Out of scope |
|---|---|
| The code in this repository | Third-party dependencies (report upstream; tell us too if HYCLEUS is affected) |
| Crypto container (`.hcl`), key hierarchy, Shamir shares | GitHub, PyPI or the OS keyring themselves |
| Vault, PIN, TOTP and USB token flows | Anything in §3 ("does not protect against") or §4 ("known weaknesses") |
| Audit chain and timestamp verification | Attacks that assume an already-compromised machine — that is §1's stated boundary |
| Backup, restore and transparent access | Missing hardening that costs nothing to state and everything to build (e.g. "use a hardware key") |

**Not a vulnerability by itself:** the SQLite database is not encrypted at
rest (§4.11), application-level controls are bypassable by someone with disk
access (§4.5), and plaintext exists on disk while a file is open for editing
(§4.10). These are written down because they are true, not because they are
unknown.

### 6.3 What helps

Affected version or commit, what an attacker gains, the steps to reproduce,
and the environment (OS, Python version). A proof of concept is welcome but
not required.

Please state **which trust boundary from §1 your attacker starts outside
of.** Most reports that turn out to be non-issues are ones where the attacker
was already assumed to have what the attack was meant to obtain.

### 6.4 What to expect

| Stage | Target |
|---|---|
| Acknowledgement | 7 days |
| Initial assessment (valid / known / out of scope) | 30 days |
| Fix or a written decision not to fix | 90 days |

HYCLEUS is maintained by one person as a non-commercial project — there is
no bounty programme and no formal SLA; the table is an intention, not a
contract. Fixes land in a release with credit, unless you prefer otherwise.

### 6.5 Coordinated disclosure

You may publish **90 days after your report**, whether or not a fix has
shipped. You do not need permission and you do not need to wait longer.
If a fix ships earlier, publish as soon as it is released.

If we go quiet, that clock still runs. A maintainer who stops answering is
not a reason for a finding to stay buried.

Please tell us if you intend to publish, so the advisory and the release
notes can go out at the same time.

### 6.6 Safe harbour

If you act in good faith under this policy, we will not pursue or support
legal action against you, and we will treat your research as authorised.

Good faith means: only your own machines and your own data, no denial of
service, no destruction or exfiltration of anyone else's data, stopping as
soon as you have demonstrated the issue, and no public disclosure before
§6.5's window.

This is a promise from this project's maintainer. It cannot bind third
parties — if your testing touches GitHub, an ISP or someone else's
infrastructure, their terms apply and this paragraph does not cover you.

### 6.7 Already known?

Everything in §3 and §4 is documented on purpose. A report that restates one
of those will be closed as known — unless you can show it is worse than
described here, which is genuinely useful.

**Also useful, and explicitly wanted:** a place where this document is
*wrong*. A claim in §2 or §5 that does not hold, a weakness in §4 whose
description understates it, a boundary in §1 that the code does not actually
enforce. Those are security findings about the security policy, and they are
harder to spot than bugs.

### 6.8 Automated analysis already in place

Before reporting, note that every push runs `ruff`, `mypy`, `bandit` and
`semgrep` (see `.github/workflows/ci.yml`), and a manually triggered
workflow fuzzes the crypto container and the Shamir implementation with
`atheris` (`.github/workflows/fuzz.yml`).

Findings from those tools that were reviewed and left in place are recorded
in `BACKLOG.md` with the reasoning. A report that repeats one of them is
still welcome if you can show the triage was wrong — that is exactly the
failure mode a second pair of eyes catches.

---
---

# Güvenlik Politikası — HYCLEUS

**Kapsam:** v2.2.0.dev (geliştirme ağacı) · Son gözden geçirme: 2026-08-16

Bu belge HYCLEUS'un neyi koruduğunu, neyi korumadığını ve halihazırda
bildiğimiz zayıflıkları anlatır. Bilinçli olarak açık sözlüdür: yalnızca
güçlü yanları sıralayan bir güvenlik belgesi güvenlik değil, pazarlamadır.

## Bu belge nasıl okunur

Uzun, çünkü dürüst cevaplar uzun. Kimsenin tamamına birden ihtiyacı yok.
Kendi satırınızı bulun, oradan başlayın ve çapraz atıfları izleyin — §2'deki
her iddia, onu sınırlayan §4 maddesine bağlanıyor.

| Kimseniz | Buradan başlayın | Sonra |
|---|---|---|
| **Denetçi ya da gözden geçiren** | §1.1 — üç saldırgan modeli | §1.2 (hangi katman hangi modele dayanıyor) → §1.3 (bildiğimiz boşluklar) → §4 (her zayıflık, kendi ifademizle) |
| **HYCLEUS üzerinde çalışan geliştirici** | §1.2 — katman matrisi | §5 (yapılar ve parametreler) → değiştirdiğiniz şeyi kapsayan §4 maddesi |
| **Kullanıcı ya da yönetici** | §2 — gerçekte ne korunuyor | §3 (ne korunmuyor) → adım adım kurtarma için `docs/kullanici-rehberi.md`, komut satırı bilgisi varsaymadan yazıldı |
| **Bir şey bildirmek üzere olan** | §6.7 — zaten biliniyor mu? | §6.2 (kapsam) → §6.3 (işe yarayanlar) → §6.1 (bize nasıl ulaşılır) |

Soruya göre:

| Soru | Bölüm |
|---|---|
| HYCLEUS kime karşı savunuyor — kime karşı savunmuyor? | §1.1 |
| Hangi katman hangi saldırganı durduruyor, her biri nerede duruyor? | §1.2 |
| Tasarımın bilinçli olarak dışında kalan ne? | §1.3, ardından §3 |
| Somut olarak, senaryo senaryo ne korunuyor? | §2 |
| Nerede zayıf ve ne kadar? | §4.1 – §4.12 |
| Hangi algoritmalar, hangi parametreler? | §5 |
| Bir bulguyu nasıl bildiririm, sonra ne oluyor? | §6 |
| USB'mi kaybettim / PIN'imi unuttum / dosyalarım bozuk görünüyor | `docs/kullanici-rehberi.md` |

Belge boyunca iki kural geçerli. **M1 / M2 / M3**, §1.1'de tanımlanan
saldırgan modellerinin adları; §2'deki her senaryo, §3'teki her sınır ve
§4'teki her zayıflık, geçerli olduğu modellerle etiketli. Ve M2 etiketli bir
iddia M3 için kendiliğinden doğru DEĞİL — etiketlerin bütün amacı, çoğunun
doğru olmadığını göstermek.

## 1. Güven sınırları ve saldırgan modelleri

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

### 1.1 Üç saldırgan modeli

Yukarıdaki şema sınırın NEREDE olduğunu söylüyor. Bu üç model sınırda KİMİN
durduğunu söylüyor. Belge boyunca M1, M2 ve M3 diye anılıyorlar.

| | Model | Elinde olan | Elinde olmayan |
|---|---|---|---|
| **M1** | **Uzaktan — ağ üzerinden** | Yalnızca HYCLEUS'un uzandığı ya da kendisine verilen şey: bir zaman damgası makamının yanıtı, bir bağımlılık, kullanıcıya gönderilmiş bir belge | Hiçbir yerel varlık. Ne dosya, ne hesap, ne makinede çalışan bir süreç |
| **M2** | **Verinin kopyası elinde, makine değil** | `data/`, `.hcl` dosyaları, bir `.hclv`, bir yedek kümesi — tam disk şifrelemesi olmayan çalınmış dizüstü, kaybolan yedek diski, elden çıkarılmış eski disk, eşitlenmiş bir klasör | PIN, OS hesap parolası, kullanılabilir bir anahtar kasası, çalışan bir oturum |
| **M3** | **Makinede, oturum açmış OS kullanıcısı olarak** | M2'nin sahip olduğu her şey, ayrıca istendiğinde anahtar kasasından `share_2`, çalışan süreç ve belleği, veritabanına yazma yetkisi | PIN ve basılı kurtarma parçası |

**Yetenek M1 → M2 → M3 yönünde büyüyor ve kapsama gerçek: M2'ye karşı
DAYANMAYAN her şey M3'e karşı da dayanmaz.** Yani bir kontrol yalnızca
hayatta kaldığı EN ZAYIF modelde anlatılmaya değer. Kapsama KONTROLLER için
geçerli, ELDEKİLER için değil: eski medyaya sahip bir M2, canlı makinede
artık bulunmayan malzemeyi taşıyor olabilir — bkz. §1.3 ve hiçbir şeyin neden
döndürülmediği için §4.4.

Gerçek dünya bu modellere şöyle düşüyor:

| Durum | Model |
|---|---|
| Kapalıyken çalınan dizüstü, tam disk şifrelemesi yok | M2 |
| Aynı dizüstü, OS hesap parolası kırıldıktan sonra | M3 — çevrimdışı ve acelesiz |
| Nakliyede kaybolan yedek diski; satılan eski disk | M2 |
| Oturum açmış kullanıcı olarak çalışan zararlı yazılım; kilitlenmemiş masa; uzaktan destek oturumu | M3 |
| Tam disk şifrelemeli, parolası bilinmeyen kapalı makine | üçünün de dışında |
| Basılı kurtarma parçasını elinde tutan kişi | bkz. §4.4 — bir pay, bir model değil |

Son satır bilinçli. Kurtarma parçası bir saldırgan modeli değil, çünkü bir
saldırganın BULUNDUĞU konum değil; üç elden herhangi birine düşebilen
anahtar malzemesi ve bunun hesabı §4.4'te veriliyor.

### 1.2 Hangi katman dayanıyor, kime karşı

✅ dayanıyor · ⚠️ maliyeti yükseltiyor, kapatmıyor · ❌ geçerli değil ·
— o model için erişilemez.

| Katman | M1 | M2 | M3 |
|---|---|---|---|
| Dosya içeriğinde AES-256-GCM | — | ✅ | ⚠️ PIN kadar güçlü — ya da tek bir kilitsiz oturum kadar kısa (§1.3) |
| GCM etiketi / AAD doğrulaması (kurcalama tespiti) | — | ✅ | ⚠️ anahtarlı, yani sahtelenemez — ta ki M3 anahtarı kilitsiz bir oturumda yakalayana kadar (§1.3) |
| AAD *gizliliği* (dosya adı, düz metin SHA-256, kimlikler) | — | ❌ başlıkta okunabilir (§3) | ❌ |
| Argon2id PIN → KEK → `share_1` | — | ✅ | ⚠️ çevrimdışı kaba kuvvet, hız sınırı yok (§3) |
| Shamir 2-of-3 | — | ✅ kasa tek pay veriyor, tek pay hiçbir şey | ❌ `share_2` zaten onda |
| `share_2`'yi tutan OS anahtar kasası | — | ⚠️ blob diskle birlikte gidiyor; OS hesap parolası onu açar — kayıt TPM'e mühürlü DEĞİLSE | ❌ ona cevap veriyor |
| Saklanan sırların TPM 2.0 mührü (yalnızca Windows) | — | ✅ varsa: blob o yonga olmadan işe yaramaz (§4.13) | ❌ TPM de onlara cevap veriyor |
| Kasa HMAC'i, anahtar = HKDF(HWID) | — | ❌ HWID bir sır değil (§4.2) | ❌ |
| HWID üzerinden cihaz bağı | — | ❌ bkz. §1.3 | ❌ |
| Giriş hız sınırı / kilitleme | — | ❌ uygulamayı kullanmıyorlar (§4.5) | ⚠️ tek bir `DELETE` kaldırıyor (§3) |
| TOTP ikinci faktörü | — | ❌ izledikleri yolda değil | ❌ sır, onlara cevap veren kasada |
| USB kara listesi | — | ❌ | ❌ tek bir veritabanı yazımı (§4.1) |
| Denetim hash zinciri + dış çapa | — | — | ⚠️ tespit, asla engelleme değil (§4.6) |
| Haftalık bütünlük taraması | — | — | ⚠️ oturum kilitliyken dosya sahtelenemez, karar her zaman sahtelenebilir (§4.7) |
| Hareketsizlik kilidi | — | — | ⚠️ yalnızca uygulama penceresi (§4.8) |
| SafeZone temizliği | — | ⚠️ mantıksal katmanda en iyi çaba (§3) | ⚠️ belge açıkken düz metin diskte (§4.10) |
| RFC 3161 zaman damgası | ⚠️ düşman bir makam da geçerli görünen token üretir (§4.9) | ⚠️ fragman GCM etiketinin dışında, sökülebilir (§4.9) | ⚠️ |
| Yedekteki veritabanı dışa aktarımının şifrelenmesi | — | ✅ (§4.11) | ✅ anahtar yine gerekli |

M3 etiketli satırlar, hiç saldırganı olmayan nedenleri de kapsıyor — bit
çürümesi, bozuk bir kopya, yazma sırasındaki çökme. Bütünlük taraması
bunları ayırt etmiyor ve etmesi de gerekmiyor.

### 1.3 Her model ne elde ediyor, kapsam dışı ne kalıyor

**M1 — ne dayanıyor.** HYCLEUS hiçbir port açmıyor, hiçbir sunucu
çalıştırmıyor ve ağa açık bir hesap sistemi sunmuyor — §4.5'teki roller bir
kablo üzerinden değil, uygulamanın içinde uygulanıyor. Dağıtılan uygulamada
tek bir dışa giden yol var: `CORE/timestamp.py` içindeki RFC 3161 isteği ve
dosya başına isteğe bağlı. İstek, yanıtta karşılaştırılan bir
nonce taşıyor, yanıt boyutu sınırlı, ayardaki adres `http`/`https` ile
kısıtlı — böylece bir ayar satırı damgalamayı yerel dosya okuyucusuna
çeviremiyor — ve ortaya çıkan token hiç ağ kullanılmadan doğrulanıyor
(§4.9).

**M1 — ne dayanmıyor.** O tek istek, **düz metnin SHA-256'sını** üçüncü bir
tarafa gönderiyor. §3 zaten bu hash'in bir dosyayı çözmeden doğrulamaya
yaradığını kabul ediyor; damgalama o yeteneği zaman damgası makamına ve
ayardaki adres düz `http` ise yol üzerindeki herkese veriyor. Ayrıca düşman
ya da taklit bir makam kusursuz doğrulanan bir token döndürebilir, çünkü
güven kökü token'ın İÇİNDE geliyor — bunu yalnızca dışarıdan verilen bir
kök (`--trusted-root`) kapatıyor (§4.9).

**M1 — kapsam dışı.** Tedarik zinciri. Bağımlılıklar her push'ta taranıyor
(`.github/workflows/ci.yml` içindeki `pip-audit`) ama bu raporlamadır,
kontrol değil. HYCLEUS'un çağırdığı üçüncü taraf motorların — platformun
antivirüsü — kendi ağ davranışı var ve bu proje onu yönetmiyor.

**M2 — ne dayanıyor.** HYCLEUS'un asıl kurgulandığı model bu ve tasarımın en
güçlü olduğu yer burası. Dosya içerikleri AES-256-GCM ve anahtar hiçbir
zaman bütün hâlde saklanmıyor. Kasa dosyası yalnızca Argon2id ile mühürlü
`share_1`'i veriyor — yani **PIN kırılsa bile saldırganın elinde tek bir pay
kalıyor ve tek pay bilgi kuramsal olarak hiçbir şey** (§4.4). `share_2`,
güncel bir kurulumun veritabanında DEĞİL ve yedeğe zaten hiç yazılmıyor
(`usb_tokens` dışarıda bırakılıyor, §4.11). Bozulma ve kurcalama, M2'nin
sahip olmadığı bir anahtara karşı tespit edilebiliyor.

Tek bir istisna var ve §4.4'ün "hiçbir şey döndürülmüyor" ısrarının nedeni
de bu: `share_2`, **OS anahtar kasasına taşınmadan önce**
`usb_tokens.share_2` sütununda düz metin olarak duruyordu. O yükseltmeden
ÖNCE alınmış ham bir `data/` kopyası onu hâlâ taşıyor ve kırılmış bir PIN'le
birleştiğinde ana anahtarı GERÇEKTEN yeniden kuruyor. Migration canlı
kopyanın üzerine yazıp onu temizliyor; makineden çoktan çıkmış bir kopyaya
ulaşamıyor.

**M2 — ne dayanmıyor.** §3'ün ilk paragrafındaki her şey: veritabanı diskte
düz metin, yani dosya adları, kullanıcı kayıtları, roller, HWID'ler ve tüm
denetim günlüğü okunabilir; her `.hcl` başlığındaki AAD de okunabilir. Kasa
HMAC'i, HWID'yi bilen herkes tarafından üretilebilir (§4.2). Uygulama
seviyesindeki her kontrol — hız sınırı, kara liste, hareketsizlik kilidi,
TOTP — basitçe YOK, çünkü M2 uygulamayı çalıştırmıyor (§4.5).

**M2 — kapsam dışı, ve iki durum da gerçek.** Birincisi: **HWID bir donanım
sırrı değil ve bazı cihazlarda donanımdan hiç türemiyor.** Depolama yığını
kullanılamaz bir seri bildirdiğinde `get_usb_hwid()` `data/usb_ids.json`
içinde saklanan bir UUID'ye düşüyor — gerçek bir cihazda ölçüldü ve
`BACKLOG.md` içinde **B-025** olarak kayıtlı. O cihaz sınıfında, `data/`
dizininin bir kopyasını tutan kişi cihaz kimliğini **USB olmadan** yeniden
üretiyor. HWID zaten bir sır değildi (§4.2), yani gizlilik kaybı yok; ama
"bu cihaza bağlı" ifadesi kulağa geldiğinden zayıf ve yukarıdaki sınır
şeması bu bilgiyle okunmalı. İkincisi: `DEV_MODE` kurulumları (§4.3) —
orada dosya anahtarı yalnızca HWID'den türüyor, yani M2 her şeyi çözüyor.
Derlenmiş çalıştırılabilirlerde zorla kapalı.

**M3 — ne dayanıyor.** Çok az şey ve §1'in giriş paragrafı bunu açıkça
söylüyor. İki şey ayakta kalıyor. GCM etiketi **anahtarlı**, yani M3 bir
dosyayı yok edebilir ama değiştirip doğrulanır hâlde bırakamaz (§4.7) —
§4.7'nin söylemediği tek bir koşulla: bu ancak M3 ana anahtarı **kilitli
olmayan** bir oturumda yakalamadığı sürece geçerli, çünkü o anda anahtar
süreç belleğinde (§3, "Bellek") ve anahtarlı olan her şey onunla birlikte
düşüyor. Ve o hâle soğuktan ulaşmak için PIN hâlâ gerekli: M3'ün elinde
`share_2` var ve ikinci bir paya ihtiyacı var; bu da kasanın Argon2id mührü
ya da basılı kâğıt demek. §1'in adını koyduğu engel tam olarak bu.

**M3 — ne dayanmıyor.** Anahtar kasası ona cevap veriyor. Uygulama
seviyesindeki her kontrol bir veritabanı yazımı uzaklıkta (§4.1, §4.5,
§4.8). Kilit sayacı silinebilir (§3). Bir belge açık olduğu sürece düz metin
`data/safezone/` içinde (§4.10), oturum kilitli değilken de süreç belleğinde
(§3). Zaman damgası fragmanı, dosyayı bozmadan sökülebilir (§4.9).

**M3 — bilinçli olarak kapsam dışı.** §6.2 zaten "makinenin hâlihazırda ele
geçirildiğini varsayan saldırılar" bildirimlerini kapsam dışı ilan ediyor ve
bu bir kaçamak değil: M3 sınırın KENDİSİ, içindeki bir şey değil. HYCLEUS'un
M3'e karşı sağladığı şey **engelleme değil kanıt** — denetim zinciri, dış
çapa ve bütünlük taraması, bir M3 saldırganının varlığını SONRADAN görünür
kılmak için var. Bunun gerçekten işe yarayıp yaramadığı, çapanın M3'ün
ulaşamayacağı bir yerde durmasına bağlı; §4.6'daki `HYCLEUS_AUDIT_ANCHOR`
tartışması tam olarak bunu, yani gerçek bir özellik ile bir zahmet arasındaki
farkı anlatıyor.

## 2. HYCLEUS'un koruduğu senaryolar

**Model** sütunu, kararın hangi saldırgana karşı iddia edildiğini söylüyor
(§1.1). Bir süs değil, bir kapsam: M2 etiketli bir satır **M3 hakkında
hiçbir iddia taşımıyor** ve bu kararların birkaçı, saldırgan oturum açmış OS
kullanıcısı olduğunda gerçekten değişiyor. Her birinin nereye düştüğü
§1.2'de.

| Senaryo | Model | Korunuyor mu | Neyle |
|---|---|---|---|
| Şifreli dosya (`.hcl`) makineden kopyalandı | M2 | ✅ | AES-256-GCM; anahtar hiçbir yerde bütün durmuyor |
| Ciphertext veya GCM tag'inde tek byte değişti | M2 | ✅ | GCM doğrulaması — `AuthenticationError`, asla sessizce yanlış veri |
| Başlıktaki metadata (dosya adı, user_id, hwid, SHA-256) düzenlendi | M2 | ✅ | Metadata GCM AAD'sidir; her değişiklik doğrulamayı düşürür |
| Aynı anahtar dosyalar arasında yeniden kullanıldı | M2 · M3 | ✅ | Her şifrelemede taze 12 byte `os.urandom` nonce |
| Vault dosyası (`.hclv`) kopyalandı, PIN bilinmiyor | M2 | ✅ | Argon2id KEK (time=3, bellek=64 MB, para=4) + GCM |
| `share_2` veritabanından okundu | M2 | ✅ güncel bir kurulumda | Artık orada değil — OS anahtar kasasında. O taşımadan **önce** alınmış ham bir `data/` kopyası onu hâlâ düz metin taşıyor; istisnanın hesabı §1.3'te |
| Yalnızca bir Shamir payı ele geçirildi | M2 | ✅ | 2-of-3 bilgi-teorik olarak güvenli; tek pay hiçbir şey sızdırmaz |
| Arayüz üzerinden PIN kaba kuvveti | M3 | ⚠️ Yavaşlatılır | 5 hatada 30 sn, 300 sn'ye tırmanır, sayaç DB'de kalıcı |
| Denetim kaydının ORTASINDAN bir satırın değiştirilmesi/silinmesi | M3 | ⚠️ Tespit edilir, engellenmez | SHA-256 hash zinciri; `verify_audit_chain()` tam olarak hangi kayıt olduğunu söyler — bkz. §4.6 |
| En yeni denetim kayıtlarının silinmesi (kuyruğun kesilmesi) | M3 | ⚠️ Yalnızca çıpayla tespit edilir | Zincirin ucu veritabanının dışına, `data/audit_anchor.log`'a yazılır — bkz. §4.6 |
| Değişiklikten sonra tüm zincirin yeniden hesaplanması | M3 | ⚠️ Yalnızca çıpayla tespit edilir | Hash anahtarsızdır; yalnızca dıştaki çıpa itiraz eder — bkz. §4.6 |
| Bir `.hcl` dosyasının diskte sessizce bozulması (bit çürümesi, yarım kopyalama, müdahale) | M3 | ⚠️ Bulunur, ama kararı silinebilir | Haftalık bütünlük taraması her GCM tag'ini dosyayı açmadan doğrular; dosyanın kendisi sahtelenemez, `files.integrity_status` içindeki karar silinebilir — koşullar ve gerekçe §4.7'de |
| Başında kimse olmayan, açık kalmış bir oturuma erişilmesi | M3 | ⚠️ Süreyle sınırlı | Hareketsizlik kilidi: USB takılı olsa bile N dakika giriş olmazsa oturum kilitlenir, açmak PIN ister — bkz. §4.8 |
| Çözülmüş kopyaların sistem TEMP dizininde kalması | M2 · M3 | ✅ Oraya hiç yazılmaz | Geçici düz metin `data/safezone/`'a gider; çıkışta ve sonraki açılışta imha edilir — bkz. §4.8 |

## 3. HYCLEUS'un **korumadığı** senaryolar

Bunlar hata değil, tasarımın sınırlarıdır. Her biri, ait olduğu saldırgan
modelleriyle etiketli (§1.1).

**Diski okuyabilen saldırgan.** *(M2 · M3)* SQLite veritabanı (`data/hycleus.db`)
**şifreli değildir.** Dosya adları, kullanıcı kayıtları, roller, HWID'ler ve
denetim kaydının tamamı diskte düz metindir. `sqlcipher3` planlanmış bir
geçiştir, mevcut bir özellik değil. Şifreli dosya *içerikleri* korunmaya
devam eder; etraflarındaki her şey korunmaz.

**Diske yazabilen saldırgan.** *(M3)* Denetim kaydı, aynı şifresiz veritabanında
sıradan bir tablodur ve dosyaya yazabilen birinin satır değiştirmesini ya da
silmesini hiçbir şey engellemez. v2.2'den itibaren bu müdahaleler *fark
edilebilir* — kayıt, ucu veritabanının dışına çıpalanan bir hash zinciridir.
Ama fark etmek engellemek değildir, zincir yalnızca yükseltmeden SONRAKİ
kayıtları kapsar ve iki tespit mekanizmasından biri yeterince titiz bir
saldırgan tarafından aşılabilir. Buna güvenmeden önce §4.6'yı okuyun.

**Vault'un çevrimdışı kaba kuvvetle kırılması.** *(M2)* `.hclv` kopyalanıp rahatça
saldırıya uğrayabilir; bu kod hiç çalışmaz. Dayatılan tek maliyet
Argon2id'dir (time=3, bellek=64 MB, paralellik=4). Giriş sınırlaması burada
anlamsızdır — o uygulamanın içindedir, saldırgan ise uygulamayı kullanmıyor.

**Giriş sınırlamasının kaldırılması.** *(M3)* Sayaç, şifresiz veritabanındaki
`login_attempts` tablosundadır. `DELETE FROM login_attempts` kilidi kaldırır.
Şifrelenemez — uygulamanın kendi kilidini okuyabilmesi gerekir. Sistem
saatini geri almak da kilidi erken düşürür; `locked_until` mutlak zaman
damgasıdır, çünkü monotonik saat yeniden başlatmada sıfırlanır ve en çok
önemsediğimiz özelliği kaybettirirdi.

**Ele geçirilmiş OS kullanıcı hesabı.** *(M3)* Anahtar kasası `share_2`'yi oturum
açmış kullanıcıya verir. O kullanıcı olarak çalışan zararlı yazılım da
HYCLEUS'un istediği gibi isteyebilir.

**Bellek.** *(M3)* Çözülmüş içerik Python `bytes` nesnelerinde durur. Ara tamponlar
`ctypes.memset` ile sıfırlanır, ama Python veriyi çoktan kopyalamış olabilir
ve döndürülen `bytes` değiştirilemez olduğu için silinemez. Bellek dökümü ya
da takas dosyası düz metin içerebilir.

**Güvenli silme garantisi.** *(M2)* Migration eski sırrı silmeden önce üzerine
yazar. Bu, yazmanın aynı fiziksel sektöre indiğini varsayar — SSD'de (wear
levelling), kopyala-yaz dosya sistemlerinde (btrfs, ReFS), snapshot'larda ve
VM imajlarında bu yanlıştır. Mantıksal katmanda elden gelenin en iyisidir,
bir silme değil.

**Metadata gizliliği.** *(M2 · M3)* `.hcl` dosyasındaki AAD bloğu — orijinal dosya adı,
düz metnin SHA-256'sı, zaman damgaları, `user_id`, `hwid` — doğrulanır ama
**şifrelenmez.** Dosya başlığında okunabilir. SHA-256 ayrıca şüphelenilen bir
dosyanın şifresi çözülmeden doğrulanmasına imkân verir.

> Çevrimdışı saldırgan senaryolarını kapatan kontrol **tam disk
> şifrelemesidir.** HYCLEUS onun yerine geçmez.

## 4. Sakladığımız zayıflıklar yok — bilinenler

Her madde, ilgilendirdiği saldırgan modelleriyle açılıyor (§1.1). Yalnızca
M3'ün ulaşabildiği bir zayıflık, M2'nin kopyalanmış bir diskle
ulaşabildiğinden BAŞKA bir şeydir; bu etiketleme tam olarak ikisini denk
okuma hatasını önlemek için var.

### 4.1 USB'yi kara listeye almak hiçbir şeyi iptal etmez

> **Saldırgan modelleri:** M3

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

> **Saldırgan modelleri:** M2 · M3

Vault'un HMAC-SHA256 imza anahtarı `HKDF(hwid)`'dir — ve HWID bir USB seri
numarasıdır, sır değil. `data/usb_ids.json` içinde, veritabanında saklanır ve
cihazın kendisinden okunabilir. **HWID'i bilen herkes geçerli bir vault HMAC'ı
üretebilir.**

Dolayısıyla HMAC yalnızca HWID'i bilmeyen birine karşı kurcalama *kanıtı*
sağlar ki bu zayıf bir varsayımdır. Gizlilik buna dayanmıyor: ciphertext,
Argon2id/PIN türevli KEK altında AES-256-GCM ile korunuyor ve HWID AAD olarak
bağlanıyor. HMAC ikinci, daha zayıf bir katmandır — kapıyı tutan o değildir.

### 4.3 DEV_MODE dosya anahtarını yalnızca HWID'den türetir

> **Saldırgan modelleri:** M2 · M3

`DEV_MODE` açıkken (ve yalnızca donmuş çalıştırılabilir olarak çalışmıyorken)
dosya şifreleme anahtarı `PBKDF2-HMAC-SHA256(hwid, sabit tuz, 100 000)`
olur — **PIN hiç işin içinde değildir.** HWID'i bilen herkes tüm dosyaların
şifresini çözebilir. Bu bir geliştirme kolaylığıdır ve derlenmiş
çalıştırılabilirlerde zorla kapatılır (`sys.frozen`), ama gerçek veri tutan
bir makinede asla açmayın.

### 4.4 Kurtarma parçası anahtara giden üçüncü yoldur

> **Saldırgan modelleri:** M2 · M3

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

> **Saldırgan modelleri:** M2 · M3

USB HWID kontrolü ve giriş sınırlaması *HYCLEUS arayüzü üzerinden*
yapılabilecekleri sınırlar. İkisi de dosyalar üzerinde doğrudan çalışan
birini sınırlamaz. Bunu burada söylüyoruz çünkü README daha önce `share_2`'nin
"HWID kontrolüyle korunduğunu" iddia ediyordu — korumuyordu ve iddia
düzeltildi.

### 4.6 Denetim zinciri kurcalama KANITIDIR ve yalnızca v2.2'den itibaren geçerlidir

> **Saldırgan modelleri:** M3

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

> **Saldırgan modelleri:** M3

Haftalık arka plan taraması (`CORE/integrity.py`) kayıtlı her `.hcl`
dosyasının GCM tag'ini ve vault'un HMAC'ını doğrular; sonucu
`files.integrity_status` ve `files.integrity_checked_at` alanlarına yazar.
Denetim zincirinin aksine bu kontrol **anahtarlıdır**: GCM tag'i AES-256
master key altında hesaplanıyor, yani anahtarı olmayan biri dosyayı
değiştirip hâlâ doğrulanan bir tag üretemez. Tam olarak bu noktada güçlüdür.

**"Anahtarı olmayan" bir KOŞUL ve o koşul oturum kilidi.** Oturum *kilitli*
iken master key erişilebilir değil ve yukarıdaki cümle yazıldığı gibi
geçerli. *Kilitsiz* bir oturumda ise anahtar süreç belleğinde ve §3 zaten
bir bellek dökümünün ona ulaşabileceğini kabul ediyor — oraya ulaşan bir M3
saldırganı anahtarı elde eder ve bu belgedeki anahtarlı her denetim, bu
dahil, onunla birlikte düşer. Güç gerçek; o güç kilidin gücü.

Sınırlar:

- **Karar şifresiz veritabanında saklanıyor.** `UPDATE files SET
  integrity_status = 'ok'` bulguyu siler. *Dosya*, yukarıdaki koşul altında
  taklit edilemez; *onun hakkındaki rapor* hiçbir koşul olmadan edilebilir. Aynı bulgunun denetim kaydındaki karşılığını
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

> **Saldırgan modelleri:** M2 · M3

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

SafeZone, ihtiyaç duyacak akıştan ÖNCE konmuş bir altyapıydı. O akış artık
var — şeffaf erişim, §4.10 — ve düz metni diske yazan tek şey o. İndirmeler
hâlâ doğrudan kullanıcının seçtiği yola akıyor, SafeZone'a hiç uğramıyor.

### 4.9 Zaman damgaları çevrimdışı doğrulanabiliyor — ama güven kökü dosyadan geliyor

> **Saldırgan modelleri:** M1 · M2 · M3

Bir `.hcl` dosyası RFC 3161 zaman damgası taşıyabiliyor: AAD'de zaten
kayıtlı olan **düz metin SHA-256**'sı (`original_sha256`) bir Zaman Damgası
Otoritesi'ne imzalatılıyor. Özet başlıktan okunduğu için damgalama
**anahtar istemiyor ve düz metne hiç dokunmuyor**. Kanıtladığı şey dar ama
gerçek: bu içerik, TSA'nın imzaladığı tarihte zaten vardı.

`verify_timestamp()` artık bu iddiayı kriptografik olarak, **hiç ağa
çıkmadan** doğruluyor — imzalama sertifikası ve zinciri token'ın içinde
geliyor (`certReq=True`), yani doğrulama dosyanın kendisinden başka hiçbir
şey kullanmıyor. On kontrol sırayla koşuyor: token ayrıştırılabiliyor ve tam
olarak bir imzalayan taşıyor; imzalayanın sertifikası gömülü; `message-digest`
ve `content-type` imzalı öznitelikleri tutuyor; imza o sertifikanın açık
anahtarıyla doğrulanıyor; sertifika `timeStamping` EKU'su taşıyor
(RFC 3161 §2.3); **`genTime` anında** geçerliydi (bugün değil); zincirdeki
her sertifika bir üsttekiyle imzalanmış; ve damgalanan özet dosyanın
`original_sha256`'sıyla aynı. Komut satırı aracı da var:

```
python CORE/verify_timestamp_cli.py --verify-timestamp <dosya.hcl> [--trusted-root ca.pem]
```

Yani zaman damgası artık yalnızca bir kayıt değil. Üç sınır kaldı ve
birincisi asıl önemli olan:

**Güven kökü, doğrulanan dosyanın içinden geliyor.** Kanıtlanan şey zincirin
*iç tutarlılığı*; kökünün güvenilir olduğu değil — kök, token'la aynı
dosyada seyahat ediyor. Fragmanı yeniden yazabilen biri kendi CA'sını
üretir, kendi TSA sertifikasını keser, istediği tarihi söyleyen bir token
imzalar ve bu kod ona GEÇERLİ der; çünkü matematiksel olarak geçerlidir.
Gerçek güven, kökün dosyanın **dışında** tutulan bir depoyla
karşılaştırılmasını gerektirir: `verify_timestamp(trusted_roots=...)` ya da
CLI'da `--trusted-root`. Verilmezse sonuç `anchor_trusted=False` taşıyor ve
CLI her seferinde açık bir uyarı basıyor — varsayılan sessizce güven ima
etmiyor. Bu, §4.6'daki denetim çıpasıyla aynı biçimde bir sınır: kanıt ile
kanıtı doğrulayan şey aynı yerde durmamalı.

**Fragman GCM tag'inin dışında.** Tag yalnızca AAD ile ciphertext'i
kapsıyor; magic, sürüm byte'ı ve zaman damgası fragmanı kapsam dışı. Yani
bir damga **silinebilir**: fragman kırpılırsa dosya sorunsuz çözülür,
yalnızca damgasız görünür. "Hiç damgalanmadı" ile "damgası silindi" dosyaya
bakarak ayırt EDİLEMEZ. Damga *başka bir içeriğe uydurulamaz* — özet AAD ile
çapraz kontrol ediliyor ve başka bir dosyanın token'ı reddediliyor — ama yok
edilebilir.

**Anahtarsız damgalamada özet doğrulanmamıştır.** `original_sha256` AAD'de
duruyor ve GCM onu koruyor, ama bu korumayı kontrol etmek anahtar ister.
Hem damgalama hem doğrulama onu anahtarsız okuyor, yani "başlığın iddia
ettiği özet gerçekten damgalanmış mı" sorusuna yanıt veriyorlar. Eşlik eden
soru — "içerik gerçekten o özete mi sahip" — `verify_file()`'ın işi ve
anahtar ister. `timestamp_file()` opsiyonel bir anahtar alıyor ve verilirse
önce `verify_file()` çalıştırıyor.

**Kontrol EDİLMEYENLER:** sertifika iptali (OCSP ya da CRL yok — ikisi de ağ
ister, burası bilerek çevrimdışı) ve kendini imzalayan bir kökün kendi
imzası, ki o bir güven ifadesi taşımaz.

Kap sürümü: bu özellikten önce yazılan dosyalar `0x01` ve aynen okunmaya
devam ediyor. Yeni dosyalar `0x02` ve fragmanı **olmayan** bir `0x02` de
tamamen geçerli — damga opsiyonel ve sonradan ekleniyor. `0x01` dosyalarda
fragman hiç aranmıyor, çünkü o formatta böyle bir şey tanımlı değildi.
Fragman biçimi `0x01`'de KALDI: sertifika zinciri token'ın içinde olduğu
için ikinci bir kopya eklenmedi — birbirini tutmayabilecek iki liste, tek
listeden kötü olurdu.

### 4.10 Şeffaf erişim, düzenlediğiniz sürece düz metni diskte tutuyor

> **Saldırgan modelleri:** M2 · M3

"Aç", belgeyi SafeZone'a çözüyor, varsayılan uygulamayla açıyor,
değişikliği yeni bir nonce ile geri şifreliyor ve geçici kopyayı güvenli
siliyor. Gerçek bir boşluğu kapatıyor — önceden kullanıcı indirmek, geri
şifrelemeyi hatırlamak ve silmeyi hatırlamak zorundaydı — ama bunu diske
bir düz metin kopyası koyarak yapıyor. Bu takas açıkça yazılmalı.

**"Kapandı" diye bir olay yok.** `os.startfile()` hemen dönüyor ve tutamaç
vermiyor; Windows'ta çoğu uygulama, dosyayı zaten açık olan asıl örneğe
devredip çıkan bir başlatıcı çalıştırıyor — "süreç bitti" ile "belge
kapandı" aynı şey değil. Bu yüzden model sürüm kontrolündeki gibi
çıkış/giriş kaydı: belge, değişiklik algılanıp durulana, kullanıcı "Bitir"
diyene, uygulama kapanana ya da oturum kilitlenene kadar açık kayıtlı
duruyor. Kilit bilerek dâhil: düz metni diskte bırakan bir kilit ekranı ön
kapıyı tutup pencereyi açık bırakırdı. Kaç belgenin açık olduğu pencerede
görünüyor, çünkü "kapatmayı unuttum" sessiz bir durum olmamalı.

**Doğruluk dosya izleyicisine bağlı DEĞİL.** Word, Excel ve pek çok
düzenleyici kaydederken yeni bir dosya yazıp adını eskisinin üzerine
taşıyor; bu, `QFileSystemWatcher`'ın yol izlemesini düşürüyor ve olay hiç
gelmiyor. Bu yüzden izleyici bir optimizasyon: altında 5 saniyelik yoklama,
onun da altında kapanıştaki check-in var. Üçü de aynı soruyu soruyor: düz
metin SHA-256'sı en son şifrelenen hâlden farklı mı? İzleyici her olayı
kaçırsa bile değişiklik, kopya silinmeden önce yakalanıyor. `mtime` tek
başına yetmezdi: bazı uygulamalar onu koruyarak yazıyor, bazı araçlar
içerik değişmeden dokunuyor.

**Geri yazma atomik.** Yeniden şifrelenen dosya geçici bir yola yazılıp
`os.replace()` ile yerine konuyor. Yazma sırasında bir çökme orijinal
`.hcl`'i BOZMUYOR — §4.9'daki zaman damgası fragmanıyla aynı desen ve aynı
gerekçe: yarım yazılmış bir `.hcl` GCM doğrulamasını geçemez ve haftalık
bütünlük taraması sağlam bir belgeyi "bozuk" olarak raporlardı.

**Maruziyet penceresi düzenleme oturumu.** Belge açıkken düz metni
`data/safezone/` içinde duruyor ve §3'teki bütün sınırlar ona da geçerli:
diski okuyabilen bir saldırgan onu okuyabilir, ardından gelen güvenli silme
de mantıksal katmanda elinden geleni yapıyor (SSD wear leveling,
kopyala-yaz dosya sistemleri, snapshot'lar). Belge açma denetim kaydına
giriyor (`file_opened`) — o kayıt, düz metnin diske indiği anı işaretliyor.
Düz metni dosya sisteminden tamamen uzak tutacak tam sanal sürücü
(Dokan/WinFsp) kapsam dışı; bu ara çözüm.

### 4.11 Yedek kasayı makineden çıkarıyor — veritabanı da şifreli olarak gidiyor

> **Saldırgan modelleri:** M2

Shamir kurtarma (§4.4) kaybolan ANAHTARI kapsıyor; kaybolan DİSK için
hiçbir şey yapmıyor. Yedek o boşluğu kapatıyor ve ikisi bilerek ayrı
duruyor:

    yedek → medya kaybı        Shamir → anahtar kaybı

**`.hcl` dosyaları olduğu gibi kopyalanıyor, yeniden sarmalanmıyor.**
Zaten AES-256-GCM ve dosya başına ayrı nonce taşıyorlar. İkinci bir katman
gizlilik kazandırmazdı: AAD (özgün ad, düz metin SHA-256, zaman
damgaları, `user_id`, `hwid`) KAYNAK MAKİNEDE de başlıkta okunabilir
durumda (§3); sarmalamak, kasada zaten açık olanı yalnızca yedekte
gizlerdi. AAD maruziyetini düzeltmek bir format değişikliğidir, bir
yedekleme özelliği değil. Dürüst sonuç: yedekteki dosya adları kasanın
sızdırdığının aynısını sızdırıyor, fazlasını değil.

**Asıl maruziyet veritabanı ve o şifreleniyor.** §3 açıkça kabul ediyor:
SQLite diskte düz metin — dosya adları, kullanıcı kayıtları, roller,
HWID'ler ve denetim günlüğünün tamamı. Bunu harici medyaya kopyalamak,
binadan çıkmak üzere tasarlanmış bir şeye bütün envanteri açıkça yazmak
olurdu. Bu yüzden gereken tablolar kanonik JSON'a çıkarılıp
`encrypt_file()` ile şifreleniyor — aynı ilkel, aynı anahtar, yeni kripto
yok. Geçici düz metin döküm, yedek bitmeden güvenli siliniyor.

**Anahtar kasası yedeklenmiyor.** `.hclv` içinde Argon2id ile korunan
`share_1` var. Harici medyada bu, hazır bir çevrimdışı kaba kuvvet hedefi
olurdu — ve kaybolan tam olarak harici medyadır. Anahtar kaybı Shamir'in
işi. Sonucu açıkça: **bu yedekten dönmek çalışan bir anahtar gerektiriyor.**
Anahtar da gittiyse önce §4.4, sonra geri yükleme.

**Denetim günlüğü yedekleniyor ama geri yüklenmiyor.** Uyumluluk için
saklanması değerli, ama başka bir veritabanına yazmak aynı geçmişi iddia
eden ikinci bir zincir yaratırdı ve çıpayla (§4.6) tutmazdı. Geri yükleme
onu ayrı bir dosyaya çıkarıyor: okunabilir, canlı zincirin dışında.
`users`, `usb_tokens` ve `settings` hiç yedeklenmiyor.

**Doğrulama geri yüklemeden ÖNCE çalışıyor ve anahtar istemiyor.**
Manifesto her dosyanın ŞİFRELİ hâlinin SHA-256'sını taşıyor; bozulma,
kesilme ve eksik dosya anahtarsız yakalanıyor — zamanlanmış bir betik
yedeği kasayı açmadan kontrol edebiliyor. Anahtar verilirse
`verify_backup()` ek olarak `verify_file()` üzerinden GCM tag doğrulaması
yapıyor (düz metin birleştirilmiyor) ve düz metin manifestoyu aynı listenin
şifreli kopyasıyla karşılaştırıyor — yeniden yazılmış bir manifestoyu
yakalayan şey bu. Geri yükleme, doğrulama düşerse ÇALIŞMIYOR; dolu bir
hedefe açık onay olmadan yazmıyor ve canlı kasaya ya da veritabanına hiç
dokunmuyor.

### 4.12 Shamir payları ayrıştırıcıda doğrulanıyor — bu sertleştirme, bir açığın kapatılması değil

> **Saldırgan modelleri:** yok — bu madde bir kontrolle değil, hata
> bildirimiyle ilgili. Gerekçe aşağıda ve bölümün bütün konusu o.

Bir dış incelemeci (issue #1) kurtarma parçası çözücüsünün, çözülen değerin
kanonik biçimde olduğunu **ve** alan asalından küçük olduğunu kontrol edip
etmediğini sordu. O günkü dürüst yanıt şuydu: uzunluk kontrol ediliyordu,
aralık **hiçbir yerde** kontrol edilmiyordu — ne çözücüde ne çağıranda.

**Bu bir güvenlik açığı değildi ve nedenini söylemek önemli.** Lagrange
interpolasyonu zaten `mod p` çalışıyor, yani `y` payı ile `y + p` payı
**aynı** anahtarı kurtarıyor. Kanonik olmayan bir pay kimseye zaten
erişemeyeceği bir şey vermiyordu: sömürmek için elinizde geçerli bir pay
olması gerekiyor ve zaten sırrın tamamı o. Gizlilik kaybı yok, 2-of-3 eşiği
hiç düşmedi.

Maliyeti **hata bildirimindeydi** ve ne kadar olduğunu ölçtük:

| | |
|---|---|
| Kanonik payların 33 baytlık uzaydaki payı | **1/255** (%0,39) |
| Kanonik bir payın ilk baytı | daima `0x00` |
| `y >= p` üreten tek karakterlik yazım hataları | **%4,6** — önceden sessizce kabul |
| Aralıkta kalan tek karakterlik hatalar | %95,3 — meşru bir başka paydan ayırt edilemez, hiçbir kontrol yakalayamaz |

Yani aralık kontrolü yazım hatalarının %4,6'sını "yanlış anahtar, sonradan
gelen belirsiz hata"dan "kurtarma parçanızda yazım hatası var"a çeviriyor.
Kazanç bundan ibaret. Değerli, ama güvenlik düzeltmesi değil.

**Kontrol çözücüde değil, `_parse_share()` içinde.** Çözücü üç girişten
yalnızca biri — diğer ikisi vault dosyası ve işletim sistemi anahtar kasası
— ve `reconstruct_key()` genel, belgeli bir API: gelecekteki bir CLI ya da
üçüncü taraf bir entegrasyon onu doğrudan çağırıp çözücüyü tamamen
atlayabilirdi. Doğrulamayı darboğaza koymak o boşluğu kapatıyor. Ayrıca
`recover_master_key()` artık indisin 3 olmasını şart koşuyor; pay 1 veya 2
vermek hiçbir zaman bypass değildi (ikisi de geçerli pay ve veren kişi
onlara sahip demektir) ama sessizce çalışıp denetim kaydına yanlış olay
düşürüyordu.

**İki küçük şey olduğu gibi kalıyor.** Base32, 53 karakterlik gövdede bir
bit boşluk bırakıyor; her payın aynı sonuca çözülen iki metin gösterimi var
(Python'un `b32decode`'u artık bitleri sınamıyor). Ve tam olarak `0` değeri
artık dejenere sayılıp reddediliyor — bu, meşru bir sıfır payı da elerdi;
olasılığı ~2^-256, donanım arızasının çok altında.

**Geriye dönük uyumluluk:** basılı kurtarma parçaları etkilenmiyor.
`_fmt_share()` her zaman `(...) % p` sonucunu 66 haneye sıfır dolgulu
yazıyor ve bu biçim v1.5'ten (`cdce520`) beri değişmedi — 2-of-2 dönemi
kodu da aynı sabiti kullanıyordu. HYCLEUS'un ürettiği her pay zaten
kanonik; test paketi bunu hem üretilmiş paylar üzerinde hem gerçek bir
vault round-trip'iyle kanıtlıyor.

---

### 4.13 TPM mühürlemesi tabanı YALNIZCA M2 için yükseltiyor — ve sırrı tek bir yongaya bağlıyor

> **Saldırgan modelleri:** M2 · M3

Windows'ta TPM 2.0 varsa sırlar anahtar kasasına yazılmadan önce TPM'e
mühürleniyor (`CORE/tpm_sealing.py`). Mührü açan anahtar yonganın içinde
üretiliyor ve dışarı çıkamıyor — ölçüldü, `NCryptExportKey`
`NTE_NOT_SUPPORTED` döndürüyor. Bu şekilde yazılan kayıtlar `TPM1:` öneki
taşıyor; öneksiz kayıtlar mühürsüzdür ve eskisi gibi okunuyor.

**Kazandırdığı şey tam olarak M2, başka hiçbir şey.** §1.2, anahtar kasası
blob'unun diskle birlikte gittiğini ve OS hesap parolasının onu açtığını
söylüyor. Mühürlü bir kayıt için bu artık doğru değil — blob, o belirli
yonga olmadan işe yaramaz. **M3 etkilenmiyor**: TPM de oturum açmış
kullanıcıya, tıpkı anahtar kasası gibi, cevap veriyor. Bu, çalınmış bir
diskin altındaki tabanı yükseltiyor; ele geçirilmiş bir oturumu
savunmuyor.

**Yalnızca Windows'ta geçerli.** Linux ve macOS eskisi gibi anahtar
kasasına düşüyor; TPM'i olmayan bir Windows makinesi de öyle. O düşüş
*asla sessiz değil* — her oturumda denetim kaydına
(`tpm_sealing_unavailable`), `--selftest` çıktısına ve Yardım → Hakkında
kutusuna düşüyor. Bu, B-025'in dersinin bilinçli uygulaması: kendini
sessizce kapatan bir katman, hiç kurulmamış olandan kötüdür, çünkü belge
onu iddia etmeye devam eder.

**Bedeli gerçek ve adı veri kaybı.** TPM temizlenirse (BIOS'ta "Clear TPM",
anakart değişimi, bazı firmware güncellemeleri) anahtar yok oluyor ve
mühürlenmiş her değer **kalıcı olarak açılamaz** hâle geliyor. `share_2`
için çıkış yolu basılı kurtarma parçası (§4.4) — Shamir 2-of-3 tam olarak
bu arıza için var. TOTP sırrı için çıkış yolu ikinci faktörü yeniden
kurmak. Mühür açılamaması ASLA "kayıt yok" diye bildirilmiyor: öyle
bildirilseydi *kurulmamış* diye okunur ve çağıran tarafı yeniden kurmaya
iterdi — kurtarılabilir bir kasanın kurtarılamaz hâle gelmesi tam olarak
böyle olur.

**Mevcut kayıtlar geriye dönük MÜHÜRLENMİYOR.** Bu özellikten önce
yazılmış bir kayıt, onu bir şey yeniden yazana kadar mühürsüz kalıyor;
`share_2` için bu, yeniden sağlama demek. Yani TPM'li bir makinedeki
yerleşik bir kurulum o güne kadar hiçbir kazanım görmüyor ve arayüzün
hiçbir yeri bunu söylemiyor. `BACKLOG.md` içinde **B-042** olarak
izleniyor.

**Ne ölçüldü, ne ölçülmedi.** Yol gerçek donanımda çalıştırıldı (AMD fTPM
2.0, rev 1.59): mühürleme 1.2 ms, açma 38 ms, tek seferlik anahtar üretimi
1.33 sn. Ölçülmeyen: başka hiçbir TPM üreticisi, ve CI — hiçbir koşucuda
TPM yok, o yüzden ilgili testler orada atlanıyor ve bu yolun sağlığı tek
bir geliştirici makinesinin ölçümüne dayanıyor. B-023'teki ClamAV
çekincesinin aynısı, aynı gerekçeyle yazılıyor.

### 4.14 `.hclx` teslim paketi POLİTİKAYLA süre doluyor, matematikle değil

> **Saldırgan modelleri:** M2 · M3

`.hclx`, belgeleri kasa dışına bir geçerlilik penceresiyle taşıyor
(`CORE/hclx.py`). Yalnızca **kullanıcı verisi** için — kod taşımıyor, ve
uygulama güncellemesi bu formata bilerek BENZEMEYEN ayrı bir format: magic
baytları farklı, yani birini diğerine veren kod ilk baytta duruyor.

**Süre dolunca: paket AÇILMIYOR. SİLİNMİYOR.** İki davranış da mümkündü,
bu seçildi; o yüzden garanti ima edilmiyor, açıkça yazılıyor:

- Silmek, doğru olmayan bir şeyi ilan etmek olurdu. Alıcı paketi pencere
  içinde açtıysa düz metin zaten elinde — kaydetmiş, yazdırmış ya da
  kopyalamış olabilir. Kabı sonradan yok etmek içeriği geri getirmiyor.
- Silme zaten en iyi çaba: §3'teki bütün sınırlar geçerli (SSD wear
  levelling, kopyala-yaz dosya sistemleri, anlık görüntüler).
- Dosya alıcının makinesine ait. HYCLEUS'un onu sormadan silmesi, başkasının
  diskinde yıkıcı bir işlem olurdu ve deponun mevcut kuralıyla çelişirdi:
  sürenin dolması silmeyi *serbest* kılar, *zorunlu* değil; kararı insan
  verir (`CORE/disposal.py`).

**Yani pencere, §4.5'in tarif ettiği sınıftan bir uygulama seviyesi
kontrol — kriptografik bir kontrol DEĞİL.** İki sonucu var, ikisi de
gerçek:

- Alıcı anahtarı zorunlu olarak tutuyor (yoksa hiç açamazdı), dolayısıyla
  değiştirilmiş bir istemci pencereyi tamamen yok sayabilir.
- Kontrol **yerel saate** bakıyor. Saati geri almak paketi yeniden açar.
  §3 aynı çekinceyi giriş kilidi için zaten kabul ediyor; bilerek çevrimdışı
  bir uygulamada güvenilir bir "şimdi" yok.

Pencerenin gerçekten kazandırdığı: dürüst bir alıcının makinesinde belge
süresiz açık kalmıyor, ve **her deneme — başarılı ya da reddedilmiş —
denetim kaydına düşüyor** (`hclx_opened` / `hclx_rejected`); kim, ne zaman,
pencere içinde miydi.

**İmza, GCM tag'idir ve erişimi kasa düzeyindedir.** Yeni bir şema icat
edilmedi: gövde `encrypt_file()` ile mühürleniyor, her yerdeki aynı ilkel
ve aynı anahtar. Bu gerçek bir bütünlük veriyor — tek bayt değişse
açılmıyor. Kaynak doğrulamasını ise **yalnızca kasa granülerliğinde**
veriyor: bir paketi ancak bu kasanın master key'ini tutan biri üretebilir.
HANGİ kullanıcı olduğunu kanıtlayamaz, çünkü kasaya erişimi olan herkes o
anahtarı paylaşıyor. Manifestodaki `sender_user_id` kurcalanamaz ama bir
beyandır. Kullanıcı düzeyinde kaynak kanıtı asimetrik bir kimlik ister; bu
projede yok, sınır bulanıklaştırılmak yerine yazıldı.

**Manifesto anahtarsız okunabiliyor ve bu bilinçli.** Alıcı, açmayı
denemeden önce pencereyi ve göndereni görebilmeli; çözemeyen biri de bir
reddi loglayabilmeli. Düz metin olduğu için düzenlenebilir — bu yüzden aynı
manifesto şifreli gövdenin İÇİNDE de duruyor ve açılışta ikisi bayt bayt
karşılaştırılıyor. Pencereyi uzatmak için dış kopyayı düzenlemek burada
yakalanıyor. §4.11 yedek manifestosu için aynı deseni zaten kullanıyor.

**Üretim zamanı beyandır.** `created_at` üreten makineden geliyor ve
istediğini yazabilir. RFC 3161 damgası (§4.9) bunu güvenilir bir alt sınıra
çevirirdi; bu sürümde yapılmadı — bkz. B-035.

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
| PIN saklama | Argon2id hash (asla düz metin); yeni PIN'ler için en az 6 karakter — ama geçiş penceresi boyunca giriş ekranı mevcut 4–5 karakterlik bir PIN'i hâlâ kabul ediyor (`LOGIN_MIN_LEN = 4`), yani "en az 6" henüz her hesap için doğru değil. Köprü, kaldırma kriteri ve pencere `BACKLOG.md` / B-040 içinde |
| Sır saklama | OS anahtar kasası, servis `HYCLEUS`, adlar `share_2:<hwid>` ve `totp_secret` |
| Sır mühürleme | Yalnızca Windows + TPM 2.0: rastgele 32 baytlık DEK, sır üzerinde AES-256-GCM (AAD = kasa kullanıcı adı), DEK dışa aktarılamayan TPM RSA-2048 anahtarıyla CNG üzerinden sarmalanıyor (PKCS#1 v1.5 — OAEP'i Platform Crypto Provider reddediyor, ölçüldü); `TPM1:` öneki, düşüş GÜRÜLTÜLÜ — bkz. §4.13 |
| İkinci faktör | TOTP (RFC 6238), 6 hane, ±1 pencere |
| Yedekleme | `.hcl` dosyaları olduğu gibi (zaten GCM); DB tabloları kanonik JSON'a çıkarılıp aynı ilkelle şifreleniyor; manifesto ciphertext SHA-256 taşıyor, yani bütünlük anahtarsız kontrol edilebiliyor — `.hclv` bilerek hariç, bkz. §4.11 |
| Teslim paketi (`.hclx`) | Başlık + düz metin manifesto + eksiksiz bir `.hcl` gövdesi; imza, o gövdenin kasa master key'i altındaki GCM tag'i — yani kaynak kasa granülerliğinde kanıtlanıyor, kullanıcı başına değil; manifesto gövdenin içinde de duruyor ve bayt bayt karşılaştırılıyor; geçerlilik penceresi uygulama tarafından yerel saate karşı uygulanıyor — bkz. §4.14 |
| Güvenilir zaman damgası | RFC 3161, **düz metin** özeti üzerinden SHA-256 message imprint, nonce + `certReq`; token GCM tag'inin dışındaki opsiyonel dosya fragmanında |
| Zaman damgası doğrulaması | Çevrimdışı, ağsız: `signedAttrs` üzerindeki CMS imzası (ECDSA / RSA PKCS#1 v1.5 / PSS) gömülü imzalama sertifikasına karşı, `timeStamping` EKU, `genTime` anında geçerlilik, gömülü sertifikalar arasında zincir yürüyüşü, özetin AAD ile çapraz kontrolü — güven kökü dışarıdan verilmeli, bkz. §4.9 |

**Rastgelelik** baştan sona `os.urandom` ve `secrets`'tan gelir — nonce'lar,
tuzlar, master key'ler ve Shamir polinom katsayısı.

**Desteklenen sürüm:** yalnızca en son sürüm (şu an **v2.1.2**) güvenlik
düzeltmesi alır. Çalıştırdığınız sürüm **Yardım → Hakkında** kutusunda
yazıyor; iki dize de `CORE/version.py`'den geliyor, dolayısıyla bu belgeyle
çelişirlerse eskimiş olan belgedir.

---

## 6. Güvenlik açığı bildirimi

Güvenlik sorunları için lütfen **herkese açık issue açmayın.**

> 🔍 **HYCLEUS hiç dış güvenlik incelemesinden geçmedi ve bir inceleme
> arıyor.** Bildirmek yerine *incelemek* istiyorsanız kapsam ve açık davet
> [issue #1](https://github.com/yubin-dev/HYCLEUS/issues/1) içinde —
> eşgüdüm için doğru yer orası. Bulgular yine §6.1'den geçer.

### 6.1 Bize nasıl ulaşılır

GitHub'ın özel bildirim yolunu kullanın: **Security → Report a vulnerability**
([bu depoda](https://github.com/yubin-dev/HYCLEUS/security/advisories/new)).
Yalnızca geliştiricinin görebileceği özel bir danışma kaydı oluşturur.

> **O bağlantı 404 veriyorsa**, depo ayarlarında özel açık bildirimi
> açılmamış demektir — özellik varsayılan olarak kapalıdır ve bu belge onu
> açamaz. Bu durumda **hiçbir teknik ayrıntı içermeyen** bir herkese açık
> issue açın ("bir güvenlik sorunu bildirmek istiyorum, lütfen özel
> bildirimi açın") ve özel bir kanal bekleyin. Bulguyu oraya yazmayın.

### 6.2 Kapsam

| Kapsam içinde | Kapsam dışında |
|---|---|
| Bu depodaki kod | Üçüncü taraf bağımlılıklar (yukarı akışa bildirin; HYCLEUS etkileniyorsa bize de söyleyin) |
| Kripto kabı (`.hcl`), anahtar hiyerarşisi, Shamir payları | GitHub, PyPI veya işletim sistemi anahtar kasasının kendisi |
| Vault, PIN, TOTP ve USB token akışları | §3 ("korumadığı senaryolar") ve §4 ("bilinen zayıflıklar") içindeki her şey |
| Denetim zinciri ve zaman damgası doğrulaması | Makinenin zaten ele geçirildiğini varsayan saldırılar — bu §1'de yazılı sınırdır |
| Yedekleme, geri yükleme ve şeffaf erişim | Söylemesi bedava, yapması büyük olan sertleştirmeler (ör. "donanım anahtarı kullanın") |

**Tek başına açık sayılmayanlar:** SQLite veritabanı diskte şifresizdir
(§4.11), uygulama seviyesi kontroller diske erişebilen biri tarafından
aşılabilir (§4.5) ve bir dosya düzenlemeye açıkken düz metni diskte durur
(§4.10). Bunlar bilinmedikleri için değil, doğru oldukları için yazılıdır.

### 6.3 İşe yarayanlar

Etkilenen sürüm veya commit, saldırganın ne kazandığı, yeniden üretme
adımları ve ortam (işletim sistemi, Python sürümü). Kavram kanıtı
memnuniyetle karşılanır ama zorunlu değildir.

Lütfen **saldırganınızın §1'deki hangi güven sınırının dışından
başladığını** belirtin. Geçersiz çıkan bildirimlerin çoğunda saldırgan,
elde etmeye çalıştığı şeye zaten sahip varsayılmış oluyor.

### 6.4 Beklenecekler

| Aşama | Hedef |
|---|---|
| Alındı bildirimi | 7 gün |
| İlk değerlendirme (geçerli / bilinen / kapsam dışı) | 30 gün |
| Düzeltme ya da düzeltmeme kararının yazılı gerekçesi | 90 gün |

HYCLEUS ticari olmayan, tek kişilik bir projedir — ödül programı ve resmî
bir SLA yoktur; tablo bir niyettir, sözleşme değil. Düzeltmeler, aksini
tercih etmediğiniz sürece adınıza atıfla bir sürümde yayınlanır.

### 6.5 Eşgüdümlü ifşa

Düzeltme çıksın ya da çıkmasın, **bildiriminizden 90 gün sonra**
yayınlayabilirsiniz. İzin almanız gerekmez ve daha fazla beklemeniz
gerekmez. Düzeltme daha erken çıkarsa yayınlandığı anda yazabilirsiniz.

Bizden ses çıkmazsa bu sayaç yine işler. Yanıt vermeyi bırakan bir
geliştirici, bir bulgunun gömülü kalması için gerekçe değildir.

Yayınlamayı düşünüyorsanız haber verin ki danışma kaydı ile sürüm notları
aynı anda çıkabilsin.

### 6.6 Güvenli liman

Bu politikaya uygun ve iyi niyetle hareket ederseniz size karşı yasal yola
başvurmayacağız, böyle bir girişimi desteklemeyeceğiz ve araştırmanızı
**yetkili** sayacağız.

İyi niyet şu demek: yalnızca kendi makineniz ve kendi verinizle çalışmak,
hizmet dışı bırakmaya çalışmamak, başkasının verisini yok etmemek ve dışarı
çıkarmamak, sorunu gösterdiğiniz anda durmak ve §6.5'teki süre dolmadan
kamuya açıklamamak.

Bu, bu projenin geliştiricisinin verdiği bir sözdür. Üçüncü tarafları
bağlayamaz — testiniz GitHub'a, bir servis sağlayıcıya ya da başkasının
altyapısına dokunuyorsa onların şartları geçerlidir ve bu paragraf sizi
korumaz.

### 6.7 Zaten biliniyor mu?

§3 ve §4'teki her şey bilerek belgelenmiştir. Bunlardan birini yineleyen bir
bildirim "bilinen" olarak kapatılır — burada anlatılandan daha kötü olduğunu
gösterebiliyorsanız o başka, o gerçekten değerlidir.

**Ayrıca işe yarayan ve açıkça istenen:** bu belgenin *yanlış* olduğu bir
yer. §2 veya §5'te tutmayan bir iddia, §4'te olduğundan hafif anlatılmış bir
zayıflık, §1'de yazılı ama kodun aslında uygulamadığı bir sınır. Bunlar
güvenlik politikasının kendisine dair güvenlik bulgularıdır ve hatalardan
daha zor görülürler.

### 6.8 Halihazırda çalışan otomatik analiz

Bildirmeden önce bilin: her push'ta `ruff`, `mypy`, `bandit` ve `semgrep`
çalışıyor (`.github/workflows/ci.yml`), ayrıca elle tetiklenen bir iş akışı
kripto kabını ve Shamir uygulamasını `atheris` ile fuzz'lıyor
(`.github/workflows/fuzz.yml`).

Bu araçların gözden geçirilip yerinde bırakılan bulguları gerekçesiyle
birlikte `BACKLOG.md` içinde kayıtlı. Bunlardan birini yineleyen bir bildirim,
değerlendirmenin yanlış olduğunu gösterebiliyorsanız yine de değerlidir —
ikinci bir çift gözün yakaladığı şey tam olarak budur.
