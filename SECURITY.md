# Security Policy — HYCLEUS

**Applies to:** v2.3.0 · Last reviewed: 2026-08-21

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
| Vault HMAC, key = HKDF(share_2, info=HWID) | — | ✅ `share_2` is not on a stolen disk (§4.2, §4.13) | ❌ the credential store answers M3 too (§1.2 above) |
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
Every application-level control — rate limit, blacklist, idle lock, TOTP —
is simply absent, because M2 is not running the application (§4.5). The
vault HMAC no longer belongs in this list: it used to be forgeable by
anyone who knew the HWID, but the signing key now comes from `share_2`,
which is not in `data/` and does not travel with a stolen disk (§4.2).

**M2 — out of scope, and both cases are real.** First, **the HWID is not a
hardware secret and on some devices is not hardware-derived at all.** When
the storage stack reports an unusable serial, `get_usb_hwid()` falls back to
a UUID persisted in `data/usb_ids.json` — measured on a real device, and
recorded as **B-025** in `BACKLOG.md`. On that device class, anyone holding
a copy of `data/` reproduces the device identity **without the USB**. The
HWID was never a secret (§4.2), so no confidentiality is lost, but "bound to
this device" is weaker than it sounds and the boundary diagram above should
be read with that in mind. §4.15 closes part of this: `open_vault()`,
`authenticate_usb()` and the other trust-granting operations now refuse
this identity class outright, for anyone presenting it — reproducing the
UUID no longer buys M2 ordinary vault access either, though it still says
nothing about `share_2`, which §4.2 already covers. Second, `DEV_MODE`
installations (§4.3): there
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

### 4.2 The vault HMAC key is derived from share_2, not the HWID

> **Attacker models:** M2 · M3

Until this fix, the vault's HMAC-SHA256 signing key was `HKDF(hwid)` — and
the HWID is a USB serial number, not a secret. It is the vault file's own
name (`vaults/<hwid>.hclv`), it is stored in `data/usb_ids.json` and in the
DB, and it can be read from the device itself. **Anyone who knew the HWID
could forge a valid vault HMAC** — no PIN, no Shamir share, nothing beyond
the filename.

The signing key is now `HKDF(share_2, info=hwid)`
(`CORE/vault_manager.py::_derive_signing_key`): `share_2` supplies the key
*material*, `hwid` only binds the signature to a device through HKDF's
`info` parameter and is never used as key material itself. `share_2` is a
single Shamir share — below the 2-of-3 threshold it reveals nothing about
the master key on its own (§4.4) — but unlike the HWID it never appears in
a filename, the database, or the GCM AAD. It lives only in the OS
credential store, optionally TPM-sealed on Windows (§4.13). Verification
still needs no PIN: `share_2` is read from the store the same way
`open_vault()` already reads it, so `authenticate_usb()` (USB
re-insertion) and the weekly integrity sweep (§4.7) work exactly as before.

**What this buys, by model.** Under M2 (a stolen disk or backup, no OS
session) the attacker never had `share_2` — §1.2's Shamir row already
establishes that a stolen disk yields only `share_1`, which is
information-theoretically nothing on its own. The vault-HMAC row above
moves from ❌ to ✅ for M2: forging it now costs exactly what decrypting the
file already cost. **Under M3 nothing changes**: the credential store
answers the logged-in OS user directly (§1.2), so `share_2` was always
reachable there, and the row stays ❌ for M3 — the same limit every
credential-store-backed control in this document already has.

**What did not change.** Confidentiality never rested on the HMAC: the
ciphertext is protected by AES-256-GCM under the Argon2id/PIN-derived KEK,
with the HWID as AAD, and that did not move. The HMAC is a second,
independent layer over the *outer* envelope — magic, salt, nonce,
`token_id` — fields the GCM tag does not cover. It was never "the one
holding the door," but it is no longer forgeable from information that sits
in the open.

**Exactly what the HMAC signs.** `_sign()` is called on the *entire*
`protected` blob, not just the ciphertext:

```
protected = magic(4B) + version(1B) + salt(16B) + nonce(12B)
          + token_id(16B) + ciphertext(var) + gcm_tag(16B)
```

(`CORE/vault_manager.py:691-694`, mirrored at `:1038-1039` for role changes
and `:1095-1096` for PIN changes; signed at `:602`, `:736`, `:790` and
verified against `:795`.) GCM's own AAD is `hwid` alone
(`authenticate_additional_data(hwid.encode())`, e.g. `:685`) — it covers
`ciphertext` and `gcm_tag` directly and nothing else. So three groups of
fields inside `protected` end up covered by three different mechanisms, and
it matters which:

| Field | Covered by | How |
|---|---|---|
| `ciphertext`, `gcm_tag` | GCM tag | directly — GCM's own authentication |
| `salt`, `nonce` | GCM, *indirectly* | feed `_derive_kek`/the cipher; a changed value decrypts to garbage and the GCM tag check fails — forging a passing decryption needs the KEK, i.e. the PIN |
| `magic`, `version` | explicit checks | `_decrypt_vault` raises before touching GCM if either byte is wrong (`CORE/vault_manager.py`, the `raw[:4] != _MAGIC` / `raw[4] != _VERSION` checks) |
| `token_id` | **the outer HMAC only** | not GCM AAD, not read before decryption, no other check anywhere in `_decrypt_vault` |

`token_id` is the one field with no fallback: skip the outer HMAC and it is
provably unauthenticated. That skip is exactly what `_decrypt_vault` now
does when `share_2` is unavailable (below).

**`verify_vault()`'s guarantee has two modes, and they are not the same
strength.**

- **`share_2` present** (`authenticate_usb`, the weekly integrity sweep, and
  the normal login path before `share_2` is even needed for anything else):
  `verify_vault()` runs to completion and the outer HMAC is checked. Every
  field in `protected` — including `token_id` — is authenticated against a
  value nobody outside the credential store and the vault file together can
  reproduce. This is the vault-HMAC row's ✅ for M2 above.
- **`share_2` unavailable**, exactly one path: `recover_master_key(hwid,
  recovery_share=..., pin=...)` with the *`share_2`-is-lost* branch, via
  `_decrypt_vault` (`CORE/vault_manager.py`, the `except ValueError: pass`
  around `verify_vault(hwid)`). Here the outer HMAC is **not checked at
  all** — `magic`/`version` are still caught by the explicit checks,
  `salt`/`nonce`/`ciphertext`/`gcm_tag` are still bound together by GCM
  (forging a passing decryption still needs the PIN), but **`token_id` is
  unauthenticated**: nothing in this call path checks it against anything.

**Is the unauthenticated `token_id` exploitable? No — traced and tested.**
`_decrypt_vault` never reads or returns `token_id` in the first place (its
return value is `(share_1, role)`), so `recover_master_key`'s recovered
`master_key` is unaffected by `token_id` tampering — the Shamir math never
touches it. The only place `token_id` is ever *checked* is
`authenticate_usb`'s Layer 3 (`vault_token_hex == db_token_id`), and that
path calls `verify_vault()` directly, with no `share_2`-missing bypass — if
`share_2` is still missing there, Layer 2 rejects first and Layer 3 never
runs. And the real recovery flow (`CORE/recover_vault.py::_cmd_recover`)
follows a successful `recover_master_key()` with `reprovision_vault()`,
which writes an entirely fresh `token_id` (`uuid.uuid4()`) and overwrites
the file outright — so even a tampered value does not outlive the recovery
session that reads it. `tests/test_vault_hmac_share2.py` asserts both
halves of this directly: tampering `token_id` and running the `share_2`-less
path still returns the *correct* `master_key` (`test_tampered_token_id_is_
not_read_by_share2_less_recovery`), and reprovisioning afterward erases the
tampered value for good (`test_tampered_token_id_does_not_survive_
reprovisioning`).

This is a narrow, load-bearing assumption, not a general excuse: it holds
*because* nothing downstream of the `share_2`-less path currently branches
on `token_id`. If a future change ever makes `_decrypt_vault` or
`recover_master_key` read `token_id` for an authorization decision, this
paragraph and the two tests above go stale together and need re-deriving —
they are not a permanent guarantee, just an accurate description of the
current call graph.

**The full call graph, audited.** `recover_master_key()` has exactly one
production call site: `CORE/recover_vault.py:146`, inside `_cmd_recover()`
(`tests/test_recovery_call_graph.py::test_recover_master_key_TEK_uretim_
cagri_yeri_var` pins this — it fails, visibly, the day a second one is
added). No GUI flow, no API, no other script calls it; `UI/AdminPanel.py`
and `UI/main_window_open.py` only point the user at the CLI in prose. That
one call site does **not** unconditionally reprovision: `_cmd_recover()`
lets the user decline (`CORE/recover_vault.py:168-174`, the "Atlandı"
branch) and return with the vault still signed under the old key and
`token_id` still tampered, if it was. The reprovision-happens-immediately
story is therefore false as a blanket claim — what actually holds is
narrower, and it holds regardless of which branch runs:

- The one audit-log write in this whole path is `recover_master_key()`'s
  own `db.log("vault_recovered", detail=f"hwid={hwid} kaynak=...")`
  (`CORE/vault_manager.py:1283-1286`) — `detail` is built from exactly two
  values, `hwid` and a fixed source label; `token_id` is not a variable in
  scope for that f-string, buffered or not. `_cmd_recover()` itself never
  calls `DBManager().log(...)` at all. Its only console output about the
  recovered key is the byte length and a SHA-256 digest
  (`CORE/recover_vault.py:156-160`) — again, nothing about `token_id`.
- `_read_vault_token_id()` — the *only* function that ever reads the field
  back out of a vault file — has exactly one caller in the codebase,
  `authenticate_usb()`'s Layer 3 (`CORE/vault_manager.py:857`), and that
  path calls `verify_vault()` without the `share_2`-missing bypass. So the
  decline branch does not create a state where `token_id` gets trusted
  later without `share_2` being available again — and if `share_2` *does*
  become available again, `verify_vault()` re-checks the full outer HMAC,
  `token_id` included, and a tampered value fails it then.

`tests/test_recovery_call_graph.py` makes both of these checks executable:
`test_recover_master_key_her_cagri_yerinde_reprovision_erisilebilir` is the
structural half — an AST scan asserting every function that calls
`recover_master_key()` also calls `reprovision_vault()` somewhere in the
same body, which is *reachability*, not a claim that the decline branch
doesn't exist. `test_token_id_okuyan_TEK_yer_authenticate_usb` pins
`_read_vault_token_id()`'s single caller by AST, and
`test_vault_recovered_denetim_kaydi_token_id_icermez` tampers `token_id`,
runs the `share_2`-less recovery, and asserts the resulting `vault_recovered`
row contains neither the tampered bytes nor the string `token_id` at all.

**Migration.** A vault created before this fix carries the old, HWID-only
signature and would fail verification under the new scheme outright.
`run_migrations()` (`CORE/secret_migration.py`, schema v4,
`migrate_vault_hmac`) re-signs every registered HWID's vault at startup,
before login — `share_2` is all it needs, so no PIN prompt is involved. A
file is only re-signed if it verifies under the *old* scheme first; one
that verifies under neither is left untouched and logged as a warning, on
the assumption that "doesn't verify under either scheme" means genuinely
corrupted or tampered rather than merely un-migrated — the weekly integrity
sweep (§4.7) is where that distinction gets made, not the migration step.

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

**That "disk access" path also needs to know which hwid to combine the
share with — and whether that is hard depends entirely on which layer is
asked to do it.** `CORE/recover_vault.py`'s CLI entry points
(`_cmd_export`/`_cmd_recover`/`_cmd_status`) each call `_require_hwid()`
as the *first line of their own body*, not from `main()`'s dispatch —
proven by calling them directly, bypassing `main()` entirely, and
watching the USB check still fire (`tests/test_kurtarma_usb_kapisi.py`).
But `CORE/vault_manager.py::recover_master_key()` — the function that
actually does the math — has no such check anywhere in its source
(confirmed by reading it, not inferring it): it takes `hwid` as a plain
string argument and never calls `get_usb_hwid()`. Called directly,
bypassing the CLI script entirely, with an hwid read off the
`data/vaults/<hwid>.hclv` filename (no USB, and in the "share_1 lost"
branch, no PIN either), it reconstructs the real master key — proven
end to end, not asserted. This is not a bug and was not fixed: baking a
physical-USB check into `recover_master_key()` itself would foreclose
the very design **B-036** is still deciding whether to build (a
paper-share-plus-PIN recovery path for a *genuinely* lost USB) — the
core function deliberately does not police how its caller came to know
`hwid`, only the CLI script does. The practical reading: `_require_hwid()`
is a real defense *only when the vault is operated through its standard
CLI entry point as intended* — it adds nothing against an attacker who
already has the code-execution capability this document's M2/M3 models
assume, which is exactly the class §4.5 says application-level controls
never reach. Full analysis and line references: **B-069**.

**The design mockup's "enter with a recovery share" login screen was
deliberately never built, and a permanent test now guards the whole
`UI/` tree against it, not just the login screen.** Building it would
hand every ordinary user the USB-less, PIN-less path described above.
The test (`tests/test_kurtarma_usb_kapisi.py`) walks every `.py` file
under `UI/` (subdirectories included) for two things: an actual call to
or import of `recover_master_key`/`decode_share` — the two functions
that *reconstruct* a key from a share — and a UI label carrying the
mockup's "enter with the share" wording. It deliberately does **not**
ban `export_recovery_share`, `RecoveryShareDialog`, or a variable named
`share_3`: those are the legitimate *export* path already in
`AdminPanel.py` (PIN-gated, tested, display-only), and a first version
of this scan that included them broke on that real, correct code —
handing someone a share is not the risk; letting a share back in to
rebuild the key outside `_require_hwid()`'s gate is. Proven directly: a
`recover_master_key` import was planted in `UI/ProfileDialog.py` (a file
with nothing to do with recovery) and the scan caught it before the
change was reverted — confirming the check is not tied to the login
screen specifically, only to `UI/` as a whole.

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

**Since v2.3.0 the share can also be exported from the Admin Panel, not
only the CLI — and this is the single most sensitive screen the
application shows.** Admin Panel → Settings → "Show Recovery Share" asks
for the vault PIN, then displays the same `build_export()` output — QR
code and base32 text side by side — that `recover_vault.py --export` has
always produced. There is exactly one production path; the dialog only
renders it, and a static-analysis test checks that it never calls the QR
library itself. Showing the share on screen instead of a terminal opens
two exposure surfaces a CLI export does not have:

- **Screen capture.** On Windows the window sets `WDA_EXCLUDEFROMCAPTURE`
  (falling back to `WDA_MONITOR`, which blacks the window out in a
  capture rather than hiding that something was there) before it is
  first painted, and the dialog states on screen whether that succeeded.
  Silence is not an option — the same reasoning §4.13 gives for a TPM
  fallback applies here: a protection that turns itself off quietly is
  worse than one that was never built, because the document keeps
  claiming it. Linux and macOS have no equivalent API and the dialog says
  so plainly. This gap is **B-049**.
- **Clipboard.** The "Copy to clipboard" button warns before it copies —
  a clipboard manager with history (Windows Win+V, third-party tools)
  can retain the value regardless of anything HYCLEUS does afterwards —
  and the application clears its own copy 30 seconds later *only if* the
  clipboard still holds exactly what it wrote. If the user copied
  something else in the meantime it is left alone; overwriting someone
  else's clipboard silently would look like data loss, not a safeguard.
  None of this reaches a clipboard-history tool that already captured
  the value.

The confirmation checkbox ("I printed this and put it somewhere safe") is
**not a security control**, and it is not meant to be: it only enables
the "OK" button, while Esc and the window's own close button work
regardless. That split is deliberate — a window a user cannot dismiss
teaches nothing, it only forces a click, which is the lesson **B-003**
left behind.

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

**The trust anchor must come from outside the file, and now it can.** What
the chain proves on its own is *internal consistency*, not that its root
deserves trust — the root travels in the same file as the token. Anyone who
can rewrite the trailer can mint their own CA, issue their own TSA
certificate, sign a token saying whatever time they like, and the chain
check alone will call it valid, because mathematically it is.

The answer is a root store held outside the file, and there are now two
ways to supply one:

| Where | How | Who it is for |
|---|---|---|
| Application | `settings.tsa_trusted_roots`, managed in **Admin Panel → Settings** (`CORE/trusted_roots.py`) | Everyday use: the organisation adds its TSA root once and every later verification uses it |
| CLI | `--trusted-root ca.pem` | An auditor, who brings their own root |

**The CLI deliberately ignores the stored list.** Someone running the
command-line verifier is auditing *this machine*; reading the trust list out
of the database they are auditing would ask the question of the thing being
questioned. Only the PEM/DER parser is shared, so the two cannot drift.

**Three outcomes, and they are now visually distinct.** With no root
configured the result is `valid=True, anchor_trusted=False` and the UI
titles it "valid — but the issuing authority was not verified", in amber,
not the green of a fully verified stamp. With a matching root it is
`anchor_trusted=True`. With a root configured that does *not* match, the
result is **invalid** (`failed_check="trust_anchor"`) — configuring a root
does not merely add a badge, it hardens the verdict.

**What this does not fix.** The list lives in `settings`, and §3 concedes
that the database is plaintext on disk. Anyone who can write to it (M3) can
add their own root and make a forged stamp read as fully trusted. So the
improvement is exactly the shape of the audit anchor in §4.6: evidence and
the means of checking it are no longer in the *same file*, but they are
still on the *same machine*. Keeping the list somewhere M3 cannot reach —
as `HYCLEUS_AUDIT_ANCHOR` allows for the anchor — is not implemented; see
B-044.

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

**Batch stamping trades N signatures for one, and a proof carries the
rest of the weight.** `CORE/merkle.py` builds a domain-separated Merkle
tree over many files' `original_sha256` values, so a single TSA
signature over the root covers all of them; each file then keeps a short
path from its own leaf to that root instead of its own token. What the
signature proves does not change — "this hash existed no later than this
time" — only the cost is shared instead of paid per file. Domain
separation between leaf and internal-node hashing closes the two classic
Merkle pitfalls: a forged leaf built from an internal node's own hash,
and the CVE-2012-2459 duplicate-node ambiguity that let two different
file sets produce the same root. `verify_merkle_path()` re-walks a
file's stored path and rejects it outright if that path does not lead to
the signed root — the same failure mode as an unrecognised signature.
Every limit already stated in this section applies unchanged to a
batched stamp: the trust anchor still has to come from outside the file,
the trailer is still strippable, and the TSA still sees the plaintext
hash — only the token is shared, not the guarantee. **The batch
primitive is implemented and tested but, like single-file stamping
itself, has no caller in the shipped application** — nothing currently
calls `timestamp_file()` or `timestamp_batch()` outside the test suite,
so no file in a real vault carries a timestamp yet. See **B-035**. This
means `CORE/merkle.py`'s tree-building side (`build_leaves`/`build_tree`,
only ever reached through `timestamp_batch()`) never actually runs on
real data either — its *verification* side is a different story:
`verify_merkle_path()` above genuinely is called from the real "Damgayı
Doğrula" UI action, it just never sees a real tree to check, for the same
reason. `CORE/merkle.py`'s own module docstring states both halves
precisely. Both claims — write side dark, read side live but starved of
real input — are re-checked by AST on every test run in
`tests/test_deneysel_bagli_degil.py`, not just measured once.

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

**2026-08-29 — a proposed WAL checkpoint before the dump would have been
a no-op; the real gap was cross-table snapshot consistency, and it is now
fixed.** A `PRAGMA wal_checkpoint(TRUNCATE)` was proposed right before the
table dump, on the premise that a backup taken without one could be
incomplete. Checked first: `create_backup()` never copies the raw
`hycleus.db` file — it reads tables through `db.fetchall()` on the live
connection ([DB/db_manager.py](DB/db_manager.py), `self.conn.execute(sql,
params).fetchall()`), and in WAL mode a `SELECT` through a connection
always returns the fully committed state regardless of checkpoint status;
checkpointing only affects how much sits in `-wal` versus the main file,
never what a query sees. So the checkpoint was not added — it would not
have closed any real gap.

What *was* a real gap, verified directly: `_dump_tables()` reads
`RESTORABLE_TABLES` as one `SELECT` per table, with no transaction tying
them together. Opening a second connection to the same file and
committing a write between two of those `SELECT`s — measured with
`sqlite3` directly before touching any code — produced exactly the torn
read: the earlier table reflected the pre-write state, the later table
reflected the post-write state. Concretely, a file inserted concurrently
with a matching `quarantine` row could land in the `quarantine` dump
without ever appearing in the `files` dump — a reference to a row that
was never backed up, and a database that would fail its own foreign-key
constraints on restore. The fix wraps the whole read (`RESTORABLE_TABLES`
*and* `REFERENCE_TABLES`) in one explicit `BEGIN`…`COMMIT`, which pins a
single WAL snapshot for every table read inside it — confirmed both ways,
with and without the wrapper, before and after.

That investigation also surfaced a second, independent bug in
`apply_metadata()`: `RESTORABLE_TABLES` listed `files` *before* `folders`
and `retention_profiles`, which `files` has foreign keys into. Restoring
into an already-populated database (the only scenario the existing tests
exercised) never triggered it, because the referenced rows were already
there. Restoring into a genuinely empty database — the real "new machine"
scenario — failed with `FOREIGN KEY constraint failed`. The table order
is now dependency-safe: tables with no dependencies first, `files` after
what it references, `file_tags`/`quarantine` last. A round-trip test
(`tests/test_backup.py`) now restores into a separate, empty `DBManager`
instance and checks that no `quarantine.file_id` is left pointing at a
`files` row that was never restored.

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

**"Falls back to the credential store" means no hardware backing at all on
those platforms, not just "no TPM."** `CORE/tpm_sealing.py` gates on
`sys.platform == "win32"` — there is no Linux or macOS branch, not a weaker
one, none. And the underlying credential store itself does not supply the
gap by default: `keyring`'s macOS backend calls the standard Keychain
Services generic-password API, which is encrypted with a key tied to the
login password; Secure Enclave / Touch ID-gated protection is a *different*
API (`kSecAttrAccessControl`) that a caller has to ask for explicitly, and
nothing in `CORE/secret_store.py` does. `keyring`'s Linux backend talks to
whatever Secret Service provider is running — GNOME Keyring or KWallet —
and those are typically PAM-unlocked automatically at login with the same
password as the session, with no TPM or hardware token in the path by
default. So on Linux and macOS, `share_2` sits exactly where §1.2's "OS
credential store" row already says it does, with no upgrade — the row's ✅
is a Windows-with-TPM fact, not a cross-platform one, and §4.2's M2 upgrade
for the vault HMAC does not depend on it (M2 is defined in §1.1 as lacking
a usable credential store *at all*, TPM or not).

**This paragraph was not measured on Linux or macOS hardware — this review
only had Windows available.** It follows from how `keyring`'s own backends
are documented to behave and from the absence of any platform branch in
`CORE/tpm_sealing.py`/`CORE/secret_store.py`, not from a run on real Linux
or macOS machines. If that ever gets measured, this note should be replaced
with the result, the same way §4.13's Windows numbers below are.

**The cost is real and it is data loss.** Clearing the TPM (BIOS "Clear
TPM", a mainboard swap, some firmware updates) destroys the key, and every
sealed value becomes **permanently unopenable**. For `share_2` the way out
is the printed recovery share (§4.4) — this is exactly the failure Shamir
2-of-3 exists for. For the TOTP secret the way out is re-enrolling the
second factor. Unsealing failure is never reported as "no record": that
would read as *not configured* and push the caller into re-provisioning,
which is how a recoverable vault becomes an unrecoverable one.

**Existing records get resealed the first time they are read, not left
waiting for a rewrite.** This used to be a real gap (tracked as **B-042**
item 1) — sealing only happened on write, `share_2` is written once (at
registration or reprovisioning), and "a subsequent write" that never comes
meant an established installation on a TPM machine got no benefit, silently,
forever. A 2026-08-28 follow-up closed it: `CORE/secret_store.py::load()`
now attempts an opportunistic re-seal whenever it reads an unsealed record
and the TPM is currently available (`_reseal_firsatci()`) — so the first
`open_vault()` after a TPM becomes available reseals `share_2` without the
user doing anything extra. This does not read `tpm_sealing.durum().kullanilabilir`
itself (that would be a second decision point — `tests/test_tpm_sealing.py::
test_kullanilabilir_karari_baska_modulde_TEKRARLANMIYOR` guards exactly this);
it infers availability from whether `belki_muhurle()`'s return value comes
back sealed. A re-seal failure does **not** fail the read — the value was
already decrypted successfully, and refusing to hand it back because a
best-effort improvement attempt failed would be a new lockout surface that
nobody asked for — but it is not silent either: both outcomes are audited
(`tpm_reseal_completed` / `tpm_reseal_failed`). Verified with a fake-but-
consistent TPM (`test_ESKI_kurulum_ILK_ACILISTA_otomatik_yeniden_muhurleniyor`
— old unsealed install, first `open_vault()` reseals, the reseal actually
decrypts to the right key, exactly one audit row) and, since this development
machine has a real chip, on genuine hardware too
(`test_gercek_TPM_ile_ESKI_kayit_ilk_okumada_yeniden_muhurleniyor`). The
remaining B-042 items (CI never exercising the TPM path, only one vendor
measured, a real Clear-TPM never physically tried) are unrelated to this and
still open.

**Re-seal was audited for side effects, and it found a real one — not in
the re-seal code, in the credential store underneath it.** `store()`
(`CORE/secret_store.py`) has exactly two production call sites for the
secret types it handles: `share_2` (`CORE/vault_manager.py::
_save_usb_token`, and `CORE/secret_migration.py::migrate_share_2` for the
legacy-DB-column upgrade path) and the TOTP secret, global-legacy and
per-hwid (`store_totp_secret`/`store_totp_secret_for_hwid`, called from
`UI/login_dialog.py`, `CORE/registration.py`, and `CORE/secret_migration.py`
for the B-059 migration). Neither the recovery share (`share_3`, never
persisted anywhere — always re-derived) nor PIN-derived key material
(never persisted — Argon2id runs fresh on every unlock) ever reach `store()`.
`store()` itself writes **no audit-chain entry of its own** — grepped, no
`DBManager()` call in its body — so there is no generic "record written"
tag for `tpm_reseal_completed`/`tpm_reseal_failed` to collide with; reading
the chain, a `tpm_reseal_*` row is unambiguous, and
`test_reseal_ile_TAZE_kayit_denetim_zincirinde_AYIRT_EDILEBILIYOR` proves it
directly: a fresh, TPM-available registration leaves zero reseal rows, an
old-installation reseal leaves exactly one. `store()`'s own round-trip
verification calls `load()` — the same function the re-seal logic lives
in — but this can never spuriously fire: whatever `store()` just wrote is
already sealed (if TPM was available, `belki_muhurle()` sealed it before
the write) or the re-seal attempt inside that round-trip is a genuine no-op
(if TPM was unavailable, `belki_muhurle()` returns the value unchanged both
times) — proved in code and in
`test_share_2_DISI_cagri_yerinde_reseal_TETIKLENMIYOR_TAZE_yazimda` for the
non-share_2 call site specifically.

On atomicity: `_reseal_firsatci()`'s write is a single `set_password()`
call, not a create-then-delete pair — there is no `delete_password`/`erase`
call anywhere in it, so there is no window where both the old and new
values could be lost, or neither could be found. Interrupting the write
(`test_reseal_yazimi_KESILIRSE_ESKI_kayit_hala_okunabilir`, `set_password`
raising mid-call) leaves the old, unsealed record fully intact — the
failure is only reported, never allowed to corrupt or drop what was already
there.

**But auditing that call surfaced a second, real gap: Windows Credential
Manager does not delete what `set_password()` overwrites.** `keyring`'s
Windows backend (`keyring.backends.Windows.WinVaultKeyring`) emulates
multiple usernames under one service name — something native `CredWrite`
does not support — by moving whichever credential currently occupies the
bare `TargetName` into a compound one (`{username}@{service}`) before
writing the new value to the bare slot. Measured directly against the real
Windows Credential Manager on this machine (not the in-memory test double,
which does not reproduce this at all): writing `u1`, then `u2` (evicting
`u1` to `u1@HYCLEUS`), then `u1` again — the exact overwrite shape a
re-seal produces — leaves `u1`'s **old, unsealed** value sitting at
`u1@HYCLEUS` forever, invisible to `get_password()` but not deleted.
Under this project's own M2 model this is not inert: Windows credentials
are DPAPI-protected regardless of location, but if that protection is ever
defeated offline (a known class of attack against DPAPI, distinct from
needing to be logged in as the user), the orphaned compound entry hands
back the pre-TPM plaintext-equivalent value with no chip involved at all —
exactly the guarantee sealing exists to remove. This was not something
re-seal introduced — any overwrite of an existing keyring username has
always had this shape on Windows — but re-seal is a new, common source of
exactly that overwrite pattern, so it made the gap worth finding. Fixed the
same day it was found: `CORE/secret_store.py::_windows_golge_sil()` runs
after every successful `store()` and after every successful re-seal write,
Windows-only and only when the active backend actually is `WinVaultKeyring`
(checked by name, so a differently-configured backend is left alone), and
deletes the specific compound target directly via `win32cred.CredDelete` —
never through `keyring.delete_password()`, which searches *and deletes*
both the bare and compound locations for a username and would just as
happily delete the value that was only just safely written. It is
best-effort and ordered strictly after the real write is verified: if
cleanup fails, the new value is already safe and only the stale shadow
persists, exactly as it did before this fix — no new failure mode, no
regression in write safety. Verified against the real backend, not a
mock: `test_windows_golge_kopya_gercek_kasada_TEMIZLENIYOR` reproduces the
eviction, confirms the shadow exists, triggers the cleanup path, and
confirms the shadow is gone and the live value is untouched. Tracked as
**B-070**, closed the same turn it was opened, in `BACKLOG.md`.

**Did the pre-fix code actually leave a real shadow on this machine? The
first pass at this answer overclaimed; here is the corrected version,
checked against write history, not just current state.** `win32cred.
CredEnumerate` against this machine's real Credential Manager found ten
genuine HYCLEUS credentials predating this fix (five `share_2:<hwid>`,
five `totp_secret:<hwid>`; the legacy global `totp_secret` was never
written on this machine at all), none currently showing a shadow. An
earlier version of this note treated that absence as evidence that
`ensure_available()`'s accidental healing had already run for all ten —
but *absence of a shadow is also exactly what "only ever written once"
looks like*, and the audit log cannot rule that out for most of them:
`create_vault()` writes no audit entry of its own on a fresh registration
(only `reprovision_vault()`'s wrapper logs anything), and this database's
`usb_tokens` table currently holds only two rows against five distinct
`share_2` hwids ever seen in the keyring — meaning its bookkeeping has been
reset at least once since some of those credentials were written, so it
cannot testify to their full history either. For nine of the ten, no
reliable evidence of a second write exists either way; the honest
statement is that they show no shadow, and it is not known whether that is
because they were written once or because they were written twice and
already healed.

The tenth is different, and *was* pinned down directly: `audit_log`
contains exactly one `vault_reprovisioned` row, `hwid=USB-PROBE-TOKEN-ID`,
timestamped `2026-08-28T12:32:05Z`. `reprovision_vault()` only runs after
`recover_master_key()`, which (in its PIN branch, the one this row's
`kaynak=share_1+share_3` records) requires an *existing* vault file to read
`share_1` from — so this hwid necessarily had a `share_2` in the keyring
from an original registration, then a second, different `share_2` written
by the reprovision itself: a real, confirmed double write, and — compared
against this fix's commit (`91a4e21`, `19:31:03+03:00` local; the
reprovision was `15:32:05+03:00` local) — one that happened hours *before*
`_windows_golge_sil()` existed. Whether it left a shadow can no longer be
checked: the credential is gone from the keyring entirely now (`CredRead`
finds it at neither the bare nor the compound target), almost certainly
erased during unrelated manual cleanup after the throwaway hwid's use in
an earlier investigation — `secret_store.erase()` calls `keyring.
delete_password()`, which purges both locations unconditionally, taking
any shadow with it. The evidence needed to answer that one specific
question was destroyed before this question was asked.

**So the real question moved from "did a shadow exist" to "does the
healing mechanism actually work, and how completely" — and that was
answered directly, independent of any specific credential's fate.**
Reproduced against the real backend, not inferred: writing `u1` twice in a
row, nothing else in between, leaves `u1`'s old value sitting at its
compound target while the new one sits at bare — a shadow forms from a
second write alone, no third username required. Then, whether a *second,
independent* shadow can coexist with the first was tested directly by
trying to build one: writing an unrelated `u3` (to start its own shadow)
evicts whatever currently occupies the bare slot — which, at that moment,
is `u1` holding its shadowed value — and that eviction is a full overwrite
of `u1`'s compound target, not an append, so it **heals `u1`'s shadow as a
side effect of doing something else entirely**, before `u3`'s own shadow
even exists. Only after that does writing `u3` twice produce a second
shadow — and by then `u1`'s is already gone. The result, checked at every
step (`test_AYNI_ANDA_IKI_golge_YAPISAL_OLARAK_var_olamiyor`): **two
shadows can never coexist in the `HYCLEUS` service.** The single bare slot
means the *next* `set_password()` call for any different username always
heals whatever shadow currently exists before it can create a second one.
`ensure_available()`'s probe write is one reliable source of such a call —
proven separately
(`test_ensure_available_YAN_ETKI_OLARAK_eski_golgeyi_iyilestiriyor`) — but
it is not special; any real `store()` for a different username does the
same healing as a side effect.

**This makes the guarantee where it applies *complete*, not partial — but
it still is not universal, and the fixed code does not depend on it.**
Because at most one shadow can ever exist, one further write for anyone
else always closes it entirely — there is no "healed some, missed others"
outcome to guard against, contrary to what motivated this question. The
gap that remains is exactly the one already documented: if the
shadow-creating overwrite is the *last* write this service ever receives —
no further `store()`, no further `ensure_available()` call, ever — the
single shadow persists indefinitely, unhealed, exactly as exploitable as
B-070 originally described. Because no currently-unhealed shadow could be
found on this machine to verify a cleanup pass against, none was written
this turn, per the instruction governing this check — the fix that matters
is the one already in `store()`/`_reseal_firsatci()` (`91a4e21`), which
closes this on every write deterministically and does not depend on
anyone else ever writing again afterward.

**What was measured and what was not.** The path was exercised on real
hardware (AMD fTPM 2.0, rev 1.59): seal 1.2 ms, unseal 38 ms, one-time key
generation 1.33 s. Not measured: any other TPM vendor, and CI — no runner
has a TPM, so those tests skip there and the path's health rests on one
developer machine. Same caveat as ClamAV in B-023, stated for the same
reason.

**`erase()` had the same two-target problem, in reverse: not a stale copy
left behind, but a stale copy resurrected.** The paragraph above notes in
passing that `secret_store.erase()` calls `keyring.delete_password()`,
"which purges both locations unconditionally" — true of the *outcome*,
but the library's own source
(`keyring/backends/Windows.py::WinVaultKeyring.delete_password()`) does it
as two separate `CredDelete` calls in a loop, bare target first, compound
second, with no verification between them and no recovery if the process
dies in between. Proven directly against this machine's real Credential
Manager, not inferred: build a shadow (write `u1` twice), then perform
only the *first* half of what the library's own delete does — delete the
bare target alone, leaving the compound untouched, exactly what a crash
between the two calls would leave — and `get_password()`, unable to find
the bare target, falls back to the compound and hands back the **old**
value as if it were current. A credential believed erased keeps answering
with stale data — the K0-3 failure mode by name, and worse than the
`store()` shadow above: that one was merely invisible; this one is visible
and wrong.

Fixed by not going through the library's `delete_password()` on this
backend at all: `_windows_erase()` deletes the two targets itself,
**compound first, bare last** — the reverse of the library's own order,
deliberately. Reversing it changes what an interruption between the two
steps can leave behind: if it dies after the shadow is gone but before the
bare copy is touched, `get_password()` still finds the bare target and
returns the *current* value — `erase()` is simply incomplete, exactly as
if it had not been called yet, never wrong. Each deletion is followed by
its own read-back check (`CredRead` must come back not-found) with up to
three retries before raising rather than returning a false success, and
the whole operation is idempotent — a target that is already gone, or
that belongs to a different username, is left alone and not treated as an
error. Verified against the real backend:
`test_erase_KUTUPHANENIN_KENDI_silmesi_KESINTIYE_UGRARSA_eski_deger_GERI_DONUYOR`
reproduces the vulnerable half-deleted state and confirms the resurrection
described above;
`test_erase_WINDOWS_kesintiye_dayanikli_asla_ESKI_deger_DONDURMUYOR`
injects the same interruption into the fixed code path (via a monkeypatched
`CredDelete` that raises right after the real deletion succeeds) and
confirms `get_password()` never returns anything but the current value,
that the interrupted call raises rather than reporting success, and that a
second `erase()` call finishes the job;
`test_erase_gercek_kasada_HER_IKI_hedef_de_TEMIZLENIYOR_ve_IDEMPOTENT`
confirms the ordinary, uninterrupted path removes both targets and that
erasing an already-erased username returns `False`, not an error. Tracked
as a dated addendum to **B-070** in `BACKLOG.md`.

**Does `_windows_erase()` check ownership before touching the bare slot,
or could it delete or corrupt someone else's still-valid credential
sitting there?** Checked by reading the code, not assumed: each target
step (`CORE/secret_store.py::_windows_hedefi_dogrulayarak_sil()`) reads
the target first and compares its `UserName` against the one being
erased — `if mevcut.get("UserName") != username: return False` — before
any `CredDelete` is attempted, for *both* the compound and the bare
target the same way. The check already existed (added when `_windows_
erase()` was first written, to stay correct under the "someone else's
value legitimately occupies bare right now" case that `store()`'s own
eviction logic produces constantly), so nothing needed adding — but
"the code has a branch for it" and "the branch actually works" are
different claims, and only the second was tested here.

Proven against the real Credential Manager: write `A` (takes bare), then
write `B` (evicts `A` to compound, `B` now holds bare) — precisely the
state `store()` leaves behind on every ordinary second write — then call
`erase(A)`. Result: `B`'s bare entry is read back afterward byte-for-byte
identical (same `UserName`, same blob), `keyring.get_password(service,
B)` still returns `B`'s value, and `A`'s own compound copy is genuinely
gone (`CredRead` → not-found) while `secret_store.load(A)` returns
`None`. `erase(A)` never touches a target it does not own — a wrong-owner
match returns `False` and moves on rather than deleting or overwriting
what it finds. Permanent regression test: `test_erase_CAPRAZ_SAHIPLIK_
bare_yuvasindaki_BASKA_kullanicinin_kaydina_DOKUNMUYOR`.

**Independently confirmed against this machine's ten real production
credentials, not assumed safe because the synthetic test passed.** A
snapshot of all ten (`TargetName`, `UserName`, SHA-256 of the credential
blob) was taken before this turn's test run and compared against a second
snapshot taken after the full suite (2713 tests, including every
Windows-only real-backend test in this file) finished: identical count,
identical `UserName` per entry, identical hash per entry — zero deleted,
zero added, zero changed. The cross-ownership guarantee tested above
holds in practice, not just in the synthetic scenario built to exercise
it.

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

**None of the above currently happens to a real user's data — `create_package()`
and `open_package()` have no caller in the shipped application.** Everything
stated in this section is true of the code and is exercised by
`tests/test_hclx.py`, but nothing in the UI, the CLI surface, or any
scheduled job calls either function outside the test suite — measured the
same way §4.9 measured `timestamp_file()`/`timestamp_batch()`, and kept
honest the same way: `tests/test_deneysel_bagli_degil.py` re-checks this
claim by AST on every run, so wiring either function to a real menu or CLI
action without updating this section will fail a test, not drift silently.
`CORE/hclx.py`'s own module docstring carries the same
EXPERIMENTAL/NOT-WIRED marker. See **B-043** for what is missing (a send
flow, an open flow, and a dialog for a rejected package) and why it was
deliberately left for a separate decision.

---

### 4.15 A device with an unreadable serial now fails closed, not silently

> **Attacker models:** M2 · M3

**B-025's silent half is fixed; its root cause is not.** On some USB
storage devices the storage stack reports an empty, `"0"`, or
control-character serial — measured on a real KIOXIA TransMemory (§4's
sibling finding, `BACKLOG.md` B-025). `CORE/usb_manager._sanitize_hwid()`
has always fallen back to a UUID persisted in `data/usb_ids.json` for that
case, so the same physical device keeps the same identity across
re-insertions — but that identity comes from a **file next to the vault**,
not from the device. Until now, that fallback fired without a trace:
`get_usb_hwid()` returned the UUID exactly like a real serial, and every
caller — registration, login, USB re-authentication — treated it as an
ordinary, hardware-bound HWID.

**What changed.** Two things, at two different layers:

- **Visible.** `_get_or_create_uuid()` logs a warning
  (`CORE/usb_manager.py`) the first time it mints a UUID for a given raw
  value — not on every subsequent read of the same device, which would
  just be poll-loop noise. The same event is also written to the audit
  chain (`DBManager().log("weak_hwid_uuid_assigned", detail=...)`, best
  effort — swallowed if the DB is not yet connected, since this probe can
  run before login, e.g. from `setup_usb.py`) — a plain application-log
  line alone would sit outside the one chain the system treats as
  evidence-grade (§4.6); anything outside it can be edited or deleted
  without breaking the chain's own verification. `is_uuid_fallback_hwid(hwid)`
  answers the question for any hwid string without a live USB probe, by
  checking whether it is one of `usb_ids.json`'s values — the file
  `_get_or_create_uuid()` itself always writes to, so the check is
  canonical by construction.
- **Fail-closed.** `CORE/vault_manager._reject_if_weak_binding()` calls
  that check at the entry to every operation that would extend *trust* to
  such an identity — `create_vault()` for a fresh registration **and**
  for a reprovision (`anchor_share` set — see below), `open_vault()`,
  `authenticate_usb()`, `read_vault_role()`, `change_vault_role()`,
  `change_vault_pin()` — and raises `USBAuthError` before doing anything
  else. Each rejection writes a `weak_hwid_binding_rejected` audit row
  (`hwid`, the operation name) and reaches the same UI paths blacklist
  rejections already use (`UI/login_dialog.py`'s `except USBAuthError as
  exc: self._show_error(str(exc))`, `UI/main_window_lock.py`'s "USB
  Reddedildi" dialog) — so the message a locked-out user sees is not the
  generic wrong-PIN one, for the same reason §4.1 gives for blacklisting:
  reusing it would send them into a retry loop that ends at the rate
  limiter.

**What is deliberately exempt, and why it differs from the blacklist
precedent.** `verify_vault()` is untouched — the weekly integrity sweep
(§4.7) must still be able to tell whether a weakly-bound vault is corrupt,
so detection stays available even where trust does not. `recover_master_
key()` is untouched too, and this is the opposite choice from §4.1's
blacklist, which **does** block recovery because it is an administrative
revocation — someone decided this device should stop working. A weak
binding is a hardware limitation the user did not choose; cutting off
their only way to *read* their own data back would strand exactly the
users this fix exists to protect, not punish them.

That exemption is narrower than it first looks, though, and a follow-up
review (2026-08-28) tightened it: `recover_master_key()` only *reads* —
it reconstructs `master_key` from an existing share plus the printed
recovery share, nothing more. `reprovision_vault()` (the `anchor_share`-
carrying call to `create_vault()`) is a separate act — it *writes* a new
vault, binding the recovered `master_key` to a **new** hwid — and binding
is exactly the trust decision this section exists to gate, indistinguishable
from a fresh registration in that respect. So `create_vault()` no longer
exempts the `anchor_share`-set branch: both branches call
`_reject_if_weak_binding()`, just with a different operation label
("USB kaydı" vs. "USB kaydı (kurtarma sonrası yeniden kurulum)") so the
audit row and the on-screen message say which one fired. Concretely: a
user whose only device is weakly bound can still call `recover_master_key()`
and see/export their key, but `reprovision_vault()` on that same device
raises `USBAuthError` — the recovered secret is real and retrievable, it
just cannot be sealed into a new, permanently-trusted vault until a device
with a readable serial is plugged in. Verified adversarially in
`tests/test_usb_weak_binding.py::test_reprovision_YAZMA_zayif_hwid_icin_REDDEDILIR`
(read still works, write is rejected, rejection is audited) alongside
`test_kurtarma_OKUMA_zayif_hwid_icin_MUAF` (read path unaffected) and
`test_reprovision_GUCLU_hwid_ile_calismaya_devam_eder` (a normal,
strongly-bound reprovision — old hwid read, new hwid write — is unaffected,
guarding against a regression in the common case already covered by
`tests/test_recovery_e2e.py`).

**What this does not fix.** The root cause — `get_usb_hwid()` reading only
the storage stack, not the USB node identity `CORE/hwid_probe.py` already
knows how to read — is still open (BACKLOG B-025, item 1 of its remediation
list). This change stops the silence and stops new trust from being
granted on a weak identity; it does not make more devices report a real
serial. A device that hits this path is still, after this fix, unable to
register or log in normally — the difference is that it now says so, in
the log and on screen, instead of quietly becoming "donanıma bağlı" in
name only.

---

### 4.16 Torn-read risk in multi-table reports — a codebase-wide sweep, one real hit

> **Attacker models:** none — this section is about internal consistency,
> not about an adversary. A concurrent *legitimate* write during report
> generation is the trigger, not an attack.

§4.11's backup fix (`create_backup()` reading `RESTORABLE_TABLES` and
`REFERENCE_TABLES` as separate, unwrapped `SELECT`s) raised an obvious
follow-up: is that pattern — multiple sequential table reads with no
transaction tying them to a single snapshot — used anywhere else,
specifically in export/report code, where a torn result could look like a
clean one?

**Swept, and what was found.** Every export/report/CSV/PDF generator in
`CORE/` and `UI/` was checked for multi-table reads without a wrapping
transaction:

- `CORE/export.py`'s `aad_map()` — one query, one table (`files`), chunked
  only for SQLite's placeholder limit. No cross-table risk.
- `CORE/audit_chain.py`'s `verify_audit_chain()` — reads `settings` once
  and `audit_log` two or three times, unwrapped. Technically multiple
  reads, but `audit_log` is append-only and the extra reads are counts
  used for *informational* framing ("N kayıt kapsam dışı"), not values the
  hash-chain math depends on matching exactly — a row appended mid-read
  just means one more entry gets verified, not a corrupted verdict. Left
  as-is.
- `CORE/inventory.py`'s `generate_retention_inventory()` — **a real hit,
  fixed.** See below.
- `UI/AuditLogDialog.py`'s `_export_txt()` — a related but *differently
  shaped* problem, **confirmed live and fixed in a follow-up (BACKLOG
  B-073)**. See below, after the inventory finding.

**The real hit: `generate_retention_inventory()`.** This function
generates HYCLEUS's KVKK (Turkish data-protection law) retention
inventory — a report explicitly meant to be handed to a regulator or
auditor as evidence that data retention policy is being followed
(`export_inventory_csv()`, `export_inventory_pdf()`). Its own module
docstring already states the design goal in the strongest terms
available: *"rapor ile uygulama ayrışamaz"* — the report and the app's
actual enforcement logic can never disagree, because the report computes
status by calling the exact same functions (`check_disposal()`) that gate
real deletion. That guarantee held for *logic* consistency. It did not
hold for *temporal* consistency: `generate_retention_inventory()` opens
with one JOIN across `files`, `retention_profiles`, `users` and an
`audit_log` subquery, then — by the module's own documented design,
"Bu N+1 sorgu demektir" — calls `check_disposal()` once per row, which
issues four **more**, separate re-reads of `files`/`retention_profiles`,
all unwrapped.

Measured directly: two files on the same 10-year retention profile,
reassign the *second* file to a 1-year profile via a second connection
right as that file's `check_disposal()` call is about to read its
`retention_profile_id` — the resulting row showed `profile_name` from the
**old** profile (already captured by the first JOIN) next to a `status`
computed against the **new** one, an internally self-contradictory line in
a document meant to prove compliance to a regulator. A row like that isn't
just "wrong" the way a stale count is wrong — it is the exact failure mode
the module's own docstring calls out as unacceptable: the report claiming
one policy while the underlying data reflects another, in the same
sentence.

**Fix — identical in shape to §4.11's.** The whole read (the base JOIN and
every row's `check_disposal()` calls) is now wrapped in one explicit
`BEGIN`…`COMMIT`, pinning a single WAL snapshot for the entire report.
Confirmed both ways: the raw building blocks (base query + per-row check,
called directly, unwrapped) reproduce the torn row; the real function,
under the same injected concurrent write, does not.

**Not exploitable today, worth fixing anyway.** `generate_retention_inventory()`
has no UI entry point yet — `UI/AdminPanel.py` carries it only as a
commented-out usage sample, and BACKLOG.md's PyInstaller entry already
tracks it as a real, packaged (its `reportlab` dependency is bundled),
tested, just-not-wired feature. The bug was real in the code regardless of
whether a button calls it today, and fixing it now — while the failure
mode is fresh and a test can pin it — is cheaper than rediscovering it
after the feature is wired into a compliance workflow.

**The related finding: `AuditLogDialog._export_txt()`, confirmed and
fixed.** The exported row list came from `self._table`, populated by
whatever `_load()` call last ran (dialog open, or the last "Filtrele"/
"Sıfırla" click); the header's record count and chain state came from a
**fresh** `zincir_raporu()` call made at export time. Reproduced live,
end to end, before touching any code: open the dialog (three prior audit
rows load), append a fourth row directly to `audit_log` — simulating any
other part of the running app logging an action while the dialog sits
open, without the dialog refreshing — then trigger the export. The file
came back with `Doğrulanan : 5 kayıt` and `Son kayıt : id=5` in the
header, immediately followed by a 4-row table and a footer reading
`Bu dışa aktarımdaki kayıt sayısı: 4` — an export whose own header and
footer disagree about how many records it covers, with the fifth record
entirely absent from the list a reader would count. This was not a
transaction problem (the stale side is a Qt widget, not a second SQL
query) and the fix is the shape the report-consistency principle actually
calls for here: not synchronizing two data sources, but producing them
back to back from one. `_export_txt()` now calls `self._load()`
immediately before building the export, so the row list and the
`zincir_raporu()` call that builds the header run one after the other
with no user code — no dialog staying open, no waiting on the file picker
— in between. Re-running the exact reproduction above with the fix in
place: header and footer both read `5`, and the fifth row appears in the
list. A permanent regression test
(`tests/test_audit_log_dialog_export.py`) reproduces the same background
write against a real `AuditLogDialog` instance and asserts the header
count, the footer count, and the actual number of listed rows all agree
with the live database — confirmed to fail against the pre-fix code
(`{'dogrulanan': 5, 'altyazi': 4}`, matching the manual reproduction
exactly) before the fix and pass after. `txt_basligi()` already states
plainly that the export is not signed, which limits how much weight a
mismatch like this could have carried — but it was a real, reproducible
gap in a file whose whole purpose (per its own B-006 comment) is to carry
the audit trail's chain state off the machine, and F2-2/K4-20's planned
signed-report flow will build on this same export path, so it needed
closing now rather than being inherited.

**Error path checked too.** `create_backup()`'s new transaction (§4.11)
and this one both wrap the read in `try/…/finally: db.conn.execute
("COMMIT")`. Verified directly, for both: inject a synthetic exception
partway through the read (past `BEGIN`, mid-loop), confirm the exception
still propagates to the caller (the `finally` does not swallow it), and
confirm `sqlite3.Connection.in_transaction` is `False` immediately after —
the transaction does not hang open. An open transaction left behind by a
half-finished report would matter beyond that one report: it can block a
later `PRAGMA wal_checkpoint` from truncating the WAL file.

### 4.17 RBAC was enforced only in the UI — the DB layer trusted every caller

> **Attacker models:** M2 · M3

Confirmed live before writing any code. `CORE/roles.py::can_write()` is
the codebase's single decision point for "can this role write" — but the
only callers were four `UI/main_window*.py` files, deciding which
buttons to hide, whether drag-and-drop is accepted, or which tab is
visible. `DB/db_manager.py::execute()` had no concept of a caller's role
at all; it ran whatever SQL it was given. A direct call —
`DBManager().execute("INSERT INTO folders …")` issued from a script, a
dialog that forgot the check, or a `CORE` function reached by a path
other than the gated button — went through unconditionally, Salt Okunur
(read-only) role or not.

That gap was not hypothetical inside this codebase: `UI/TagDialog.py`
turned out to have zero calls to `is_readonly_role`/`can_write` anywhere
in it — it relies entirely on the "+ Yeni Etiket" button that opens it
being hidden for a read-only role. Reached any other way (a future
context-menu addition, a bug), tag creation and deletion would go
straight through. Confirmed with a script calling `DBManager().execute()`
directly — no UI involved, no dialog constructed: with a Salt Okunur role
active, `INSERT INTO files`, `INSERT INTO folders`, `INSERT INTO tags`,
`INSERT INTO file_tags`, `INSERT INTO quarantine`, and
`INSERT INTO retention_profiles` all went through untouched.

**Fix: `DBManager.execute()` is the enforcement point, not a
per-call-site convention.** `UI/main_window.py::_apply_role_restrictions()`
— the one place the codebase already funnels every role change through
(initial login via `main.py`, USB reauth, `reload_app_mode()`) — now
also calls `DBManager().set_active_role(role)`. `execute()` parses the
target table out of the SQL it is given and, for a defined set of
business-data tables, refuses any write a `can_write(role)` check would
refuse, raising `YazmaYetkisiYokError`. This runs regardless of which
`CORE` function, which UI dialog, or which absence of a dialog issued the
call — the same check whether the write came from a hidden button, a
bug, or a script that skipped the UI on purpose.

**Deliberately out of scope, and why — measured, not assumed.** Three
tables that go through the same `execute()` are *not* gated:

- `users` — `CORE/session_user.py::sync_session_user()` writes here on
  every login and every USB reauth, before a role is even fully "in
  session" (and, on reauth, potentially still carrying the *previous*
  session's role). Gating this table would have meant a read-only user
  could not log in.
- `login_attempts` — `CORE/rate_limit.py`'s failed-attempt bookkeeping
  has to work regardless of role, including mid-session during a failed
  reauth.
- `settings` — a mixed table. `imha_ttl_hours`/`idle_lock_minutes`/
  `app_mode` are admin-only in the UI already (a separate
  `is_admin_role` gate, not `can_write`), but
  `CORE/backup_reminder.py::ertele()`/`yedek_alindi()` write here from
  the "Yedek Al…" menu action, which — confirmed by reading
  `UI/main_window.py`'s view menu — carries no `can_write` check at all
  today and is reachable by every role. Gating the whole table would
  have broken backups for read-only users; gating it by key was judged
  out of scope for this pass and left as a BACKLOG follow-up rather than
  silently narrowed.

**Two automatic cleaners needed an explicit bypass, not a role check.**
`CORE/disposal.py::purge_expired_file()` and `sweep_retention_expired()`
both write to `files` — a gated table — but neither runs "as" the
logged-in user. Both are, by their own docstrings, the single entry
point for automatic cleaners that act "without asking anyone" once a
countdown expires or a retention period lapses. Both have two callers:
`CORE/scheduler.py`'s APScheduler background thread, and — for the
countdown case — a `QTimer` tick on the main thread while a user is
looking at the Disposal Room, so a thread-identity check could not
distinguish either from an interactive write. Confirmed the highest-value
alternative — "skip the check off the main thread" — would not have
worked at all: `UI/main_window_table.py`'s `_FileRunnable`, the code path
that actually adds a file, runs on a `QThreadPool` worker thread, not the
main thread. Both functions now wrap their `db.execute()` call in
`DBManager.system_write()`, a thread-local bypass — thread-local
specifically because the background scheduler thread, the `QThreadPool`
file-add workers, and the GUI thread all share the same `DBManager`
singleton, and a shared (non-thread-local) flag would have let one
thread's bypass leak into another's. Confirmed live: with a read-only
role active, both functions still complete their write.

**The bypass mechanism itself was then audited, live — no leak found,
but a separate real gap was.** Three questions about `system_write()`
were checked directly rather than assumed from reading the code: does
the thread-local depth counter reset correctly when the `with` block
exits via an exception rather than normally (`try`/`finally` around
`yield` — confirmed: the counter returns to `0` even mid-write); does it
leak across `QThreadPool`'s reuse of the same OS thread for different
tasks over time (simulated with `ThreadPoolExecutor(max_workers=1)`,
forcing two submitted jobs onto the identical OS thread — one aborted
mid-`system_write()` with a synthetic exception, the next running a
normal, role-checked write right after — confirmed: the second job was
still correctly rejected, `threading.local()` combined with
`try`/`finally` held); and does nesting work (a sanity check, not a
security question — confirmed the depth counter, not a boolean, unwinds
one level at a time). All three came back clean. What the same
investigation surfaced instead: a write rejected by
`_yazma_yetkisini_dogrula()` produced **no audit trail at all** — unlike
`weak_hwid_binding_rejected` (`CORE/vault_manager.py`) and
`usb_auth_rejected`, which both log the rejection before raising, the
RBAC write rejection — arguably the most security-relevant rejection in
the codebase — passed silently.

**Fixed: the rejection now writes `rbac_write_rejected` to the audit
chain before raising**, with `role`, the target table, the SQL verb
(`INSERT`/`UPDATE`/`DELETE`/`REPLACE`), and the caller's module/function/
line (`sys._getframe(2)`, resolved to the frame that called
`execute()`) all in `detail`. Recursion was checked, not assumed: `self.
log()` calls `CORE.audit_chain.append_entry()`, which writes through
`self.conn` — the raw `sqlite3.Connection` — and never sees
`self.execute()` at all; `audit_log` is also outside
`_RBAC_KORUMALI_TABLOLAR` regardless. Two independent guarantees against
the same failure mode, confirmed live: rejecting a write under a
read-only role produces exactly one new `audit_log` row, and a
legitimate write made through `system_write()` — where nothing was ever
rejected — produces none.

A permanent regression suite (`tests/test_db_manager_rbac.py`) calls
`DBManager().execute()` and `CORE.folders.create_folder()` directly — no
UI constructed — with a read-only role set, for every gated table, and
asserts rejection; asserts the three excluded tables remain writable
under the same role; asserts the two automatic cleaners still complete
under a read-only role; asserts a rejected write produces exactly one
`rbac_write_rejected` row with the expected `role`/`table`/`op`/`caller`
fields, across several gated tables and SQL verbs; asserts a legitimate
`system_write()` write produces no such row; and includes a
mutation-contrast test that disables the check and confirms the same
write would have gone through without it. Confirmed against the pre-fix
code directly, twice: with `DB/db_manager.py`, `CORE/disposal.py`, and
`UI/main_window.py` stashed back to their previous state, the test
module fails to *import* — `YazmaYetkisiYokError` does not exist yet —
the strongest form of "this suite cannot pass by accident"; and, later,
with only the audit-logging addition to `DB/db_manager.py` stashed back
out, the two audit-specific tests fail on their own (`0` rows added
instead of `1`) while the rest of the suite still passes, confirming
they measure the logging behaviour specifically and not just the
rejection.

**What this does not claim.** `can_write()` does not distinguish
Yönetici from Standart — a non-admin, non-read-only session bypassing an
admin-only UI dialog (retention-profile management, which has no UI
entry point yet, for instance) would not be caught by this check; only a
read-only one would. That is a different, narrower axis (`is_admin_role`,
not `can_write`) and a distinct problem from the one this fix closes;
`CORE/session_user.py::oturum_yetkisi_gecerli_mi()`'s own docstring
already flags a related boundary in the same spot (the DB schema's
`role` column cannot represent Standart vs. Salt Okunur at all). Noted,
not fixed here.

### 4.18 The lock screen stopped checkout, but not a bulk download already in flight

> **Attacker models:** M2 · M3

§4.10 states that locking closes every open checkout, "on purpose: a
lock screen that leaves plaintext on disk would guard the front door and
leave a window open." That claim is true for checkout — `_lock()`
synchronously calls `_close_all_checkouts()` before showing the overlay.
It was not true for the other place this codebase writes plaintext to a
location the user picked: bulk download.

**Measured, not assumed.** `_lock()` never touches `QThreadPool`, any
worker thread, or any `should_continue`/stop-event mechanism — it is UI
state only (overlay, blur, `centralWidget().setEnabled(False)`) plus the
checkout close. Single-file downloads and checkout opens are synchronous
main-thread calls with no `QApplication.processEvents()` in the middle,
so — confirmed by reading, not assumed — the Qt event loop cannot
interleave with them at all; `_poll_usb()`'s timer literally has no
chance to run until the call returns, by which point the file is already
fully written or not written at all. Bulk download is different:
`UI/main_window_bulk.py`'s progress callback calls
`QApplication.processEvents()` once per file so the progress dialog
stays responsive over a long batch, and that is a real re-entry point —
if a USB pull happened to land inside one of those calls, `_poll_usb()`
could run, show the lock overlay, and the export loop — which never
checked lock state, only the progress dialog's Cancel button — would
keep decrypting and writing the remaining files to disk, screen locked
or not.

Reproduced live before writing any fix: eight files queued for bulk
download, a `should_continue`/`on_progress` pair standing in for the
real UI wiring, with the callback itself flipping a `locked` flag while
processing file index 3 (`_poll_usb`'s effect, without needing real USB
hardware). Against the pre-fix code, file index 3 was written anyway —
`saved=4`, one file past the lock point.

**Fixed: `should_continue` is checked a second time, right after the
progress callback returns, immediately before the next file is
decrypted** (`CORE/export.py::export_to_directory()`) — the loop already
checked it once before calling `on_progress`, but that check happens
*before* the only point where re-entry is possible, so it cannot see a
lock that occurs during that call. The second check closes exactly that
window, and only runs when `on_progress` was actually given (so a caller
with no progress callback — no re-entry possible — sees the exact same
call count as before; a dedicated test pins this). Between the two
checks, and during `decrypt_file()`/`write_bytes()` themselves, the
event loop never spins, so a file is always either fully written or
never started — never partially. `UI/main_window_bulk.py`'s
`should_continue` lambda now reads `self._locked` in addition to the
Cancel button, which is the one-line change that actually connects the
CORE-level fix to the real lock signal; a dedicated UI-level test drives
the production `_on_ctx_bulk_download()` handler end to end (real
`HycleusWindow`, real encryption, TOTP-gated) and flips `self._locked`
from inside `QProgressDialog.setValue()` — the exact call the real
progress callback makes — confirming the wiring, not just the
underlying mechanism.

**Zeroize, honestly scoped.** `decrypt_file()` gained an opt-in
`zeroizable=True` mode: instead of returning `bytes(buf)` — an immutable
copy nothing can ever erase, per the limit already documented in §3 —
it hands back the very `bytearray` the decryption wrote into, letting
the caller call the (now public) `zero_bytearray()` on it once the
plaintext has served its purpose. Two internal guarantees, checked live
rather than assumed: on any exception path the buffer is still zeroed in
`decrypt_file()`'s own `finally` (only the success-with-`zeroizable=True`
path skips that, since the returned value *is* that same buffer, and
`finally` runs before the caller receives it — zeroing there would hand
back an already-blank buffer, confirmed live and then guarded against);
and a spy on `zero_bytearray()` confirms it is called exactly once per
file, with the plaintext that file actually contained, immediately after
`write_bytes()`. Existing callers are unaffected — the default is
unchanged, and every other call site (`CORE/checkout.py`,
`CORE/backup.py`, `CORE/hclx.py`, `UI/main_window_files.py`) still gets
plain `bytes`; only `export_to_directory()` — the path this finding is
about — was switched to the new mode. `export_to_zip()` was left on the old
(`bytes`) path deliberately: it has no `on_progress`/`processEvents()`
call anywhere in its loop, so it is not reentrant and was not part of
the measured gap; converting it is a separate, lower-value change noted
in BACKLOG rather than folded in here.

### 4.19 Cross-platform HWID re-checked (2026-08-29): still no fresh hardware data, so the tool to get it was built instead

> **Attacker models:** none — this is a portability/architecture question,
> not a security boundary. `CORE/hwid_probe.py` is a prototype and is not
> wired into the app (`tests/test_hwid_probe.py::
> test_the_prototype_is_not_wired_into_the_app` guards that with an AST
> sweep of the whole tree).

The standing question, asked again this turn: does the same USB stick
produce the same HWID on Windows, Linux, and macOS? BACKLOG **B-016**
already answers it for the one token physically measured — twice, on real
hardware, in an earlier session (2026-08-16 and 2026-08-19): the token has
a real descriptor serial, it reads identically from both the USB stack and
the storage stack, it survives a port change unchanged, and it never falls
back to the machine-local `usb_ids.json` UUID. That measurement stands;
this turn did not repeat it, and did not need to.

**What this turn's environment could and could not add.** Running
`python -m CORE.hwid_probe` here, right now, prints `USB depolama aygıtı
bulunamadı.` — this session's environment has no USB storage device
attached, and only Windows is reachable from it (no Linux or macOS box).
So the one measurement still open per B-016 — the *same* stick read on
Linux, where `ID_SERIAL_SHORT` is the theoretically-shared field — could
not be taken today, for a mundane reason (no hardware here), not because
the prior finding was doubted. Saying so plainly matters more than staying
silent about it: `docs/hwid-crossplatform.md`'s own "Prototipin sınırları"
table already flags Linux and macOS as unverified against real tools, and
that line is still accurate today.

**What did change: the missing step got a tool instead of staying manual.**
`docs/hwid-crossplatform.md`'s "Sonraki adım için gereken" section used to
describe the remaining test as "plug the same stick into three OSes, run
the probe, and compare the output" — meaning by eye. `CORE/hwid_probe.py`
now has `--json` (serialise this platform's reading to a file) and
`--compare A.json B.json` (diff two such files and exit non-zero on
mismatch, the same exit-code convention `CORE/backup_cli.py` already
uses: 0 match, 1 no match, 2 usage error). `to_dict()`/`from_dict()`
round-trip every raw field except the derived `stable_id` — that stays a
property recomputed from the raw fields on load, deliberately, so the
dump can never disagree with itself the way a cached derived value could
(the same single-source-of-truth reasoning `CORE/pin_rotation.py`
documents for its own decision function). None of this required hardware
to build or test: the 15 new tests in `tests/test_hwid_probe.py` §7 drive
the JSON round-trip and the `--compare` exit codes directly, verified with
a live mutation (the exit-code line was temporarily hardcoded to always
return 0; `test_cli_compare_ESLESMEZSE_cikis_kodu_1` failed as expected,
confirming the assertion is load-bearing, then reverted). What remains
genuinely unverified is unchanged: whether `pyudev`/sysfs and `ioreg`
actually emit the documented shapes on real Linux/macOS boxes. That gap
closes with two commands, not a manual comparison, whenever someone has
the hardware — it just did not close today.

**The architecture question this feeds is not new, and is not reopened
here.** `docs/hwid-crossplatform.md`'s file-token migration proposal
already exists and is unchanged by this turn; B-016 already narrowed its
urgency once real hardware was measured (serial-bearing devices need no
migration; serial-less devices are the actual remaining gap, and that was
already true before today). This entry does not add a new backlog item —
it re-confirms the existing one is still accurately scoped and gives it a
runnable comparison tool for the day physical multi-OS access exists.

---

### 4.20 Audit log moved from a modal to a full page, and a per-row chain-integrity column (a role gate gap found and closed along the way)

> **Attacker models:** none for the page move or the HALKA column
> themselves — this is an observability improvement, surfacing a result
> `verify_audit_chain()` already computed, not a new security boundary.
> One incidental finding below *is* an access-control gap.

**What moved.** `UI/AuditLogDialog.py` (a modal `QDialog`) is gone;
`UI/AuditLogView.py` is a full page in `_govde_yigini`
(`QStackedWidget`), the same pattern §4.17/§4.18's neighbor,
`UI/GuvenlikView.py`, already established: state (filters, selected tab)
persists across navigation instead of being thrown away on close, and the
page cascades its styling from `main_window_theme.py::_apply_theme()`
rather than owning a private stylesheet. Five tabs (Tümü/Dosya/Kimlik/
Yönetim/Uyarı) filter the same table by action category — implemented
with a bare `QTabBar` (not `QTabWidget`) precisely so five near-identical
tables didn't have to be built and kept in sync; `UI/AdminPanel.py`'s
`QTabWidget` is the right tool for its own case (genuinely different
content per tab) and the wrong one here.

**The new HALKA column: decided against a second hash walk.** The task
was explicit about the question to answer first: does this depend on
`verify_audit_chain()`'s existing row-level output, or does it need new
computation? It depends. `CORE/audit_chain.py::verify_audit_chain()`
already hashes every chained row once and records only the failures in
`ChainVerification.breaks`; a second, independent hash walk in the UI
layer to answer "is *this* row's own link intact" would have been the
sixth instance of this repo's most repeated defect — two implementations
of one fact, silently drifting apart (B-003/B-004/B-007/B-008/B-010/
B-011). Instead, `link_status()`/`link_statuses()` were added to
`CORE/audit_chain.py` as a pure *reading* of the existing result: a row
is out-of-scope if its id precedes `start_id` (or the chain never
started — "never verified" is a different claim from "verified and
intact," the same distinction `CORE/hwid_probe.py::compare()`'s "unknown"
result already draws for a different reason), broken if it's the
`entry_id` of a `modified`/`unhashed` break, intact otherwise. No new
`compute_entry_hash()` call anywhere in the new code — checked directly:
`tests/test_audit_chain.py::test_link_status_YENI_hash_hesaplamiyor_
SADECE_breaks_i_okuyor` spies on `compute_entry_hash` and asserts it is
never invoked by `link_statuses()`. `AuditLogView._load()` calls
`CORE.audit_report.zincir_raporu()` once per refresh and feeds the same
`ChainVerification` to both the HALKA column and the TXT export header —
one verification, two consumers, continuing (and tightening) the fix
§B-073 already made for the export path alone: `_export_txt()` no longer
calls `zincir_raporu()` a second time itself, it reuses `self._son_rapor`
from the `_load()` it triggers immediately before exporting, removing
even the small window for the two numbers to disagree that remained
before.

**Verified adversarially, the way the task asked.** A record was
tampered with directly via `UPDATE audit_log SET detail = … WHERE id = ?`
— bypassing `append_entry()`, i.e. exactly what an attacker with disk
write access would do — and two independent readings were compared:
the HALKA cell the user would actually see, and a direct call to
`verify_audit_chain()` on the same connection.
`tests/test_audit_log_view.py::test_BILEREK_kirilmis_halka_KOPUK_
gosterilir_ve_verify_ile_TUTARLI` asserts they agree — the tampered
row's `entry_id` is both `verify_audit_chain()`'s `first_broken_id` and
the id whose HALKA cell reads "Kopuk" — and that neighboring, untouched
rows stay "Sağlam" (no false positives). A second, live mutation
(temporarily inverting the intact/broken text mapping) confirmed the
test actually fails when the column is wrong, not just when data is
missing: `tests/test_audit_chain.py`'s own mutation on `link_status()`
itself (hardcoding it to always return "intact") was caught the same
way, by five tests, at the `CORE` layer where the read actually happens.

**The incidental finding: a role-gate gap in the entry point being
moved.** `_on_open_audit_log()` had no admin check of its own — reachability
depended entirely on the sidebar button being hidden
(`_apply_role_restrictions`) for non-admin roles. The hamburger menu's
"📋 Denetim Günlüğü" item (`_on_hamburger_menu`) called the exact same
method with no role check anywhere in that path, meaning a non-admin
role could already reach the audit log through the second entry point
before this turn — a real, if narrow, gap that predates this change
(low severity: the audit log is a read surface, not a write one, and the
gap required knowing to open the hamburger menu rather than being
visibly offered). Migrating this method to something that stays mounted
as a persistent page — rather than a modal instantiated fresh each
`.exec()` — was reason enough not to carry that gap forward silently:
`_on_open_audit_log()` now checks `is_admin_role(self._role)` itself,
the same pattern `_on_open_admin_panel()` already uses, so it closes for
both entry points regardless of which one is called.
`tests/test_audit_log_view.py::test_yonetici_OLMAYAN_ENGELLENIYOR`
constructs a real `HycleusWindow` with a non-admin role and asserts the
page never becomes current.

**Follow-up (same day): the menu itself still offered the option it then
refused.** The function-level gate closes the real hole, but a follow-up
check asked the narrower UX question directly: does the hamburger menu
*item* hide for a non-admin role, the way the sidebar button next to it
already does — and does `_on_open_admin_panel()`'s own menu item
("🔌 USB Yönetimi") actually follow that pattern already, the way the
comment above implied? Reading `_on_hamburger_menu()` in full answered
both at once: **neither item was gated.** `act_audit` and `act_usb` were
both added unconditionally, with no `.setVisible()`/`.setEnabled()` call
tied to role anywhere in that method — the "same pattern as
`_on_open_admin_panel()`" the previous entry described was only ever true
of the *function-level* check; at the menu level, USB Yönetimi had
carried the identical gap all along, undiscovered until this method was
read end to end for this specific question. No comment or BACKLOG entry
anywhere claims this was deliberate, and a non-admin role clicking either
item got nothing but a rejection dialog — worse UX than the option simply
not being there, and the kind of "offer then refuse" surface that trains
users to click through warnings. Both items now check
`is_admin_role(self._role)` and call `.setVisible()`/`.setEnabled()` on
the resulting `QAction`, matching the sidebar's existing
`_apply_role_restrictions()` convention exactly; "💬 Destek" was left
unconditional on purpose — `ContactDialog` carries no role restriction of
its own, so hiding it would be a new, invented restriction rather than a
consistency fix. This is additive, not a replacement: the function-level
check stays exactly as it was, so a direct call — bypassing the menu
entirely — is still rejected regardless of what the menu shows, the same
layered-defense shape §4.17's K1-14 finding established for
`DB/db_manager.py::system_write()` (a UI/menu-level control for the
common path, an independent check underneath that does not trust it).
Verified two ways: `tests/test_audit_log_view.py::
test_yonetici_OLMAYAN_DOGRUDAN_cagrida_da_REDDEDILIYOR_ve_UYARI_gosterilir`
calls `_on_open_audit_log()` directly — no menu, no click — with a
non-admin role and asserts both that the page never opens *and* that the
user actually sees a rejection dialog (a K1-14-style direct call, so a
silent no-op could not pass by accident); `tests/test_audit_log_view.py::
test_hamburger_menusunde_YONETICI_OLMAYANA_denetim_ve_usb_gizli` builds
the real menu (via the same `QMenu` subclass-and-record technique
`tests/test_backup_verify_ui.py` already used, not a direct
`QMenu.exec` monkeypatch — `tests/test_timestamp_ui.py`'s documented
reason) for a non-admin role and asserts both items are invisible and
disabled, while "Destek" stays visible; a paired admin-role test and two
live mutations (one reverting each new gate) confirmed both tests fail
when the fix is absent, not just when the DB or window state is wrong.

---

### 4.21 Permanent deletion could be torn by a crash — a durable intent queue closes the window

> **Attacker models:** none — this is a data-integrity/resilience fix
> against process crashes and power loss, not an access-control boundary.
> The RBAC change made along the way (below) is the one item here with a
> real attacker model.

**The gap.** `CORE/disposal.py::purge_file()` and `purge_expired_file()`
permanently destroy a file in two independent steps: `Path.unlink()` on
disk, then `DELETE FROM files WHERE id = ?` in the database. If the
process dies between the two — power loss, a kill, a crash — the database
is left believing a file exists that no longer does on disk. Nothing
detected this; the next read of that row would simply fail to open a file
that isn't there, with no record of why.

**The fix: a write-ahead intent queue, not a bigger transaction.** SQLite
can't make `unlink()` and a `DELETE` atomic together — one is a filesystem
call, the other a database write. Instead, `disposal_queue`
(`DB/migrations.py` Migration 25) records the intent to delete *before*
either physical step runs: `db.execute()` commits immediately per call
(`DB/db_manager.py::execute()`), so once the row is inserted it is durable
regardless of what happens next. The sequence is then: (1) insert the
queue row, (2) `unlink()` the file, (3) delete the `files` row and the
queue row. Both (2) and (3) are idempotent — `unlink()` only runs if the
path still `exists()`, and deleting an already-gone row is a no-op — so it
does not matter which exact instruction the process died on; any leftover
queue row unambiguously means steps (2)/(3) did not both finish.

`resume_pending_disposals()` is called once at startup, in `main.py`, in
the same section that already calls `CORE/safezone.py::purge_orphans()`
right before it — the same "empty on a clean shutdown, non-empty means the
previous session crashed" pattern §4.8 established for SafeZone, applied
to permanent-deletion bookkeeping instead of leftover plaintext. It
replays steps (2) and (3) for every row still in the queue and logs
`disposal_resumed` per file; a single row's failure (a locked file, etc.)
does not stop the rest, matching `CORE/safezone.py::purge()`'s existing
reasoning that stopping early would leave recoverable rows stuck.

**RBAC follow-on.** `disposal_queue` was added to `DB/db_manager.py::
_RBAC_KORUMALI_TABLOLAR` alongside `files`. Without that, a Salt Okunur
(read-only) session — which cannot write to `files` directly — could still
have inserted a row into `disposal_queue` with raw SQL, and had a future
startup delete that file for it, going around `_require_approval()`
entirely. `resume_pending_disposals()` and the enqueue/dequeue calls
inside `purge_expired_file()` run under `db.system_write()` for the same
reason `sweep_retention_expired()` already does: startup recovery acts for
the system, not on behalf of anyone's interactive role.
`tests/test_db_manager_rbac.py::
test_salt_okunur_is_verisi_tablolarina_dogrudan_yazamiyor` gained a
`disposal_queue` case in its existing parametrization, proving a read-only
session is rejected the same way it already is for `files`.

**Verified with mutation contrast, twice.** `tests/test_disposal.py::
TestYarimKalanImhaKurtarmasi` constructs the crash state directly (a
`disposal_queue` row with no corresponding cleanup having run yet) rather
than attempting to actually kill a process mid-write, and covers both
orderings: disk deletion already done but the `files` row not yet
(simulating a crash right after `unlink()`), and neither step done yet
(simulating a crash right after the intent was recorded). Two live
mutations confirmed the tests actually discriminate: disabling the
`files` DELETE inside `resume_pending_disposals()` failed three of the six
new tests, and separately disabling its disk `unlink()` failed two —
including `test_birden_fazla_yarim_kalan_islem_tek_turda_tamamlaniyor`,
which leaves two files in the two different crash states in the same
queue and asserts both are cleaned up in one pass, not just the first one
found.

**Follow-up (same day): is `CORE/disposal.py` really the only door, and
can the recovery itself be interrupted?** Two separate questions, both
answered by measurement rather than assumption.

*Structural audit — is there a second deletion path?* Every production
`.unlink(`/`os.remove(`/`os.unlink(`/`shred_file(` call site in `CORE/`,
`UI/`, and `DB/` was enumerated and checked for a `DELETE FROM files` in
the same function body. The candidates the task named by name were all
ruled out on inspection, not by assumption: F4-1's bulk "move to Imha"
(`UI/main_window_bulk.py::_on_ctx_bulk_move_to_imha`) only calls
`move_to_imha()`, which never touches disk (it relabels and sets a TTL,
nothing else) — it isn't a deletion path at all. The USB-record deletion
flow (`CORE/vault_manager.py`) and the `--reset` reprovisioning flow
(`CORE/setup_usb.py::_do_reset`) both delete `.hclv` vault files and
`usb_tokens` rows — a different table entirely, no `DELETE FROM files`
anywhere near them. `quarantine` is cleaned up by SQLite's own `ON DELETE
CASCADE` on `quarantine.file_id REFERENCES files(id)`
(`DB/db_manager.py::_SCHEMA`), not by any Python deletion code. The result
was turned into a permanent structural test rather than a one-time
finding: `tests/test_disposal.py::TestKarantinaTemizligiKorumasi::
test_CORE_UI_DB_genelinde_disposal_queue_atlayan_baska_bir_silme_yolu_yok`
walks every function definition under the three directories with `ast`
and flags any body that combines a disk-deletion call with `DELETE FROM
files` but does *not* also call `_enqueue(`/`_dequeue(` — the three
legitimate functions all pass (they call one or both), and a live
mutation (a throwaway function pasted into `CORE/` doing exactly that
combination, no queue involved) confirmed the test fails when a bypass is
actually present, not just when nothing is. The scope is stated in the
test's own docstring: this is a text/AST check, not a call-graph trace —
a bypass split across two functions (one unlinks, and separately calls
something that deletes the row) would not be caught. No such split exists
today; that limit is disclosed, not hidden. Nothing to route through
`disposal_queue` followed from this, because nothing else was found.

*Can `resume_pending_disposals()` itself be interrupted mid-recovery?*
The function's own claim — "it doesn't matter which step it died on" —
had only been tested for the *original* `purge_file()`/
`purge_expired_file()` call, never for a crash during recovery's own
replay. Two tests construct three pending queue rows and kill the second
one's processing with a `KeyboardInterrupt` (deliberately not an
`Exception` — the function's per-row `except Exception` is intentional
design that keeps one row's ordinary failure from blocking the rest, so
proving a genuine process-level death requires an exception that
escapes it) at two different points: inside the `with db.system_write():
db.execute(DELETE...); _dequeue(...)` block (between its own two
separately-committing statements) and at the disk `unlink()` itself
(before either statement runs). The two points produce genuinely
different intermediate states, both consistent with "never partially
destroyed": interrupted at the DB step, the second file's disk copy and
`files` row are *already gone* — only the now-cosmetic queue row remains,
because `db.execute()` commits each call independently
(`DB/db_manager.py::execute()`); interrupted at the disk step, the second
file is untouched, identical to the third row that was never reached at
all. In both cases the first row (processed before the interruption) is
fully complete and the third (never reached) is fully untouched — and a
second call to `resume_pending_disposals()` right after finishes both
remaining rows correctly, without re-emitting a `disposal_resumed` audit
entry for the already-completed first row. Two more live mutations
confirmed both tests discriminate: widening the per-row handler from
`except Exception` to `except BaseException` (which would swallow the
simulated crash and let the loop wrongly continue to the third row) failed
both tests, and reordering `_dequeue()` before the `files` DELETE inside
`resume_pending_disposals()` failed the DB-step test specifically.

---

### 4.22 A scan timeout could hang the worker pool on large archives — Python's own `subprocess.run` timeout has a Windows blind spot

> **Attacker models:** none directly — this is an availability/resilience
> fix (a large or adversarially-crafted archive degrading the upload
> pipeline), not a confidentiality or integrity boundary. A malicious
> archive engineered to trigger this would be a nuisance (files stuck
> "Taranıyor…"), not a bypass: the file stays in Karantina either way.

**The gap looked closed and wasn't.** `CORE/scanner_backends.py::run_tool()`
already called `subprocess.run(argv, timeout=SCAN_TIMEOUT)` (120s) —
on paper, a strict ceiling. CPython's own Windows branch of that timeout
handling has a documented blind spot: on `TimeoutExpired`, `run()` calls
`process.kill()` and then, on Windows specifically, makes a **second,
unbounded** `communicate()` call to drain whatever output remains. If the
killed process had spawned a child that inherited the stdout/stderr pipe
handles — plausible for `MpCmdRun.exe` scanning a large archive, which may
spin up a helper process to unpack/inspect it — killing the parent does
not close those handles. The pipe never reaches EOF, and that second
`communicate()` blocks forever. The `timeout=120` parameter that looked
like a hard ceiling was, for exactly the large-archive case named in the
task, not actually one: a `QThreadPool` worker slot (`UI/main_window.py`
caps the pool at 6) could be occupied indefinitely, the same "silent hang
instead of a fast, visible failure" shape `.github/workflows/ci.yml`'s own
`timeout-minutes` comment describes for a stuck CI step.

**The fix moves the CI lesson inside the process, not just onto it.**
`run_tool()` now drives `subprocess.Popen` directly: on timeout it calls
`kill()` and then `wait(timeout=KILL_GRACE)` — never a second
`communicate()`. `wait()` watches the process's own exit status, not pipe
closure, so a lingering grandchild holding the pipe open cannot block it;
the worker is freed within `timeout + KILL_GRACE` regardless of what the
killed tree does afterward, at the acceptable cost of not draining output
that a timed-out run has no use for anyway.

**Timeout is now a distinct verdict, not folded into "unknown."** Before
this change, a timeout and "no antivirus installed" produced the same
signal (`mock_result()`, `verdict="unknown"`) — a file nobody could scan
looked identical to a file that genuinely couldn't be reached. Both
backends now return `timeout_result()` (`verdict="timeout"`, `mock=False`
— a real attempt was made, the outcome just isn't known) instead of `None`
on `subprocess.TimeoutExpired`. The UI surfaces this distinctly: a new
badge (`⏱ Zaman Aşımı`), and on the manual rescan path
(`UI/main_window_files.py::_on_ctx_scan_done()`) an explicit warning —
"tarama zaman aşımına uğradı, manuel inceleme gerekli." No file move is
needed here: the "🔍 Tara" action only appears on rows already labeled
Karantina (every upload path defaults new files to Karantina — checked
directly, every `_handle_dropped_file`/`_handle_dropped_folder` call site
passes `label="Karantina"` explicitly), so a timeout simply leaves the
file where quarantine already put it. The batch-upload path collects a
count instead of popping one dialog per large file and reports it in the
existing end-of-batch summary.

**Verified two ways, at two different layers.** `tests/test_scanner_backends.py`
proves the `run_tool()` fix directly: a mocked `Popen` asserts
`communicate()` is called exactly once and `wait(KILL_GRACE)` — not a
second `communicate()` — follows `kill()`; a companion test with a real
subprocess (`python -c "time.sleep(30)"`, `timeout=1`) confirms the bound
holds end to end. `tests/test_scan_timeout_worker_pool.py` proves the
higher-level claim the task actually asked for: inside a real `QThreadPool`
(2 threads, 3 files, one made artificially slow), the two fast files
complete *before* the slow one finishes, not after — a stuck scan does not
serialize the pool behind it. Three live mutations confirmed all of this
is load-bearing: reintroducing the dangerous second `communicate()` broke
the `run_tool()` unit test; making every simulated scan equally slow (not
just one) broke the worker-pool test's timing assertions; disabling the
new `elif result.verdict == "timeout"` branch broke the UI-message tests.

**A separate, pre-existing bug surfaced and was deliberately left alone.**
The first version of the worker-pool test used the real `_FileRunnable`
end to end (encryption, DB write, and scan) and was intermittently flaky —
about 1 run in 10 — with SQLite errors (`"another row available"`,
`"cannot commit - no transaction is active"`) that trace to
`_FileRunnable.run()` sharing one `sqlite3.Connection`
(`check_same_thread=False`, but not otherwise safe for concurrent access)
across multiple real `QThreadPool` worker threads for its DB write.
`CORE/scanner.py::_save_to_db()` already opens its own connection per scan
thread specifically to avoid this; `_FileRunnable.run()`'s own
`record_encrypted_file()` call does not follow that pattern. This is a
real, independent concurrency defect, not an artifact of the test — but it
is about concurrent *file-add* writes, not about scan timeouts, so it is
out of scope here and was not fixed; the test was rewritten to isolate
just the `scan_file()` step (matching what `_FileRunnable.run()` itself
calls) so it no longer depends on the unrelated race. Noted in `BACKLOG.md`
for a future turn.

**Follow-up (2026-08-30): the `kill()`+`wait()` fix above still leaked —
proved, then fixed, at the OS-handle layer.** The fix above closed the
*worker* on time but never checked whether it left anything behind. It did:
`stdout=PIPE`/`stderr=PIPE` was still in place, and CPython's own pipe
reader runs on a background thread (`Popen._readerthread`) that blocks in
`fh.read()` until EOF. CPython's source is explicit that on timeout it
**does not** close those threads or handles — the comment reads "the
threads remain reading and the fds left open in case the user calls
communicate again." If a grandchild inherits the write end of the pipe (the
exact `MpCmdRun.exe`-spawns-a-helper case this section already describes)
that read never reaches EOF, and the reader thread — and the handle it
holds — never terminates.

**Measured, not assumed.** A reproduction using `cmd /c "ping -n 9999
127.0.0.1"` as the timed-out process (`cmd.exe` is the direct child
`run_tool()` manages and kills; `ping.exe` is a grandchild that inherits
`cmd.exe`'s stdout/stderr and survives the kill, orphaned, still holding the
pipe open — structurally identical to a helper process MpCmdRun.exe might
spawn) drove 30 back-to-back timeouts through the pre-follow-up `run_tool()`
and measured the calling process with `psutil.Process().num_handles()` /
`threading.active_count()`: **+153 handles, +60 threads — both growing in
exact lockstep with the iteration count** (~5 handles + 2 threads per
timeout), not settling back down given idle time afterward. A genuine,
unbounded, permanent leak, not a transient delay.

**The "obvious" fix was tried and it's worse than the bug.** The natural
next step — close `proc.stdout`/`proc.stderr` explicitly right after
`kill()`+`wait()` (or equivalently, drive the whole thing through
`with subprocess.Popen(...) as proc:`, since `Popen.__exit__` makes exactly
those same `.close()` calls) — was implemented and measured against the
same reproduction. **Both deadlock the calling thread.** On Windows,
closing a pipe handle while another thread has a pending blocking
`ReadFile()` on that same handle does not release the reader; it blocks the
closer too, synchronously, forever. Had this shipped, a `QThreadPool`
worker would freeze *deterministically* on every large-archive-with-helper
scan — the exact worker-pool lock this whole section exists to prevent,
now guaranteed instead of merely possible.

**The actual fix: stop using a pipe.** CPython only spawns a reader thread
when `stdout=PIPE`/`stderr=PIPE`. `run_tool()` now redirects the child's
stdout/stderr to real temporary files instead (`tempfile.mkstemp()`); on
success the files are read back and decoded, on timeout they're simply not
read (unneeded either way). With no pipe, there is no reader thread and no
`fh.read()` call that can ever block — a grandchild holding the file handle
open has nothing left in HYCLEUS's own process to leak or deadlock. The
same 30-iteration reproduction against the fixed `run_tool()`: **+2 handles
total (a one-time cost, not per-iteration), +0 threads, no deadlock.**

**One residual, disclosed rather than hidden.** If a grandchild is still
holding the temp file open at cleanup time, `os.unlink()` fails (Windows
won't delete an open file) and the file is left on disk — confirmed: all 60
temp files (30 iterations × stdout+stderr) remained after the leak
reproduction. This is now pure disk residue — no live thread, no live
handle in HYCLEUS's own process — rather than a resource leak. Mitigated,
not left to accumulate forever: every `run_tool()` call opens with a
best-effort sweep (`_eski_gecici_dosyalari_temizle()`) that removes any of
HYCLEUS's own stale temp files older than one hour — far beyond
`SCAN_TIMEOUT + KILL_GRACE` (~125s), so it can never touch a file from a
scan still genuinely in flight.

**Verified with a permanent regression test at the OS-resource layer.**
`tests/test_scan_timeout_handle_leak.py` reproduces the grandchild-holds-
the-pipe scenario for real (60 iterations, within the requested 50-100
range, chosen for CI runtime) and asserts handle/thread growth stays flat
rather than proportional to iteration count. Mutation-proved: reintroducing
the `stdout=PIPE`/`communicate()` pattern into `run_tool()` and re-running
this test failed it immediately (302 handles for 60 iterations, `302 <
120` assertion false) — confirmed genuinely discriminating, then reverted
and confirmed green again. `tests/test_scanner_backends.py`'s existing
`run_tool()` unit tests were updated for the new `Popen(stdout=<file>,
stderr=<file>)` + `wait()` shape (the fake `Popen` no longer has a
`communicate()` method at all — calling it now raises `AttributeError`
outright rather than requiring an assertion to catch a stray call) and a
new test directly asserts the arguments passed to `Popen` are not
`subprocess.PIPE`.

**Second follow-up (same day): temp-file safety audit — three areas clean,
one real gap found and closed.** Moving `run_tool()`'s stdout/stderr off a
pipe and onto real temp files (above) raised four new questions of its
own: is the temp filename predictable, can concurrent scans collide on a
name, can the stale-file sweep race itself, and who can read the file. All
four were investigated with evidence, not assumption, before any fix was
written.

1. *Creation API — no risk.* `tempfile.mkstemp()` (`CORE/scanner_backends.py`,
   the two calls right before the file is opened) opens with `O_CREAT |
   O_EXCL` — on Windows this maps to `CreateFile(..., CREATE_NEW, ...)`,
   which atomically fails if anything (file, directory, reparse point)
   already exists at that path, and the name itself is 8 random characters
   from a `random.Random()` instance seeded once per process from
   `os.urandom`. A local process pre-planting a file or symlink at a
   guessed name cannot get `run_tool()` to open it: creation fails outright
   and `mkstemp()` retries with a new random name.

2. *Concurrency — no risk, measured.* 20 real `run_tool()` calls run in
   parallel on an actual `QThreadPool` (`maxThreadCount=20`), with
   `tempfile.mkstemp()` wrapped (observation only, no source change) to
   record every filename produced: 40 filenames (20 calls × stdout+stderr),
   **40 unique, zero collisions** — the direct empirical consequence of
   `O_EXCL`'s atomicity in (1).

3. *Sweep race — no risk, forced and measured.* `_eski_gecici_dosyalari_
   temizle()`'s `unlink()` was already inside `except OSError: pass`
   (`FileNotFoundError` is an `OSError` subclass), so a second thread
   losing the race to delete an already-gone file should already be
   silently absorbed. Forced it rather than trusting the reasoning: backdated
   a real file's mtime past the one-hour threshold with `os.utime()`, then
   had **12 threads call the real, unmodified sweep function simultaneously**
   via a `threading.Barrier` (all 12 hit the code at the same instant).
   Result: zero exceptions escaped, the file was removed exactly once.

4. *File permissions — real gap, found and closed.* `os.open(...,
   mode=0o600)` doesn't translate into a real ACL on Windows (CPython's
   own documented behavior: on Windows the mode argument can only affect
   the read-only DOS attribute). The file the current code created
   inherited whatever ACL its parent `%TEMP%` directory carried, verified
   by creating a real file and reading its ACL: alongside the current user,
   `SYSTEM`, and `Administrators`, a group (`CodexSandboxUsers` in the
   measured environment) and an unresolved SID also held `Modify` rights —
   demonstrating concretely that "only the running user can read this"
   was an environment assumption, not something the code guaranteed. On a
   shared or terminal-server-style host, or wherever `%TEMP%`'s ACL has
   been widened by policy, another local account could read scan output —
   file paths, the ClamAV signature name, verdict text.

**Fixed: an explicit, non-inherited DACL, not trust in `%TEMP%`'s.**
`_gecici_dosyayi_kullaniciya_kisitla()` runs immediately after each temp
file is created (both stdout and stderr) and, on Windows, replaces its DACL
with exactly two entries — the current process token's user SID and
`SYSTEM` — via `win32security.SetFileSecurity(...,
DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, ...)`.
`PROTECTED_DACL_SECURITY_INFORMATION` is what actually cuts inheritance;
without it Windows would silently merge the new ACEs back in with the
parent's. Verified directly against a real file with the same measurement
method as the audit: `win32security.GetFileSecurity()` afterward reports
exactly `{current user, SYSTEM}` — confirmed independently with `icacls`
too, and the previously-present group/unresolved-SID entries are gone. A
small, disclosed residual window remains: the file exists for a few
microseconds between `mkstemp()`'s creation and this call, still carrying
the wider inherited ACL — closing that fully would mean hand-rolling
`mkstemp()`'s own atomic unique-name loop against `CreateFile` with a
security descriptor supplied at creation time, out of scope for this
change. `pywin32` is not a new dependency — `requirements.txt` already
requires it transitively via `wmi` on Windows, and `CORE/secret_store.py`
and `CORE/hwid_probe.py` already do the same lazy, platform-gated
`import win32...` pattern used here. Best-effort like the rest of this
module's cleanup logic: if `SetFileSecurity` fails for any reason, a
warning is logged and the scan proceeds with the file's original
(pre-this-change) inherited ACL — not a regression, the prior behavior.

**Verified two ways.** `tests/test_scan_timeout_dacl.py`: a unit test
creates a real file, restricts it, and asserts the real queried DACL is
exactly `{current user, SYSTEM}`; an integration test spies on
`_gecici_dosyayi_kullaniciya_kisitla` and confirms `run_tool()` actually
calls it for both temp files (the unit test alone can't catch the call
being dropped from `run_tool()`, since it invokes the helper directly); a
third confirms a `SetFileSecurity` failure doesn't break the scan.
Mutation-proved: commenting out the two calls in `run_tool()` failed the
integration test immediately (0 calls recorded instead of 2) — confirmed
discriminating, then reverted and confirmed green again.

---

### 4.23 The Profile page shows one device, not a device list — a schema constraint, not a UI gap

> **Attacker models:** none — this section documents a design constraint
> discovered while building the Profile page's "Devices and sessions"
> section, not a vulnerability.

**The mockup implied a multi-device list; the schema forbids one.**
`UI/ProfileView.py`'s "Devices and sessions" section was built against a
mockup showing a list of registered USB devices per account. Before
writing it, the actual data model was checked rather than assumed:
`users.hwid` carries a partial `UNIQUE` index
(`DB/migrations.py::_m23_users_hwid_unique`, B-060) — a HYCLEUS account
can be bound to at most one HWID, full stop. This is not an oversight;
B-060 closed a real gap where the same physical USB token could
authenticate as more than one account, letting one identity impersonate
another's authority. Undoing that constraint to support a device list
would reopen exactly the hole B-060 closed.

**Decision, made explicit rather than silently reinterpreted.** The
question was put back to the user rather than guessed at, and the answer
was: build the section against today's real 1-account-1-device model (it
renders a single row — the account's own token, whether it's the one
currently inserted, its registration date, and its blacklist status — via
`CORE/usb_tokens.py::token_kayitlarini_getir()`, the exact same query
`UI/AdminPanel.py`'s fleet-wide USB Management tab uses, narrowed with a
`hwid=` filter so the two views can never diverge) rather than building a
multi-row UI the schema can't actually populate, and rather than silently
loosening B-060 to make the mockup literally true. A real multi-device
model, if ever wanted, is a separate, deliberate architectural decision —
tracked as its own backlog item (`BACKLOG.md` B-082), not something to
slip in as a side effect of a UI migration.

**Verified against the fleet-wide view, not just unit-tested in
isolation.** `tests/test_profile_view.py` constructs both `AdminPanel`
and `ProfileView` against the same seeded `usb_tokens` row and asserts
their rendered cells agree, then adds a second, unrelated token for a
different account and asserts the `hwid=` filter actually excludes it
(without that second row, a broken filter and a working one would return
identically-shaped results by coincidence — the test would pass either
way). Mutation-proved: disabling the filter in
`token_kayitlarini_getir()` immediately broke the row-count assertion
(2 rows shown instead of 1); reverted and confirmed green again.

---

### 4.24 The USB Management modal became three persistent pages — the always-constructed sidebar pattern needed a role check it never had to have before

> **Attacker models:** (a) a non-admin session getting a live Python
> reference to an admin-only page's write actions purely because the
> page is now unconditionally built at window construction, where the
> old modal simply didn't exist until an admin opened it; (b) a
> yönetici's session being demoted or its USB pulled while one of the
> three pages is the visible page, where the old modal's own bespoke
> polling loop was the only thing watching for that.

**The split.** `UI/AdminPanel.py` (a single application-modal `QDialog`
with three `QTabWidget` tabs: USB Tokens, Pending Registrations,
Settings) was removed and replaced with three separate full pages in
`_govde_yigini` (the same `QStackedWidget` pattern as `GuvenlikView`/
`AuditLogView`/`ProfileView`), each with its own sidebar entry point:
`UI/UsbTokensView.py`, `UI/PendingRegistrationsView.py`,
`UI/AdminSettingsView.py`. Shared style helpers and the live-authority guard
live in the new `UI/admin_common.py`. Data model untouched — this was a
navigation/layout change only, per the scoping instruction that started
the turn.

**A defense that became redundant, and one that didn't.** The old
`AdminPanel` ran its own 3-second `QTimer` re-checking DB authority and
showing a warning banner + disabling its tabs, because it was an
application-modal top-level window the main window's own `_lock()`/
`_poll_usb()` (B-064/B-066) had no way to reach. Once the three pages
live inside `centralWidget()`, that reachability gap is gone —
`_lock()`'s `centralWidget().setEnabled(False)` already covers them, so
the redundant timer and banner were deleted rather than tripled across
three files. What did **not** go away: `centralWidget().setEnabled(False)`
only blocks mouse/keyboard event delivery, it does nothing to a direct
Python method call (`page._on_approve()` invoked by a test, a bug, or
future code that holds a reference to the page). That was always the
*actual* guarantee behind the old panel's per-action re-validation, and
it doesn't depend on modal-vs-embedded — so `UI.admin_common.
yonetici_hala_yetkili()` keeps re-checking `oturum_yetkisi_gecerli_mi()`
immediately before every mutating action (approve/reject/blacklist/
role-change/delete/settings-save/trusted-root add-remove/recovery-share
export), exactly as `AdminPanel._yonetici_hala_yetkili()` did.

**A gap the embedding itself introduced, closed before it shipped.** The
old `AdminPanel` only ever existed as a live object between
`is_admin_role(role)` passing and the modal being closed — a
non-admin session's `HycleusWindow` never had a reference to one at all.
The three new pages are constructed unconditionally at window build time
(the same pattern `GuvenlikView`/`AuditLogView`/`ProfileView` already
use), so a non-admin session's window now genuinely holds
`window._pending_view`, `window._usb_tokens_view`, `window.
_admin_settings_view` as live objects — reachable by direct method call
regardless of the sidebar button or the `_on_open_*` entry-point role
gate being hidden/blocked. `oturum_yetkisi_gecerli_mi()` alone does
**not** close this: it only checks whether the DB role has *drifted*
from the role the session started with, so a session that was validly
non-admin from the start would pass it. `yonetici_hala_yetkili()` was
therefore written to check `is_admin_role(pencere._role)` **first**,
failing closed before the drift check ever runs — restoring, at the
object/method level, the boundary the old modal got for free simply by
not existing yet.

**The failure path changed shape, not strength.** A modal that fails its
guard can `reject()` itself closed. A page embedded in the main window
cannot meaningfully "close" — so a failed guard now calls `pencere.
_lock("revoked")`, the exact mechanism `_poll_usb()` already uses for the
same condition, rather than a bespoke dialog-dismissal path.

**Verified, not asserted.** The B-064 regression tests
(`tests/test_authz_invariants.py::
test_b064_bekleyen_kayitlar_usb_cikinca_onayi_reddediyor` and its
mutation-contrast sibling) were ported from constructing a standalone
`AdminPanel` to constructing `PendingRegistrationsView` against a
minimal fake window and asserting `pencere._locked is True` /
`"revoked" in pencere._lock_reasons` after a guard failure — the
mutation-contrast test confirms the same scenario succeeds when
`yonetici_hala_yetkili` is monkeypatched to always return `True`,
proving the assertion is load-bearing rather than vacuous.

**One more consequence of "always constructed": stale colors.** The
three pages set their stylesheets directly from `pencere._T` (matching
`AdminPanel`'s original approach) rather than the object-name QSS
cascade `GuvenlikView`/`AuditLogView`/`ProfileView` use — deliberately
kept, not a B-055 violation waived: rewriting three complex, semantically
state-dependent (danger/success button variants) screens onto the
central QSS was out of scope for a navigation-only turn. But
`AdminPanel` being a modal meant it was always freshly constructed with
the *current* theme at open time; a persistent page is not. Because the
theme picker is reachable from every page via the hamburger menu (unlike
before, when the modal blocked it), a theme change while one of these
three pages was the visible page would leave it showing stale colors
until the next navigation. Closed via the same mechanism `AuditLogView`
already used for its own manually-painted columns: `UI/
main_window_theme.py::_refresh_after_theme_change()` now also calls
each admin page's `_restyle()`.

**A follow-up audit found one page whose `__init__` fired a query before
the role gate ever ran — measured, not assumed.** "Always constructed"
means `__init__` runs for a non-admin session's window too, so the
question of exactly *where* `is_admin_role()` sits relative to
`__init__`/first data load isn't rhetorical — it was checked per page by
reading the actual constructor, not inferred from the pattern.
`UsbTokensView`/`PendingRegistrationsView` build only empty widgets in
`__init__` (`_make_table`/`_make_pending_table`) and defer every query to
`.yenile()`, which production only ever calls from the role-gated
`main_window.py::_on_open_usb_tokens`/`_on_open_pending`. `
AdminSettingsView` did not follow that pattern: its `__init__` called
`_load_settings()` (`DBManager.get_setting`/`get_idle_timeout_minutes`/
`get_app_mode`) and, through `_tsa_kok_bloku()`, `_tsa_yukle()`
(`CORE.trusted_roots.oku()`) unconditionally — for *every* window,
admin or not, before `_on_open_admin_settings()`'s role check had a
chance to run. Nothing here is secret-grade data (global app settings,
a public trust-anchor list), but it was still the exact defect class
being asked about: a query genuinely executing before the gate, with
only the *rendering* withheld. Fixed by removing both calls from
`__init__`/`_build_ui()` (the list widget and delete button now start
in their empty/disabled default state, set explicitly rather than by a
load that no longer runs there) — `.yenile()` already called both, so
production behavior at the (gated) point of actual display is
unchanged. Mutation-proved: temporarily reverting the fix and rerunning
`tests/test_admin_pages_construction_guard.py::
test_admin_settings_view_ADMIN_OLMAYAN_pencerede_construction_sirasinda_
sorgu_atmiyor` reproduced the exact failure (`_mode_combo` showing the
DB's real `BIREYSEL` value immediately after construction, for a
`"Standart"` — non-admin — window); reverted back and confirmed green.

**`is_admin_role()` is not redundant with the DB write layer's RBAC gate
— verified, not asserted.** `DBManager.execute()`'s `
_yazma_yetkisini_dogrula()` (B-074) rejects writes only for
`can_write(role) is False`, i.e. only `"Salt Okunur"` — and
`can_write("Standart")` is `True` (already established in
`tests/test_roles.py`). A `"Standart"` session is therefore a role the
DB layer's own gate would **not** stop from writing at all; it is not
an admin role either. `tests/test_admin_pages_construction_guard.py`
constructs a real `"Standart"`-role `HycleusWindow`, reaches its
already-built (per the paragraph above) `_usb_tokens_view`/
`_pending_view`/`_admin_settings_view` directly — never calling
`_on_open_*()` — and calls a mutating handler on each
(`_on_toggle_blacklist`, `_on_approve`, `_on_save_settings`) with no UI
interaction at all. Each is rejected and the window is locked
(`"revoked"`), which only `UI.admin_common.yonetici_hala_yetkili()`'s
own `is_admin_role(pencere._role)` check can be responsible for, since
the DB layer would have allowed the write to proceed. Mutation-proved
per handler-family: monkeypatching `yonetici_hala_yetkili` to always
return `True` lets the same `"Standart"`-role call through and the DB
row actually changes.

**The revoked-role window while a page stays open — measured, not
assumed.** Removing `AdminPanel`'s own polling loop (above) raised an
obvious question: if a session's role is downgraded elsewhere (a second
admin session, no USB ever pulled) while one of the three pages is
open, does it keep operating on stale authority until something else
notices? Two things were already true before this turn and remain true:
(1) `main_window.py`'s own `_poll_usb()` (B-066, unmodified by this
work) polls `oturum_yetkisi_gecerli_mi()` every 3 seconds regardless of
which page is showing and locks the whole `centralWidget()` — including
whichever of the three admin pages is currently visible — on a mismatch;
(2) every *mutating* handler on all three pages calls `
yonetici_hala_yetkili()`, which performs its own fresh
`oturum_yetkisi_gecerli_mi()` call synchronously, immediately before the
write. The two are independent: `_poll_usb()` bounds how long the UI
*looks* interactive after a revocation to at most ~3 seconds, but a
click on an "Approve"/"Reject"/"Blacklist"/"Save" button re-validates
against the database at the moment of the click, not against
`pencere._role`'s value from login — so the actual write-time exposure
window is not "up to 3 seconds," it's the gap between the click and the
guard's own query, which is effectively zero. `tests/
test_admin_pages_construction_guard.py::
test_sayfa_guard_rol_dusurulunce_usb_takiliyken_de_reddediyor` proves
this narrower claim directly: it drops a live admin session's DB role to
`'user'` with the USB never removed and `_poll_usb()` never invoked at
all, then calls `PendingRegistrationsView._on_approve()` straight on the
already-open page — rejected, window locked. Its mutation-contrast
sibling confirms the same scenario succeeds with
`yonetici_hala_yetkili` bypassed, showing the assertion measures the
guard itself and not `_poll_usb()` incidentally catching it first.

**Follow-up: is `.yenile()` itself actually safe to call directly — checked,
not assumed.** The paragraph that stood here previously asserted this
asymmetry was "deliberate, not an oversight" without having actually
tried it. A dedicated audit did: every call site of `.yenile()` across
`UI/`, `CORE/`, `DB/`, and `main.py` was enumerated (`grep -rn
"\.yenile()"`) and each one traced. The result — `.yenile()` HAS three
call sites, all in `main_window.py`, one per page
(`_on_open_usb_tokens:430`, `_on_open_pending:442`,
`_on_open_admin_settings:454`), each the *last* statement in its
function, directly after that same function's own `is_admin_role(self.
_role)` check with an unconditional early `return` on failure — no
branch, no deferred callback, no gap a role change could land in between
the check and the call. No `QTimer`, no signal/slot connection, and no
"Yenile" button reaches `.yenile()` either (the refresh buttons call the
narrower `_load()`/`_load_pending()` directly, not `.yenile()`, so
`.yenile()`'s only job is the page-open path). `_refresh_after_theme_
change()`'s per-page call is to `_restyle()`, a separate, verified
DB-free method (styling calls only), not `.yenile()`.

**But `.yenile()` had no check of its own — direct instantiation proved
it, not assumed it.** Tracing the *entry points* is not the same claim
as ".yenile() is safe if called some other way," and this was tested
literally: a real `"Standart"`-role (non-admin) `HycleusWindow` was
built, its already-existing `_usb_tokens_view`/`_pending_view`/
`_admin_settings_view` were reached directly, and `.yenile()` was called
on each with `main_window.py::_on_open_*()` never invoked. Before a fix,
this genuinely queried and populated the table/combo/list on all three
pages — `.yenile()` carried no `is_admin_role()` check of its own, only
the *mutating* handlers did. **Fixed:** `UI.admin_common.
sayfa_erisimi_var_mi()` — an early-return `is_admin_role(pencere._role)`
check, deliberately lighter than `yonetici_hala_yetkili()` (no live
`oturum_yetkisi_gecerli_mi()` round-trip; this guards a read, not a
write, and live role-drift is already `yonetici_hala_yetkili()`'s and
`_poll_usb()`'s job) — now sits at the top of all three `.yenile()`
methods. Mutation-proved both directions in
`tests/test_admin_pages_construction_guard.py`: the same direct-call scenario
was captured red before the fix (temporarily reverted via `git stash`,
rerun, reverted back), and a companion test confirms that monkeypatching
`sayfa_erisimi_var_mi` to always return `True` lets the same
`"Standart"`-role direct call populate the table again — proving the
guard itself, not something else, is what blocks it.

---

### 4.25 The audit log export grew from one format to three — and the PDF stops short of the RFC 3161 seal on purpose

> **Attacker models:** none — this section documents a scope decision made
> while building the export options, not a vulnerability.

**The mockup asked for three formats; one already existed.**
`UI/AuditLogView.py` had a single "Düz Metin (TXT)" export. This turn added
"Tablo" (CSV) and "İmzalı Rapor" (PDF) alongside it — mockup-driven, not
a security fix. All three now read from the exact same `_load()`-filtered
row set (the date range, action, and tab filters currently applied in the
UI) rather than opening a second, independently-filtered query path: the
existing TXT export already reads the rendered table, and the new formats
read a parallel, unrendered `DenetimSatiri` list `_load()` now also builds
from the identical query — one fetch, three renderers, not three fetches.

**The RFC 3161 question, decided rather than inherited.** The "İmzalı
Rapor" name and the informal K4-20/F2-2 references already in this file
(§4.16) both point at the same open question: does "signed" mean the PDF
carries the audit chain's own cryptographic evidence, or does it mean the
PDF *file itself* gets timestamped by an external RFC 3161 authority the
way file contents already can be (`UI/TimestampDialog.py`)? This turn
built the former and explicitly deferred the latter — tracked as its own
item, `BACKLOG.md` B-087, not silently folded into "later." The PDF is
not a placeholder pretending to be sealed: it embeds `zincir_raporu()`'s
full result (chain integrity, first break if any, and the external anchor
comparison — the "dış çıpa" the task asked for) directly in the document
body, so a reader doesn't need to run a separate command to see whether
the chain the file describes was intact at export time. What it does not
do is prove the PDF file itself wasn't altered after that point — and it
says so, in the document, in the same register `txt_basligi()` already
uses for the same limitation ("bu dosya imzalı DEĞİLDİR"): a bold line
reading the export was not sealed with an RFC 3161 timestamp, immediately
under the chain-status paragraph, not buried in a footnote.

**Why CSV, not XLSX.** The task listed "CSV/XLSX" together for the table
format. CSV was picked and XLSX was not: `CORE/inventory.py::
export_inventory_csv()` already established `utf-8-sig` (BOM-prefixed
UTF-8) as this codebase's answer to "Excel must open this file correctly
without mangling Turkish characters," and CSV is also the format a SIEM
actually ingests — a real `.xlsx` writer would have meant a new
dependency (`openpyxl` or equivalent) for a format neither named consumer
(Excel, SIEM) specifically needs over CSV.

**The table export is deliberately richer than the TXT one, not merely
reformatted.** The UI table truncates HWIDs to 16 characters and formats
timestamps for readability — reasonable for a screen, wrong for a file a
SIEM will parse. `DenetimSatiri` (the shared row type both new exporters
consume) carries the untruncated HWID, the raw ISO timestamp, the raw
action string, and the full `detail` field — genuinely separate columns,
not the UI's five display columns with commas between them. Verified
directly: a 30-character synthetic HWID is asserted truncated with an
ellipsis in the UI table and present in full, ellipsis-free, in the CSV.

**The download action logs itself now — for all three formats, including
the one that didn't before.** The task asked that the download action be
audited; auditing it meant retrofitting the pre-existing TXT export too,
which had never logged itself in the ~2 months (§4.16, §4.20) it had
already been hardened for chain-consistency and role-gating. All three
export methods now call a shared `_log_disa_aktarim()` after a
successful write (matching `UI/main_window_files.py`'s established
"log after the write succeeds, before the confirmation dialog" ordering
for `file_downloaded`) — one `audit_log_exported` action with a
`format=` field distinguishing the three, mirroring how `usb_role_
changed`/`setting_changed` already encode a variant in `detail=` rather
than minting a new action name per variant. Verified for all three
formats via a parametrized test that counts matching `audit_log` rows
before and after each export call and checks the recorded `user_id` and
`format=` value; a companion test confirms a *cancelled* export (empty
path from the file picker) writes nothing, so the assertion isn't
vacuously true for an action that always logs regardless of outcome. An
AST-based test (matching the existing check that `_export_txt` actually
calls `_load()`/`txt_basligi()`, not just contains their names as
strings) confirms all three export methods genuinely call `_load()`,
their respective `export_csv()`/`export_pdf()`, and
`_log_disa_aktarim()` — not merely that those names appear somewhere in
the file.

**A test-verifiability decision surfaced by the PDF path.**
`export_inventory_pdf()`'s existing tests search the raw PDF bytes for
expected text (`b"KVKK" in out.read_bytes()`) without a PDF-parsing
dependency — that works there because the searched string happens to be
the document `title`, which reportlab stores uncompressed in the PDF's
Info dictionary regardless of content-stream compression. Body text
(table cells, the chain-status paragraph) is not similarly guaranteed
findable — measured directly: an action-name marker embedded only in a
table cell was *not* found in the raw bytes of a PDF built with
reportlab's default settings. Passing `pageCompression=0` to
`SimpleDocTemplate` fixed this (verified the same marker becomes
searchable) without adding a PDF-parsing dependency for either module,
at the cost of a larger, uncompressed file — an acceptable trade for an
export a human occasionally downloads, not a hot path.

---

## 5. Cryptographic details

| Layer | Construction |
|---|---|
| File contents | AES-256-GCM, 12-byte random nonce, 16-byte tag, 64 KB streaming |
| File metadata | GCM AAD — JSON, authenticated, **not encrypted** |
| Integrity of plaintext | SHA-256 computed before encryption, bound into the AAD |
| Vault KEK | Argon2id(PIN, 16-byte salt), time=3, memory=64 MB, parallelism=4, 32-byte output |
| Vault sealing | AES-256-GCM, AAD = HWID (device binding) |
| Vault signature | HMAC-SHA256, key = HKDF-SHA256(share_2, info=HWID) — see §4.2 |
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

**Supported version:** only the latest release (currently **v2.3.0**)
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

**A fourth, project-specific check runs in the same `pytest` suite as
everything else in this document:** `tests/test_ui_yasakli_iddia_terimleri.py`
parses every string constant in every `UI/**/*.py` file (via `ast`, so
comments are never scanned — only what could actually reach the screen)
and fails the build if a banned, unverified architecture claim appears.
The list, and why each entry is on it:

| Term | Why it's banned | Allowed context |
|---|---|---|
| `AIR-GAPPED` / `air-gapped` | The app reaches the TSA over the network (§1.1, M1) — it is not air-gapped, unconditionally | None — banned in every UI string |
| `ZERO-TRUST` / `zero-trust` | Not an architecture this app implements or claims anywhere else | None |
| `ÇEVRİMDIŞI` / `çevrimdışı` ("offline") | True of one *specific, verified* capability (RFC 3161 timestamp verification, §4.9 — genuinely network-free, measured) but false as a claim about the application as a whole | Only inside the exact phrase "çevrimdışı doğrula-" (qualifying that one verification action) — everything else, including a standalone status badge, is banned |

This exists because the same claim leaked into the UI twice: once nearly
(a comment in `UI/main_window_palette.py` records that "v2.5 ·
AIR-GAPPED" was deliberately dropped from a ported theme), and once for
real (the two-column login redesign copied "● ÇEVRİMDIŞI" straight from
a mockup into `UI/login_dialog.py`, 2026-08-26). The fix that caught the
second leak checked one file; this one checks every file `UI/` will ever
have, the same structural move B-056 made for a drifting module count
in this README. Full incident history: **B-071** in `BACKLOG.md`.

**2026-08-29 — extended to `UI/`'s subdirectories and to `CORE`/`DB`
exception messages.** Two follow-up gaps were measured and closed in the
same file:

1. The glob was `UI/*.py` (top level only). `UI/` has no subdirectory
   today, but a planted file under a temporary `UI/_gecici_altdizin_kaniti/`
   proved the pattern would have silently skipped one — the scan stayed
   green with a live `AIR-GAPPED` string sitting one level down. Switched
   to a recursive walk (excluding `__pycache__`); the same planted file was
   then caught, and a permanent `tmp_path` regression test now guards the
   fix.
2. `CORE`/`DB` define the exception classes (`USBAuthError`,
   `VaultTamperedError`, `AuthenticationError`, `BackupError`,
   `CheckoutError`, `TrustedRootError`, `PinRotationError`, and others) whose
   `str(exc)` reaches the user raw in several places — `AdminPanel.py`,
   `main_window_open.py`, `main_window_lock.py`, `ProfileDialog.py`,
   `main_window_files.py`, `login_dialog.py`, `PinRotationDialog.py` all
   pass an exception straight into a `QMessageBox`. A CORE/DB exception
   message is therefore exactly as user-facing as a UI string and needed
   the same scan. Scanning *every* string constant in CORE/DB (the same
   method used for `UI/`) was tried first and measured to produce real
   false positives: module docstrings in `backup.py`, `hclx.py`,
   `rate_limit.py`, `timestamp.py`, and `timestamp_verify.py` discuss
   offline verification and offline brute-force attacks in prose no user
   ever sees, using grammatical forms (negations, nominalizations) the
   allowlist didn't cover. The scan was narrowed instead to only the string
   arguments of `raise SomeError(...)` calls — the one part of CORE/DB that
   can actually leak through `str(exc)`. That eliminated all seven false
   positives and kept the one genuine hit
   (`CORE/timestamp.py:672`'s `"...bu damga sonradan çevrimdışı
   doğrulanamaz."`, a limitation notice, not an architecture claim), which
   was added to the allowed-context list alongside the existing
   "çevrimdışı doğrula-" forms.

**2026-08-29 (continued) — one-level backtracking for `raise Class(var)`.**
The `raise`-only CORE/DB scan (above) inspected only `ast.Constant` nodes
inside the `raise` call — a `raise Class(msg)` where `msg` is a variable
has no `Constant` node in that subtree at all, so it was invisible to the
scan. Measured directly: planting `msg = "AIR-GAPPED doğrulama modu
etkin"` followed by `raise USBAuthError(msg)` in a temporary CORE file
left the scan at zero violations (the planted file was removed
immediately after). No production code does this today (grep confirmed),
but the gap was real, so the scan was extended rather than merely
documented: it now walks each function/module body in order, tracks the
nearest preceding `name = "literal"` assignment in the same scope, and
resolves `raise Class(name)` against it — a simple one-level, sequential
lookup, not a full data-flow analysis. A nested `def`/`class` starts a
fresh scope (no inheritance from the enclosing function, so a same-named
variable elsewhere can't be mistaken for the one in scope); an assignment
after the `raise` is correctly ignored. Four permanent tests cover this:
the injected-variable case is caught, a same-named variable in a
different function is not wrongly resolved, an assignment written after
the `raise` is not wrongly resolved, and the real CORE/DB tree still
produces zero violations with backtracking enabled.

**2026-08-29 (continued, again) — multi-hop chains, with a depth cap and
cycle guard.** The one-level backtracking above only recorded `name =
"literal"` assignments — `name = other_variable` (a name-to-name
transfer) was never recorded at all, so the chain became invisible from
the second hop on. Measured directly: planting `tmp = "AIR-GAPPED
doğrulama modu etkin"; msg = tmp; raise USBAuthError(msg)` in a temporary
CORE file left the scan at zero violations (removed immediately after).
The fix splits assignment tracking into two shapes — `("literal", value)`
or `("name", other_name)` — and resolves a `raise Class(name)` argument
by following that chain to a literal, up to `_MAKS_ZINCIR_DERINLIGI` (10)
hops. Two protections, neither silent: a **cycle** (the same name
reappearing in the chain, e.g. `a = b; b = a`) is detected and reported
via `warnings.warn` rather than looping forever; a chain that exceeds the
10-hop cap without resolving is reported the same way. Either case
resolves to "no message found" (not a violation) rather than crashing or
hanging — a chain this tangled means the scanned code is already
unreadable, and the scanner degrading gracefully with a visible warning
was chosen over failing the build on code the scan genuinely can't
interpret. Reassigning a tracked name to something untraceable (e.g. a
function call result) drops the stale entry rather than leaving a dead
literal behind. Still not a full data-flow analysis — only straight-line
name-to-name/name-to-literal chains resolve; anything assigned from an
expression is untraced. Five permanent tests cover this: a two-hop chain
resolves, a three-hop chain resolves, a cyclic assignment completes
without hanging and emits the cycle warning, an artificial 15-hop chain
exercises the depth cap independently of the cycle guard, and the real
CORE/DB tree still produces zero violations with multi-hop resolution
enabled.

**2026-08-29 (continued, once more) — f-strings (`ast.JoinedStr`), and a
check for `+`-concatenation.** Tested directly: `raise
USBAuthError(f"AIR-GAPPED doğrulama: {hwid}")` planted straight in a
`raise` call was already caught with no code change — `ast.walk` finds a
`JoinedStr`'s literal `Constant` fragments the same way it finds any
other string constant in the subtree. But assigning the f-string to a
variable first — `msg = f"AIR-GAPPED doğrulama: {hwid}"; raise
USBAuthError(msg)` — measured at zero violations, because the chain
tracker's assignment recorder only understood a direct string literal or
a name-to-name transfer; a `JoinedStr` value fell through to "untraceable,
drop the entry." A third case was added: `ad = f"..."` now records
`("literal", joined_literal_only)`, where the literal text is only the
plain segments of `values` — `ast.FormattedValue` nodes (the
`{interpolation}` itself) are skipped, so the interpolated content (a
variable name, never user data at scan time) never enters the scan and
can't produce a false positive from an oddly-named variable. Checked
whether `+`-concatenation (`ast.BinOp` with `ast.Add`) appears in raise
messages too: it does, in three places in `CORE/timestamp.py` (literal +
`", ".join(...)` + literal), all as direct `raise` arguments — none go
through an assignment first. Those are already caught with no extra code,
by the same `ast.walk` mechanism that already covered f-strings directly.
No CORE/DB assignment builds a message with `+` before raising it (checked
directly — the eight `BinOp`-with-string assignments outside of `raise`
calls are all byte-packing, SQL-query, or count arithmetic, none of them
exception text), so chain resolution for `+`-concatenation remains an
unimplemented, documented gap: `msg = "a" + "b"; raise X(msg)` would not
resolve today. Four permanent tests cover the f-string work: a direct
f-string is caught, a variable-assigned f-string is caught, the
interpolated segment is proven to never enter the scan (and not to raise
an exception itself), and the real CORE/DB tree — which contains a real
f-string-based raise message in `CORE/tpm_sealing.py` — still produces
zero violations.

**2026-08-29 (confirmed, no code change) — the codebase is clean; a
non-code design mockup is not.** Re-ran the scan as a checkup, not a
fix: `tests/test_ui_yasakli_iddia_terimleri.py` — 27/27 passing, zero
banned claims anywhere in `UI/`, `CORE/`, or `DB/`. Separately, the
design mockup artifact that originated this whole leak (see **B-071**
in `BACKLOG.md`, "Incident history" above) was re-read and still
contains "HYCLEUS v2.5 · AIR-GAPPED", a standalone "● ÇEVRİMDIŞI"
badge, and a general "tamamen çevrimdışı" ("fully offline") claim —
the same three claims this section exists to keep out of the app. That
artifact is not source code the scan covers, and it was **not edited**:
it is a ~660 KB single-line minified bundle (double-escaped HTML inside
a JS template string inside a JSON wrapper), not an editable HTML
source, and there is no way to render and visually verify a patch to it
from here (an unverifiable change is worse than no change). It is recorded here
instead as a stale reference: that mockup predates, and has no
bearing on, what `UI/login_dialog.py` actually does today. The scan
above is the authority on the running application; the mockup is design
history, not a spec.

---
---

# Güvenlik Politikası — HYCLEUS

**Kapsam:** v2.3.0 · Son gözden geçirme: 2026-08-21

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
| Kasa HMAC'i, anahtar = HKDF(share_2, info=HWID) | — | ✅ `share_2` çalınan diskte yok (§4.2, §4.13) | ❌ anahtar kasası M3'e de cevap veriyor (yukarıda §1.2) |
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
denetim günlüğü okunabilir; her `.hcl` başlığındaki AAD de okunabilir.
Uygulama seviyesindeki her kontrol — hız sınırı, kara liste, hareketsizlik
kilidi, TOTP — basitçe YOK, çünkü M2 uygulamayı çalıştırmıyor (§4.5). Kasa
HMAC'i artık bu listede değil: eskiden HWID'yi bilen herkes tarafından
üretilebiliyordu, ama imza anahtarı artık `share_2`'den geliyor — o da
`data/` içinde değil, çalınan diskle birlikte gitmiyor (§4.2).

**M2 — kapsam dışı, ve iki durum da gerçek.** Birincisi: **HWID bir donanım
sırrı değil ve bazı cihazlarda donanımdan hiç türemiyor.** Depolama yığını
kullanılamaz bir seri bildirdiğinde `get_usb_hwid()` `data/usb_ids.json`
içinde saklanan bir UUID'ye düşüyor — gerçek bir cihazda ölçüldü ve
`BACKLOG.md` içinde **B-025** olarak kayıtlı. O cihaz sınıfında, `data/`
dizininin bir kopyasını tutan kişi cihaz kimliğini **USB olmadan** yeniden
üretiyor. HWID zaten bir sır değildi (§4.2), yani gizlilik kaybı yok; ama
"bu cihaza bağlı" ifadesi kulağa geldiğinden zayıf ve yukarıdaki sınır
şeması bu bilgiyle okunmalı. §4.15 bunun bir kısmını kapatıyor:
`open_vault()`, `authenticate_usb()` ve diğer güven veren işlemler artık bu
kimlik sınıfını, onu kim sunarsa sunsun, tamamen reddediyor — UUID'yi
yeniden üretmek M2'ye artık sıradan vault erişimi de kazandırmıyor, gerçi
bu hâlâ `share_2` hakkında hiçbir şey söylemiyor, onu zaten §4.2 kapsıyor.
İkincisi: `DEV_MODE` kurulumları (§4.3) —
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

### 4.2 Vault HMAC anahtarı share_2'den türetiliyor, HWID'den değil

> **Saldırgan modelleri:** M2 · M3

Bu düzeltmeden önce vault'un HMAC-SHA256 imza anahtarı `HKDF(hwid)`'ydi —
ve HWID bir USB seri numarasıdır, sır değil. Vault dosyasının kendi adı
(`vaults/<hwid>.hclv`), `data/usb_ids.json` içinde ve veritabanında saklanır,
cihazın kendisinden de okunabilir. **HWID'i bilen herkes geçerli bir vault
HMAC'ı üretebiliyordu** — ne PIN, ne bir Shamir payı, dosya adından fazlası
gerekmiyordu.

İmza anahtarı artık `HKDF(share_2, info=hwid)`
(`CORE/vault_manager.py::_derive_signing_key`): anahtar *materyalini*
`share_2` sağlıyor, `hwid` yalnızca HKDF'nin `info` parametresinde geçip
imzayı bir cihaza bağlıyor — anahtar materyali olarak asla kullanılmıyor.
`share_2` tek bir Shamir payı — 2-of-3 eşiğinin altında, master_key
hakkında tek başına hiçbir bilgi vermiyor (§4.4) — ama HWID'in aksine bir
dosya adında, veritabanında ya da GCM AAD'ında hiç görünmüyor. Yalnızca OS
anahtar kasasında duruyor, Windows'ta isteğe bağlı olarak TPM-mühürlü
(§4.13). Doğrulama hâlâ PIN gerektirmiyor: `share_2`, `open_vault()`'un
zaten okuduğu yerden okunuyor — bu yüzden `authenticate_usb()` (USB yeniden
takma) ve haftalık bütünlük taraması (§4.7) eskisi gibi çalışmaya devam
ediyor.

**Bu neyi değiştiriyor, modele göre.** M2'de (çalınan disk/yedek, OS
oturumu yok) saldırganın hiçbir zaman `share_2`'si olmadı — §1.2'deki
Shamir satırı zaten çalınan bir diskin yalnızca `share_1` verdiğini, bunun
da bilgi-teorik olarak hiçbir şey olduğunu söylüyor. Yukarıdaki vault-HMAC
satırı M2 için ❌'den ✅'ye taşınıyor: onu forge etmek artık dosyayı zaten
çözmenin maliyetiyle aynı. **M3'te hiçbir şey değişmiyor**: anahtar kasası
oturum açmış OS kullanıcısına doğrudan cevap veriyor (§1.2), yani
`share_2` orada zaten erişilebilirdi ve satır M3 için ❌ kalıyor — bu
belgedeki anahtar-kasası-destekli her kontrolün zaten taşıdığı aynı sınır.

**Ne değişmedi.** Gizlilik hiçbir zaman HMAC'e dayanmadı: ciphertext,
Argon2id/PIN türevli KEK altında AES-256-GCM ile korunuyor, HWID AAD olarak
bağlanıyor, ve bu hiç değişmedi. HMAC, *dış* zarf üzerinde (magic, salt,
nonce, `token_id` — GCM tag'inin kapsamadığı alanlar) ikinci, bağımsız bir
katman. Hiçbir zaman "kapıyı tutan" değildi, ama artık açıkta duran bir
bilgiden forge edilebilir de değil.

**HMAC'ın imzaladığı TAM alan.** `_sign()`, yalnızca ciphertext'i değil,
`protected` blobunun TAMAMINI imzalıyor:

```
protected = magic(4B) + version(1B) + salt(16B) + nonce(12B)
          + token_id(16B) + ciphertext(değişken) + gcm_tag(16B)
```

(`CORE/vault_manager.py:691-694`, rol değişikliğinde `:1038-1039`, PIN
değişikliğinde `:1095-1096`'da aynı biçim tekrarlanıyor; imzalama `:602`,
`:736`, `:790`, karşılaştırma `:795`.) GCM'in KENDİ AAD'ı yalnızca `hwid`
(`authenticate_additional_data(hwid.encode())`, ör. `:685`) — bu yalnızca
`ciphertext` ve `gcm_tag`'i doğrudan kapsıyor. Yani `protected` içindeki
alanlar üç FARKLI mekanizmayla korunuyor, hangisi önemli:

| Alan | Neyle korunuyor | Nasıl |
|---|---|---|
| `ciphertext`, `gcm_tag` | GCM tag | doğrudan — GCM'in kendi kimlik doğrulaması |
| `salt`, `nonce` | GCM, DOLAYLI | `_derive_kek`'e/şifreye girdi; değiştirilirse çözüm çöp çıkar ve GCM tag kontrolü düşer — geçen bir çözüm forge etmek KEK'i, yani PIN'i gerektirir |
| `magic`, `version` | açık kontroller | `_decrypt_vault`, GCM'e hiç girmeden `raw[:4] != _MAGIC` / `raw[4] != _VERSION` kontrolünde patlar (`CORE/vault_manager.py`) |
| `token_id` | **YALNIZCA dış HMAC** | GCM AAD'ı değil, şifre çözmeden önce okunmuyor, `_decrypt_vault` içinde başka hiçbir kontrol yok |

`token_id` yedeği olmayan tek alan: dış HMAC atlanırsa kanıtlanabilir
biçimde doğrulanmamış kalıyor. `_decrypt_vault`'un `share_2` yokken
(aşağıda) yaptığı tam olarak bu atlama.

**`verify_vault()`'ın garantisi İKİ MODDA çalışıyor, ve ikisi aynı güçte
değil.**

- **`share_2` MEVCUTKEN** (`authenticate_usb`, haftalık bütünlük taraması ve
  normal giriş yolu — `share_2` başka bir şey için gerekmeden önce bile):
  `verify_vault()` sonuna kadar çalışır ve dış HMAC kontrol edilir.
  `protected` içindeki HER alan — `token_id` dahil — kasa VE vault dosyası
  birlikte olmadan hiç kimsenin yeniden üretemeyeceği bir değere karşı
  doğrulanır. Yukarıdaki vault-HMAC satırının M2 için ✅ olmasının nedeni bu.
- **`share_2` YOKKEN**, tam olarak tek bir yolda: `recover_master_key(hwid,
  recovery_share=..., pin=...)`'ın *"share_2 kayıp"* dalı, `_decrypt_vault`
  üzerinden (`CORE/vault_manager.py`, `verify_vault(hwid)` etrafındaki
  `except ValueError: pass`). Burada dış HMAC **HİÇ KONTROL EDİLMEZ** —
  `magic`/`version` yine açık kontrollerle yakalanıyor,
  `salt`/`nonce`/`ciphertext`/`gcm_tag` yine GCM ile birbirine bağlı (geçen
  bir çözüm hâlâ PIN gerektiriyor), ama **`token_id` doğrulanmıyor**: bu
  çağrı zincirinde ona karşı hiçbir kontrol yok.

**Doğrulanmayan `token_id` sömürülebilir mi? Hayır — izlendi ve test edildi.**
`_decrypt_vault` `token_id`'yi zaten hiç okumuyor/döndürmüyor (dönüş değeri
`(share_1, role)`), yani `recover_master_key`'in kurtardığı `master_key`
`token_id` kurcalamasından ETKİLENMİYOR — Shamir matematiği ona hiç
dokunmuyor. `token_id`'nin KONTROL EDİLDİĞİ tek yer `authenticate_usb`'ın
3. Katmanı (`vault_token_hex == db_token_id`) ve o yol `verify_vault()`'ı
DOĞRUDAN çağırıyor, `share_2`-yokluğu atlaması olmadan — orada `share_2`
hâlâ yoksa Katman 2 önce reddeder, Katman 3 hiç çalışmaz. Gerçek kurtarma
akışı da (`CORE/recover_vault.py::_cmd_recover`) başarılı bir
`recover_master_key()`'i `reprovision_vault()` ile izliyor — o da TAMAMEN
taze bir `token_id` (`uuid.uuid4()`) yazıp dosyanın üzerine tamamen yeniden
yazıyor. Yani kurcalanan bir değer bile onu okuyan kurtarma oturumundan
daha uzun yaşamıyor. `tests/test_vault_hmac_share2.py` bu iki yarıyı
doğrudan doğruluyor: `token_id`'yi kurcalayıp `share_2`-siz yolu çalıştırmak
hâlâ DOĞRU `master_key`'i döndürüyor
(`test_tampered_token_id_is_not_read_by_share2_less_recovery`), ve
sonrasında yeniden kurma kurcalanan değeri kalıcı olarak siliyor
(`test_tampered_token_id_does_not_survive_reprovisioning`).

Bu dar, yük taşıyan bir varsayım — genel bir bahane değil: TAM OLARAK
`share_2`-siz yolun altında hiçbir şeyin şu an `token_id`'ye göre dallanmaması
YÜZÜNDEN geçerli. Gelecekte bir değişiklik `_decrypt_vault`'u ya da
`recover_master_key`'i bir yetkilendirme kararı için `token_id` okuyacak
hâle getirirse, bu paragraf ve yukarıdaki iki test BİRLİKTE bayatlar ve
yeniden türetilmeleri gerekir — bunlar kalıcı bir garanti değil, mevcut çağrı
grafiğinin doğru bir tasviri.

**Denetlenmiş tam çağrı grafiği.** `recover_master_key()`'in TEK bir üretim
çağrı yeri var: `CORE/recover_vault.py:146`, `_cmd_recover()` içinde
(`tests/test_recovery_call_graph.py::test_recover_master_key_TEK_uretim_
cagri_yeri_var` bunu sabitliyor — ikinci bir yer eklenirse görünür biçimde
kırılır). Hiçbir GUI akışı, hiçbir API, başka hiçbir betik onu çağırmıyor;
`UI/AdminPanel.py` ve `UI/main_window_open.py` kullanıcıyı yalnızca METİNLE
CLI'ye yönlendiriyor. O TEK çağrı yeri KOŞULSUZ yeniden kurmuyor:
`_cmd_recover()` kullanıcının reddetmesine izin veriyor
(`CORE/recover_vault.py:168-174`, "Atlandı" dalı) ve vault eski anahtarla
imzalı, `token_id` de kurcalanmışsa kurcalanmış olarak dönüyor. Yani
"reprovision hemen çalışır" hikâyesi genel bir iddia olarak YANLIŞ —
gerçekte geçerli olan daha dar, ve hangi dal çalışırsa çalışsın geçerli:

- Bu yolun tamamındaki TEK denetim kaydı yazma işlemi `recover_master_key()`'in
  kendi `db.log("vault_recovered", detail=f"hwid={hwid} kaynak=...")`
  çağrısı (`CORE/vault_manager.py:1283-1286`) — `detail` yalnızca İKİ
  değerden kuruluyor, `hwid` ve sabit bir kaynak etiketi; `token_id` o
  f-string'in kapsamında bir değişken bile değil, tamponlanmış olsun
  olmasın. `_cmd_recover()`'ın kendisi hiçbir yerde `DBManager().log(...)`
  çağırmıyor. Kurtarılan anahtar hakkındaki tek konsol çıktısı byte uzunluğu
  ve bir SHA-256 özeti (`CORE/recover_vault.py:156-160`) — yine `token_id`
  hakkında hiçbir şey yok.
- `_read_vault_token_id()` — bir vault dosyasından bu alanı GERİ OKUYAN TEK
  fonksiyon — kod tabanında tek bir çağırana sahip, `authenticate_usb()`'ın
  3. Katmanı (`CORE/vault_manager.py:857`), ve o yol `verify_vault()`'ı
  `share_2`-yokluğu atlaması OLMADAN çağırıyor. Yani reddetme dalı,
  `token_id`'nin `share_2` tekrar mevcut olmadan sonradan güvenilir hâle
  geldiği bir durum YARATMIYOR — ve `share_2` GERÇEKTEN tekrar mevcut
  olursa, `verify_vault()` dış HMAC'ın TAMAMINI (`token_id` dahil) yeniden
  kontrol ediyor ve o noktada kurcalanmış bir değer başarısız oluyor.

`tests/test_recovery_call_graph.py` bu iki iddiayı çalıştırılabilir hâle
getiriyor: `test_recover_master_key_her_cagri_yerinde_reprovision_
erisilebilir` yapısal yarı — `recover_master_key()`'i çağıran her
fonksiyonun AYNI gövdede `reprovision_vault()`'u da çağırdığını doğrulayan
bir AST taraması, yani *erişilebilirlik*, reddetme dalının yokluğunu
İDDİA ETMİYOR. `test_token_id_okuyan_TEK_yer_authenticate_usb`,
`_read_vault_token_id()`'in tek çağıranını AST ile sabitliyor, ve
`test_vault_recovered_denetim_kaydi_token_id_icermez` `token_id`'yi
kurcalıyor, `share_2`-siz kurtarmayı çalıştırıyor ve ortaya çıkan
`vault_recovered` satırının ne kurcalanan baytları ne de "token_id" dizesini
hiçbir biçimde içermediğini doğruluyor.

**Migration.** Bu düzeltmeden önce oluşturulmuş bir vault eski, yalnızca
HWID'e dayanan imzayı taşıyor ve yeni şemayla doğrudan doğrulanamaz.
`run_migrations()` (`CORE/secret_migration.py`, şema v4,
`migrate_vault_hmac`) kayıtlı her HWID'in vault'unu açılışta, girişten
önce yeniden imzalıyor — yalnızca `share_2` gerekiyor, PIN istemi yok. Bir
dosya YALNIZCA önce *eski* şemayla doğrulanıyorsa yeniden imzalanıyor;
ikisiyle de doğrulanmayan bir dosyaya dokunulmuyor ve bir uyarı olarak
kaydediliyor — "ikisiyle de doğrulanmıyor" gerçekten bozulmuş/kurcalanmış
anlamına geldiği varsayımıyla, yalnızca göç edilmemiş değil; bu ayrımı
yapan yer haftalık bütünlük taraması (§4.7), migration adımı değil.

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

**Yukarıdaki "disk erişimi" yolu da payı hangi hwid ile birleştireceğini
bilmeyi gerektiriyor — bunun ne kadar zor olduğu TAMAMEN hangi katmana
sorulduğuna bağlı.** `CORE/recover_vault.py`'nin CLI giriş noktaları
(`_cmd_export`/`_cmd_recover`/`_cmd_status`) her biri `_require_hwid()`'i
KENDİ gövdesinin ilk satırında çağırıyor, `main()`'in dispatch'inden
değil — `main()` hiç çalıştırılmadan bu fonksiyonlar doğrudan çağrılıp
USB kontrolünün yine de tetiklendiği kanıtlandı
(`tests/test_kurtarma_usb_kapisi.py`). Ama asıl matematiği yapan
`CORE/vault_manager.py::recover_master_key()`'in kaynağında böyle bir
kontrol HİÇ yok (okunarak doğrulandı, çıkarım yapılmadı): hwid'i sıradan
bir string parametresi olarak alıyor ve hiçbir zaman `get_usb_hwid()`
çağırmıyor. CLI script'ine hiç uğramadan, `data/vaults/<hwid>.hclv`
dosya adından okunan bir hwid ile (USB yok, "share_1 kayıp" dalında PIN
de yok) doğrudan çağrıldığında gerçek master_key'i geri getiriyor —
uçtan uca kanıtlandı, varsayılmadı. Bu bir hata değil ve düzeltilmedi:
`recover_master_key()`'in kendisine koşulsuz bir fiziksel-USB kontrolü
gömmek, **B-036**'nın hâlâ karar bekleyen tasarımını (gerçekten kaybolan
bir USB için basılı parça + PIN ile kurtarma) YAPISAL OLARAK imkânsız
kılardı — çekirdek fonksiyon, çağıranın `hwid`'i NASIL bildiğini
bilerek denetlemiyor, yalnızca CLI script'i denetliyor. Pratik okuma:
`_require_hwid()` YALNIZCA kasa standart CLI giriş noktasından, olağan
şekilde çalıştırıldığında gerçek bir savunma — bu belgenin M2/M3
modellerinin zaten varsaydığı kod-çalıştırma yeteneğine sahip bir
saldırgana karşı hiçbir şey katmıyor, ki bu tam olarak §4.5'in
"uygulama seviyesi kontroller asla ulaşmaz" dediği sınıf. Tam analiz ve
satır referansları: **B-069**.

**Tasarım mockup'ının "kurtarma parçasıyla gir" giriş ekranı kasıtlı
olarak hiç eklenmedi, ve kalıcı bir test artık bunu yalnızca giriş
ekranında değil, `UI/` ağacının TAMAMINDA koruyor.** Bu ekranı inşa
etmek yukarıda anlatılan USB'siz, PIN'siz yolu HER sıradan kullanıcıya
açardı. Test (`tests/test_kurtarma_usb_kapisi.py`) `UI/` altındaki HER
`.py` dosyasını (alt dizinler dahil) iki şey için tarıyor: bir payı
ALIP master_key'i YENİDEN KURAN iki fonksiyona (`recover_master_key`/
`decode_share`) gerçek bir çağrı/ithal, ve mockup'ın "payla gir" ifadesini
taşıyan bir arayüz etiketi. Bilerek `export_recovery_share`,
`RecoveryShareDialog` ya da `share_3` adlı bir değişkeni YASAKLAMIYOR:
bunlar `AdminPanel.py`'de zaten var olan meşru DIŞA AKTARIM yolu
(PIN'le korunan, test edilmiş, yalnızca gösteren) — ve bu taramanın ilk
sürümü onları da yasaklayınca tam da bu gerçek, doğru koda çarpıp
patladı. Bir payı ELDEN VERMEK risk değil; payı GERİ ALIP kapıyı
(`_require_hwid()`) atlayarak anahtarı yeniden kurmak risk. Doğrudan
kanıtlandı: kurtarmayla hiçbir ilgisi olmayan `UI/ProfileDialog.py`'ye
geçici bir `recover_master_key` ithali eklendi ve tarama, değişiklik
geri alınmadan önce bunu yakaladı — kontrolün yalnızca giriş ekranına
değil, `UI/`'nin bütününe bağlı olduğunun kanıtı.

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

**v2.3.0'dan itibaren pay yalnızca CLI'dan değil, Yönetici Paneli'nden de
dışa aktarılabiliyor — ve bu, uygulamanın gösterdiği en hassas ekran.**
Yönetici Paneli → Ayarlar → "Kurtarma Parçasını Göster" önce vault PIN'ini
istiyor, sonra `recover_vault.py --export`'un hep ürettiği `build_export()`
çıktısını — QR kodu ve base32 metni yan yana — gösteriyor. Üretim yolu
tek; diyalog onu yalnızca GÖSTERİYOR ve bir statik analiz testi QR
kütüphanesini kendi başına hiç çağırmadığını doğruluyor. Payı bir
terminal yerine ekranda göstermek, CLI dışa aktarımının taşımadığı iki
maruziyet yüzeyi açıyor:

- **Ekran yakalama.** Windows'ta pencere ilk boyanmadan önce
  `WDA_EXCLUDEFROMCAPTURE` bayrağını kuruyor (Win10 2004 öncesinde
  `WDA_MONITOR`'a düşüyor — bu, yakalamada pencereyi SİYAH gösteriyor,
  bir şeyin var olduğunu gizlemek yerine), ve diyalog bunun başarılı olup
  olmadığını ekranda açıkça yazıyor. Sessizlik bir seçenek değil — §4.13'ün
  TPM düşüşü için verdiği gerekçe burada da geçerli: sessizce kendini
  kapatan bir koruma, hiç yapılmamış olandan daha kötüdür, çünkü belge
  onun varlığını iddia etmeye devam eder. Linux ve macOS'ta karşılık
  gelen bir API yok ve diyalog bunu açıkça söylüyor. Bu boşluk **B-049**
  olarak kayıtlı.
- **Pano.** "Panoya Kopyala" düğmesi kopyalamadan ÖNCE uyarıyor — geçmiş
  tutan bir pano yöneticisi (Windows Win+V, üçüncü taraf araçlar)
  HYCLEUS'un sonrasında yaptığı hiçbir şeye rağmen değeri saklı
  tutabiliyor — ve uygulama kendi kopyasını 30 saniye sonra, YALNIZCA
  pano hâlâ tam olarak yazdığı şeyi tutuyorsa temizliyor. Kullanıcı bu
  arada başka bir şey kopyaladıysa dokunulmuyor; başkasının panosunu
  sessizce üzerine yazmak bir güvenlik önlemi değil, veri kaybı gibi
  görünürdü. Hiçbiri, değeri zaten yakalamış bir pano geçmişi aracına
  ulaşmıyor.

Onay kutusu ("Bu parçayı yazdırdım ve güvenli bir yere koydum") **bir
güvenlik kontrolü değildir** ve öyle olması da amaçlanmadı: yalnızca
"Tamam" düğmesini etkinleştiriyor, Esc ve pencerenin kendi kapatma
düğmesi her durumda çalışıyor. Bu ayrım bilinçli — kullanıcının
kapatamadığı bir pencere hiçbir şey öğretmez, yalnızca bir tıklamaya
zorlar; bu da **B-003**'ün bıraktığı derstir.

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

**Güven kökü dosyanın DIŞINDAN gelmeli — ve artık gelebiliyor.** Zincirin
tek başına kanıtladığı şey *iç tutarlılık*; kökünün güvenilir olduğu değil
— kök, token'la aynı dosyada seyahat ediyor. Fragmanı yeniden yazabilen
biri kendi CA'sını üretir, kendi TSA sertifikasını keser, istediği tarihi
söyleyen bir token imzalar ve tek başına zincir kontrolü ona GEÇERLİ der;
çünkü matematiksel olarak geçerlidir.

Cevap, dosyanın dışında tutulan bir kök deposu ve artık iki yoldan
verilebiliyor:

| Nerede | Nasıl | Kimin için |
|---|---|---|
| Uygulama | `settings.tsa_trusted_roots`, **Yönetim Paneli → Ayarlar**'dan yönetiliyor (`CORE/trusted_roots.py`) | Günlük kullanım: kurum kendi TSA kökünü bir kez ekliyor, sonraki her doğrulama onu kullanıyor |
| Komut satırı | `--trusted-root ca.pem` | Kendi kökünü getiren denetçi |

**Komut satırı, kayıtlı listeyi BİLEREK yok sayıyor.** Komut satırı
doğrulayıcısını çalıştıran kişi *bu makineyi* denetliyor; güven listesini
denetlediği veritabanından okumak, sorulan sorunun cevabını sorunun
kaynağına sordurmak olurdu. Ortaklaşan tek şey PEM/DER ayrıştırıcısı, yani
ikisi ayrışamıyor.

**Üç sonuç var ve artık görsel olarak da ayrışıyorlar.** Kök tanımlı
değilken sonuç `valid=True, anchor_trusted=False` oluyor ve arayüz onu
"geçerli — ama damgayı atan kurum doğrulanmadı" diye, tam doğrulanmış bir
damganın yeşiline değil KEHRİBAR renge boyayarak başlıklandırıyor.
Eşleşen bir kök varsa `anchor_trusted=True`. Tanımlı bir kök varsa ve
eşleşmiyorsa sonuç **geçersiz** (`failed_check="trust_anchor"`) — yani kök
tanımlamak sadece bir rozet eklemiyor, kararı sertleştiriyor.

**Bunun ÇÖZMEDİĞİ şey.** Liste `settings` içinde ve §3 veritabanının diskte
düz metin olduğunu kabul ediyor. Oraya yazabilen biri (M3) kendi kökünü
ekleyip sahte bir damgayı tam güvenilir gösterebilir. Yani kazanım tam
olarak §4.6'daki denetim çıpasının biçiminde: kanıt ile onu doğrulayan şey
artık *aynı dosyada* değil, ama hâlâ *aynı makinede*. Listeyi M3'ün
ulaşamayacağı bir yerde tutmak — çıpa için `HYCLEUS_AUDIT_ANCHOR`'ın
sağladığı gibi — yapılmadı; bkz. B-044.

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

**Toplu damgalama N imzayı bire indiriyor, ağırlığın geri kalanını bir
kanıt taşıyor.** `CORE/merkle.py` çok sayıda dosyanın `original_sha256`
değerleri üzerine alan-ayrımlı bir Merkle ağacı kuruyor, böylece tek bir
TSA imzası kökü damgalayarak hepsini kapsıyor; her dosya da kendi
token'ı yerine kendi yaprağından köke giden kısa bir yol tutuyor.
İmzanın kanıtladığı şey değişmiyor — "bu özet, o tarihte zaten vardı" —
yalnızca maliyet dosya başına değil paylaşılarak ödeniyor. Yaprak ve iç
düğüm özetleri arasındaki alan ayrımı iki klasik Merkle tuzağını
kapatıyor: bir iç düğümün kendi özetinden kurulan sahte bir yaprak, ve
CVE-2012-2459'un iki farklı yaprak kümesinin aynı kökü üretmesine izin
veren tek-düğüm belirsizliği. `verify_merkle_path()` bir dosyanın
kayıtlı yolunu yeniden yürüyor ve o yol imzalanmış köke çıkmıyorsa
doğrudan reddediyor — tanınmayan bir imzayla aynı başarısızlık biçimi.
Bu bölümde daha önce söylenen her sınır, toplu bir damgaya da değişmeden
uygulanıyor: güven kökü hâlâ dosyanın dışından gelmeli, fragman hâlâ
sökülebilir ve TSA hâlâ düz metnin özetini görüyor — paylaşılan yalnızca
token, garanti değil. **Toplu ilkel uygulanmış ve test edilmiş ama, tekil
damgalamanın kendisi gibi, dağıtılan uygulamada hiçbir çağıranı yok** —
`timestamp_file()`'ı ya da `timestamp_batch()`'i test paketi dışında hiçbir
şey çağırmıyor, yani gerçek bir kasadaki hiçbir dosya henüz damgalı değil.
Bkz. **B-035**. Bunun anlamı, `CORE/merkle.py`'nin ağaç KURMA tarafının
(`build_leaves`/`build_tree`, yalnızca `timestamp_batch()` üzerinden
erişiliyor) da gerçek veri üzerinde hiç çalışmadığı — DOĞRULAMA tarafı
farklı bir hikâye: yukarıdaki `verify_merkle_path()` gerçek "Damgayı
Doğrula" arayüz eyleminden GERÇEKTEN çağrılıyor, sadece aynı nedenle
görecek gerçek bir ağaç hiç bulmuyor. `CORE/merkle.py`'nin kendi modül
docstring'i iki yarıyı da net biçimde yazıyor. İki iddia da — yazma
tarafı kör, okuma tarafı bağlı ama girdisiz — her test koşusunda AST ile
yeniden doğrulanıyor: `tests/test_deneysel_bagli_degil.py`, tek seferlik
bir ölçüm değil.

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

**2026-08-29 — dump'tan önce önerilen bir WAL checkpoint hiçbir şeyi
düzeltmezdi; gerçek boşluk tablolar-arası anlık görüntü tutarlılığıydı ve
şimdi düzeltildi.** Tablo dökümünden hemen önce bir `PRAGMA
wal_checkpoint(TRUNCATE)` önerildi — gerekçe: checkpoint yapılmadan
alınan bir yedeğin eksik olabileceği. Önce kontrol edildi:
`create_backup()` ham `hycleus.db` dosyasını HİÇ kopyalamıyor — tabloları
canlı bağlantı üzerinden `db.fetchall()` ile okuyor
([DB/db_manager.py](DB/db_manager.py), `self.conn.execute(sql,
params).fetchall()`) ve WAL modunda bir bağlantı üzerinden yapılan
`SELECT` her zaman tamamen COMMIT edilmiş durumu döndürür, checkpoint
durumundan bağımsız olarak; checkpoint yalnızca `-wal` ile ana dosya
arasındaki dağılımı etkiler, bir sorgunun NE gördüğünü asla. Bu yüzden
checkpoint eklenmedi — gerçek bir boşluğu kapatmayacaktı.

Gerçek bir boşluk OLAN şey, doğrudan ölçüldü: `_dump_tables()`,
`RESTORABLE_TABLES`'ı tablo başına bir `SELECT` ile okuyor, aralarını
bağlayan hiçbir transaction yok. Aynı dosyaya ikinci bir bağlantı açıp
bu SELECT'lerden ikisi arasına bir yazma COMMIT etmek — koda dokunmadan
ÖNCE doğrudan `sqlite3` ile ölçüldü — tam olarak yırtık okumayı üretti:
erken okunan tablo yazmadan ÖNCEki hâli, geç okunan tablo yazmadan
SONRAKİ hâli yansıtıyordu. Somut olarak: eşzamanlı eklenen bir dosyaya
karşılık gelen bir `quarantine` satırı, o dosyayı HİÇ içermeyen bir
`files` dökümüyle birlikte dump'a girebiliyordu — hiç yedeklenmemiş bir
satıra referans, ve geri yüklendiğinde kendi foreign-key kısıtlarını
ihlal edecek bir veritabanı. Düzeltme, TÜM okumayı (`RESTORABLE_TABLES`
VE `REFERENCE_TABLES`) tek bir açık `BEGIN`...`COMMIT` içine alıyor — bu,
içindeki HER tablo okumasına TEK bir WAL anlık görüntüsü sabitliyor;
sarmalayıcı VARKEN ve YOKKEN, önce ve sonra, iki yönde de doğrulandı.

Bu inceleme ikinci, bağımsız bir hatayı da ortaya çıkardı:
`apply_metadata()`'da `RESTORABLE_TABLES`, `files`'ı, `files`'ın foreign
key ile bağlı olduğu `folders` ve `retention_profiles`'tan ÖNCE
listeliyordu. ZATEN DOLU bir veritabanına geri yüklemek (mevcut testlerin
tek sınadığı senaryo) bunu hiç tetiklemiyordu, çünkü referans verilen
satırlar zaten oradaydı. GERÇEKTEN BOŞ bir veritabanına geri yüklemek —
gerçek "yeni makine" senaryosu — `FOREIGN KEY constraint failed` ile
patlıyordu. Tablo sırası artık bağımlılık-güvenli: önce bağımlılığı
OLMAYAN tablolar, sonra referans verdiği şeylerden SONRA `files`, en son
`file_tags`/`quarantine`. Bir round-trip testi (`tests/test_backup.py`)
artık ayrı, boş bir `DBManager` örneğine geri yükleyip hiçbir
`quarantine.file_id`'nin geri yüklenmemiş bir `files` satırına işaret
etmediğini doğruluyor.

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

**"Anahtar kasasına düşüyor" o platformlarda hiç donanım desteği yok
demektir, yalnızca "TPM yok" değil.** `CORE/tpm_sealing.py`,
`sys.platform == "win32"` kapısında duruyor — Linux ya da macOS dalı yok,
zayıf bir dalı bile yok, hiç yok. Ve altındaki anahtar kasasının kendisi de
bu boşluğu varsayılan olarak doldurmuyor: `keyring`'in macOS arka ucu
standart Keychain Services generic-password API'sini çağırıyor, bu da
giriş parolasına bağlı bir anahtarla şifreleniyor; Secure Enclave / Touch
ID korumalı erişim FARKLI bir API (`kSecAttrAccessControl`) ve çağıranın
onu AÇIKÇA istemesi gerekiyor — `CORE/secret_store.py` içinde hiçbir yer
bunu yapmıyor. `keyring`'in Linux arka ucu hangi Secret Service sağlayıcısı
çalışıyorsa onunla konuşuyor — GNOME Keyring ya da KWallet — ve bunlar
genellikle PAM ile oturum parolasıyla girişte otomatik açılıyor,
varsayılan olarak yolda hiçbir TPM ya da donanım token'ı yok. Yani Linux ve
macOS'ta `share_2`, §1.2'nin "OS anahtar kasası" satırının zaten söylediği
yerde duruyor, hiçbir yükseltme olmadan — o satırın ✅'si Windows+TPM'e özgü
bir gerçek, platformlar arası değil, ve §4.2'nin vault HMAC için M2
yükseltmesi buna bağlı DEĞİL (M2, §1.1'de kullanılabilir bir anahtar
kasasından TAMAMEN yoksun olarak tanımlanıyor, TPM olsun olmasın).

**Bu paragraf Linux ya da macOS donanımında ÖLÇÜLMEDİ — bu incelemede
yalnızca Windows vardı.** `keyring`'in kendi arka uçlarının belgelenen
davranışından ve `CORE/tpm_sealing.py`/`CORE/secret_store.py` içinde hiçbir
platform dalı olmamasından çıkıyor, gerçek bir Linux ya da macOS
makinesinde çalıştırılmış bir ölçümden değil. Bir gün ölçülürse bu not,
aşağıdaki §4.13'ün Windows rakamlarıyla aynı şekilde, sonuçla
değiştirilmeli.

**Bedeli gerçek ve adı veri kaybı.** TPM temizlenirse (BIOS'ta "Clear TPM",
anakart değişimi, bazı firmware güncellemeleri) anahtar yok oluyor ve
mühürlenmiş her değer **kalıcı olarak açılamaz** hâle geliyor. `share_2`
için çıkış yolu basılı kurtarma parçası (§4.4) — Shamir 2-of-3 tam olarak
bu arıza için var. TOTP sırrı için çıkış yolu ikinci faktörü yeniden
kurmak. Mühür açılamaması ASLA "kayıt yok" diye bildirilmiyor: öyle
bildirilseydi *kurulmamış* diye okunur ve çağıran tarafı yeniden kurmaya
iterdi — kurtarılabilir bir kasanın kurtarılamaz hâle gelmesi tam olarak
böyle olur.

**Mevcut kayıtlar artık ilk OKUNDUKLARINDA yeniden mühürleniyor —
bir yazımı beklemiyor.** Bu gerçek bir boşluktu (`BACKLOG.md` **B-042**
madde 1) — mühürleme yalnızca YAZMA anında oluyordu, `share_2` yalnızca
bir kez yazılıyor (kayıt ya da yeniden sağlama sırasında), ve hiç gelmeyen
"bir sonraki yazım" demek, TPM'li bir makinedeki yerleşik bir kurulumun
bu özellikten SESSİZCE, SONSUZA KADAR hiçbir kazanım görmemesi demekti.
2026-08-28 tarihli bir takip bunu kapattı: `CORE/secret_store.py::load()`
artık mühürsüz okuduğu bir kaydı, TPM şu an kullanılabiliyorsa hemen
fırsatçı bir şekilde yeniden mühürlüyor (`_reseal_firsatci()`) — yani TPM
bu özelliği kazandıktan sonraki İLK `open_vault()`, kullanıcı ekstra
hiçbir şey yapmadan `share_2`'yi yeniden mühürlüyor. Bu, `tpm_sealing.
durum().kullanilabilir`'i KENDİSİ okumuyor (bu ikinci bir karar noktası
olurdu — `tests/test_tpm_sealing.py::
test_kullanilabilir_karari_baska_modulde_TEKRARLANMIYOR` tam olarak bunu
engelliyor); `belki_muhurle()`'nin döndürdüğü değerin mühürlü dönüp
dönmediğine bakarak çıkarım yapıyor. Yeniden mühürleme başarısız olursa
OKUMA yine de BAŞARISIZ OLMUYOR — değer zaten başarıyla çözülmüştü, bir
iyileştirme denemesinin patlaması yüzünden onu vermemek kimsenin
istemediği yeni bir kilitlenme yüzeyi açardı — ama sessiz de değil: her
iki sonuç da denetleniyor (`tpm_reseal_completed` / `tpm_reseal_failed`).
Sahte ama iç-tutarlı bir TPM'le doğrulandı
(`test_ESKI_kurulum_ILK_ACILISTA_otomatik_yeniden_muhurleniyor` — eski/
mühürsüz bir kurulumu simüle ediyor, ilk `open_vault()`'un yeniden
mühürlediğini, yeni mührün gerçekten doğru anahtarı verdiğini ve tam
olarak bir denetim kaydı düştüğünü doğruluyor) ve bu geliştirme
makinesinde GERÇEK donanımla da
(`test_gercek_TPM_ile_ESKI_kayit_ilk_okumada_yeniden_muhurleniyor`).
B-042'nin kalan maddeleri (CI'da TPM yolunun hiç çalışmaması, tek
üreticinin ölçülmüş olması, gerçek bir Clear-TPM'in fiziksel olarak hiç
denenmemiş olması) bununla ilgisiz ve hâlâ açık.

**Reseal'in yan etkileri denetlendi, ve GERÇEK bir tane bulundu — reseal
kodunda değil, ALTINDAKİ kasada.** `store()`'un (`CORE/secret_store.py`)
kapsadığı sır tipleri için üretim kodunda tam olarak iki çağrı yeri var:
`share_2` (`CORE/vault_manager.py::_save_usb_token`, ve eski DB sütununu
göçüren `CORE/secret_migration.py::migrate_share_2`) ve TOTP sırrı, hem
eski-global hem HWID-başına (`store_totp_secret`/
`store_totp_secret_for_hwid` — `UI/login_dialog.py`, `CORE/registration.py`
ve B-059 göçü için `CORE/secret_migration.py`'den çağrılıyor). Ne kurtarma
payı (`share_3`, hiçbir yerde saklanmıyor — her zaman yeniden türetiliyor)
ne de PIN-türevi anahtar materyali (hiç saklanmıyor — Argon2id her açılışta
taze çalışıyor) `store()`'a hiç ulaşmıyor. `store()`'un KENDİSİ hiçbir
denetim zinciri kaydı YAZMIYOR — grep edildi, gövdesinde `DBManager()`
çağrısı yok — yani `tpm_reseal_completed`/`tpm_reseal_failed` ile
çakışabilecek jenerik bir "kayıt yazıldı" etiketi YOK; zinciri okuyan biri
için bir `tpm_reseal_*` satırı tek anlamlı, ve
`test_reseal_ile_TAZE_kayit_denetim_zincirinde_AYIRT_EDILEBILIYOR` bunu
doğrudan kanıtlıyor: taze, TPM'li bir kayıt SIFIR reseal satırı bırakıyor,
eski bir kurulumun reseal'i TAM OLARAK BİR satır bırakıyor. `store()`'un
kendi round-trip doğrulaması `load()`'u çağırıyor — reseal mantığının
YAŞADIĞI aynı fonksiyon — ama bu asla sahte bir tetiklemeye yol açamıyor:
`store()`'un az önce yazdığı değer YA zaten mühürlü (TPM varsa
`belki_muhurle()` yazmadan önce mühürlemişti) YA DA o round-trip'in
içindeki reseal denemesi gerçek bir no-op (TPM yoksa `belki_muhurle()`
değeri her iki seferde de değiştirmeden döndürür) — bu kodda kanıtlandı ve
share_2 DIŞI çağrı yeri için özel olarak
`test_share_2_DISI_cagri_yerinde_reseal_TETIKLENMIYOR_TAZE_yazimda`'da da.

Atomiklik konusunda: `_reseal_firsatci()`'nin yazımı TEK bir
`set_password()` çağrısı, create-then-delete bir çift DEĞİL — içinde
hiçbir yerde `delete_password`/`erase` çağrısı yok, yani ne eski ne yeni
değerin birlikte kaybolabileceği bir pencere var. Yazımı kesmek
(`test_reseal_yazimi_KESILIRSE_ESKI_kayit_hala_okunabilir`, `set_password`
çağrı ortasında fırlatıyor) eski, mühürsüz kaydı TAM SAĞLAM bırakıyor —
başarısızlık yalnızca RAPORLANIYOR, zaten orada duran şeyi bozmasına ya da
silmesine asla izin verilmiyor.

**Ama bu denetim ikinci, gerçek bir boşluk daha çıkardı: Windows Credential
Manager, `set_password()`'ün üzerine yazdığı şeyi SİLMİYOR.** `keyring`'in
Windows arka ucu (`keyring.backends.Windows.WinVaultKeyring`), native
`CredWrite`'ın desteklemediği "aynı serviste birden fazla kullanıcı adı"nı,
çıplak (bare) `TargetName`'i o an işgal eden krediyi yeni değer yazılmadan
ÖNCE compound bir hedefe (`{username}@{service}`) taşıyarak simüle ediyor.
Bu makinedeki GERÇEK Windows Credential Manager'a karşı doğrudan ölçüldü
(bellek-içi test taklidi bunu HİÇ üretmiyor): `u1` yazılıp, sonra `u2`
yazılıp (`u1` `u1@HYCLEUS`'a taşınıyor), sonra `u1` TEKRAR yazılınca —
reseal'in ürettiği TAM OLARAK aynı üzerine-yazma şekli — `u1`'in ESKİ,
MÜHÜRSÜZ değeri `u1@HYCLEUS`'ta SONSUZA KADAR kalıyor: `get_password()`'e
görünmez ama SİLİNMEMİŞ. Bu projenin kendi M2 modelinde bu önemsiz değil:
Windows kimlik bilgileri konumdan bağımsız DPAPI ile korunuyor, ama bu
koruma bir gün çevrimdışı kırılırsa (DPAPI'ye karşı bilinen bir saldırı
sınıfı, kullanıcı olarak oturum açmış olmaktan farklı) yetim compound
kayıt, hiçbir yongaya ihtiyaç duymadan mühürleme-öncesi düz metne eşdeğer
değeri geri veriyor — tam olarak mühürlemenin kaldırmak için var olduğu
garantiyi. Bunu reseal İCAT ETMEDİ — mevcut bir kullanıcı adının üzerine
YAZILMASI Windows'ta hep bu şekildeydi — ama reseal, TAM OLARAK bu üzerine-
yazma örüntüsünün yeni ve yaygın bir kaynağı, o yüzden boşluğu bulmaya
değdi. Bulunduğu gün kapatıldı: `CORE/secret_store.py::_windows_golge_sil()`
her başarılı `store()`'dan sonra VE her başarılı reseal yazımından sonra
çalışıyor, yalnızca Windows'ta ve yalnızca aktif backend GERÇEKTEN
`WinVaultKeyring` İSE (ada bakarak kontrol ediliyor, farklı yapılandırılmış
bir backend'e dokunulmuyor), ve hedef compound kaydı DOĞRUDAN
`win32cred.CredDelete` ile siliyor — `keyring.delete_password()`
KULLANILMIYOR, çünkü o hem bare hem compound konumda AYNI kullanıcı adını
arayıp ikisini de siler; az önce güvenle yazılmış değeri de silme riski
taşırdı. Best-effort ve KESİNLİKLE ana yazımın doğrulanmasından SONRA
sıralanıyor: temizlik başarısız olursa yeni değer zaten güvende, yalnızca
eski gölge kalmaya devam eder — bu düzeltmeden ÖNCEki hâliyle aynı, yeni
bir başarısızlık modu ya da yazma güvenliğinde bir gerileme yok. GERÇEK
backend'e karşı doğrulandı, sahte değil:
`test_windows_golge_kopya_gercek_kasada_TEMIZLENIYOR` tahliyeyi
yeniden üretiyor, gölgenin var olduğunu doğruluyor, temizlik yolunu
tetikliyor, ve gölgenin gittiğini VE canlı değerin dokunulmamış kaldığını
doğruluyor. `BACKLOG.md`'de **B-070** olarak izleniyor, bulunduğu turda
kapandı.

**Düzeltme-öncesi kod bu makinede GERÇEKTEN bir gölge bırakmış mıydı? İlk
geçiş fazla iddialıydı; bu, yazım GEÇMİŞİNE karşı doğrulanmış düzeltilmiş
hâli.** Bu makinenin gerçek Credential Manager'ına karşı
`win32cred.CredEnumerate` çalıştırıldı ve bu düzeltmeden ÖNCEye ait on
gerçek HYCLEUS kimlik bilgisi bulundu (beş `share_2:<hwid>`, beş
`totp_secret:<hwid>`; eski global `totp_secret` bu makinede hiç
yazılmamış), hiçbiri şu an bir gölge göstermiyor. Bu notun ÖNCEKİ bir
sürümü bu yokluğu, `ensure_available()`'ın kazara iyileşmesinin onuncusu
için de ÇALIŞMIŞ olduğunun kanıtı sayıyordu — ama *bir gölgenin yokluğu,
"yalnızca bir kez yazıldı" durumunun da TAM OLARAK görünüşüdür*, ve
denetim kaydı bunu çoğu için EKARTE EDEMİYOR: `create_vault()` taze bir
kayıtta KENDİ hiçbir denetim satırı yazmıyor (yalnızca
`reprovision_vault()`'un sarmalayıcısı bir şey logluyor), ve bu
veritabanının `usb_tokens` tablosu şu an, keyring'de görülmüş beş farklı
`share_2` hwid'ine karşı yalnızca İKİ satır tutuyor — yani defteri, o
kayıtların bazıları yazıldığından beri en az bir kez sıfırlanmış, o yüzden
onların TAM geçmişine de tanıklık edemiyor. Ondan dokuzu için, iki yönde de
güvenilir bir kanıt yok; dürüst ifade, hiçbirinin gölge göstermediği ama
bunun "bir kez yazıldılar" mı yoksa "iki kez yazılıp ÇOKTAN iyileştiler"
mi olduğunun bilinmediğidir.

Onuncusu farklı, ve GERÇEKTEN sabitlendi: `audit_log`'da tam olarak bir
`vault_reprovisioned` satırı var, `hwid=USB-PROBE-TOKEN-ID`,
`2026-08-28T12:32:05Z` damgalı. `reprovision_vault()` yalnızca
`recover_master_key()`'den SONRA çalışır — o da (bu satırın kaydettiği
`kaynak=share_1+share_3` PIN dalında) `share_1`'i okumak için MEVCUT bir
vault dosyası GEREKTİRİR — yani bu hwid'in özgün bir kayıttan gelen bir
`share_2`'si zaten kasadaydı, sonra reprovision'ın kendisi İKİNCİ, FARKLI
bir `share_2` yazdı: gerçek, doğrulanmış bir çift yazım — ve bu düzeltmenin
commit'iyle (`91a4e21`, yerel `19:31:03+03:00`; reprovision yerel
`15:32:05+03:00`'teydi) karşılaştırıldığında, `_windows_golge_sil()` var
olmadan SAATLER önce olmuş bir çift yazım. Bunun bir gölge bırakıp
bırakmadığı artık kontrol EDİLEMİYOR: kayıt artık kasada HİÇ yok (`CredRead`
ne çıplak ne compound hedefte buluyor), neredeyse kesin biçimde daha önceki
bir soruşturmada bu tek kullanımlık hwid'in kullanımından SONRA yapılan
ilgisiz manuel bir temizlik sırasında silindi — `secret_store.erase()`
`keyring.delete_password()`'i çağırıyor, o da HER İKİ konumu da koşulsuz
temizliyor, varsa gölgeyi de birlikte götürerek. Bu soru sorulmadan ÖNCE,
cevaplamak için gereken kanıt zaten yok edilmişti.

**Yani asıl soru "bir gölge var mıydı"dan "iyileşme mekanizması GERÇEKTEN
çalışıyor mu, ne kadar TAM"a kaydı — ve bu, belirli bir kaydın kaderinden
BAĞIMSIZ olarak doğrudan cevaplandı.** Gerçek backend'e karşı yeniden
üretildi, çıkarılmadı: `u1`'i art arda iki kez yazmak, arada BAŞKA HİÇBİR
şey olmadan, `u1`'in eski değerini kendi compound hedefinde bırakırken
yenisi çıplak yuvaya gidiyor — bir gölge, İKİNCİ bir kullanıcı adına HİÇ
gerek kalmadan, yalnızca ikinci bir yazımdan oluşuyor. Sonra, BAĞIMSIZ
İKİNCİ bir gölgenin BİRLİKTE var olup olamayacağı doğrudan denenerek
sınandı: alakasız bir `u3` yazmak (kendi gölgesini kurmaya başlamak için)
o an çıplak yuvayı işgal edeni tahliye ediyor — ki o an bu, gölgelenmiş
değerini tutan `u1` — ve bu tahliye, `u1`'in compound hedefinin bir EKLEME
değil TAM BİR ÜZERİNE YAZMASI, yani **`u1`'in gölgesini, tamamen BAŞKA bir
şey yaparken, yan etki olarak İYİLEŞTİRİYOR** — `u3`'ün kendi gölgesi daha
VAR OLMADAN. Ancak ONDAN SONRA `u3`'ü iki kez yazmak ikinci bir gölge
üretiyor — ve o zamana kadar `u1`'inki çoktan gitmiş oluyor. Her adımda
kontrol edilen sonuç
(`test_AYNI_ANDA_IKI_golge_YAPISAL_OLARAK_var_olamiyor`): **`HYCLEUS`
servisinde iki gölge ASLA bir arada var olamıyor.** Tek çıplak yuva demek,
farklı bir kullanıcı adı için BİR SONRAKİ `set_password()` çağrısının,
ikinci bir gölge oluşturmadan ÖNCE, o an var olan gölgeyi HER ZAMAN
iyileştirmesi demek. `ensure_available()`'ın sonda yazımı böyle bir
çağrının güvenilir bir kaynağı — ayrıca kanıtlandı
(`test_ensure_available_YAN_ETKI_OLARAK_eski_golgeyi_iyilestiriyor`) — ama
ÖZEL değil; farklı bir kullanıcı adı için yapılan HERHANGİ gerçek `store()`
de aynı iyileşmeyi yan etki olarak yapıyor.

**Bu, geçerli olduğu yerde garantiyi PARÇALI değil TAM yapıyor — ama hâlâ
evrensel değil, ve düzeltilmiş kod buna DAYANMIYOR.** En fazla bir gölge
var olabildiği için, başka herhangi biri için yapılan bir sonraki yazım
HER ZAMAN onu TAMAMEN kapatıyor — bu soruyu doğuran "bazılarını iyileştirdi,
bazılarını kaçırdı" sonucu diye bir şey yok. Kalan boşluk zaten belgelenmiş
olanla AYNI: gölge yaratan üzerine-yazma bu servisin aldığı SON yazımsa —
bir daha `store()` yok, bir daha `ensure_available()` çağrısı yok, HİÇ —
tek gölge süresiz kalıyor, İYİLEŞMEMİŞ, B-070'in ORİJİNAL olarak tarif
ettiği kadar sömürülebilir. Bu makinede doğrulanacak İYİLEŞMEMİŞ bir gölge
BULUNAMADIĞI için bu turda bir temizlik geçişi YAZILMADI — bu denetimi
yöneten talimata göre; asıl önemli düzeltme zaten `store()`/
`_reseal_firsatci()` içinde (`91a4e21`), bu her yazımda DETERMİNİSTİK
olarak kapatıyor ve başka birinin bir daha yazmasına HİÇ bağlı değil.

**Ne ölçüldü, ne ölçülmedi.** Yol gerçek donanımda çalıştırıldı (AMD fTPM
2.0, rev 1.59): mühürleme 1.2 ms, açma 38 ms, tek seferlik anahtar üretimi
1.33 sn. Ölçülmeyen: başka hiçbir TPM üreticisi, ve CI — hiçbir koşucuda
TPM yok, o yüzden ilgili testler orada atlanıyor ve bu yolun sağlığı tek
bir geliştirici makinesinin ölçümüne dayanıyor. B-023'teki ClamAV
çekincesinin aynısı, aynı gerekçeyle yazılıyor.

**`erase()`'in de aynı iki-hedef sorunu vardı — ama TERSİNE: arkada
kalan eski bir kopya değil, DİRİLEN eski bir kopya.** Yukarıdaki paragraf
geçerken `secret_store.erase()`'in `keyring.delete_password()`'i
çağırdığını, "o da HER İKİ konumu da koşulsuz temizliyor" dediğini
söylüyor — SONUÇ olarak doğru, ama kütüphanenin kendi kaynağı
(`keyring/backends/Windows.py::WinVaultKeyring.delete_password()`) bunu
İKİ AYRI `CredDelete` çağrısıyla, bir döngüde, önce bare sonra compound
hedef olacak şekilde yapıyor — aralarında doğrulama YOK, process arada
ölürse geri alma YOK. Bu makinenin GERÇEK Credential Manager'ına karşı
doğrudan kanıtlandı, çıkarılmadı: bir gölge kur (`u1`'i iki kez yaz),
sonra kütüphanenin kendi silmesinin yalnızca İLK yarısını yap — bare
hedefi TEK BAŞINA sil, compound'a hiç dokunmadan, tam olarak iki çağrı
arasında bir çökmenin bırakacağı durum — ve `get_password()`, bare'i
bulamayınca compound'a düşerek, ESKİ değeri sanki güncelmiş gibi geri
veriyor. Silindiğine inanılan bir kayıt, eski veriyle cevap vermeye devam
ediyor — tam adıyla K0-3 arızası, ve yukarıdaki `store()` gölgesinden
daha kötü: o yalnızca GÖRÜNMEZDİ; bu GÖRÜNÜR ve YANLIŞ.

Düzeltme, bu backend'de `delete_password()`'e HİÇ uğramamak: `_windows_
erase()` iki hedefi kendisi siliyor, **önce compound, SONRA bare** —
kütüphanenin kendi sırasının BİLEREK tersi. Sırayı ters çevirmek, iki
adım arasındaki bir kesintinin arkada NEYİ bırakabileceğini değiştiriyor:
gölge gittikten ama bare'e daha dokunulmadan ölürse, `get_password()`
hâlâ bare'i bulup GÜNCEL değeri döndürüyor — `erase()` yalnızca YARIM
kalmış oluyor, sanki hiç çağrılmamış gibi, ASLA yanlış değil. Her silme
kendi geri-okuma kontrolüyle takip ediliyor (`CredRead` "bulunamadı"
dönmeli), yanlış bir başarı bildirmek yerine üç denemeye kadar tekrar
deniyor, ve tüm işlem idempotent — zaten yok olan ya da başka bir
kullanıcı adına ait bir hedefe dokunulmuyor, hata sayılmıyor. Gerçek
backend'e karşı doğrulandı:
`test_erase_KUTUPHANENIN_KENDI_silmesi_KESINTIYE_UGRARSA_eski_deger_GERI_DONUYOR`
yukarıda tarif edilen dirilişi yeniden üretip kanıtlıyor;
`test_erase_WINDOWS_kesintiye_dayanikli_asla_ESKI_deger_DONDURMUYOR` aynı
kesintiyi DÜZELTİLMİŞ koda enjekte edip (gerçek silme başarılı olur
olmaz fırlayan monkeypatch'lenmiş bir `CredDelete` ile)
`get_password()`'ün ASLA güncelden başka bir şey döndürmediğini, yarım
kalan çağrının başarı raporlamak yerine fırlattığını, ve ikinci bir
`erase()` çağrısının işi tamamladığını doğruluyor;
`test_erase_gercek_kasada_HER_IKI_hedef_de_TEMIZLENIYOR_ve_IDEMPOTENT`
sıradan, kesintisiz yolda her iki hedefin de gerçekten silindiğini ve
zaten silinmiş bir kullanıcı adını tekrar silmenin hata değil `False`
döndürdüğünü doğruluyor. `BACKLOG.md`'de **B-070**'e tarihli bir ek not
olarak izleniyor.

**`_windows_erase()` bare yuvasına dokunmadan önce sahiplik kontrolü
yapıyor mu, yoksa orada duran BAŞKASININ hâlâ geçerli kaydını silebilir/
bozabilir mi?** Varsayılmadı, kod okunarak doğrulandı: her hedef adımı
(`CORE/secret_store.py::_windows_hedefi_dogrulayarak_sil()`) önce hedefi
okuyup `UserName`'ini silinmek istenen kullanıcı adıyla karşılaştırıyor —
`if mevcut.get("UserName") != username: return False` — herhangi bir
`CredDelete` denenmeden ÖNCE, hem compound hem bare hedef için AYNI
şekilde. Kontrol zaten vardı (`_windows_erase()` ilk yazıldığında
eklenmiş — `store()`'un kendi tahliye mantığının sürekli ürettiği
"bare'i o an başka birinin geçerli değeri işgal ediyor" durumunda doğru
kalmak için), o yüzden eklenecek bir şey yoktu — ama "kodda bunun için
bir dal var" ile "o dal gerçekten işe yarıyor" farklı iddialar, ve
burada yalnızca ikincisi test edildi.

Gerçek Credential Manager'a karşı kanıtlandı: `A` yazılır (bare'i alır),
sonra `B` yazılır (`A` compound'a tahliye edilir, `B` artık bare'i
tutuyor) — tam olarak `store()`'un HER sıradan ikinci yazımda bıraktığı
durum — sonra `erase(A)` çağrılır. Sonuç: `B`'nin bare kaydı sonradan
bayt bayt aynı okunuyor (aynı `UserName`, aynı blob),
`keyring.get_password(service, B)` hâlâ `B`'nin değerini döndürüyor, ve
`A`'nın kendi compound kopyası gerçekten gitmiş (`CredRead` → bulunamadı)
while `secret_store.load(A)` `None` dönüyor. `erase(A)` sahibi olmadığı
bir hedefe ASLA dokunmuyor — yanlış sahiplik eşleşmesi `False` dönüp
geçiyor, silmiyor ya da üzerine yazmıyor. Kalıcı regresyon testi:
`test_erase_CAPRAZ_SAHIPLIK_bare_yuvasindaki_BASKA_kullanicinin_
kaydina_DOKUNMUYOR`.

**Bu makinedeki on gerçek üretim credential'ına karşı BAĞIMSIZCA teyit
edildi — sentetik test geçti diye güvenli varsayılmadı.** Bu turun test
koşusundan ÖNCE onunun tamamının (`TargetName`, `UserName`, credential
blobunun SHA-256'sı) bir anlık görüntüsü alındı ve tam suite (2713 test,
bu dosyadaki her Windows'a özgü gerçek-backend testi dahil) bittikten
SONRA alınan ikinci bir anlık görüntüyle karşılaştırıldı: aynı sayı, her
kayıt için aynı `UserName`, her kayıt için aynı hash — sıfır silinen,
sıfır eklenen, sıfır değişen. Yukarıda test edilen çapraz-sahiplik
garantisi yalnızca onu sınamak için kurulan sentetik senaryoda değil,
pratikte de tutuyor.

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

**Yukarıdakilerin HİÇBİRİ şu an gerçek bir kullanıcının verisine olmuyor —
`create_package()` ve `open_package()`'ın dağıtılan uygulamada hiçbir
çağıranı yok.** Bu bölümde anlatılan her şey KOD için doğru ve
`tests/test_hclx.py` tarafından çalıştırılıyor, ama arayüzde, CLI
yüzeyinde ya da zamanlanmış bir işte bu iki fonksiyonu test paketi
dışında çağıran hiçbir şey yok — §4.9'un `timestamp_file()`/
`timestamp_batch()` için yaptığı ölçümün aynısı, aynı dürüstlükle:
`tests/test_deneysel_bagli_degil.py` bu iddiayı her koşuda AST ile
yeniden doğruluyor, yani bu iki fonksiyon bu bölüm güncellenmeden gerçek
bir menüye/CLI eylemine bağlanırsa bir test SESSİZCE değil, KIRILARAK
haber verir. `CORE/hclx.py`'nin kendi modül docstring'i aynı
EXPERIMENTAL/NOT-WIRED notunu taşıyor. Neyin eksik olduğu (gönderme
akışı, açma akışı, reddedilen paket için bir diyalog) ve bunun neden
bilinçli olarak ayrı bir karara bırakıldığı **B-043**'te.

---

### 4.15 Seri numarası okunamayan bir cihaz artık kapalı hatayla duruyor, sessizce değil

> **Saldırgan modelleri:** M2 · M3

**B-025'in sessiz yarısı düzeltildi; kök nedeni değil.** Bazı USB depolama
cihazlarında depolama yığını boş, `"0"` ya da kontrol karakteri içeren bir
seri bildiriyor — gerçek bir KIOXIA TransMemory'de ölçüldü (§4'ün kardeş
bulgusu, `BACKLOG.md` B-025). `CORE/usb_manager._sanitize_hwid()` bu
durumda her zaman `data/usb_ids.json`'da saklı bir UUID'ye düşüyordu — aynı
fiziksel cihaz yeniden takıldığında aynı kimliği almaya devam ediyor, ama o
kimlik cihazdan değil **vault'un yanındaki bir dosyadan** geliyor. Şimdiye
kadar bu düşüş izsiz gerçekleşiyordu: `get_usb_hwid()` UUID'yi tıpkı gerçek
bir seri gibi döndürüyordu ve her çağıran — kayıt, giriş, USB yeniden
kimlik doğrulama — onu sıradan, donanıma bağlı bir HWID gibi ele alıyordu.

**Ne değişti.** İki farklı katmanda iki şey:

- **Görünür.** `_get_or_create_uuid()` verilen bir ham değer için ilk kez
  UUID ürettiğinde bir uyarı log'a düşüyor (`CORE/usb_manager.py`) —
  AYNI cihazın her sonraki okunuşunda değil, o yalnızca yoklama döngüsü
  gürültüsü olurdu. Aynı olay denetim zincirine de yazılıyor
  (`DBManager().log("weak_hwid_uuid_assigned", detail=...)`, best effort —
  DB henüz bağlı değilse yutuluyor, çünkü bu prob login'den önce de
  çalışabiliyor, ör. `setup_usb.py`) — yalnızca uygulama logunda kalsaydı,
  sistemin delil-değeri kabul ettiği TEK zincirin (§4.6) dışında kalırdı;
  o zincirin dışındaki hiçbir şey, zincirin kendi doğrulamasını bozmadan
  düzenlenip silinebilir. `is_uuid_fallback_hwid(hwid)` bu soruyu, canlı
  bir USB probu gerektirmeden, herhangi bir hwid dizesi için cevaplıyor —
  `usb_ids.json`'ın DEĞERLER kümesine bakarak; `_get_or_create_uuid()`'in
  KENDİSİ her zaman bu dosyaya yazdığı için kontrol yapı gereği kanonik.
- **Kapalı hata (fail-closed).**
  `CORE/vault_manager._reject_if_weak_binding()` bu kontrolü, böyle bir
  kimliğe GÜVEN veren her işlemin girişinde çağırıyor — taze kayıt İÇİN
  DE, kurtarma sonrası yeniden kurulum İÇİN DE `create_vault()`
  (`anchor_share` durumuna bakılmaksızın — aşağıya bakın), `open_vault()`,
  `authenticate_usb()`, `read_vault_role()`, `change_vault_role()`,
  `change_vault_pin()` — ve başka hiçbir şey yapmadan `USBAuthError`
  fırlatıyor. Her red bir `weak_hwid_binding_rejected` denetim satırı
  yazıyor (`hwid`, işlem adı) ve kara liste reddlerinin zaten kullandığı
  aynı arayüz yollarına ulaşıyor (`UI/login_dialog.py`'nin `except
  USBAuthError as exc: self._show_error(str(exc))`'ü,
  `UI/main_window_lock.py`'nin "USB Reddedildi" diyaloğu) — yani kilitlenen bir
  kullanıcının gördüğü mesaj genel "PIN yanlış" mesajı DEĞİL, §4.1'in kara
  liste için verdiği aynı gerekçeyle: onu tekrar kullanmak kullanıcıyı
  rate limiter'da biten bir tekrar deneme döngüsüne sokardı.

**Neyin bilerek muaf tutulduğu, ve kara liste emsalinden neden farklı.**
`verify_vault()` dokunulmadı — haftalık bütünlük taraması (§4.7) zayıf
bağlı bir vault'un bozuk olup olmadığını hâlâ söyleyebilmeli, yani
saptama güven olmayan yerde de erişilebilir kalıyor. `recover_master_
key()` de dokunulmadı, ve bu §4.1'in kara listesinin TAM TERSİ bir
seçim — o kurtarmayı da BİLEREK engelliyor çünkü o idari bir iptal: biri bu
cihazın artık çalışmaması gerektiğine karar verdi. Zayıf bağlama
kullanıcının seçmediği bir donanım kısıtı; kendi verisini GERİ OKUMANIN
tek yolunu kesmek, tam olarak bu düzeltmenin korumak istediği kullanıcıları
cezalandırır, korumaz.

Ama bu muafiyet göründüğünden dar, ve 2026-08-28 tarihli bir takip
incelemesi onu daralttı: `recover_master_key()` yalnızca OKUYOR — mevcut
bir paydan ve basılı kurtarma parçasından `master_key`'i yeniden
üretiyor, başka hiçbir şey yapmıyor. `reprovision_vault()` (create_vault()'un
`anchor_share` taşıyan çağrısı) ayrı bir eylem — kurtarılan `master_key`'i
YENİ bir hwid'e bağlayan YENİ bir vault YAZIYOR — ve bağlama tam olarak bu
bölümün kapatmaya çalıştığı güven kararı, taze kayıttan bu açıdan farksız.
O yüzden `create_vault()` artık `anchor_share` verilen dalı muaf
tutmuyor: her iki dal da `_reject_if_weak_binding()`'i çağırıyor, yalnızca
farklı bir işlem etiketiyle ("USB kaydı" vs. "USB kaydı (kurtarma sonrası
yeniden kurulum)") — denetim satırı ve ekrandaki mesaj hangisinin
tetiklendiğini söylesin diye. Somut olarak: tek cihazı zayıf bağlı bir
kullanıcı hâlâ `recover_master_key()`'i çağırıp anahtarını
görebilir/dışa aktarabilir, ama AYNI cihazda `reprovision_vault()`
`USBAuthError` fırlatır — kurtarılan sır gerçek ve erişilebilir kalır,
yalnızca seri numarası okunabilen bir cihaz takılana kadar YENİ, kalıcı
olarak güvenilen bir vault'a mühürlenemez. Bu,
`tests/test_usb_weak_binding.py::test_reprovision_YAZMA_zayif_hwid_icin_REDDEDILIR`
içinde çekişmeli olarak doğrulandı (okuma çalışıyor, yazma reddediliyor,
red denetleniyor) — `test_kurtarma_OKUMA_zayif_hwid_icin_MUAF` (okuma yolu
etkilenmiyor) ve `test_reprovision_GUCLU_hwid_ile_calismaya_devam_eder`
(normal, güçlü bağlı bir yeniden kurulum — eski hwid'den okuma, yeni
hwid'e yazma — etkilenmiyor, zaten `tests/test_recovery_e2e.py`'nin
kapsadığı yaygın durumda regresyona karşı) ile birlikte.

`anchor_share`'in kendisi hâlâ aynı iki durumu ayırt etmek için kullanılıyor
(`master_key`/polinom korunsun mu), ama artık `_reject_if_weak_binding()`'i
atlamıyor.

**Bunun düzeltmediği şey.** Kök neden — `get_usb_hwid()`'in yalnızca
depolama yığınına bakması, `CORE/hwid_probe.py`'nin zaten okumayı bildiği
USB düğüm kimliğine değil — hâlâ açık (BACKLOG B-025, giderim listesinin 1.
maddesi). Bu değişiklik sessizliği durduruyor ve zayıf bir kimlik üzerine
yeni güven inşa edilmesini engelliyor; daha fazla cihazın gerçek bir seri
bildirmesini SAĞLAMIYOR. Bu yola düşen bir cihaz, bu düzeltmeden sonra da
normal şekilde kayıt olamıyor ya da giriş yapamıyor — fark, artık bunu
log'da ve ekranda AÇIKÇA söylemesi, sessizce "donanıma bağlı" görünmesi
yerine.

### 4.16 Çok tablolu raporlarda yırtık-okuma riski — kod tabanı genelinde bir tarama, bir gerçek isabet

> **Saldırgan modelleri:** yok — bu bölüm iç tutarlılıkla ilgili, bir
> düşmanla değil. Rapor üretimi sırasında eşzamanlı, MEŞRU bir yazma
> tetikleyici, saldırı değil.

§4.11'in yedekleme düzeltmesi (`create_backup()`'ın `RESTORABLE_TABLES` ve
`REFERENCE_TABLES`'ı ayrı, sarmalanmamış `SELECT`'lerle okuması) doğal bir
takip sorusu doğurdu: bu desen — birden fazla ardışık tablo okuması, tek
bir anlık görüntüye bağlayan hiçbir transaction olmadan — başka bir yerde,
özellikle export/rapor kodunda kullanılıyor mu; kullanılıyorsa, yırtık bir
sonuç temiz görünebilir mi?

**Tarandı, ne bulundu.** `CORE/` ve `UI/`'deki her export/rapor/CSV/PDF
üreticisi, sarmalayıcısız çok-tablolu okumalar için kontrol edildi:

- `CORE/export.py`'nin `aad_map()`'i — tek sorgu, tek tablo (`files`),
  yalnızca SQLite'ın yer tutucu sınırı için parçalanmış. Tablolar-arası
  risk yok.
- `CORE/audit_chain.py`'nin `verify_audit_chain()`'i — `settings`'i bir
  kez, `audit_log`'u iki-üç kez, sarmalanmamış okuyor. Teknik olarak
  birden fazla okuma, ama `audit_log` yalnızca-ekleme (append-only) ve ek
  okumalar hash-zincir matematiğinin TAM eşleşmesine bağlı olmayan,
  BİLGİLENDİRİCİ çerçeveleme için kullanılan sayaçlar ("N kayıt kapsam
  dışı") — okuma sırasında eklenen bir satır yalnızca bir kayıt daha
  doğrulanmış olması demek, bozuk bir hüküm değil. Olduğu gibi bırakıldı.
- `CORE/inventory.py`'nin `generate_retention_inventory()`'si — **gerçek
  bir isabet, düzeltildi.** Aşağıda.
- `UI/AuditLogDialog.py`'nin `_export_txt()`'i — ilişkili ama FARKLI
  BİÇİMLİ bir sorun, **canlı doğrulandı ve bir takip turunda düzeltildi
  (BACKLOG B-073)**. Aşağıda, envanter bulgusundan sonra.

**Gerçek isabet: `generate_retention_inventory()`.** Bu fonksiyon
HYCLEUS'un KVKK saklama envanterini üretiyor — bir denetçiye ya da
düzenleyiciye, veri saklama politikasına UYULDUĞUNUN KANITI olarak
verilmesi açıkça amaçlanan bir rapor (`export_inventory_csv()`,
`export_inventory_pdf()`). Modülün kendi docstring'i tasarım hedefini
elden gelen en güçlü ifadeyle zaten söylüyor: *"rapor ile uygulama
ayrışamaz"* — rapor ile uygulamanın GERÇEK uygulama mantığı asla
çelişemez, çünkü rapor durumu, GERÇEK silmeyi kapı gibi kullanan AYNI
fonksiyonları (`check_disposal()`) çağırarak hesaplıyor. Bu güvence
MANTIK tutarlılığı için geçerliydi. ZAMANSAL tutarlılık için geçerli
değildi: `generate_retention_inventory()` `files`, `retention_profiles`,
`users` ve bir `audit_log` alt sorgusu üzerinde TEK bir JOIN ile başlıyor,
sonra — modülün kendi belgelediği tasarımla, "Bu N+1 sorgu demektir" —
her satır için BİR KEZ `check_disposal()` çağırıyor, o da
`files`/`retention_profiles`'ı DÖRT KEZ DAHA, ayrı ayrı, sarmalanmadan
yeniden okuyor.

Doğrudan ölçüldü: aynı 10 yıllık saklama profilindeki iki dosyadan
İKİNCİSİ, tam da `check_disposal()`'ı `retention_profile_id`'sini okumak
ÜZEREYKEN ikinci bir bağlantıyla 1 yıllık bir profile YENİDEN ATANDI —
sonuç satırı, `profile_name`'i (İLK JOIN'den, ESKİ profil) YENİ profile
göre hesaplanmış bir `status`'ün YANINDA gösterdi — bir düzenleyiciye
uyumu kanıtlamak İÇİN üretilen bir belgede, kendi içinde ÇELİŞEN bir
satır. Böyle bir satır yalnızca bayat bir sayı gibi "yanlış" değil — tam
olarak modülün kendi docstring'inin KABUL EDİLEMEZ dediği başarısızlık
biçimi: raporun BİR politika iddia ederken altındaki verinin AYNI cümle
içinde BAŞKA bir politikayı yansıtması.

**Düzeltme — §4.11'inkiyle AYNI biçimde.** Bütün okuma (temel JOIN VE her
satırın `check_disposal()` çağrıları) artık tek bir açık
`BEGIN`...`COMMIT` içinde — raporun TAMAMI için TEK bir WAL anlık
görüntüsü sabitliyor. İki yönde de doğrulandı: ham yapı taşları (temel
sorgu + per-satır kontrol, doğrudan çağrılarak, sarmalanmadan) yırtık
satırı yeniden üretiyor; gerçek fonksiyon, AYNI enjekte edilmiş eşzamanlı
yazma altında, üretmiyor.

**Bugün istismar edilebilir değil, yine de düzeltilmeye değer.**
`generate_retention_inventory()`'nin henüz bir UI giriş noktası yok —
`UI/AdminPanel.py` onu yalnızca yorum satırına alınmış bir kullanım
örneği olarak taşıyor, ve BACKLOG.md'nin PyInstaller maddesi onu zaten
gerçek, paketlenmiş (`reportlab` bağımlılığı gömülü), test edilmiş,
yalnızca henüz BAĞLANMAMIŞ bir özellik olarak takip ediyor. Hata koddaki
GERÇEK bir hataydı, bugün bir düğmenin onu çağırıp çağırmadığından
BAĞIMSIZ olarak — ve onu şimdi, hata biçimi hâlâ tazeyken ve bir test onu
sabitleyebilecekken düzeltmek, özellik bir uyum iş akışına bağlandıktan
SONRA yeniden keşfetmekten ucuz.

**İlişkili bulgu: `AuditLogDialog._export_txt()`, doğrulandı ve
düzeltildi.** Dışa aktarılan satır listesi `self._table`'dan geliyordu
(diyalog açılışından ya da son "Filtrele"/"Sıfırla"dan kalma, hangisi son
çalıştıysa ondan); başlık satırının kayıt sayısı ve zincir durumuysa dışa
aktarım ANINDA yapılan TAZE bir `zincir_raporu()` çağrısından geliyordu.
Koda dokunmadan ÖNCE, uçtan uca canlı olarak yeniden üretildi: diyaloğu
aç (üç önceki denetim satırı yükleniyor), `audit_log`'a DOĞRUDAN dördüncü
bir satır ekle — çalışan uygulamanın başka bir yerinin, diyalog açıkken
ve YENİLENMEDEN, bir işlem kaydettiğini taklit ediyor — sonra dışa
aktarımı tetikle. Dönen dosyanın başlığı `Doğrulanan : 5 kayıt` ve
`Son kayıt : id=5` diyordu, hemen ardından 4 satırlık bir tablo ve
`Bu dışa aktarımdaki kayıt sayısı: 4` yazan bir altyazı geliyordu —
kendi başlığı ile altyazısı kaç kaydı kapsadığı konusunda ÇELİŞEN, bir
okuyucunun sayacağı listede beşinci kaydın TAMAMEN yok olduğu bir dışa
aktarım. Bu bir transaction sorunu değildi (bayat taraf bir Qt widget'ı,
ikinci bir SQL sorgusu değil) ve düzeltme, rapor-tutarlılığı ilkesinin
burada GERÇEKTEN istediği biçimde: iki veri kaynağını senkronize etmek
değil, ikisini ARKA ARKAYA, TEK bir kaynaktan üretmek. `_export_txt()`
artık dışa aktarımı kurmadan HEMEN önce `self._load()`'ı çağırıyor,
böylece satır listesi ile başlığı üreten `zincir_raporu()` çağrısı
aralarına hiçbir kullanıcı kodu (diyaloğun açık kalması, dosya seçici
beklemesi) GİRMEDEN art arda çalışıyor. Yukarıdaki aynı canlı senaryo
düzeltmeyle tekrarlandığında: başlık ve altyazı ikisi de `5` okuyor, ve
beşinci satır listede görünüyor. Kalıcı bir regresyon testi
(`tests/test_audit_log_dialog_export.py`) aynı arka plan yazmasını gerçek
bir `AuditLogDialog` örneğine karşı tekrarlıyor ve başlıktaki sayının,
altyazıdaki sayının ve fiilen listelenen satır sayısının ÜÇÜNÜN de canlı
veritabanıyla eşleştiğini doğruluyor — düzeltmeden ÖNCEki kodda başarısız
olduğu (`{'dogrulanan': 5, 'altyazi': 4}`, elle yapılan tekrarla TAM
eşleşiyor) ve düzeltmeden SONRA geçtiği doğrulandı. `txt_basligi()` zaten
dışa aktarımın imzalı OLMADIĞINI açıkça söylüyor, bu da böyle bir
uyuşmazlığın taşıyabileceği ağırlığı sınırlıyor — ama bu, kendi B-006
notuna göre bütün amacı denetim izinin zincir durumunu makine dışına
taşımak olan bir dosyada gerçek, yeniden üretilebilir bir boşluktu, ve
F2-2/K4-20'nin planladığı imzalı rapor akışı TAM OLARAK bu dışa aktarım
yolunun üzerine inşa edilecek — o yüzden miras alınmak yerine şimdi
kapatılması gerekiyordu.

**Hata yolu da kontrol edildi.** `create_backup()`'ın yeni transaction'ı
(§4.11) ve bu ikisi de okumayı `try/.../finally: db.conn.execute
("COMMIT")` içine alıyor. İkisi için de doğrudan doğrulandı: okumanın
ortasına (`BEGIN`'den sonra, döngü içinde) yapay bir exception enjekte
edilip, exception'ın çağırana YANSIDIĞI (finally'nin onu YUTMADIĞI) ve
hemen ardından `sqlite3.Connection.in_transaction`'ın `False` OLDUĞU
doğrulandı — transaction asılı kalmıyor. Yarım kalmış bir raporun arkasında
bırakacağı açık bir transaction yalnızca o raporu etkilemekle kalmaz:
sonraki bir `PRAGMA wal_checkpoint`'in WAL dosyasını kısaltmasını
bloklayabilir.

### 4.17 RBAC yalnızca UI'da uygulanıyordu — DB katmanı her çağırana güveniyordu

> **Saldırgan modelleri:** M2 · M3

Hiçbir kod yazılmadan önce CANLI doğrulandı. `CORE/roles.py::can_write()`
kod tabanının "bu rol yazabilir mi" sorusuna tek karar noktası — ama tek
çağıranları dört `UI/main_window*.py` dosyasıydı: hangi düğmenin
gizleneceğine, sürükle-bırakın kabul edilip edilmeyeceğine, hangi
sekmenin görüneceğine onlar karar veriyordu. `DB/db_manager.py::execute()`
çağıranın rolünden TAMAMEN habersizdi; kendisine verilen SQL'i sorgusuz
sualsiz çalıştırıyordu. Bir script'ten çağrılan doğrudan bir
`DBManager().execute("INSERT INTO folders …")`, kontrolü unutmuş bir
diyalog, ya da gizli düğme dışındaki bir yoldan ulaşılan bir `CORE`
fonksiyonu — hepsi kayıtsız şartsız geçiyordu, Salt Okunur rolde olsun ya
da olmasın.

Bu boşluk bu kod tabanında teorik değildi: `UI/TagDialog.py`'nin içinde
hiçbir yerde `is_readonly_role`/`can_write` çağrısı OLMADIĞI ortaya çıktı
— tamamen kendisini açan "+ Yeni Etiket" düğmesinin salt okunur rolde
gizlenmesine güveniyor. Başka bir yoldan ulaşılsa (ileride eklenecek bir
sağ tık menüsü, bir hata), etiket oluşturma ve silme dosdoğru geçerdi.
Doğrudan `DBManager().execute()` çağıran bir script ile doğrulandı — hiç
UI yok, hiç diyalog kurulmadı: Salt Okunur rol aktifken `INSERT INTO
files`, `INSERT INTO folders`, `INSERT INTO tags`, `INSERT INTO
file_tags`, `INSERT INTO quarantine` ve `INSERT INTO retention_profiles`
hepsi dokunulmadan geçti.

**Düzeltme: `DBManager.execute()` uygulama noktası, çağrı-yeri-başına bir
kural DEĞİL.** `UI/main_window.py::_apply_role_restrictions()` — kod
tabanının rol her değiştiğinde zaten tek yerden geçirdiği nokta (girişte
`main.py` üzerinden, USB reauth'ta, `reload_app_mode()`'da) — artık
`DBManager().set_active_role(role)`'ü de çağırıyor. `execute()` kendisine
verilen SQL'in hedef tablosunu ayrıştırıyor ve tanımlı bir iş verisi
tablosu kümesi için, `can_write(role)` kontrolünün reddedeceği her yazıyı
reddedip `YazmaYetkisiYokError` fırlatıyor. Bu, çağrının hangi `CORE`
fonksiyonundan, hangi UI diyaloğundan, ya da diyalog YOKLUĞUNDAN geldiğine
bakmaksızın çalışıyor — yazı gizli bir düğmeden, bir hatadan ya da UI'ı
bilerek atlayan bir script'ten gelsin, aynı kontrol.

**Bilerek kapsam dışı bırakılanlar, ve nedeni — ÖLÇÜLDÜ, varsayılmadı.**
Aynı `execute()`'tan geçen üç tablo GATE'LENMEDİ:

- `users` — `CORE/session_user.py::sync_session_user()` her girişte ve
  her USB reauth'ta buraya yazıyor, rol henüz TAM olarak "oturuma
  bağlanmadan" önce (ve reauth'ta, hâlâ ÖNCEKİ oturumun rolünü
  taşıyor olabilirken). Bu tabloyu kısıtlamak, salt okunur bir
  kullanıcının GİRİŞ BİLE YAPAMAMASI anlamına gelirdi.
- `login_attempts` — `CORE/rate_limit.py`'nin başarısız deneme defteri
  rolden bağımsız çalışmalı, başarısız bir reauth sırasında oturum
  ORTASINDA da dahil.
- `settings` — karışık bir tablo. `imha_ttl_hours`/`idle_lock_minutes`/
  `app_mode` UI'da zaten yalnızca yönetici yazabiliyor (`can_write`
  DEĞİL, ayrı bir `is_admin_role` kapısı), ama
  `CORE/backup_reminder.py::ertele()`/`yedek_alindi()` buraya "Yedek
  Al…" menü eyleminden yazıyor — `UI/main_window.py`'nin Görünüm
  menüsü okunarak doğrulandı: bugün HİÇBİR `can_write` kontrolü
  taşımıyor ve her rol tarafından erişilebilir. Tüm tabloyu kısıtlamak
  salt okunur kullanıcılar için yedeklemeyi kırardı; anahtar bazında
  kısıtlamak bu turun kapsamı dışı sayıldı ve sessizce daraltılmak
  yerine BACKLOG'a takip maddesi olarak bırakıldı.

**İki otomatik temizleyici rol kontrolü değil, açık bir bypass
gerektirdi.** `CORE/disposal.py::purge_expired_file()` ve
`sweep_retention_expired()` ikisi de `files`'a — gate'lenmiş bir tabloya
— yazıyor, ama ikisi de giriş yapmış kullanıcı "ADINA" çalışmıyor. İkisi
de, kendi docstring'lerine göre, bir sayaç sıfıra inince ya da bir
saklama süresi dolunca "kimseye sormadan" davranan otomatik
temizleyicilerin tek giriş noktası. İkisinin de iki çağıranı var:
`CORE/scheduler.py`'nin APScheduler arka plan iş parçacığı, ve — sayaç
durumunda — kullanıcı İmha Odası'na bakarken ana iş parçacığında çalışan
bir `QTimer` tik'i — yani bir iş parçacığı kimliği kontrolü ikisini de
etkileşimli bir yazıdan AYIRAMAZDI. En yüksek değerli alternatifin —
"ana iş parçacığı DIŞINDAYSA kontrolü atla" — hiç işe yaramayacağı
doğrulandı: dosya EKLEMEYİ fiilen yapan kod yolu,
`UI/main_window_table.py`'nin `_FileRunnable`'ı, ana iş parçacığında
DEĞİL, bir `QThreadPool` işçi iş parçacığında çalışıyor. Her iki
fonksiyon da artık `db.execute()` çağrısını `DBManager.system_write()`
içine alıyor — THREAD-LOCAL bir bypass, ÖZELLİKLE thread-local çünkü
arka plan zamanlayıcı iş parçacığı, `QThreadPool` dosya-ekleme işçileri
ve GUI iş parçacığı AYNI `DBManager` tekil örneğini paylaşıyor; paylaşılan
(thread-local OLMAYAN) bir bayrak bir iş parçacığının bypass'ını
BAŞKASINA sızdırırdı. Canlı doğrulandı: Salt Okunur rol aktifken, her iki
fonksiyon da yazısını tamamlamaya devam ediyor.

**Bypass mekanizmasının kendisi sonra CANLI incelendi — sızıntı
bulunamadı, ama AYRI, gerçek bir boşluk bulundu.** `system_write()`
hakkında üç soru kod okunarak VARSAYILMADI, doğrudan kontrol edildi:
thread-local derinlik sayacı `with` bloğu normal DEĞİL, bir exception ile
sona erdiğinde doğru sıfırlanıyor mu (`yield` etrafında `try`/`finally`
— doğrulandı: sayaç yazı YARIDA KESİLSE bile `0`'a dönüyor); `QThreadPool`'un
aynı OS thread'ini farklı görevler için zaman içinde yeniden kullanmasına
sızıyor mu (`ThreadPoolExecutor(max_workers=1)` ile simüle edildi — iki
gönderilen görev AYNI OS thread'ine zorlandı, biri `system_write()`
ortasında yapay bir exception'la yarıda kesildi, hemen ardındaki normal,
rol-kontrollü bir yazı çalıştırıldı — doğrulandı: ikinci görev yine doğru
şekilde reddedildi, `threading.local()` + `try`/`finally` kombinasyonu
tuttu); ve iç içe çağrı doğru çalışıyor mu (bir güvenlik sorusu değil,
sağlık kontrolü — sayacın, bir boole DEĞİL, bir seferde bir seviye
çözüldüğü doğrulandı). Üçü de temiz çıktı. Aynı inceleme bunun yerine
ŞUNU ortaya çıkardı: `_yazma_yetkisini_dogrula()`'nın reddettiği bir yazı
HİÇBİR audit izi bırakmıyordu — `weak_hwid_binding_rejected`
(`CORE/vault_manager.py`) ve `usb_auth_rejected`'in ikisi de reddetmeden
ÖNCE kaydediyorken, RBAC yazma reddi — kod tabanındaki en güvenlik-
ilgili red belki de — sessizce geçiyordu.

**Düzeltildi: red artık `raise`'den ÖNCE denetim zincirine
`rbac_write_rejected` yazıyor**, `detail`'de `role`, hedef tablo, SQL
fiili (`INSERT`/`UPDATE`/`DELETE`/`REPLACE`) ve çağıranın modül/fonksiyon/
satırı (`sys._getframe(2)`, `execute()`'u çağıran çerçeveye çözülüyor)
ile birlikte. Rekürsiyon VARSAYILMADI, kontrol edildi: `self.log()`
`CORE.audit_chain.append_entry()`'yi çağırıyor, o da `self.conn` — ham
`sqlite3.Connection` — üzerinden yazıyor ve `self.execute()`'u hiç
GÖRMÜYOR; `audit_log` zaten `_RBAC_KORUMALI_TABLOLAR`'ın dışında. Aynı
başarısızlık moduna karşı İKİ bağımsız garanti, canlı doğrulandı: Salt
Okunur rolde bir yazıyı reddetmek TAM OLARAK bir yeni `audit_log`
satırı üretiyor, ve `system_write()` üzerinden yapılan meşru bir yazı —
hiçbir şey reddedilmediği için — hiç üretmiyor.

Kalıcı bir regresyon paketi (`tests/test_db_manager_rbac.py`)
`DBManager().execute()`'u ve `CORE.folders.create_folder()`'ı doğrudan
çağırıyor — hiç UI kurulmadan — Salt Okunur rol ayarlıyken, her
gate'lenmiş tablo için, ve reddi doğruluyor; üç hariç tutulan tablonun
aynı rolde yazılabilir KALDIĞINI doğruluyor; iki otomatik temizleyicinin
salt okunur rolde de tamamlandığını doğruluyor; reddedilen bir yazının,
birden fazla gate'lenmiş tablo ve SQL fiilinde, tam olarak bir
`rbac_write_rejected` satırı ürettiğini VE `role`/`table`/`op`/`caller`
alanlarının beklenen değerleri taşıdığını doğruluyor; meşru bir
`system_write()` yazısının böyle bir satır ÜRETMEDİĞİNİ doğruluyor; ve
kontrolü devre dışı bırakıp AYNI yazının onsuz geçeceğini gösteren bir
mutasyon-kontrastı testi içeriyor. Düzeltmeden ÖNCEki koda karşı
doğrudan, İKİ KEZ doğrulandı: `DB/db_manager.py`, `CORE/disposal.py` ve
`UI/main_window.py` önceki hâllerine `git stash` ile geri alındığında,
test modülü İÇE AKTARILAMIYOR bile — `YazmaYetkisiYokError` henüz yok —
"bu paket kazayla geçemez"in en güçlü biçimi; ve daha SONRA, yalnızca
audit-loglama eklentisi `DB/db_manager.py`'den geri alındığında, audit'e
özgü iki test TEK BAŞINA başarısız oluyor (`1` yerine `0` satır
eklenmiş) — paketin geri kalanı geçmeye devam ederken — bu da o iki
testin GERÇEKTEN loglama davranışını ölçtüğünü, yalnızca reddi değil,
kanıtlıyor.

**Bunun iddia ETMEDİĞİ.** `can_write()` Yönetici'yi Standart'tan
AYIRMIYOR — yönetici-only bir UI diyaloğunu (ör. henüz UI girişi olmayan
saklama profili yönetimi) atlayan yönetici-olmayan ama salt-okunur-da-
olmayan bir oturum bu kontrol tarafından YAKALANMAZ, yalnızca salt okunur
bir oturum yakalanır. Bu farklı, daha dar bir eksen (`can_write` değil,
`is_admin_role`) ve bu düzeltmenin kapattığı sorundan AYRI bir problem;
`CORE/session_user.py::oturum_yetkisi_gecerli_mi()`'nin kendi docstring'i
zaten aynı noktada ilişkili bir sınırı işaretliyor (DB şemasının `role`
sütunu Standart ile Salt Okunur'u hiç AYIRT EDEMİYOR). Not düşüldü,
burada düzeltilmedi.

### 4.18 Kilit ekranı checkout'u durduruyordu, ama devam eden bir toplu indirmeyi değil

> **Saldırgan modelleri:** M2 · M3

§4.10 kilitlenmenin her açık checkout'u kapattığını söylüyor, "bilerek:
diskte düz metin bırakan bir kilit ekranı ön kapıyı korur, bir pencereyi
açık bırakırdı." Bu iddia checkout için doğru — `_lock()` overlay'i
göstermeden ÖNCE senkron olarak `_close_all_checkouts()` çağırıyor. Bu
kod tabanının düz metni kullanıcının seçtiği bir konuma yazdığı DİĞER
yer — toplu indirme — için doğru DEĞİLDİ.

**Ölçüldü, varsayılmadı.** `_lock()` hiçbir zaman `QThreadPool`'a,
herhangi bir işçi iş parçacığına ya da herhangi bir `should_continue`/
durdurma-olayı mekanizmasına dokunmuyor — yalnızca UI durumu (overlay,
bulanıklaştırma, `centralWidget().setEnabled(False)`) artı checkout
kapatma. Tekli dosya indirmeleri ve checkout açmaları, arasında
`QApplication.processEvents()` OLMAYAN senkron ana iş parçacığı
çağrıları — bu yüzden (varsayılmadı, okunarak doğrulandı) Qt olay
döngüsü bunlarla ASLA iç içe geçemiyor; `_poll_usb()`'un zamanlayıcısının
çalışma fırsatı çağrı dönene kadar hiç olmuyor, o noktada dosya zaten
ya tamamen yazılmış ya da hiç yazılmamış oluyor. Toplu indirme farklı:
`UI/main_window_bulk.py`'nin ilerleme geri çağrımı, ilerleme penceresinin
uzun bir turda tepkisiz kalmaması için dosya başına bir kez
`QApplication.processEvents()` çağırıyor, ve bu GERÇEK bir yeniden giriş
noktası — USB tam o çağrılardan birinin İÇİNDE çekilseydi, `_poll_usb()`
çalışabilir, kilit overlay'ini gösterebilirdi, ve yalnızca ilerleme
penceresinin İptal düğmesini dinleyip kilit durumunu HİÇ kontrol
etmeyen dışa aktarma döngüsü, ekran kilitli olsun ya da olmasın, kalan
dosyaları çözüp diske yazmaya devam ederdi.

Hiçbir düzeltme yazılmadan ÖNCE canlı yeniden üretildi: sekiz dosya
toplu indirmeye kuyruğa alındı, gerçek UI bağlamasının yerine geçen bir
`should_continue`/`on_progress` çifti, geri çağrımın KENDİSİ dosya
index=3'ü işlerken bir `locked` bayrağını çeviriyor (`_poll_usb`'un
etkisi, gerçek USB donanımına gerek kalmadan). Düzeltmeden ÖNCEki koda
karşı, dosya index 3 yine de yazıldı — `saved=4`, kilit noktasının bir
dosya ötesi.

**Düzeltildi: `should_continue`, ilerleme geri çağrımı döndükten hemen
sonra, bir sonraki dosya çözülmeden HEMEN önce İKİNCİ KEZ kontrol
ediliyor** (`CORE/export.py::export_to_directory()`) — döngü bunu
`on_progress`'i çağırmadan önce zaten bir kez kontrol ediyordu, ama o
kontrol yeniden girişin MÜMKÜN OLDUĞU TEK noktadan ÖNCE gerçekleşiyor,
yani o çağrı sırasında oluşan bir kilidi göremiyor. İkinci kontrol tam
o pencereyi kapatıyor, ve yalnızca `on_progress` GERÇEKTEN verildiyse
çalışıyor (böylece ilerleme geri çağrımı olmayan bir çağıran — yeniden
giriş mümkün değil — eskisiyle TAM AYNI çağrı sayısını görüyor;
buna adanmış bir test bunu sabitliyor). İki kontrol arasında, ve
`decrypt_file()`/`write_bytes()`'in kendisi sırasında, olay döngüsü hiç
dönmüyor, yani bir dosya her zaman ya TAMAMEN yazılıyor ya HİÇ
başlamıyor — asla yarım kalmıyor. `UI/main_window_bulk.py`'nin
`should_continue` lambda'sı artık İptal düğmesine EK OLARAK
`self._locked`'ı da okuyor — CORE seviyesindeki düzeltmeyi gerçek kilit
sinyaline bağlayan tek satırlık değişiklik BU; buna adanmış bir UI
seviyesi testi gerçek `_on_ctx_bulk_download()` işleyicisini uçtan uca
sürüyor (gerçek `HycleusWindow`, gerçek şifreleme, TOTP korumalı) ve
`self._locked`'ı `QProgressDialog.setValue()`'nun İÇİNDEN çeviriyor —
gerçek ilerleme geri çağrımının yaptığı TAM O çağrı — yalnızca altta
yatan mekanizmayı değil, bağlamanın kendisini de doğruluyor.

**Zeroize, dürüstçe kapsamlandırıldı.** `decrypt_file()` isteğe bağlı bir
`zeroizable=True` modu kazandı: `bytes(buf)` — §3'te zaten belgelenmiş
sınır gereği hiçbir zaman silinemeyecek değiştirilemez bir kopya —
döndürmek yerine, çözümlemenin yazdığı TA KENDİSİ olan `bytearray`'i
geri veriyor, çağıranın düz metin işini bitirince onun üzerinde (artık
genel) `zero_bytearray()`'i çağırmasına izin veriyor. Varsayılmayıp
CANLI kontrol edilen iki iç garanti: herhangi bir hata yolunda tampon
hâlâ `decrypt_file()`'ın kendi `finally`'sinde sıfırlanıyor (yalnızca
`zeroizable=True` ile BAŞARILI dönüş yolu bunu atlıyor, çünkü döndürülen
değer TAM OLARAK o tamponun kendisi ve `finally` çağırana ulaşmadan
ÖNCE çalışıyor — orada sıfırlamak çağırana zaten boşalmış bir tampon
verirdi, bu canlı doğrulanıp sonra korumaya alındı); ve
`zero_bytearray()` üzerindeki bir casus, her dosya için TAM OLARAK bir
kez, o dosyanın GERÇEKTEN taşıdığı düz metinle, `write_bytes()`'ten
HEMEN sonra çağrıldığını doğruluyor. Mevcut çağıranlar ETKİLENMİYOR —
varsayılan değişmedi, ve diğer her çağrı yeri (`CORE/checkout.py`,
`CORE/backup.py`, `CORE/hclx.py`, `UI/main_window_files.py`) hâlâ düz
`bytes` alıyor; yalnızca `export_to_directory()` — bu bulgunun konusu
olan yol — yeni moda geçirildi. `export_to_zip()` BİLEREK eski (`bytes`)
yolda bırakıldı: döngüsünde hiçbir yerde `on_progress`/
`processEvents()` çağrısı yok, yani yeniden giriş yapılabilir değil ve
ölçülen boşluğun parçası değildi; onu dönüştürmek ayrı, daha düşük
değerli bir değişiklik — buraya katılmak yerine BACKLOG'a not düşüldü.

### 4.19 Çapraz platform HWID yeniden gözden geçirildi (2026-08-29): hâlâ taze donanım verisi yok, bunun yerine onu ALACAK araç yapıldı

> **Saldırgan modelleri:** yok — bu bir taşınabilirlik/mimari sorusu,
> güvenlik sınırı değil. `CORE/hwid_probe.py` bir prototip ve uygulamaya
> bağlı değil (`tests/test_hwid_probe.py::
> test_the_prototype_is_not_wired_into_the_app` bunu tüm ağacı tarayan
> bir AST denetimiyle koruyor).

Duran soru, bu turda yeniden soruldu: aynı USB çubuğu Windows, Linux ve
macOS'ta aynı HWID'yi veriyor mu? BACKLOG **B-016** bunu, önceki bir
oturumda gerçek donanımda İKİ KEZ fiziksel olarak ölçülmüş tek token için
zaten yanıtlıyor (2026-08-16 ve 2026-08-19): token'ın gerçek bir
tanımlayıcı serisi var, hem USB yığınından hem depolama yığınından
BİREBİR AYNI okunuyor, port değişikliğine değişmeden dayanıyor ve hiçbir
zaman makineye özel `usb_ids.json` UUID fallback'ine düşmüyor. O ölçüm
duruyor; bu tur onu TEKRARLAMADI ve tekrarlamaya gerek de yoktu.

**Bu turun ortamı ne katabildi, ne katamadı.** `python -m CORE.hwid_probe`
şu anda, burada çalıştırıldığında `USB depolama aygıtı bulunamadı.`
basıyor — bu oturumun ortamında takılı bir USB depolama aygıtı yok ve
buradan yalnızca Windows'a erişilebiliyor (Linux ya da macOS makinesi
yok). Yani B-016'nın hâlâ açık bıraktığı tek ölçüm — AYNI çubuğun,
`ID_SERIAL_SHORT`'un teorik olarak ortak alan olduğu Linux'ta okunması —
bugün alınamadı; sebep sıradan (burada donanım yok), önceki bulgudan
şüphe duyulduğu için değil. Bunu açıkça söylemek, sessiz kalmaktan daha
değerli: `docs/hwid-crossplatform.md`'nin kendi "Prototipin sınırları"
tablosu Linux ve macOS'u zaten gerçek araçlara karşı doğrulanmamış diye
işaretliyor ve o satır bugün hâlâ doğru.

**Değişen şey: eksik adım elle değil, bir araçla kapatılabilir hâle
geldi.** `docs/hwid-crossplatform.md`'nin "Sonraki adım için gereken"
bölümü kalan testi "aynı çubuğu üç işletim sisteminde takıp aracı
çalıştırıp çıktıları karşılaştır" diye tarif ediyordu — yani gözle.
`CORE/hwid_probe.py` artık `--json` (bu platformun okumasını bir dosyaya
serileştirir) ve `--compare A.json B.json` (iki dosyayı karşılaştırır,
uyuşmazlıkta sıfırdan farklı çıkış koduyla döner — `CORE/backup_cli.py`'nin
zaten kullandığı aynı çıkış kodu deseni: 0 eşleşti, 1 eşleşmedi, 2
kullanım hatası) bayraklarını taşıyor. `to_dict()`/`from_dict()` türetilmiş
`stable_id` HARİÇ her ham alanı kayıpsız geri veriyor — o BİLEREK bir
`@property` olarak kalıyor, her yüklemede ham alanlardan yeniden
hesaplanıyor, yani dump kendisiyle asla ÇELİŞEMEZ (önbelleklenmiş türetilmiş
bir değerin çelişebileceği gibi) — `CORE/pin_rotation.py`'nin kendi karar
fonksiyonu için belgelediği aynı tek-kaynak gerekçesiyle. Bunların hiçbiri
donanım GEREKTİRMEDİ: `tests/test_hwid_probe.py` §7'deki 15 yeni test JSON
round-trip'ini ve `--compare` çıkış kodlarını doğrudan sınıyor, canlı bir
mutasyonla doğrulandı (çıkış kodu satırı geçici olarak her zaman 0 dönecek
şekilde sabitlendi; `test_cli_compare_ESLESMEZSE_cikis_kodu_1` beklendiği
gibi BAŞARISIZ oldu, iddianın gerçekten işlevsel olduğu doğrulandı, sonra
geri alındı). Gerçekten doğrulanmamış kalan şey değişmedi: `pyudev`/sysfs
ve `ioreg`'in gerçek Linux/macOS makinelerinde belgelenmiş biçimde çıktı
verip vermediği. Bu boşluk artık elle karşılaştırma değil, iki komutla
kapanıyor — donanıma erişildiği gün; bugün kapanmadı.

**Bunun beslediği mimari soru YENİ değil, burada yeniden AÇILMIYOR.**
`docs/hwid-crossplatform.md`'nin dosya-tabanlı token'a geçiş önerisi zaten
var ve bu turda değişmedi; B-016 gerçek donanım ölçülünce onun
aciliyetini zaten daraltmıştı (serili aygıtlar geçiş gerektirmiyor, serisiz
aygıtlar asıl kalan boşluk — ve bu bugünden önce de doğruydu). Bu madde
yeni bir BACKLOG kalemi eklemiyor — mevcut olanın hâlâ doğru kapsamda
olduğunu yeniden doğruluyor ve fiziksel çoklu-OS erişimi olduğu gün için
çalıştırılabilir bir karşılaştırma aracı veriyor.

### 4.20 Denetim günlüğü modal'dan tam sayfaya taşındı; satır bazlı zincir bütünlüğü sütunu (yol boyunca bulunup kapatılan bir rol kapısı boşluğu)

> **Saldırgan modelleri:** ne sayfa taşınması ne HALKA sütunu için yok —
> bu bir gözlenebilirlik iyileştirmesi, `verify_audit_chain()`'in zaten
> hesapladığı bir sonucu görünür kılıyor, yeni bir güvenlik sınırı değil.
> Aşağıdaki tesadüfi bulgulardan biri GERÇEKTEN bir erişim kontrolü
> boşluğu.

**Ne taşındı.** `UI/AuditLogDialog.py` (modal bir `QDialog`) kalktı;
`UI/AuditLogView.py` `_govde_yigini`'nde (`QStackedWidget`) tam bir sayfa
— §4.17/§4.18'in komşusu `UI/GuvenlikView.py`'nin zaten kurduğu AYNI
desen: durum (filtreler, seçili sekme) gezinme boyunca KORUNUYOR,
kapatıldığında atılmıyor, sayfa kendi özel stil sayfasını taşımak yerine
`main_window_theme.py::_apply_theme()`'den cascade ediyor. Beş sekme
(Tümü/Dosya/Kimlik/Yönetim/Uyarı) aynı tabloyu action kategorisine göre
süzüyor — `QTabWidget` DEĞİL çıplak bir `QTabBar` ile: tam olarak beş
neredeyse özdeş tablo kurup senkron tutmamak için. `UI/AdminPanel.py`'nin
`QTabWidget`'ı kendi durumunda (sekme başına GERÇEKTEN farklı içerik)
doğru araç; burada yanlış olurdu.

**Yeni HALKA sütunu: ikinci bir hash yürüyüşüne KARŞI karar verildi.**
Görev, önce yanıtlanacak soruyu açıkça soruyordu: bu,
`verify_audit_chain()`'in mevcut satır bazlı çıktısına mı dayanacak,
yoksa yeni bir hesaplama mı gerekecek? Dayanıyor. `CORE/audit_chain.py::
verify_audit_chain()` zaten zincirli her satırı bir kez hash'liyor ve
yalnızca başarısızlıkları `ChainVerification.breaks`'e yazıyor; UI
katmanında "bu satırın KENDİ bağı sağlam mı" sorusuna yanıt vermek için
ikinci, bağımsız bir hash yürüyüşü, bu deponun en çok tekrarlanan
kusurunun altıncı örneği olurdu — bir olgunun iki uygulaması, sessizce
birbirinden sapan (B-003/B-004/B-007/B-008/B-010/B-011). Bunun yerine
`CORE/audit_chain.py`'ye `link_status()`/`link_statuses()` eklendi —
mevcut sonucun saf bir OKUNMASI: bir satır `start_id`'den önceyse (ya da
zincir hiç başlamadıysa — "hiç doğrulanmadı" ile "doğrulandı ve sağlam"
FARKLI iddialar, `CORE/hwid_probe.py::compare()`'in farklı bir gerekçeyle
zaten çizdiği "bilinmiyor" ayrımının aynısı) kapsam dışı; `modified`/
`unhashed` türünde bir kırılmanın `entry_id`'siyse kırık; aksi hâlde
sağlam. Yeni kodda hiçbir yerde YENİ bir `compute_entry_hash()` çağrısı
yok — doğrudan denetlendi: `tests/test_audit_chain.py::
test_link_status_YENI_hash_hesaplamiyor_SADECE_breaks_i_okuyor`
`compute_entry_hash`'e casus yerleştirip `link_statuses()`'un onu HİÇ
çağırmadığını doğruluyor. `AuditLogView._load()` her yenilemede `CORE.
audit_report.zincir_raporu()`'yu BİR KEZ çağırıp aynı `ChainVerification`'ı
hem HALKA sütununa hem TXT dışa aktarım başlığına besliyor — tek
doğrulama, iki tüketici; B-073'ün yalnızca dışa aktarım yolu için yaptığı
düzeltmeyi sürdürüyor (ve sıkılaştırıyor): `_export_txt()` artık
`zincir_raporu()`'yu KENDİSİ ikinci kez çağırmıyor, dışa aktarımdan hemen
önce tetiklediği `_load()`'un ürettiği `self._son_rapor`'u yeniden
kullanıyor — daha önce kalan küçük "iki sayı anlaşmazlığı" penceresi bile
kapandı.

**Görevin istediği gibi çekişmeli doğrulandı.** Bir kayıt doğrudan
`UPDATE audit_log SET detail = … WHERE id = ?` ile bozuldu —
`append_entry()`'i atlayarak, yani diske yazma erişimi olan bir
saldırganın yapacağının aynısı — ve iki BAĞIMSIZ okuma karşılaştırıldı:
kullanıcının GERÇEKTEN göreceği HALKA hücresi ve aynı bağlantıda
doğrudan `verify_audit_chain()` çağrısı.
`tests/test_audit_log_view.py::test_BILEREK_kirilmis_halka_KOPUK_
gosterilir_ve_verify_ile_TUTARLI` ikisinin ANLAŞTIĞINI doğruluyor —
bozulan satırın `entry_id`'si hem `verify_audit_chain()`'in
`first_broken_id`'i hem HALKA hücresinde "Kopuk" yazan id — ve komşu,
dokunulmamış satırların "Sağlam" kaldığını (yanlış pozitif yok). İkinci,
canlı bir mutasyon (sağlam/kırık metin eşlemesini geçici olarak ters
çevirerek) sütun yanlış olduğunda testin GERÇEKTEN kırıldığını doğruladı,
yalnızca veri eksikken değil: `tests/test_audit_chain.py`'nin kendi
mutasyonu (`link_status()`'u her zaman "sağlam" dönecek şekilde
sabitleyerek) okumanın GERÇEKTEN yapıldığı `CORE` katmanında beş test
tarafından aynı şekilde yakalandı.

**Tesadüfi bulgu: taşınan giriş noktasında bir rol-kapısı boşluğu.**
`_on_open_audit_log()`'un kendi admin kontrolü YOKTU — erişilebilirlik
tamamen kenar çubuğu düğmesinin admin olmayan roller için
gizlenmesine (`_apply_role_restrictions`) dayanıyordu. Hamburger
menüsündeki "📋 Denetim Günlüğü" (`_on_hamburger_menu`) AYNI metodu o
yolda HİÇBİR rol kontrolü olmadan çağırıyordu — yani admin olmayan bir
rol bu turdan ÖNCE de ikinci giriş noktasından denetim günlüğüne
ulaşabiliyordu; gerçek ama dar bir boşluk (düşük önem: denetim günlüğü
bir OKUMA yüzeyi, yazma değil, ve boşluk görünür sunulan bir yol değil,
hamburger menüsünü açmayı bilmeyi gerektiriyordu). Bu metodu — her
`.exec()`'te yeniden kurulan bir modal yerine — KALICI monte edilmiş bir
sayfaya taşımak, bu boşluğu sessizce taşımamak için yeterli gerekçeydi:
`_on_open_audit_log()` artık `is_admin_role(self._role)`'u KENDİSİ
kontrol ediyor, `_on_open_admin_panel()`'in zaten kullandığı aynı desen —
yani hangi giriş noktasından çağrılırsa çağrılsın kapı kapanıyor.
`tests/test_audit_log_view.py::test_yonetici_OLMAYAN_ENGELLENIYOR` gerçek
bir `HycleusWindow`'u admin olmayan bir rolle kurup sayfanın asla aktif
hâle gelmediğini doğruluyor.

**Takip (aynı gün): menünün kendisi hâlâ sonra reddedeceği seçeneği
sunuyordu.** Fonksiyon-içi kapı gerçek deliği kapatıyor, ama bir takip
kontrolü daha dar bir UX sorusunu doğrudan sordu: hamburger menüsündeki
öğe, hemen yanındaki kenar çubuğu düğmesinin ZATEN yaptığı gibi admin
olmayan role gizleniyor mu — ve `_on_open_admin_panel()`'in kendi menü
öğesi ("🔌 USB Yönetimi") yukarıdaki yorumun ima ettiği gibi bu deseni
GERÇEKTEN takip ediyor mu? `_on_hamburger_menu()`'yu baştan sona okumak
ikisini de tek seferde yanıtladı: **hiçbiri kapılı DEĞİLDİ.** `act_audit`
ve `act_usb` ikisi de koşulsuz ekleniyordu, o metodun hiçbir yerinde role
bağlı bir `.setVisible()`/`.setEnabled()` çağrısı yoktu — bir önceki
maddenin tarif ettiği "`_on_open_admin_panel()` ile aynı desen" yalnızca
FONKSİYON-İÇİ kontrol için doğruydu; menü seviyesinde USB Yönetimi de
BAŞTAN BERİ aynı boşluğu taşıyordu, tam bu soru için metod baştan sona
okununcaya kadar fark edilmeden. Hiçbir yorum ya da BACKLOG maddesi bunun
bilinçli olduğunu iddia etmiyor, ve admin olmayan bir rol her iki öğeye
tıkladığında karşısına yalnızca bir ret kutusu çıkıyordu — seçeneğin hiç
orada olmamasından daha kötü bir kullanıcı deneyimi, kullanıcıyı uyarıları
tıklayıp geçmeye alıştıran türden bir yüzey. İki öğe de artık
`is_admin_role(self._role)`'u kontrol edip sonucu `QAction`'ın
`.setVisible()`/`.setEnabled()`'ına yazıyor, kenar çubuğunun zaten
kullandığı `_apply_role_restrictions()` deseniyle BİREBİR aynı; "💬
Destek" bilerek koşulsuz bırakıldı — `ContactDialog` kendi hiçbir rol
kısıtlaması taşımıyor, onu gizlemek bir tutarlılık düzeltmesi değil, YENİ
bir kısıtlama İCAT ETMEK olurdu. Bu EKLEME, YERİNE GEÇME değil:
fonksiyon-içi kontrol AYNEN duruyor, yani menüyü tamamen atlayan doğrudan
bir çağrı hâlâ reddediliyor, menü ne gösterirse göstersin — §4.17'nin
K1-14 bulgusunun `DB/db_manager.py::system_write()` için kurduğu AYNI
katmanlı-savunma şekli (yaygın yol için bir UI/menu-level kontrol, altında ona
GÜVENMEYEN bağımsız bir kontrol). İki yoldan doğrulandı:
`tests/test_audit_log_view.py::test_yonetici_OLMAYAN_DOGRUDAN_cagrida_da_
REDDEDILIYOR_ve_UYARI_gosterilir` `_on_open_audit_log()`'u DOĞRUDAN
çağırıyor — menü yok, tıklama yok — admin olmayan bir rolle, ve HEM
sayfanın hiç açılmadığını HEM kullanıcının GERÇEKTEN bir ret kutusu
gördüğünü doğruluyor (K1-14 tarzı doğrudan çağrı, yani sessiz bir no-op
kazayla geçemez); `tests/test_audit_log_view.py::
test_hamburger_menusunde_YONETICI_OLMAYANA_denetim_ve_usb_gizli` gerçek
menüyü (`tests/test_backup_verify_ui.py`'nin zaten kullandığı AYNI
`QMenu` alt-sınıflama-ve-kaydetme tekniğiyle — doğrudan bir `QMenu.exec`
monkeypatch'i DEĞİL, `tests/test_timestamp_ui.py`'nin belgelenmiş
gerekçesiyle) admin olmayan bir role kurup iki öğenin de görünmez VE
devre dışı olduğunu, "Destek"in görünür kaldığını doğruluyor; eşleştirilmiş
bir admin-rolü testi ve iki canlı mutasyon (her yeni kapıyı ayrı ayrı geri
alarak) düzeltme yokken iki testin de GERÇEKTEN kırıldığını doğruladı,
yalnızca DB ya da pencere durumu bozulduğunda değil.

### 4.21 Kalıcı silme bir çökmeyle YARIDA KESİLEBİLİYORDU — kalıcı bir niyet kuyruğu bu pencereyi kapatıyor

> **Saldırgan modelleri:** yok — bu bir erişim-kontrolü sınırı değil,
> süreç çökmelerine ve elektrik kesintisine karşı bir veri bütünlüğü/
> dayanıklılık düzeltmesi. Yol boyunca yapılan RBAC değişikliği (aşağıda)
> gerçek bir saldırgan modeli taşıyan tek madde.

**Boşluk.** `CORE/disposal.py::purge_file()` ve `purge_expired_file()` bir
dosyayı KALICI olarak yok ederken iki bağımsız adım atıyor: diskte
`Path.unlink()`, veritabanında `DELETE FROM files WHERE id = ?`. Süreç bu
ikisinin arasında ölürse — elektrik kesintisi, öldürme, çökme —
veritabanı artık diskte olmayan bir dosyayı hâlâ var sanmaya devam eder.
Bunu hiçbir şey yakalamıyordu; o satırın sonraki okuması yalnızca orada
olmayan bir dosyayı açmayı başaramazdı, nedeni hakkında hiçbir kayıt
olmadan.

**Düzeltme: daha büyük bir transaction değil, bir yazarkasa niyet
kuyruğu.** SQLite `unlink()` ile bir `DELETE`'i birlikte atomik yapamaz —
biri dosya sistemi çağrısı, diğeri veritabanı yazısı. Bunun yerine
`disposal_queue` (`DB/migrations.py` Migration 25) niyeti HER İKİ fiziksel
adımdan ÖNCE kaydediyor: `db.execute()` her çağrıda kendi kendine commit
ediyor (`DB/db_manager.py::execute()`), yani satır bir kez eklendi mi
sonrasında ne olursa olsun kalıcı. Sıra şöyle: (1) kuyruk satırını ekle,
(2) dosyayı `unlink()` et, (3) `files` satırını ve kuyruk satırını sil.
(2) ve (3) İKİSİ de idempotent — `unlink()` yalnızca yol hâlâ `exists()`
ise çalışıyor, zaten gitmiş bir satırı silmek etkisiz — yani sürecin TAM
HANGİ komutta öldüğü önemli değil; kalan herhangi bir kuyruk satırı,
(2)/(3)'ün ikisinin de bitmediğini tartışmasız gösteriyor.

`resume_pending_disposals()` açılışta BİR KEZ çağrılıyor, `main.py`'de,
tam da `CORE/safezone.py::purge_orphans()`'ı zaten çağıran bölümün hemen
öncesinde — §4.8'in SafeZone için kurduğu AYNI "normal kapanışta boş
kalır, doluysa önceki oturum çökmüştür" deseni, bu kez artakalan düz metin
yerine kalıcı-silme defterine uygulanmış. Kuyrukta kalan her satır için
(2) ve (3)'ü yeniden oynatıyor ve dosya başına `disposal_resumed`
kaydediyor; tek bir satırın hatası (kilitli dosya, vb.) kalanları
DURDURMUYOR — `CORE/safezone.py::purge()`'ün erken çıkmanın kurtarılabilir
satırları da takılı bırakacağı gerekçesiyle aynı.

**RBAC yan etkisi.** `disposal_queue`, `DB/db_manager.py::
_RBAC_KORUMALI_TABLOLAR`'a `files`'ın yanına eklendi. Bu olmasaydı,
`files`'a doğrudan yazamayan bir Salt Okunur oturumu yine de
`disposal_queue`'ya ham SQL ile bir satır ekleyebilir ve bir sonraki
açılışın o dosyayı kendisi için silmesini sağlayabilirdi —
`_require_approval()`'ı tamamen atlayarak. `resume_pending_disposals()`
ve `purge_expired_file()` içindeki enqueue/dequeue çağrıları
`db.system_write()` altında çalışıyor, `sweep_retention_expired()`'ın
zaten aynı gerekçeyle yaptığı gibi: açılış kurtarması sistem adına
çalışıyor, kimsenin arayüz rolü adına değil. `tests/test_db_manager_rbac.py::
test_salt_okunur_is_verisi_tablolarina_dogrudan_yazamiyor` mevcut
parametrizasyonuna bir `disposal_queue` durumu kazandı, Salt Okunur bir
oturumun `files` için zaten reddedildiği AYNI şekilde reddedildiğini
kanıtlıyor.

**Mutasyon kontrastıyla, iki kez doğrulandı.** `tests/test_disposal.py::
TestYarimKalanImhaKurtarmasi` gerçek bir süreci ortasında öldürmeye
çalışmak yerine (mümkün değil) çökme durumunu doğrudan kuruyor —
temizliği henüz yapılmamış bir `disposal_queue` satırı — ve iki sırayı da
kapsıyor: disk silme zaten bitmiş ama `files` satırı henüz değil
(`unlink()`'ten hemen sonraki çökmeyi taklit ediyor) ve ikisi de HİÇ
bitmemiş (niyet kaydedildikten hemen sonraki çökmeyi taklit ediyor). İki
canlı mutasyon testlerin GERÇEKTEN ayırt ettiğini doğruladı:
`resume_pending_disposals()` içindeki `files` DELETE'i devre dışı
bırakmak altı yeni testten üçünü kırdı, ayrıca diskteki `unlink()`'i
devre dışı bırakmak ikisini kırdı —
`test_birden_fazla_yarim_kalan_islem_tek_turda_tamamlaniyor` dahil, bu
test aynı kuyrukta iki farklı çökme durumundaki iki dosyayı bırakıp
ikisinin de TEK turda temizlendiğini, yalnızca ilk bulunanın değil,
doğruluyor.

**Takip (aynı gün): gerçekten TEK kapı `CORE/disposal.py` mi, ve
kurtarmanın kendisi kesintiye uğrarsa ne olur?** İki ayrı soru, ikisi de
varsayımla değil ölçümle yanıtlandı.

*Yapısal denetim — ikinci bir silme yolu var mı?* `CORE/`, `UI/`, `DB/`
genelindeki HER `.unlink(`/`os.remove(`/`os.unlink(`/`shred_file(` çağrı
yeri listelenip aynı fonksiyon gövdesinde bir `DELETE FROM files` olup
olmadığı kontrol edildi. Görevin isim isim andığı adaylar VARSAYIMLA
değil İNCELEMEYLE elendi: F4-1'in toplu "İmhaya at" işlemi
(`UI/main_window_bulk.py::_on_ctx_bulk_move_to_imha`) yalnızca
`move_to_imha()` çağırıyor, o da diske hiç dokunmuyor (yalnızca etiket/
TTL günceller) — bu zaten bir silme yolu değil. USB kaydı silme akışı
(`CORE/vault_manager.py`) ve `--reset` yeniden-kurulum akışı
(`CORE/setup_usb.py::_do_reset`) ikisi de `.hclv` kasa dosyalarını ve
`usb_tokens` satırlarını siliyor — tamamen farklı bir tablo, yakınlarında
hiçbir `DELETE FROM files` yok. `quarantine` tablosu SQLite'ın kendi `ON
DELETE CASCADE`'i ile temizleniyor (`quarantine.file_id REFERENCES
files(id)`, `DB/db_manager.py::_SCHEMA`), herhangi bir Python silme
koduyla değil. Sonuç tek seferlik bir bulgu olarak değil kalıcı bir
yapısal test olarak bırakıldı: `tests/test_disposal.py::
TestKarantinaTemizligiKorumasi::
test_CORE_UI_DB_genelinde_disposal_queue_atlayan_baska_bir_silme_yolu_yok`
üç dizin altındaki HER fonksiyon tanımını `ast` ile geziyor ve disk-silme
çağrısıyla `DELETE FROM files`'ı aynı gövdede birleştirip `_enqueue(`/
`_dequeue(`'yi ÇAĞIRMAYAN her fonksiyonu işaretliyor — üç meşru fonksiyon
da geçiyor (ikisini de ya da birini çağırıyorlar), ve canlı bir mutasyon
(CORE/ içine yapıştırılan, tam bu birleşimi yapan ama kuyruğa hiç
dokunmayan bir kullan-at fonksiyon) testin gerçek bir bypass VARKEN
kırıldığını, yalnızca hiçbir şey yokken değil, doğruladı. Kapsam testin
kendi docstring'inde açıkça yazıyor: bu bir metin/AST kontrolü, çağrı
grafiği izlemesi değil — iki ayrı fonksiyona bölünmüş bir bypass (biri
unlink çağırır, ayrı biri satırı siler) yakalanmaz. Bugün böyle bir
bölünme yok; bu sınır gizlenmiyor, açıkça yazılıyor. Buradan
`disposal_queue`'ya bağlanacak hiçbir şey çıkmadı, çünkü başka hiçbir şey
bulunmadı.

*`resume_pending_disposals()`'IN KENDİSİ kurtarma ortasında kesilebilir
mi?* Fonksiyonun kendi iddiası — "hangi adımda öldüğü önemli değil" —
yalnızca ORİJİNAL `purge_file()`/`purge_expired_file()` çağrısı için test
edilmişti, kurtarmanın KENDİ tekrar oynatması sırasındaki bir çökme için
hiç değil. İki test üç bekleyen kuyruk satırı kurup ikincisinin işlenmesini
bir `KeyboardInterrupt` ile öldürüyor (bilerek `Exception` değil —
fonksiyonun satır-başına `except Exception`'ı bilinçli bir tasarım, bir
satırın sıradan hatasının kalanları durdurmasını engelliyor; gerçek bir
süreç-seviyesi ölümü kanıtlamak onu AŞAN bir istisna gerektiriyor) İKİ
farklı noktada: `with db.system_write(): db.execute(DELETE...);
_dequeue(...)` bloğunun İÇİNDE (kendi iki ayrı-commit'li ifadesi arasında)
ve disk `unlink()`'in kendisinde (ikisi de çalışmadan ÖNCE). İki nokta
gerçekten farklı ARA durumlar üretiyor, ikisi de "asla kısmen yok
edilmedi" ile tutarlı: DB adımında kesilince ikinci dosyanın disk kopyası
VE `files` satırı ZATEN gitmiş — yalnızca artık kozmetik olan kuyruk
satırı kalıyor, çünkü `db.execute()` her çağrıyı ayrı ayrı commit ediyor
(`DB/db_manager.py::execute()`); disk adımında kesilince ikinci dosya HİÇ
dokunulmamış, sıraya hiç girmemiş üçüncü satırla BİREBİR aynı. İki
durumda da birinci satır (kesintiden ÖNCE işlenmiş) tam tamamlanmış ve
üçüncü (sırası hiç gelmemiş) tamamen dokunulmamış — ve hemen ardından
yapılan ikinci bir `resume_pending_disposals()` çağrısı kalan iki satırı
doğru tamamlıyor, zaten tamamlanmış birinci satır için İKİNCİ bir
`disposal_resumed` denetim kaydı ÜRETMEDEN. İki canlı mutasyon daha
testlerin gerçekten ayırt ettiğini doğruladı: satır-başına yakalayıcıyı
`except Exception`'dan `except BaseException`'a genişletmek (simüle
edilen çökmeyi yutup döngünün YANLIŞLIKLA üçüncü satıra devam etmesine
izin verirdi) ikisini de kırdı, `resume_pending_disposals()` içinde
`_dequeue()`'yu `files` DELETE'inden ÖNCEYE almak özellikle DB-adımı
testini kırdı.

---

### 4.22 Büyük arşivlerde bir tarama zaman aşımı worker havuzunu kilitleyebiliyordu — Python'un kendi `subprocess.run` timeout'unun Windows'ta bir kör noktası var

> **Saldırgan modelleri:** doğrudan yok — bu bir gizlilik/bütünlük sınırı
> değil, kullanılabilirlik/dayanıklılık düzeltmesi (büyük ya da bilerek
> hazırlanmış bir arşivin yükleme hattını yavaşlatması). Bunu tetiklemek
> için tasarlanmış zararlı bir arşiv bir bypass değil bir can sıkıcı olurdu
> (dosyalar "Taranıyor…" durumunda takılı kalırdı) — dosya her hâlükârda
> Karantina'da kalır.

**Boşluk kapalı GÖRÜNÜYORDU ve değildi.** `CORE/scanner_backends.py::
run_tool()` zaten `subprocess.run(argv, timeout=SCAN_TIMEOUT)` (120s)
çağırıyordu — kağıt üzerinde katı bir tavan. CPython'un bu timeout
işleyişinin Windows dalında belgelenmiş bir kör nokta var: `TimeoutExpired`
oluşunca `run()` `process.kill()` çağırıyor, sonra ÖZELLİKLE Windows'ta,
kalan çıktıyı toplamak için İKİNCİ, SINIRSIZ bir `communicate()` daha
yapıyor. Öldürülen süreç stdout/stderr pipe tanıtıcılarını devralan bir alt
süreç doğurmuşsa — `MpCmdRun.exe`'nin büyük bir arşivi taranırken onu açıp
incelemek için bir yardımcı süreç başlatması makul bir ihtimal — ana
süreci öldürmek o tanıtıcıları KAPATMIYOR. Pipe hiç EOF'a ulaşmıyor ve o
ikinci `communicate()` SONSUZA KADAR bekliyor. Katı bir tavan gibi görünen
`timeout=120` parametresi, görevin tam olarak andığı büyük-arşiv durumunda
GERÇEKTEN bir tavan DEĞİLDİ: bir `QThreadPool` işçi yuvası (`UI/main_window.py`
havuzu 6 ile sınırlıyor) sınırsız süre işgal edilebiliyordu — takılan bir
CI adımı için `.github/workflows/ci.yml`'nin kendi `timeout-minutes`
yorumunun tarif ettiği AYNI "sessiz bekleme, hızlı ve görünür bir
başarısızlık yerine" şekli.

**Düzeltme, CI dersini sürecin ÜSTÜNE değil İÇİNE taşıyor.** `run_tool()`
artık `subprocess.Popen`'ı doğrudan sürüyor: zaman aşımında `kill()`
çağırıyor, sonra `wait(timeout=KILL_GRACE)` — ASLA ikinci bir
`communicate()` değil. `wait()` pipe'ların kapanmasına değil sürecin kendi
çıkış durumuna bakıyor, bu yüzden pipe'ı elinde tutan bir torun süreç onu
engelleyemiyor; worker, öldürülen süreç ağacı sonrasında ne yaparsa yapsın
`timeout + KILL_GRACE` içinde serbest kalıyor — kabul edilebilir bedel,
zaten zaman aşımına uğramış bir çalıştırmanın hiçbir işine yaramayacak
çıktıyı okumaktan vazgeçmek.

**Zaman aşımı artık "unknown"a karışmayan ayrı bir verdict.** Bu
değişiklikten önce zaman aşımı ile "antivirüs kurulu değil" AYNI sinyali
üretiyordu (`mock_result()`, `verdict="unknown"`) — hiç kimsenin
tarayamadığı bir dosya, gerçekten erişilemeyen bir dosyayla AYNI
görünüyordu. İki arka uç da artık `subprocess.TimeoutExpired`'da `None`
yerine `timeout_result()` döndürüyor (`verdict="timeout"`, `mock=False` —
gerçek bir deneme yapıldı, yalnızca sonuç bilinmiyor). UI bunu ayırt edici
biçimde gösteriyor: yeni bir rozet (`⏱ Zaman Aşımı`), ve manuel yeniden
tarama yolunda (`UI/main_window_files.py::_on_ctx_scan_done()`) açık bir
uyarı — "tarama zaman aşımına uğradı, manuel inceleme gerekli." Burada
dosya taşımaya gerek yok: "🔍 Tara" eylemi zaten yalnızca Karantina
etiketli satırlarda görünüyor (her yükleme yolu yeni dosyaları varsayılan
olarak Karantina'ya koyuyor — doğrudan kontrol edildi, her
`_handle_dropped_file`/`_handle_dropped_folder` çağrı yeri `label="Karantina"`ı
açıkça geçiyor), yani zaman aşımı dosyayı karantinanın zaten koyduğu
yerde bırakıyor. Toplu yükleme yolu büyük dosya başına bir kutu açmak
yerine bir sayaç topluyor ve bunu mevcut turun-sonu özetinde bildiriyor.

**İki farklı katmanda, iki yolla doğrulandı.** `tests/test_scanner_backends.py`
`run_tool()` düzeltmesini doğrudan kanıtlıyor: sahte bir `Popen`,
`communicate()`'in tam olarak BİR kez çağrıldığını ve `kill()`'den sonra
ikinci bir `communicate()` değil `wait(KILL_GRACE)`'in geldiğini
doğruluyor; gerçek bir alt süreçle (`python -c "time.sleep(30)"`,
`timeout=1`) eşlik eden test tavanın uçtan uca tuttuğunu teyit ediyor.
`tests/test_scan_timeout_worker_pool.py` görevin asıl istediği daha üst
seviye iddiayı kanıtlıyor: gerçek bir `QThreadPool` içinde (2 thread, 3
dosya, biri yapay olarak yavaş), hızlı iki dosya yavaş olan BİTMEDEN
tamamlanıyor, sonra değil — takılı bir tarama havuzu onun ARKASINA
sıralamıyor. Üç canlı mutasyon bunların hepsinin gerçekten yük taşıdığını
doğruladı: tehlikeli ikinci `communicate()`'i geri getirmek `run_tool()`
birim testini kırdı; her simüle taramayı (yalnızca biri değil) eşit
derecede yavaş yapmak worker-havuzu testinin zamanlama iddialarını kırdı;
yeni `elif result.verdict == "timeout"` dalını devre dışı bırakmak UI-mesaj
testlerini kırdı.

**Ayrı, önceden var olan bir hata ortaya çıktı ve bilerek dokunulmadan
bırakıldı.** Worker-havuzu testinin ilk sürümü gerçek `_FileRunnable`'ı
uçtan uca kullanıyordu (şifreleme, DB yazma, tarama) ve aralıklı olarak
kırılgandı — yaklaşık 10 çalıştırmada 1 — `"another row available"`,
`"cannot commit - no transaction is active"` gibi SQLite hatalarıyla; kök
neden `_FileRunnable.run()`'ın DB yazması için TEK bir `sqlite3.Connection`'ı
(`check_same_thread=False`, ama aksi hâlde eşzamanlı erişim için güvenli
DEĞİL) birden fazla GERÇEK `QThreadPool` worker thread'i arasında
paylaşması. `CORE/scanner.py::_save_to_db()` tam bunu önlemek için zaten
her tarama thread'inde kendi bağlantısını açıyor; `_FileRunnable.run()`'ın
kendi `record_encrypted_file()` çağrısı bu deseni TAKİP ETMİYOR. Bu gerçek,
bağımsız bir eşzamanlılık kusuru — testin bir yapaylığı değil — ama
eşzamanlı *dosya ekleme* yazmalarıyla ilgili, tarama zaman aşımıyla değil,
bu yüzden burada kapsam dışı bırakıldı ve DÜZELTİLMEDİ; test yalnızca
`scan_file()` adımını (`_FileRunnable.run()`'ın kendisinin çağırdığı aynı
adım) yalıtacak biçimde yeniden yazıldı, böylece ilgisiz yarış durumuna
artık bağımlı değil. Gelecek bir tur için `BACKLOG.md`'ye not düşüldü.

**Takip (2026-08-30): yukarıdaki `kill()`+`wait()` düzeltmesi HÂLÂ
sızdırıyordu — işletim sistemi tanıtıcısı katmanında kanıtlandı, sonra
düzeltildi.** Yukarıdaki düzeltme worker'ı zamanında serbest bırakıyordu
ama ARKASINDA bir şey kalıp kalmadığını hiç kontrol etmemişti. Kalıyordu:
`stdout=PIPE`/`stderr=PIPE` hâlâ yerindeydi ve CPython'un kendi pipe
okuyucusu, EOF'a kadar `fh.read()`'de bloklanan arka plan bir thread'de
çalışıyor (`Popen._readerthread`). CPython'un kendi kaynak kodu, zaman
aşımında bu thread'leri ya da tanıtıcıları KAPATMADIĞINI açıkça yazıyor —
yorum birebir: "the threads remain reading and the fds left open in case
the user calls communicate again." Bir torun süreç pipe'ın yazma ucunu
miras alırsa (bu bölümün zaten anlattığı, MpCmdRun.exe'nin bir yardımcı
süreç doğurduğu TAM O durum), o okuma asla EOF'a ulaşmıyor ve okuyucu
thread — ve tuttuğu tanıtıcı — asla sonlanmıyor.

**Varsayılmadı, ÖLÇÜLDÜ.** Zaman aşımına uğrayan süreç olarak `cmd /c
"ping -n 9999 127.0.0.1"` kullanan bir yeniden üretim (`cmd.exe`
`run_tool()`'un doğrudan yönettiği ve öldürdüğü çocuk; `ping.exe`
`cmd.exe`'nin stdout/stderr'ini miras alan ve `kill()`'den sağ çıkıp
yetim kalan, pipe'ı elinde tutmaya devam eden bir torun — MpCmdRun.exe'nin
doğurabileceği bir yardımcı süreçle YAPISAL OLARAK aynı) takip-öncesi
`run_tool()` üzerinden art arda 30 zaman aşımı tetikledi ve çağıran süreci
`psutil.Process().num_handles()` / `threading.active_count()` ile ölçtü:
**+153 tanıtıcı, +60 thread — ikisi de tekrar sayısıyla BİREBİR ORANTILI**
(zaman aşımı başına ~5 tanıtıcı + 2 thread), sonrasında beklemeyle de
geri düşmüyor. Geçici bir gecikme değil, gerçek, sınırsız, kalıcı bir
sızıntı.

**"Bariz" düzeltme denendi ve bulgudan DAHA KÖTÜ çıktı.** Doğal bir sonraki
adım — `kill()`+`wait()`'ten HEMEN SONRA `proc.stdout`/`proc.stderr`'i elle
kapatmak (ya da eşdeğer olarak her şeyi `with subprocess.Popen(...) as
proc:` bloğundan geçirmek, çünkü `Popen.__exit__` TAM OLARAK aynı
`.close()` çağrılarını yapıyor) — uygulandı ve AYNI yeniden üretimle
ölçüldü. **İkisi de ÇAĞIRAN THREAD'İ KİLİTLİYOR.** Windows'ta, başka bir
thread'in AYNI handle'da bloklu bir `ReadFile()`'ı sürerken bir pipe
handle'ını kapatmak okuyucuyu serbest BIRAKMIYOR; kapatanı da eşzamanlı
olarak, sonsuza kadar dondurup bekletiyor. Bu gönderilseydi, bir
`QThreadPool` worker'ı büyük-arşiv-ile-yardımcı-süreçli HER taramada
KESİN OLARAK donardı — bu bölümün varlık sebebi olan worker-havuzu
kilitlenmesinin TAM KENDİSİ, artık yalnızca olası değil GARANTİLİ.

**Gerçek düzeltme: pipe'ı hiç kullanma.** CPython yalnızca
`stdout=PIPE`/`stderr=PIPE` verildiğinde bir okuyucu thread başlatıyor.
`run_tool()` artık çocuğun stdout/stderr'ini gerçek geçici dosyalara
yönlendiriyor (`tempfile.mkstemp()`); başarıda dosyalar geri okunup
çözümleniyor, zaman aşımında hiç okunmuyor (zaten gerekmiyor). Pipe
olmadan ne okuyucu thread var ne de bloklanabilecek bir `fh.read()` çağrısı
— dosya tanıtıcısını elinde tutan bir torun süreç, HYCLEUS'un kendi
sürecinde sızdırılacak ya da kilitlenecek hiçbir şey BIRAKMIYOR. Aynı
30-tekrarlık yeniden üretim düzeltilmiş `run_tool()`'a karşı: **toplam +2
tanıtıcı (tekrar başına DEĞİL, tek seferlik bir maliyet), +0 thread,
kilitlenme YOK.**

**Saklanmayan, açıkça yazılan bir artık.** Bir torun süreç temizlik anında
dosyayı hâlâ açık tutuyorsa `os.unlink()` başarısız olur (Windows açık bir
dosyayı silmeye izin vermez) ve dosya diskte kalır — doğrulandı: sızıntı
yeniden üretiminden sonra 60 geçici dosyanın (30 tekrar × stdout+stderr)
HEPSİ kaldı. Bu artık salt disk kalıntısı — HYCLEUS'un kendi sürecinde
canlı bir thread ya da tanıtıcı DEĞİL — bir kaynak sızıntısı değil.
Sonsuza kadar birikmeye bırakılmadı: her `run_tool()` çağrısı, HYCLEUS'un
kendi bir saatten eski kalıntı geçici dosyalarını süpüren en-iyi-çaba bir
taramayla açılıyor (`_eski_gecici_dosyalari_temizle()`) — `SCAN_TIMEOUT +
KILL_GRACE`'in (~125 sn) çok ötesinde bir eşik, bu yüzden hâlâ gerçekten
devam eden bir taramanın dosyasına asla dokunmuyor.

**İşletim sistemi kaynağı katmanında kalıcı bir regresyon testiyle
doğrulandı.** `tests/test_scan_timeout_handle_leak.py` torun-sürecin-
pipe'ı-tuttuğu senaryoyu gerçekten yeniden üretiyor (istenen 50-100
aralığında, CI süresi için 60 tekrar seçildi) ve tanıtıcı/thread
büyümesinin tekrar sayısıyla ORANTILI değil SABİT kaldığını doğruluyor.
Mutasyonla kanıtlandı: `run_tool()`'a `stdout=PIPE`/`communicate()`
desenini geri koyup bu testi yeniden çalıştırmak testi ANINDA kırdı (60
tekrarda 302 tanıtıcı, `302 < 120` doğrulaması yanlış) — gerçekten ayırt
ettiği doğrulandı, sonra geri alınıp yeşile döndüğü teyit edildi.
`tests/test_scanner_backends.py`'nin mevcut `run_tool()` birim testleri
yeni `Popen(stdout=<dosya>, stderr=<dosya>)` + `wait()` biçimine göre
güncellendi (sahte `Popen`'ın artık bir `communicate()` metodu bile yok —
çağrılırsa bir doğrulamanın onu yakalamasını beklemeden doğrudan
`AttributeError` fırlatıyor) ve `Popen`'a geçilen argümanların
`subprocess.PIPE` OLMADIĞINI doğrudan denetleyen yeni bir test eklendi.

**İkinci takip (aynı gün): geçici dosya güvenliği denetimi — üç alan
temiz, biri gerçek boşluk çıktı ve kapatıldı.** `run_tool()`'un stdout/
stderr'ini pipe'tan gerçek geçici dosyalara taşımak (yukarıda) kendi
başına dört yeni soru doğurdu: geçici dosya adı tahmin edilebilir mi,
eşzamanlı taramalar bir adda çakışabilir mi, eski-dosya süpürmesi kendi
içinde yarışabilir mi, dosyayı kim okuyabilir. Dördü de bir düzeltme
yazılmadan ÖNCE, varsayımla değil kanıtla incelendi.

1. *Oluşturma API'si — risk yok.* `tempfile.mkstemp()`
   (`CORE/scanner_backends.py`, dosya açılmadan hemen önceki iki çağrı)
   `O_CREAT | O_EXCL` ile açıyor — Windows'ta bu `CreateFile(...,
   CREATE_NEW, ...)`'e karşılık geliyor, hedefte HERHANGİ bir şey (dosya,
   dizin, reparse point) zaten varsa atomik olarak başarısız oluyor, adın
   kendisi de işlem başına bir kez `os.urandom`'dan tohumlanan bir
   `random.Random()`'dan çekilen 8 rastgele karakter. Yerel bir sürecin
   tahmin edilen bir adda önceden dosya/symlink hazırlaması `run_tool()`'u
   onu açmaya ZORLAYAMIYOR: oluşturma doğrudan başarısız oluyor,
   `mkstemp()` yeni bir rastgele adla tekrar deniyor.

2. *Eşzamanlılık — risk yok, ölçüldü.* Gerçek bir `QThreadPool`
   (`maxThreadCount=20`) üzerinde 20 gerçek `run_tool()` çağrısı paralel
   çalıştırıldı, `tempfile.mkstemp()` (yalnızca gözlem için, kaynak
   değiştirilmeden) sarmalanıp üretilen her ad kaydedildi: 40 ad (20
   çağrı × stdout+stderr), **40'ı da benzersiz, sıfır çakışma** — (1)'deki
   `O_EXCL` atomikliğinin doğrudan ampirik sonucu.

3. *Süpürme yarış durumu — risk yok, zorlanıp ölçüldü.* `_eski_gecici_
   dosyalari_temizle()`'nin `unlink()`'i zaten `except OSError: pass`
   içindeydi (`FileNotFoundError` bir `OSError` alt sınıfı), yani ikinci
   bir thread'in zaten silinmiş bir dosyayı silme yarışını kaybetmesi
   halihazırda sessizce yutulmalıydı. Varsayıma güvenmek yerine
   zorlandı: gerçek bir dosyanın mtime'ı `os.utime()` ile 1 saatlik
   eşiğin ötesine geri tarihlendi, sonra **12 thread `threading.Barrier`
   ile GERÇEK, değiştirilmemiş süpürme fonksiyonunu TAM AYNI ANDA**
   çağırdı (12'si de kodu aynı anda vurdu). Sonuç: sıfır exception
   dışarı sızdı, dosya tam olarak bir kez silindi.

4. *Dosya izinleri — gerçek boşluk, bulundu ve kapatıldı.* `os.open(...,
   mode=0o600)` Windows'ta gerçek bir ACL'e ÇEVRİLMİYOR (CPython'un kendi
   belgelediği davranış: Windows'ta mode argümanı yalnızca salt-okunur DOS
   bayrağını etkileyebilir). O ana kadarki kodun oluşturduğu dosya, ebeveyn
   `%TEMP%` dizininin ACL'ini olduğu gibi devralıyordu — gerçek bir dosya
   oluşturup ACL'i okuyarak doğrulandı: mevcut kullanıcı, `SYSTEM` ve
   `Administrators`'ın yanında bir grup (ölçülen ortamda
   `CodexSandboxUsers`) ve çözülmemiş bir SID de `Modify` hakkına sahipti
   — "yalnızca çalıştıran kullanıcı okuyabilir" varsayımının kod
   tarafından GARANTİ EDİLMEDİĞİNİ, bir ortam varsayımı olduğunu somut
   olarak gösterdi. Paylaşımlı ya da terminal-server tarzı bir makinede,
   ya da `%TEMP%`'in ACL'i politika ile genişletilmiş herhangi bir yerde,
   başka bir yerel hesap tarama çıktısını — dosya yolu, ClamAV imza adı,
   verdict metni — okuyabilirdi.

**Düzeltildi: açık, kalıtımsız bir DACL — `%TEMP%`'inkine GÜVENMİYOR.**
`_gecici_dosyayi_kullaniciya_kisitla()` her geçici dosya oluşturulduktan
(hem stdout hem stderr) hemen sonra çalışıyor ve Windows'ta DACL'i tam
olarak iki girişle değiştiriyor — mevcut süreç token'ının kullanıcı SID'i
ve `SYSTEM` — `win32security.SetFileSecurity(...,
DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, ...)`
ile. Kalıtımı GERÇEKTEN kesen `PROTECTED_DACL_SECURITY_INFORMATION` —
onsuz Windows yeni ACE'leri ebeveynin ACE'leriyle sessizce birleştirirdi.
Denetimle AYNI ölçüm yöntemiyle gerçek bir dosya üzerinde doğrulandı:
`win32security.GetFileSecurity()` sonrasında tam olarak `{mevcut kullanıcı,
SYSTEM}` bildiriyor — `icacls` ile de bağımsız olarak teyit edildi, ve
önceden mevcut grup/çözülmemiş-SID girişleri artık YOK. Küçük, saklanmayan
bir kalan pencere var: dosya `mkstemp()`'in oluşturmasıyla bu çağrı
arasında birkaç mikrosaniye boyunca hâlâ geniş kalıtılan ACL'i taşıyor —
bunu tamamen kapatmak `mkstemp()`'in kendi atomik benzersiz-ad döngüsünü
`CreateFile`'a oluşturma anında verilen bir güvenlik tanımlayıcısıyla elle
yeniden yazmak anlamına gelirdi, bu değişikliğin kapsamı dışında. `pywin32`
yeni bir bağımlılık değil — `requirements.txt` Windows'ta `wmi` üzerinden
onu zaten dolaylı olarak zorunlu kılıyor, ve `CORE/secret_store.py` ile
`CORE/hwid_probe.py` burada kullanılan AYNI tembel, platforma-kapılı
`import win32...` desenini zaten kullanıyor. Bu modülün geri kalan
temizlik mantığı gibi BEST EFFORT: `SetFileSecurity` herhangi bir nedenle
başarısız olursa bir uyarı loglanır ve tarama dosyanın ORİJİNAL (bu
değişiklikten ÖNCEKİ) kalıtılan ACL'iyle devam eder — bir gerileme değil,
önceki davranışın aynısı.

**İki yolla doğrulandı.** `tests/test_scan_timeout_dacl.py`: bir birim
testi gerçek bir dosya oluşturup kısıtlıyor ve gerçek sorgulanan DACL'in
tam olarak `{mevcut kullanıcı, SYSTEM}` olduğunu doğruluyor; bir
entegrasyon testi `_gecici_dosyayi_kullaniciya_kisitla`'yı gözetleyip
`run_tool()`'un onu her iki geçici dosya için de GERÇEKTEN çağırdığını
kanıtlıyor (birim testi TEK BAŞINA, yardımcı fonksiyonu doğrudan çağırdığı
için, çağrının `run_tool()`'dan düşmesini yakalayamaz); üçüncüsü bir
`SetFileSecurity` başarısızlığının taramayı bozmadığını doğruluyor.
Mutasyonla kanıtlandı: `run_tool()`'daki iki çağrı geçici olarak
yorum satırına alındı — entegrasyon testi ANINDA kırıldı (2 yerine 0 çağrı
kaydedildi) — gerçekten ayırt ettiği doğrulandı, sonra geri alınıp yeşile
döndüğü teyit edildi.

---

### 4.23 Profil sayfası tek bir cihaz gösteriyor, cihaz listesi değil — bir şema kısıtlaması, bir UI eksikliği değil

> **Saldırgan modelleri:** yok — bu bölüm Profil sayfasının "Cihazlar ve
> oturum" bölümü inşa edilirken bulunan bir tasarım kısıtlamasını
> belgeliyor, bir zafiyeti değil.

**Mockup çoklu cihaz listesi ima ediyordu; şema buna izin vermiyor.**
`UI/ProfileView.py`'nin "Cihazlar ve oturum" bölümü, hesap başına kayıtlı
USB cihazlarının bir listesini gösteren bir mockup'a karşı inşa edildi.
Yazmadan ÖNCE gerçek veri modeli varsayılmadı, İNCELENDİ: `users.hwid`
kısmi bir `UNIQUE` indeks taşıyor (`DB/migrations.py::
_m23_users_hwid_unique`, B-060) — bir HYCLEUS hesabı en fazla BİR HWID'e
bağlanabilir, nokta. Bu bir gözden kaçırma değil; B-060 aynı fiziksel USB
token'ının birden fazla hesap olarak kimlik doğrulayabildiği, bir kimliğin
diğerinin yetkisini gasp edebildiği gerçek bir açığı kapattı. O
kısıtlamayı bir cihaz listesi desteklemek için geri almak, B-060'ın
kapattığı deliği TAM OLARAK yeniden açmak anlamına gelirdi.

**Sessizce yeniden yorumlanmadı, açık bir karara bağlandı.** Soru
tahmin edilmek yerine kullanıcıya geri soruldu ve cevap şu oldu:
bölüm bugünün gerçek 1-hesap-1-cihaz modeline karşı inşa edilsin (tek bir
satır gösteriyor — hesabın kendi token'ı, şu an takılı olan cihaz olup
olmadığı, kayıt tarihi, kara liste durumu — `CORE/usb_tokens.py::
token_kayitlarini_getir()` ile, `UI/AdminPanel.py`'nin filo-geneli USB
Yönetimi sekmesinin kullandığı TAM OLARAK AYNI sorgu, yalnızca `hwid=`
filtresiyle daraltılmış, böylece iki görünüm ASLA ayrışamaz) — şemanın
gerçekte dolduramayacağı çok satırlı bir UI inşa etmek yerine, ve
mockup'ı gerçek kılmak için B-060'ı sessizce gevşetmek yerine. Gerçek bir
çoklu cihaz modeli, gerçekten isteniyorsa, ayrı ve bilinçli bir mimari
karardır — kendi backlog maddesi olarak izleniyor (`BACKLOG.md` B-082),
bir UI taşımasının yan etkisi olarak sızdırılmadı.

**Filo-geneli görünüme karşı doğrulandı, yalnızca izole birim test
edilmedi.** `tests/test_profile_view.py` hem `AdminPanel`'i hem
`ProfileView`'ı AYNI tohumlanmış `usb_tokens` satırına karşı kurup
gösterdikleri hücrelerin uyuştuğunu doğruluyor, sonra FARKLI bir hesap
için ikinci, ilgisiz bir token ekleyip `hwid=` filtresinin onu GERÇEKTEN
dışarıda bıraktığını doğruluyor (o ikinci satır olmadan, bozuk bir filtre
ile çalışan bir filtre TESADÜFEN aynı şekilli sonucu döndürürdü — test
her iki durumda da geçerdi). Mutasyonla kanıtlandı:
`token_kayitlarini_getir()`'deki filtre devre dışı bırakılınca satır
sayısı denetimi ANINDA kırıldı (1 yerine 2 satır gösterildi); geri
alınıp tekrar yeşile döndüğü teyit edildi.

---

### 4.24 USB Yönetimi modalı üç kalıcı sayfaya bölündü — koşulsuz kurulan kenar çubuğu deseni, daha önce hiç gerekmemiş bir rol kontrolü gerektirdi

> **Saldırgan modelleri:** (a) yönetici olmayan bir oturumun, sayfa artık
> pencere kurulumunda KOŞULSUZ inşa edildiği için yalnızca bu yüzden
> yönetici-yalnız bir sayfanın yazma eylemlerine canlı bir Python
> referansı elde etmesi — eski modal, bir yönetici onu AÇMADAN önce
> zaten HİÇ var olmuyordu; (b) üç sayfadan biri görünürken bir
> yöneticinin oturumunun düşürülmesi ya da USB'sinin çekilmesi — eski
> modalin kendi özel yoklama döngüsü bunu izleyen TEK şeydi.

**Bölünme.** `UI/AdminPanel.py` (üç `QTabWidget` sekmesi taşıyan tek bir
application-modal `QDialog`: USB Tokenlar, Bekleyen Kayıtlar, Ayarlar)
kaldırıldı ve `_govde_yigini`'nde (`GuvenlikView`/`AuditLogView`/
`ProfileView` ile AYNI `QStackedWidget` deseni) her biri kendi kenar
çubuğu giriş noktasına sahip üç ayrı tam sayfayla değiştirildi:
`UI/UsbTokensView.py`, `UI/PendingRegistrationsView.py`,
`UI/AdminSettingsView.py`. Paylaşılan stil yardımcıları ve canlı yetki
denetimi yeni `UI/admin_common.py`'de yaşıyor. Veri modeline
dokunulmadı — turu başlatan kapsam talimatına uygun olarak yalnızca bir
navigasyon/layout değişikliğiydi.

**Gereksiz hâle gelen bir savunma, ve gelmeyen bir tanesi.** Eski
`AdminPanel` kendi 3 saniyelik `QTimer`'ını çalıştırıp DB yetkisini
yeniden kontrol ediyor, bir uyarı şeridi gösterip sekmelerini devre dışı
bırakıyordu — çünkü application-modal, üst seviye bir pencereydi ve ana
pencerenin kendi `_lock()`/`_poll_usb()`'si (B-064/B-066) ona hiçbir
şekilde ulaşamıyordu. Üç sayfa artık `centralWidget()`'ın İÇİNDE
yaşadığına göre bu erişilemezlik boşluğu ortadan kalktı —
`_lock()`'un `centralWidget().setEnabled(False)`'ı zaten onları
kapsıyor, bu yüzden gereksiz zamanlayıcı ve şerit üç dosyaya
üçlenmek yerine SİLİNDİ. Ortadan KALKMAYAN şey: `centralWidget().
setEnabled(False)` yalnızca fare/klavye olay iletimini engelliyor,
doğrudan bir Python metot çağrısına (bir test, bir hata ya da sayfaya
referans tutan gelecekteki bir kod tarafından çağrılan
`sayfa._on_approve()`) hiçbir şey yapmıyor. Eski panelin her-eylem-
öncesi yeniden doğrulamasının ASIL garantisi zaten HEP buydu ve
modal/gömülü ayrımından BAĞIMSIZDI — bu yüzden `UI.admin_common.
yonetici_hala_yetkili()` her yetkili eylemden (onayla/reddet/kara
listeye al/rol değiştir/sil/ayarları kaydet/güvenilir kök ekle-kaldır/
kurtarma parçası dışa aktar) HEMEN ÖNCE `oturum_yetkisi_gecerli_mi()`'yi
yeniden kontrol etmeye devam ediyor — `AdminPanel._yonetici_hala_
yetkili()`'nin yaptığının BİREBİR AYNISI.

**Gömülmenin kendisinin açtığı bir boşluk, sevkiyattan ÖNCE kapatıldı.**
Eski `AdminPanel`, `is_admin_role(role)` geçtikten modal kapanana kadar
geçen sürede canlı bir nesne olarak var oluyordu — yönetici olmayan bir
oturumun `HycleusWindow`'u ona hiçbir zaman bir referans TUTMUYORDU.
Yeni üç sayfa artık pencere kurulumunda KOŞULSUZ inşa ediliyor
(`GuvenlikView`/`AuditLogView`/`ProfileView`'ın zaten kullandığı AYNI
desen), yani yönetici olmayan bir oturumun penceresi artık `window.
_pending_view`, `window._usb_tokens_view`, `window._admin_settings_view`'ı
CANLI nesneler olarak tutuyor — kenar çubuğu düğmesi ya da `_on_open_*`
giriş noktası rol kapısı gizli/engelli olsa bile doğrudan metot
çağrısıyla erişilebilir. `oturum_yetkisi_gecerli_mi()` TEK BAŞINA bu
boşluğu KAPATMIYOR: yalnızca DB rolünün oturumun BAŞLADIĞI rolden
SAPIP SAPMADIĞINA bakıyor, yani başından beri geçerli biçimde yönetici
olmayan bir oturum bu kontrolden GEÇERDİ. `yonetici_hala_yetkili()` bu
yüzden ÖNCE `is_admin_role(pencere._role)`'u kontrol edecek şekilde
yazıldı, sapma kontrolü hiç çalışmadan KAPALI başarısız oluyor — eski
modalin salt HENÜZ VAR OLMAYARAK bedavaya kazandığı sınırı, nesne/metot
seviyesinde yeniden kuruyor.

**Başarısızlık yolu ŞEKİL değiştirdi, GÜÇ değil.** Kendi denetimini
geçemeyen bir modal kendini `reject()` ile kapatabilir. Ana pencereye
gömülü bir sayfa anlamlı biçimde "kapanamaz" — bu yüzden başarısız bir
denetim artık `pencere._lock("revoked")` çağırıyor, `_poll_usb()`'nin
AYNI durum için ZATEN kullandığı mekanizmanın TAM OLARAK aynısı, özel
bir diyalog-kapatma yolu değil.

**Kanıtlandı, iddia edilmedi.** B-064 regresyon testleri
(`tests/test_authz_invariants.py::
test_b064_bekleyen_kayitlar_usb_cikinca_onayi_reddediyor` ve mutasyon-
kontrastlı kardeşi) standalone bir `AdminPanel` kurmaktan, minimal sahte
bir pencereye karşı `PendingRegistrationsView` kurup denetim
başarısızlığından sonra `pencere._locked is True` / `"revoked" in
pencere._lock_reasons` doğrulamaya taşındı — mutasyon-kontrastlı test,
`yonetici_hala_yetkili` her zaman `True` dönecek şekilde
monkeypatch'lendiğinde AYNI senaryonun BAŞARILI olduğunu doğrulayarak
denetimin gerçekten yük taşıdığını, boş bir iddia olmadığını kanıtlıyor.

**"Koşulsuz kurulmanın" bir sonucu daha: bayat renkler.** Üç sayfa
kendi stylesheet'ini (`AdminPanel`'in özgün yaklaşımıyla AYNI biçimde)
doğrudan `pencere._T`'den kuruyor — `GuvenlikView`/`AuditLogView`/
`ProfileView`'ın kullandığı nesne-adı QSS cascade'inden DEĞİL, kasıtlı
olarak öyle bırakıldı, bir B-055 ihlali görmezden gelinmedi: üç
karmaşık, semantik olarak duruma bağlı (danger/success buton
varyantları) ekranı merkezî QSS'e taşımak, navigasyon-yalnızca bir tur
için kapsam dışıydı. Ama `AdminPanel`'in modal olması, her açılışta O
ANKİ temayla TAZE kurulduğu anlamına geliyordu; kalıcı bir sayfa için bu
geçerli değil. Tema seçici artık (eskiden modalin bunu ENGELLEDİĞİNİN
aksine) her sayfadan hamburger menüsüyle erişilebilir olduğundan, bu üç
sayfadan biri görünürken tema değişirse, bir sonraki gezinmeye kadar
bayat renklerde kalırdı. `AuditLogView`'ın kendi elle boyanan sütunları
için ZATEN kullandığı AYNI mekanizmayla kapatıldı: `UI/
main_window_theme.py::_refresh_after_theme_change()` artık her admin
sayfasının `_restyle()`'ını da çağırıyor.

**Bir takip denetimi, rol kapısı hiç çalışmadan bir sorgu atan bir sayfa
buldu — varsayılmadı, ÖLÇÜLDÜ.** "Koşulsuz kurulma" yönetici olmayan bir
oturumun penceresi için de `__init__`'in çalıştığı anlamına geliyor,
yani `is_admin_role()`'un `__init__`/ilk veri yüküne göre TAM OLARAK
NEREDE durduğu sorusu retorik değildi — gerçek kurucu kod OKUNARAK
sayfa başına kontrol edildi, desenden çıkarım yapılmadı.
`UsbTokensView`/`PendingRegistrationsView` `__init__`'te yalnızca BOŞ
widget'lar kuruyor (`_make_table`/`_make_pending_table`) ve her sorguyu
`.yenile()`'ye erteliyor, ki üretim onu YALNIZCA rol-kapılı
`main_window.py::_on_open_usb_tokens`/`_on_open_pending`'ten çağırıyor.
`AdminSettingsView` bu deseni İZLEMİYORDU: `__init__`'i
`_load_settings()`'i (`DBManager.get_setting`/`get_idle_timeout_minutes`/
`get_app_mode`) ve `_tsa_kok_bloku()` üzerinden `_tsa_yukle()`'yi
(`CORE.trusted_roots.oku()`) KOŞULSUZ çağırıyordu — yönetici olsun
olmasın HER pencere için, `_on_open_admin_settings()`'in rol kontrolü
hiç çalışma fırsatı bulmadan ÖNCE. Burada gizli-sınıf bir veri yok
(genel uygulama ayarları, herkese açık bir güven-çıpası listesi) ama
yine de sorulan TAM OLARAK o kusur sınıfıydı: bir sorgu kapıdan ÖNCE
gerçekten çalışıyor, yalnızca GÖRÜNTÜLEME esirgeniyordu. İkisi de
`__init__`/`_build_ui()`'dan kaldırılarak düzeltildi (liste widget'ı ve
silme düğmesi artık başlangıç/devre-dışı durumlarına, artık orada
çalışmayan bir yükten değil, AÇIKÇA kondu) — `.yenile()` ikisini de
ZATEN çağırıyordu, yani üretimde (kapılı) gerçek görüntülenme anındaki
davranış DEĞİŞMEDİ. Mutasyonla kanıtlandı: düzeltme geçici olarak geri
alınıp `tests/test_admin_pages_construction_guard.py::
test_admin_settings_view_ADMIN_OLMAYAN_pencerede_construction_sirasinda_
sorgu_atmiyor` yeniden çalıştırıldığında TAM OLARAK aynı başarısızlık
tekrar üretildi (`_mode_combo`, `"Standart"` — yönetici olmayan — bir
pencerede construction'dan HEMEN sonra DB'nin gerçek `BIREYSEL`
değerini gösteriyordu); geri alınıp tekrar yeşile döndüğü teyit edildi.

**`is_admin_role()`, DB yazma katmanının RBAC kapısıyla YEDEKLİ (redundant)
değil — iddia edilmedi, KANITLANDI.** `DBManager.execute()`'un
`_yazma_yetkisini_dogrula()`'sı (B-074) yazmayı yalnızca
`can_write(role) is False` için reddediyor, yani yalnızca `"Salt
Okunur"` — ve `can_write("Standart")` `True` (`tests/test_roles.py`'de
ZATEN kurulu bir gerçek). "Standart" bir oturum bu yüzden DB katmanının
KENDİ kapısının yazmayı hiç DURDURMAYACAĞI bir rol; aynı zamanda
yönetici de değil. `tests/test_admin_pages_construction_guard.py`
gerçek bir `"Standart"` rollü `HycleusWindow` kuruyor, (yukarıdaki
paragrafa göre) ZATEN inşa edilmiş `_usb_tokens_view`/`_pending_view`/
`_admin_settings_view`'ına DOĞRUDAN ulaşıyor — `_on_open_*()`'i HİÇ
çağırmadan — ve her birinde bir yetkili eylemi (`_on_toggle_blacklist`,
`_on_approve`, `_on_save_settings`) hiçbir UI etkileşimi OLMADAN
çağırıyor. Her biri reddediliyor ve pencere kilitleniyor (`"revoked"`)
— bundan yalnızca `UI.admin_common.yonetici_hala_yetkili()`'nin KENDİ
`is_admin_role(pencere._role)` kontrolü sorumlu olabilir, çünkü DB
katmanı yazmanın devam etmesine İZİN VERİRDİ. Eylem-ailesi başına
mutasyonla kanıtlandı: `yonetici_hala_yetkili`'yi her zaman `True`
dönecek şekilde monkeypatch'lemek AYNI `"Standart"`-rollü çağrının
geçmesine izin veriyor ve DB satırı GERÇEKTEN değişiyor.

**Sayfa açıkken düşürülen rol penceresi — varsayılmadı, ÖLÇÜLDÜ.**
`AdminPanel`'in kendi yoklama döngüsünü kaldırmak (yukarıda) doğal bir
soru doğurdu: bir oturumun rolü BAŞKA bir yerden (ikinci bir yönetici
oturumu, USB HİÇ çekilmeden) düşürülürse, üç sayfadan biri açıkken,
sayfa başka bir şey fark edene kadar eski yetkiyle çalışmaya devam mı
ediyor? Bu turdan önce de doğru olan ve DOĞRU KALAN iki şey var: (1)
`main_window.py`'nin kendi `_poll_usb()`'si (B-066, bu çalışmayla
DEĞİŞTİRİLMEDİ) hangi sayfa görünürse görünsün `oturum_yetkisi_
gecerli_mi()`'yi her 3 saniyede bir yokluyor ve bir uyuşmazlıkta TÜM
`centralWidget()`'ı — o an görünen üç admin sayfasından hangisi olursa
olsun DAHİL — kilitliyor; (2) üç sayfadaki HER yetkili handler
`yonetici_hala_yetkili()`'yi çağırıyor, ki bu da YAZMADAN HEMEN ÖNCE
kendi taze `oturum_yetkisi_gecerli_mi()` çağrısını EŞ ZAMANLI (senkron)
yapıyor. İkisi BİRBİRİNDEN BAĞIMSIZ: `_poll_usb()` bir düşüşten sonra
arayüzün en fazla ~3 saniye "etkileşimli GÖRÜNMESİNİ" sınırlıyor, ama
"Onayla"/"Reddet"/"Kara Listeye Al"/"Kaydet" düğmesine bir tıklama
girişte `pencere._role`'ün değerine karşı değil, TIKLAMA ANINDA
veritabanına karşı yeniden doğrulanıyor — yani asıl yazma-anı maruziyet
penceresi "en fazla 3 saniye" DEĞİL, tıklama ile guard'ın kendi sorgusu
arasındaki fark, ki bu da FİİLEN sıfır. `tests/
test_admin_pages_construction_guard.py::
test_sayfa_guard_rol_dusurulunce_usb_takiliyken_de_reddediyor` bu daha
DAR iddiayı doğrudan kanıtlıyor: canlı bir yönetici oturumunun DB
rolünü USB HİÇ çıkarılmadan ve `_poll_usb()` HİÇ çağrılmadan `'user'`e
düşürüyor, sonra ZATEN açık olan sayfada doğrudan
`PendingRegistrationsView._on_approve()`'u çağırıyor — reddediliyor,
pencere kilitleniyor. Mutasyon-kontrastlı kardeşi, AYNI senaryonun
`yonetici_hala_yetkili` atlatıldığında BAŞARILI olduğunu doğrulayarak
denetimin `_poll_usb()`'nin tesadüfen önce yakalamasını değil, guard'ın
KENDİSİNİ ölçtüğünü gösteriyor.

**Takip: `.yenile()`'nin kendisi doğrudan çağrılsa GERÇEKTEN güvenli mi —
kontrol edildi, VARSAYILMADI.** Burada daha önce duran paragraf bu
asimetrinin "kasıtlı, bir gözden kaçırma değil" olduğunu, hiç DENEMEDEN
iddia ediyordu. Ayrılmış bir denetim bunu YAPTI: `.yenile()`'nin
`UI/`, `CORE/`, `DB/`, `main.py` genelindeki HER çağrı yeri sayıldı
(`grep -rn "\.yenile()"`) ve her biri izlendi. Sonuç — `.yenile()`'nin
TAM OLARAK üç çağrı yeri var, hepsi `main_window.py`'de, sayfa başına
bir tane (`_on_open_usb_tokens:430`, `_on_open_pending:442`,
`_on_open_admin_settings:454`), her biri kendi fonksiyonunun SON
ifadesi, o AYNI fonksiyonun kendi `is_admin_role(self._role)`
kontrolünden HEMEN sonra, başarısızlıkta koşulsuz erken `return` ile —
kontrol ile çağrı arasına bir rol değişikliğinin sığabileceği hiçbir
dal, ertelenmiş callback ya da boşluk yok. Hiçbir `QTimer`, sinyal/slot
bağlantısı YOK, ve hiçbir "Yenile" düğmesi de `.yenile()`'ye
ULAŞMIYOR (yenile düğmeleri `.yenile()` değil, doğrudan daha DAR
`_load()`/`_load_pending()`'i çağırıyor — yani `.yenile()`'nin TEK işi
sayfa-açma yolu). `_refresh_after_theme_change()`'in sayfa başına
çağrısı `_restyle()`'a — ayrı, DB'siz olduğu doğrulanmış bir metoda
(yalnızca stil çağrıları) — `.yenile()`'ye DEĞİL.

**Ama `.yenile()`'nin KENDİ kontrolü yoktu — doğrudan örnekleme bunu
KANITLADI, varsaymadı.** Giriş noktalarını izlemek "'.yenile()' başka
bir yoldan çağrılsa güvenlidir" iddiasıyla AYNI şey değil, ve bu
GERÇEKTEN denendi: gerçek bir `"Standart"` rollü (yönetici olmayan)
`HycleusWindow` kuruldu, ZATEN var olan `_usb_tokens_view`/
`_pending_view`/`_admin_settings_view`'ına DOĞRUDAN ulaşıldı ve
`main_window.py::_on_open_*()` HİÇ çağrılmadan her birinde `.yenile()`
çağrıldı. Düzeltmeden ÖNCE, bu üç sayfanın da tablosunu/combo'sunu/
listesini GERÇEKTEN sorgulayıp dolduruyordu — `.yenile()`'nin kendi
`is_admin_role()` kontrolü YOKTU, yalnızca YETKİLİ (yazan) handler'lar
taşıyordu. **Düzeltildi:** `UI.admin_common.sayfa_erisimi_var_mi()` —
erken-dönüşlü bir `is_admin_role(pencere._role)` kontrolü,
`yonetici_hala_yetkili()`'den KASITLI olarak daha hafif (canlı
`oturum_yetkisi_gecerli_mi()` gidiş-dönüşü YOK; bu bir OKUMAYI koruyor,
YAZMAYI değil, canlı rol düşüşü zaten `yonetici_hala_yetkili()`'nin ve
`_poll_usb()`'nin işi) — artık üç `.yenile()` metodunun da BAŞINDA.
`tests/test_admin_pages_construction_guard.py`'de İKİ YÖNDE de
mutasyonla kanıtlandı: AYNI doğrudan-çağrı senaryosu düzeltmeden ÖNCE
kırmızı yakalandı (`git stash`'le geçici olarak geri alınıp yeniden
koşturuldu, geri getirildi), ve bir eşlik eden test,
`sayfa_erisimi_var_mi`'yi her zaman `True` dönecek şekilde
monkeypatch'lemenin AYNI `"Standart"`-rollü doğrudan çağrının tabloyu
YENİDEN doldurmasına izin verdiğini doğrulayarak, engelleyenin
BAŞKA bir şey değil, guard'ın KENDİSİ olduğunu kanıtlıyor.

---

### 4.25 Denetim günlüğü dışa aktarımı bir formattan üçe çıktı — ve PDF, RFC 3161 mührünü BİLEREK durdu

> **Saldırgan modelleri:** yok — bu bölüm dışa aktarım seçenekleri
> kurulurken verilen bir kapsam kararını belgeliyor, bir zafiyeti değil.

**Mockup üç format istedi; biri zaten vardı.** `UI/AuditLogView.py`'de
tek bir "Düz Metin (TXT)" dışa aktarımı vardı. Bu tur onun yanına "Tablo"
(CSV) ve "İmzalı Rapor" (PDF) ekledi — mockup güdümlü, bir güvenlik
düzeltmesi değil. Üçü de artık TAM OLARAK AYNI `_load()`-filtrelenmiş
satır kümesinden (o an UI'da uygulanan tarih aralığı, işlem ve sekme
filtreleri) okuyor, ikinci, bağımsız filtrelenmiş bir sorgu yolu AÇMADAN:
eski TXT dışa aktarımı zaten render edilmiş tabloyu okuyor, yeni
formatlar ise `_load()`'un ARTIK AYNI sorgudan kurduğu paralel, render
edilmemiş bir `DenetimSatiri` listesini okuyor — tek getirme, üç
render'layıcı, üç getirme DEĞİL.

**RFC 3161 sorusu, miras alınmadı, KARARA BAĞLANDI.** "İmzalı Rapor" adı
ve bu belgede zaten duran resmi olmayan K4-20/F2-2 referansları (§4.16)
AYNI açık soruya işaret ediyor: "imzalı" PDF'in zincirin KENDİ
kriptografik kanıtını taşıması mı, yoksa PDF DOSYASININ KENDİSİNİN
(dosya içeriklerinin zaten sahip olduğu gibi, `UI/TimestampDialog.py`)
dış bir RFC 3161 otoritesi tarafından zaman damgalanması mı? Bu tur
İLKİNİ inşa etti ve İKİNCİSİNİ AÇIKÇA ertelendi — kendi maddesi olarak
izleniyor, `BACKLOG.md` B-087, sessizce "sonraya" içine katlanmadı. PDF,
mühürlenmiş GİBİ davranan bir yer tutucu DEĞİL: `zincir_raporu()`'nun
TAM sonucunu (zincir bütünlüğü, varsa ilk kırılma, VE görevin istediği
dış çıpa karşılaştırması) belge gövdesine DOĞRUDAN gömüyor, yani okuyan
kişi dosyanın anlattığı zincirin dışa aktarım anında sağlam olup
olmadığını görmek için ayrı bir komut çalıştırmak ZORUNDA değil. YAPMADIĞI
şey — PDF dosyasının KENDİSİNİN o andan sonra değiştirilmediğini
kanıtlamak — ve bunu, `txt_basligi()`'nin AYNI kısıtlama için zaten
kullandığı AYNI üslupla ("bu dosya imzalı DEĞİLDİR") SÖYLÜYOR: zincir-
durumu paragrafının HEMEN altında, bir dipnotta gömülü değil, dışa
aktarımın RFC 3161 zaman damgasıyla mühürlenmediğini söyleyen kalın bir
satır.

**Neden CSV, XLSX değil.** Görev "CSV/XLSX"i Tablo formatı için BİRLİKTE
listeledi. CSV seçildi, XLSX seçilmedi: `CORE/inventory.py::
export_inventory_csv()` zaten `utf-8-sig`i (BOM önekli UTF-8) bu
kod tabanının "Excel bu dosyayı Türkçe karakterleri bozmadan doğru
açmalı" sorusuna cevabı olarak kurmuştu, ve CSV aynı zamanda bir SIEM'in
FİİLEN aldığı format — gerçek bir `.xlsx` yazıcısı, isimlendirilen İKİ
tüketicinin de (Excel, SIEM) CSV'ye göre ÖZEL OLARAK ihtiyaç duymadığı
bir format için yeni bir bağımlılık (`openpyxl` ya da eşdeğeri) demek
olurdu.

**Tablo dışa aktarımı TXT'ninkinin KASITLI OLARAK daha zengini, yalnızca
yeniden biçimlendirilmiş hâli DEĞİL.** UI tablosu HWID'leri 16 karaktere
kırpıyor ve zaman damgalarını okunabilirlik için biçimlendiriyor — ekran
için makul, bir SIEM'in ayrıştıracağı dosya için YANLIŞ. `DenetimSatiri`
(iki yeni dışa aktarıcının da PAYLAŞTIĞI satır tipi) kırpılmamış HWID'i,
ham ISO zaman damgasını, ham action dizesini ve TAM `detail` alanını
taşıyor — GERÇEKTEN ayrık sütunlar, UI'nin beş görüntü sütunu arasına
virgül koymak DEĞİL. Doğrudan doğrulandı: 30 karakterlik sentetik bir
HWID'in UI tablosunda üç nokta ile kırpıldığı, CSV'de İSE TAM, üç
noktasız hâliyle var olduğu doğrulandı.

**İndirme eylemi artık kendini kaydediyor — üç format için de, eskiden
etmeyen dahil.** Görev indirme eyleminin denetlenmesini istedi; bunu
denetlemek eski TXT dışa aktarımını da GERİYE DÖNÜK düzeltmek anlamına
geliyordu — zincir tutarlılığı ve rol kapılaması için ZATEN sertleştirilmiş
olduğu ~2 aylık sürede (§4.16, §4.20) hiçbir zaman kendini kaydetmemişti.
Üç dışa aktarım metodu da artık başarılı bir yazımdan SONRA paylaşılan bir
`_log_disa_aktarim()` çağırıyor (`UI/main_window_files.py`'nin `file_
downloaded` için zaten kurduğu "yazım başarılı olduktan SONRA, onay
diyaloğundan ÖNCE kaydet" sırasıyla AYNI) — tek bir `audit_log_exported`
eylemi, üçünü ayıran bir `format=` alanıyla, `usb_role_changed`/`setting_
changed`'in her varyant için yeni bir eylem adı basmak yerine zaten
`detail=`'da bir varyant kodladığı deseni yansıtarak. Üç format için de
her dışa aktarım çağrısından ÖNCE VE SONRA eşleşen `audit_log` satırları
sayılıp kaydedilen `user_id` ve `format=` değeri kontrol eden
parametrize bir testle doğrulandı; bir eşlik eden test, İPTAL edilen bir
dışa aktarımın (dosya seçiciden boş yol) HİÇBİR ŞEY yazmadığını
doğruluyor, yani iddia sonuçtan BAĞIMSIZ her zaman kaydeden bir eylem
için BOŞ bir iddia değil. AST tabanlı bir test (`_export_txt`'in
GERÇEKTEN `_load()`/`txt_basligi()` çağırdığını, yalnızca adlarının
dizede geçtiğini DEĞİL doğrulayan mevcut denetimle AYNI desen) üç dışa
aktarım metodunun da GERÇEKTEN `_load()`'u, kendi `export_csv()`/
`export_pdf()`'ini VE `_log_disa_aktarim()`'i çağırdığını — o adların
dosyada bir yerde geçmesinden FAZLASINI — doğruluyor.

**PDF yolunun ortaya çıkardığı bir test-doğrulanabilirlik kararı.**
`export_inventory_pdf()`'in mevcut testleri, bir PDF-ayrıştırma
bağımlılığı OLMADAN beklenen metni ham PDF baytlarında arıyor (`b"KVKK"
in out.read_bytes()`) — bu ORADA çalışıyor çünkü aranan dize TESADÜFEN
belge `title`'ı, ki reportlab bunu içerik akışı sıkıştırmasından BAĞIMSIZ
olarak PDF'in Info sözlüğünde sıkıştırılmadan tutuyor. Gövde metni (tablo
hücreleri, zincir-durumu paragrafı) AYNI GÜVENCEYE sahip DEĞİL — doğrudan
ölçüldü: yalnızca bir tablo hücresine gömülü bir action-adı işareti,
reportlab'ın VARSAYILAN ayarlarıyla kurulmuş bir PDF'in ham baytlarında
BULUNAMADI. `SimpleDocTemplate`'e `pageCompression=0` geçmek bunu
düzeltti (AYNI işaretin aranabilir hâle geldiği doğrulandı) — HERHANGİ
bir modüle bir PDF-ayrıştırma bağımlılığı EKLEMEDEN, bedeli daha büyük,
sıkıştırılmamış bir dosya — bir insanın ara sıra indirdiği bir dışa
aktarım için kabul edilebilir bir takas, sık çalışan bir yol değil.

---

## 5. Kriptografik ayrıntılar

| Katman | Yapı |
|---|---|
| Dosya içeriği | AES-256-GCM, 12 byte rastgele nonce, 16 byte tag, 64 KB akış |
| Dosya metadata | GCM AAD — JSON, doğrulanır, **şifrelenmez** |
| Düz metin bütünlüğü | Şifrelemeden önce hesaplanan SHA-256, AAD'a bağlanır |
| Vault KEK | Argon2id(PIN, 16 byte tuz), time=3, bellek=64 MB, paralellik=4, 32 byte |
| Vault mühürleme | AES-256-GCM, AAD = HWID (cihaz bağlama) |
| Vault imzası | HMAC-SHA256, anahtar = HKDF-SHA256(share_2, info=HWID) — bkz. §4.2 |
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

**Desteklenen sürüm:** yalnızca en son sürüm (şu an **v2.3.0**) güvenlik
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

**Dördüncü, projeye özgü bir kontrol de bu belgedeki her şeyle AYNI
`pytest` suite'inde çalışıyor:** `tests/test_ui_yasakli_iddia_terimleri.py`
`UI/**/*.py` altındaki HER dosyadaki her string sabitini (`ast` ile, yani
yorumlar HİÇ taranmıyor — yalnızca ekrana gerçekten çıkabilecek şeyler)
ayrıştırıyor ve yasaklı, doğrulanmamış bir mimari iddia bulursa yapıyı
kırıyor. Liste, ve her maddenin neden orada olduğu:

| Terim | Neden yasaklı | İzin verilen bağlam |
|---|---|---|
| `AIR-GAPPED` / `air-gapped` | Uygulama TSA'ya ağ üzerinden ulaşıyor (§1.1, M1) — hava boşluklu değil, koşulsuz | Yok — hiçbir UI dizesinde |
| `ZERO-TRUST` / `zero-trust` | Bu uygulamanın hiçbir yerde uyguladığı ya da iddia ettiği bir mimari değil | Yok |
| `ÇEVRİMDIŞI` / `çevrimdışı` | Belirli, DOĞRULANMIŞ bir yetenek için (RFC 3161 zaman damgası doğrulaması, §4.9 — gerçekten ağsız, ölçüldü) doğru, ama uygulamanın TAMAMI hakkında bir iddia olarak yanlış | Yalnızca "çevrimdışı doğrula-" bigramının TAM İÇİNDE (o tek doğrulama eylemini nitelerken) — geri kalan her şey, bağımsız bir durum rozeti dahil, yasak |

Bu kontrol, aynı iddianın UI'ye İKİ KEZ sızmasından doğdu: bir kez neredeyse
(`UI/main_window_palette.py`'deki bir yorum, "v2.5 · AIR-GAPPED"'in
portlanan bir temadan BİLEREK çıkarıldığını kayda geçiriyor), bir kez
gerçekten (iki-sütunlu giriş ekranı yeniden tasarımı "● ÇEVRİMDIŞI"'yi
bir mockup'tan doğrudan `UI/login_dialog.py`'ye kopyaladı, 2026-08-26).
İkinci sızıntıyı yakalayan düzeltme tek bir dosyayı kontrol ediyordu; bu
kontrol `UI/`'nin bundan sonra sahip olacağı HER dosyayı kapsıyor —
B-056'nın bu README'deki sürüklenen modül sayısı için yaptığı AYNI
yapısal hamle. Olayın tam geçmişi: `BACKLOG.md`'de **B-071**.

**2026-08-29 — `UI/`'nin alt dizinlerine ve `CORE`/`DB` exception
mesajlarına genişletildi.** Aynı dosyada iki takip boşluğu ölçüldü ve
kapatıldı:

1. Desen `UI/*.py`'ydi (yalnızca üst düzey). `UI/` bugün alt dizin
   içermiyor, ama geçici bir `UI/_gecici_altdizin_kaniti/` altına ekilen
   bir dosya, deseninin bir alt dizindekini sessizce atlayacağını
   kanıtladı — bir seviye aşağıda duran canlı bir `AIR-GAPPED` dizesiyle
   tarama yeşil kaldı. Özyinelemeli bir taramaya geçildi (`__pycache__`
   hariç); aynı ekili dosya sonra yakalandı ve düzeltmeyi kalıcı bir
   `tmp_path` regresyon testi koruyor.
2. `CORE`/`DB`, `str(exc)` yoluyla kullanıcıya HAM ulaşan exception
   sınıflarını (`USBAuthError`, `VaultTamperedError`, `AuthenticationError`,
   `BackupError`, `CheckoutError`, `TrustedRootError`, `PinRotationError` ve
   diğerleri) tanımlıyor — `AdminPanel.py`, `main_window_open.py`,
   `main_window_lock.py`, `ProfileDialog.py`, `main_window_files.py`,
   `login_dialog.py`, `PinRotationDialog.py` hepsi bir exception'ı doğrudan
   bir `QMessageBox`'a geçiriyor. Bir CORE/DB exception mesajı bu yüzden bir
   UI dizesi kadar kullanıcıya açık ve aynı taramayı gerektiriyordu.
   CORE/DB'nin TÜM string sabitlerini taramak (`UI/`'de kullanılan yöntemin
   aynısı) önce denendi ve gerçek yanlış-pozitifler ürettiği ölçüldü:
   `backup.py`, `hclx.py`, `rate_limit.py`, `timestamp.py`,
   `timestamp_verify.py`'nin modül docstring'leri, hiçbir kullanıcının
   görmediği düz yazıda çevrimdışı doğrulamayı ve çevrimdışı kaba kuvvet
   saldırılarını, izin verilen listenin kapsamadığı dilbilgisi biçimleriyle
   (olumsuzlar, isim-fiiller) tartışıyor. Tarama bunun yerine yalnızca
   `raise SomeError(...)` çağrılarının string argümanlarına daraltıldı —
   CORE/DB'nin `str(exc)` yoluyla gerçekten sızabilecek TEK parçası. Bu,
   yedi yanlış pozitifin tamamını ortadan kaldırdı ve tek gerçek isabeti
   korudu (`CORE/timestamp.py:672`'nin
   `"...bu damga sonradan çevrimdışı doğrulanamaz."` mesajı — bir SINIRLAMA
   bildirimi, bir mimari iddia değil), bu da mevcut "çevrimdışı doğrula-"
   biçimlerinin yanına izin verilen bağlam listesine eklendi.

**2026-08-29 (devam) — `raise Sinif(degisken)` için tek-seviye geri
izleme.** Yukarıdaki `raise`-yalnızca CORE/DB taraması, `raise`
çağrısının İÇİNDE yalnızca `ast.Constant` düğümlerini arıyordu —
`raise Sinif(msg)` (`msg` bir değişken) çağrısının o alt ağacında HİÇ
`Constant` düğümü yok, yani tarama için görünmezdi. Doğrudan ölçüldü:
geçici bir CORE dosyasına `msg = "AIR-GAPPED doğrulama modu etkin"`,
ardından `raise USBAuthError(msg)` eklenince tarama SIFIR ihlalde kaldı
(geçici dosya kanıttan hemen sonra silindi). Bugün hiçbir üretim kodu bu
kalıbı kullanmıyor (grep ile doğrulandı), ama boşluk gerçekti, o yüzden
tarama yalnızca belgelenmedi, genişletildi: artık her fonksiyon/modül
gövdesini SIRAYLA gezip aynı kapsamdaki en yakın önceki `ad = "literal"`
atamasını takip ediyor ve `raise Sinif(ad)`'i buna göre çözüyor — basit,
tek seviyeli, sıralı bir arama, tam bir veri akışı analizi DEĞİL. İç içe
bir `def`/`class` YENİ bir kapsam başlatıyor (çevreleyen fonksiyondan
miras almıyor, yani başka bir yerdeki aynı isimli bir değişkenle
karıştırılamıyor); `raise`'den SONRA yazılan bir atama doğru şekilde
YOK SAYILIYOR. Bunu 4 kalıcı test kapsıyor: enjekte edilen değişken
kalıbı yakalanıyor, farklı bir fonksiyondaki aynı isimli değişken
YANLIŞLIKLA çözülmüyor, `raise`'den SONRA yazılan bir atama
YANLIŞLIKLA çözülmüyor, ve gerçek CORE/DB ağacı geri izleme etkinken
hâlâ sıfır ihlal üretiyor.

**2026-08-29 (devam, yine) — çok-hop zincirler, azami derinlik ve döngü
korumasıyla.** Yukarıdaki tek-seviye geri izleme yalnızca `ad =
"literal"` atamalarını kaydediyordu — `ad = baska_degisken` (isimden-isme
aktarım) HİÇ kaydedilmiyordu, yani zincir ikinci hoptan itibaren
görünmezdi. Doğrudan ölçüldü: geçici bir CORE dosyasına `tmp =
"AIR-GAPPED doğrulama modu etkin"; msg = tmp; raise USBAuthError(msg)`
eklenince tarama SIFIR ihlalde kaldı (kanıttan hemen sonra silindi).
Düzeltme, atama kaydını iki biçime ayırıyor — `("literal", deger)` ya da
`("isim", baska_ad)` — ve bir `raise Sinif(ad)` argümanını, en fazla
`_MAKS_ZINCIR_DERINLIGI` (10) hop boyunca bu zinciri bir literal'e kadar
takip ederek çözüyor. İki koruma var, ikisi de SESSİZ değil: bir **döngü**
(aynı ismin zincirde tekrar görünmesi, ör. `a = b; b = a`) sonsuza dek
dönmek yerine tespit edilip `warnings.warn` ile bildiriliyor; 10 hop
içinde çözülmeyen bir zincir de aynı şekilde bildiriliyor. Her iki durum
da "mesaj bulunamadı" (ihlal SAYILMAZ) sonucuna varıyor — çökme ya da
asılı kalma yerine: bu kadar dolaşık bir zincir, taranan kodun zaten
anlaşılmaz olduğu anlamına gelir, taramanın görünür bir uyarıyla zarifçe
gerilemesi, yorumlayamadığı kod yüzünden derlemeyi kırmasına tercih
edildi. İzlenemez bir değere (ör. bir fonksiyon çağrısının sonucu) yeniden
atanan bir isim, bayat kaydını sözlükten SİLİYOR. Hâlâ tam bir veri akışı
analizi DEĞİL — yalnızca doğrusal isimden-isme/isimden-literale zincirler
çözülüyor, bir ifadeden atanan hiçbir şey izlenmiyor. Bunu 5 kalıcı test
kapsıyor: iki-hop bir zincir çözülüyor, üç-hop bir zincir çözülüyor,
döngüsel bir atama asılı kalmadan tamamlanıp döngü uyarısını üretiyor,
yapay bir 15-hop zincir azami derinlik sınırını döngü korumasından
BAĞIMSIZ olarak sınıyor, ve gerçek CORE/DB ağacı çok-hop çözümü etkinken
hâlâ sıfır ihlal üretiyor.

**2026-08-29 (devam, bir kez daha) — f-string'ler (`ast.JoinedStr`) ve
`+` birleştirmesi için kontrol.** Doğrudan ölçüldü: `raise
USBAuthError(f"AIR-GAPPED doğrulama: {hwid}")` bir `raise` çağrısına
doğrudan eklenince hiçbir kod değişikliği olmadan zaten yakalanıyordu —
`ast.walk`, bir `JoinedStr`'ın düz literal `Constant` parçalarını, alt
ağaçtaki başka herhangi bir string sabiti bulduğu gibi buluyor. Ama
f-string'i önce bir değişkene atamak — `msg = f"AIR-GAPPED doğrulama:
{hwid}"; raise USBAuthError(msg)` — SIFIR ihlalde ölçüldü, çünkü zincir
takipçisinin atama kaydedicisi yalnızca doğrudan bir string literal ya da
isimden-isme aktarımı anlıyordu; bir `JoinedStr` değeri "izlenemez, kaydı
sil" dalına düşüyordu. Üçüncü bir biçim eklendi: `ad = f"..."` artık
`("literal", yalnizca_birlesmis_literal)` kaydediyor, burada literal metin
yalnızca `values`'ın düz parçaları — `ast.FormattedValue` düğümleri
(`{interpolasyon}`'un kendisi) ATLANIYOR, yani interpolasyon içeriği (tarama
anında bir değişken adı, asla kullanıcı verisi değil) hiçbir zaman taramaya
girmiyor ve tuhaf isimli bir değişkenden yanlış pozitif üretemiyor.
`+`-birleştirmesinin (`ast.BinOp`, `ast.Add`) de raise mesajlarında geçip
geçmediği kontrol edildi: geçiyor, `CORE/timestamp.py`'de üç yerde
(literal + `", ".join(...)` + literal), hepsi DOĞRUDAN `raise` argümanı
olarak — hiçbiri önce bir atamadan geçmiyor. Bunlar, f-string'leri zaten
doğrudan kapsayan AYNI `ast.walk` mekanizmasıyla, hiçbir ek kod olmadan
zaten yakalanıyor. Hiçbir CORE/DB ataması bir mesajı `+` ile kurup SONRA
raise etmiyor (doğrudan kontrol edildi — `raise` çağrıları DIŞINDAKİ sekiz
string-içeren `BinOp` ataması byte-paketleme, SQL sorgusu ya da sayaç
aritmetiği, hiçbiri exception metni değil), o yüzden `+`-birleştirmesi
için zincir çözümü bugün UYGULANMAMIŞ, belgelenmiş bir sınır olarak
kalıyor: `msg = "a" + "b"; raise X(msg)` bugün çözülmez. F-string
çalışmasını 4 kalıcı test kapsıyor: doğrudan bir f-string yakalanıyor,
değişkene atanmış bir f-string yakalanıyor, interpolasyon parçasının
hiçbir zaman taramaya girmediği (ve kendisinin bir hataya yol açmadığı)
kanıtlanıyor, ve gerçek CORE/DB ağacı — `CORE/tpm_sealing.py`'de GERÇEK
bir f-string tabanlı raise mesajı içeriyor — hâlâ sıfır ihlal üretiyor.

**2026-08-29 (teyit edildi, kod değişikliği YOK) — kod tabanı temiz;
kod-dışı bir tasarım mockup'ı DEĞİL.** Tarama bir düzeltme değil, bir
kontrol turu olarak yeniden çalıştırıldı:
`tests/test_ui_yasakli_iddia_terimleri.py` — 27/27 geçti, `UI/`, `CORE/`
ya da `DB/`'nin hiçbirinde yasaklı bir iddia yok. Ayrı bir bulgu olarak,
bu bölümün kaynağı olan tasarım mockup'ı (bkz. `BACKLOG.md`'de
**B-071**, yukarıdaki "Bu kontrol ... doğdu" paragrafı) yeniden okundu
ve hâlâ "HYCLEUS v2.5 · AIR-GAPPED" metnini, bağımsız bir
"● ÇEVRİMDIŞI" rozetini VE genel bir "tamamen çevrimdışı" iddiasını
taşıdığı görüldü — bu bölümün uygulamadan uzak tutmaya çalıştığı aynı
üç iddia. O artifact bu taramanın kapsadığı kaynak kod DEĞİL ve
DÜZENLENMEDİ: ~660 KB'lık, tek satırlık, minified bir bundle (bir JSON
sarmalayıcı içinde bir JS template string'i içinde çift-kaçışlı HTML) —
düzenlenebilir bir HTML kaynağı değil, ve buradan render edip görsel
olarak DOĞRULAMANIN bir yolu yok — bu taramanın kendi testlerine
uyguladığı AYNI ilke (doğrulanamayan bir değişiklik, değişiklik
yapmamaktan daha kötüdür). Bunun yerine burada ESKİ bir referans olarak
kaydedildi: o mockup, `UI/login_dialog.py`'nin bugün gerçekte ne
yaptığından ÖNCE gelir ve onunla bir ilgisi yoktur. Yukarıdaki tarama,
çalışan uygulama üzerinde otorite; mockup bir tasarım geçmişidir, bir
şartname değil.
