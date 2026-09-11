# Mutation Testing at HYCLEUS — What We Broke on Purpose, and What Happened

**Applies to:** v2.4.0.dev · Valid through commit `da18340` (2026-09-11)

This document exists to answer one question in plain language: *"Is this
application actually secure, and how do you know?"* It summarizes every
manual mutation-testing round run against HYCLEUS to date. The technical
raw data lives in `BACKLOG.md` (search for "Mutasyon Araştırmaları") —
this page is a readable digest built on top of it, not a replacement.

🇹🇷 [Türkçe sürüm aşağıda](#mutasyon-testi--hycleusta-ne-bilerek-bozduk-ne-oldu)

---

## 1. What is mutation testing, and why does it prove more than "tests pass"?

A normal test suite answers "does the code do what it's supposed to do?"
It says nothing about whether the tests would actually notice if someone
*broke* the code — quietly removed a check, weakened a comparison, or
skipped a step. A test suite with 3,000 green checkmarks can still miss a
one-line security hole, if nothing in it happens to exercise that line.

Mutation testing closes that gap directly: **we deliberately damage the
real code — one small, realistic change at a time — and watch whether the
existing tests notice.** A password check changed from "reject wrong
passwords" to "accept everything." A comparison flipped from `<` to `<=`.
A safety check simply deleted. Then we run the test suite against the
damaged code.

Two outcomes, and only two:

- **Killed** — a test fails. The safety property really is being checked,
  by a real test, right now. This is the strongest evidence a test suite
  can give.
- **Survived** — every test still passes, on visibly broken code. This
  means the property was never actually being verified — the code might
  be fine today, or it might not be, but nothing would tell us if it broke
  tomorrow.

Every "survived" result was then handled exactly one of three ways, never
left ambiguous:

1. **A real gap** — a new test was written, proven to fail on the broken
   code and pass on the real code, then the damage was reverted. The gap
   is now permanently guarded.
2. **An equivalent mutant** — the change looks different but provably
   cannot alter behavior (e.g. renaming a constant that is only ever used
   in an error message). Explained, not "fixed," because there is nothing
   to fix.
3. **Out of scope** — the mutation targets a mechanism the code
   deliberately does not implement, or a boundary the design intentionally
   draws elsewhere. Cited against the actual code or an existing design
   note, not assumed.

A fourth, rarer label — **"no control at all"** — means the survived
mutation exposed a genuine missing safeguard, not just a missing test. Six
of these were found; two remain open and are covered in §4.

Every mutation was reverted immediately after being measured
(`git diff` empty before moving to the next one) — production code was
only changed when a fix was the deliberate outcome of a round, never left
half-applied.

---

## 2. The numbers

Two systematic rounds cover the whole application, using the same method,
directly comparable:

| Round | Mutations | Killed | Fixed (new test) | Equivalent | Out of scope | Other |
|---|---|---|---|---|---|---|
| Hand-written 100-scenario list (8 sections) | 100 | 55 | 24 | 7 | 14 | — |
| Full crypto/security catalog, 4 parts (MC-M001–200) | 200 | 92 | 27 | 5 | 74 | 2 |
| **Total** | **300** | **147** | **51** | **12** | **88** | **2** |

Read plainly: of 300 deliberate attempts to break something,

- **198 (66%)** were caught immediately by tests that already existed —
  the strongest possible confirmation those tests do their job.
- **51 (17%)** exposed a real blind spot in the test suite. Every one of
  these got a new, permanent test before this round closed, proven to
  fail on the broken code first.
- **88 (29%)** targeted something the application either doesn't do at
  all (so there was nothing to break) or deliberately does differently by
  design (documented in the code itself, not just asserted here).
- **12 (4%)** were mutations that, on inspection, could not have changed
  any observable behavior — the kind of finding that shows the exercise
  was thorough, not that it missed something.
- **2** surfaced a genuine gap in the *application*, not just in its
  tests — filed as backlog items rather than fixed on the spot, since
  fixing them meant a product decision. See §4.

Two earlier, separate rounds add further ground truth: a 54-mutation pass
over the cryptography/timestamping core (12 real gaps found, all closed
the same session) and a partial run of a second 200-item catalog
(46 of 200 scenarios; on hold, unrelated numbering to the round above).
Counting everything ever run by hand against real code: **400 mutation
scenarios**, methodology unchanged throughout.

---

## 3. The ten most concrete gaps found — and closed

These are picked for how tangible the "what could have gone wrong"
story is, not by any formal severity score. Function names and file paths
are pushed to the footnote after each item; the prose stands on its own.

**1. "Permanently deleted" files weren't actually erased.**
The Disposal Room's permanent-delete action told users their file was
gone for good. In reality it only removed the file's name from the
folder listing — the file's encrypted contents stayed fully readable on
disk with ordinary recovery tools, until something else happened to write
over that spot. Since every file in a vault shares one encryption key,
recovering *any* deleted ciphertext plus the key later would have
un-deleted it. Fixed: permanent delete now overwrites the file with
random data three times before removing it, the same secure-erase routine
already used elsewhere in the app.[^1]

**2. A crash mid-save could corrupt the entire vault, not just one file.**
Saving the vault (which happens on PIN change, role change, and vault
creation) wrote directly over the existing vault file. If the power went
out or the app crashed in the middle of that write, the file could be
left half-written — and the vault file is the one file that holds the
key material for everything else. Fixed: saves now go to a temporary file
first, get flushed to disk, and only then atomically replace the real
file — so a crash mid-write leaves the *old*, still-valid vault in place.[^2]

**3. Swapping in a blocked USB mid-session could have bypassed the block.**
HYCLEUS lets an administrator blacklist a lost or stolen USB key. That
block is enforced wherever a session starts — but a *third* code path
(swapping the USB stick while already logged in) had never actually been
exercised by any test, ever, in the project's history. Testing it for
real confirmed the block does hold on this path too — but only because
nothing had ever proven it, and a future edit to that one function could
silently have broken it without anyone noticing for months. A permanent
test now runs this exact scenario end-to-end, and the risk is documented
as a standing caution for anyone touching that code.[^3]

**4. Any user, even a read-only one, could erase the tamper-evident audit log.**
The audit trail is designed so that any tampering is detectable — each
entry is cryptographically chained to the one before it. But the database
rule that should have blocked deleting entries outright was missing for
this one table; a plain "delete everything" command, available to any
logged-in role, would have succeeded silently. The next integrity check
would have noticed the log was gone — after it was already gone. Fixed:
the database itself now refuses any delete or content edit on that table,
no matter which role or code path asks.[^4]

**5. The auto-lock timer could silently never start.**
HYCLEUS is supposed to re-lock itself after a period of inactivity. The
timer that makes that happen is set up when the app window opens — but no
test had ever confirmed the timer actually *starts running*, only that
the lock logic is correct once triggered. Disabling the start line broke
nothing across 180 tests. A vault left open and unattended, with this one
line silently broken, would simply never lock. A test now confirms the
timer is actually armed on startup.[^5]

**6. The vault's master key wasn't wiped from memory after use.**
Two of the most sensitive values in the app — the key-encryption key and
the file master key — were kept as ordinary, immutable memory the whole
time they were used, relying on Python's garbage collector to eventually
clean them up. A memory dump taken shortly after using the vault could
still have contained them. Fixed: both are now converted to a mutable
buffer and explicitly zeroed out the moment they're no longer needed, the
same pattern the encryption layer already used elsewhere.[^6]

**7. Every file in a vault shared one single encryption key.**
This was safe on its own — the key never leaves protected storage — but
it meant a single point of failure: any weakness in how one file's
encryption is handled would potentially affect every file at once, with
no isolation between them. A defense-in-depth layer was added: each file
now gets its own one-time sub-key, derived fresh from the master key and
never reused, so a problem with one file's encryption can't spread.[^7]

**8. Recovery paper share was shown on screen with no privacy shield.**
The one-time recovery code (the "paper share," shown once during setup)
already had screen-capture blocking and a confirm-before-closing guard —
but the QR code and text appeared on screen fully visible the instant the
dialog opened, with nothing to stop someone glancing over the user's
shoulder from reading it. Fixed: the content now opens hidden behind a
"tap to reveal" step, so it's only visible when the user deliberately
chooses to look at it.[^8]

**9. Closing the app mid-upload could abandon files half-processed.**
Uploading files runs on background worker threads. If a user closed the
app while an upload was still in progress, the app would quit immediately
without waiting for those workers to finish — potentially leaving a file
partially encrypted, or encrypted with no matching database record.
Fixed: closing the app now waits (with a timeout) for pending upload work
to finish first, and logs loudly if it can't.[^9]

**10. The Disposal Room's "grace period" had never been checked for its actual unit.**
Files sent to the Disposal Room sit for a fixed retention period before
they become eligible for permanent deletion — meant to be measured in
hours. No test had ever checked *how many* hours the count actually
represents; only that some countdown existed. A silent bug that turned
"24 hours" into "24 minutes" would have passed every existing test. A new
test now pins the real duration, within a small tolerance.[^10]

---

## 4. What's still open, and why

These twelve items are tracked, not hidden. None represents an active
break-in path in the shipped application today — each is either a
defense-in-depth improvement, a low-probability edge case, or a change
that reaches into enough of the codebase that it deserves a deliberate
decision rather than a quick patch slipped into a testing round.

- **Sanity checks with no real cryptographic weakness behind them**
  (`B-127` degenerate/all-zero encryption keys, `B-128` no memory ceiling
  on decrypting one very large file) — AES-256 has no known "weak key"
  class the way older ciphers did, and no legitimate code path can even
  produce a degenerate key today. Adding the check is cheap defense in
  depth, not a fix for something exploitable; the threshold to use is a
  product call, not decided yet.
- **Changes that require touching a shared function's contract everywhere
  it's called** (`B-130` the session's master key isn't zeroed while the
  screen is locked, `B-141` TOTP codes have no replay-window protection,
  `B-136` a SQL `LIKE` pattern could theoretically be confused by an
  underscore in a device ID, `B-138` no structural test yet pins that key
  material never leaks into the vault's metadata) — each is real and each
  is scoped, but each also means auditing or changing every caller of a
  widely-used function, which is exactly the kind of change that should
  not happen quietly inside a testing pass.
- **Policy decisions with broad reach** (`B-131` audit log entries have no
  content validation, `B-133` new usernames aren't validated at the
  function that actually creates the account — only in the one screen
  that calls it today, `B-129` a couple of automated code-scanner
  warnings are suppressed with a documented rationale rather than
  resolved) — the fix in each case means picking a rule that will apply
  everywhere, which is a decision for a human, not something to default
  into.
- **UI/UX gaps found this month** (`B-145` three different "send to
  Disposal Room" buttons in the interface don't go through the same
  approval gate the core deletion logic offers, though the actual
  deletion-time safety check still protects the file regardless;
  `B-146` releasing a file from quarantine doesn't check whether it was
  ever actually scanned) — both are real rough edges, neither is a
  security hole today, and both need a product decision about the
  intended user flow before code changes.

Every one of these was found by the *same* rigorous process as the ten
items in §3 — the difference is not how they were found, but that closing
them responsibly means more than writing one test.

---

## 5. Validity and how this gets updated

This document reflects every mutation-testing round completed through
commit `da18340` (2026-09-11) — the 100-scenario hand-written round, the
full 200-item crypto/security catalog (all 4 parts), and the two earlier
partial rounds referenced in §2. The raw, line-by-line record of every
individual mutation lives in `BACKLOG.md` under "Mutasyon Araştırmaları"
and is the source of truth if this summary and that record ever disagree.

**When a new mutation round runs:** the raw results go into `BACKLOG.md`
first, exactly like every round before it. This document is then
refreshed from that record — §2's totals recomputed, §3 re-picked only if
a newer finding is genuinely more illustrative than what it would
displace, and §4's list adjusted as items close or new ones open. This
page is a summary of `BACKLOG.md`, never the other way around; it should
never be edited to say something the underlying record doesn't say.

[^1]: `CORE/disposal.py::purge_file()`/`purge_expired_file()` now call
`CORE/secure_erase.py::shred_file()`. Backlog: `B-134`.
[^2]: `CORE/vault_manager.py::_rewrite_vault()`, aligned with the existing
temp-file → `fsync` → `os.replace()` pattern already used by
`CORE/checkout.py`. Backlog: `B-142`.
[^3]: `UI/main_window_lock.py::_trigger_usb_reauth()`; test:
`tests/test_lock_overlay.py::test_trigger_usb_reauth_kara_listedeki_cihazi_DOGRU_pinle_bile_ACMIYOR`.
See SECURITY.md §4.1. Mutation catalog ID: MC-M147.
[^4]: `DB/migrations.py::_m27_audit_log_immutable()` — four SQLite
triggers on `audit_log` (`DELETE`/content `UPDATE`, unconditional).
Backlog: `B-132`.
[^5]: `UI/main_window.py` (`self._idle_timer.start()`); test:
`test_idle_timer_gercekten_baslatiliyor`. Mutation catalog ID: MC-M098.
[^6]: `CORE/vault_manager.py`, six call sites, using
`CORE.crypto.zero_bytearray()`. Backlog: `B-139`.
[^7]: `CORE/crypto.py::_derive_file_key()` — HKDF-SHA256 per-file subkey,
version-gated so existing files keep working unchanged. Backlog: `B-140`.
[^8]: `UI/RecoveryShareDialog.py` — reveal-on-demand block added around
the existing screen-capture exclusion. Backlog: `B-144`.
[^9]: `UI/main_window.py::closeEvent()` — `QThreadPool.waitForDone()`
added with a timeout. Backlog: `B-143`.
[^10]: `CORE/disposal.py::move_to_imha()`; test:
`test_ttl_sayaci_gercekten_saat_biriminde`. Mutation catalog ID: MC-M180.

---

# Mutasyon Testi — HYCLEUS'ta Ne Bilerek Bozduk, Ne Oldu

**Geçerlilik:** v2.4.0.dev · `da18340` commit'ine kadar geçerli (2026-09-11)

Bu belge tek bir soruyu sade dille yanıtlamak için var: *"Bu uygulama
gerçekten güvenli mi, nereden biliyorum?"* Bugüne kadar HYCLEUS'a karşı
yapılan TÜM elle mutasyon testi turlarını özetliyor. Ham teknik veri
`BACKLOG.md`'de yaşıyor ("Mutasyon Araştırmaları" başlığını arayın) —
bu sayfa onun üzerine kurulu okunabilir bir özet, yerini almıyor.

🇬🇧 [English version above](#mutation-testing-at-hycleus--what-we-broke-on-purpose-and-what-happened)

---

## 1. Mutasyon testi nedir, neden normal test suite'inden daha güçlü bir kanıt?

Normal bir test suite'i "kod olması gerektiği gibi çalışıyor mu?" sorusunu
yanıtlar. Ama bir şey *bozulursa* — bir kontrol sessizce kaldırılırsa,
bir karşılaştırma zayıflatılırsa, bir adım atlanırsa — testlerin bunu
gerçekten FARK EDER mi sorusuna hiçbir şey söylemez. 3.000 yeşil testi
olan bir paket, hiçbiri o tek satırı hiç çalıştırmadığı için tek satırlık
bir güvenlik açığını gözden kaçırabilir.

Mutasyon testi bu boşluğu doğrudan kapatır: **gerçek kodu kasıtlı olarak,
tek seferde küçük ve gerçekçi bir şekilde bozuyoruz — sonra mevcut
testlerin bunu fark edip etmediğine bakıyoruz.** "Yanlış şifreyi
reddet"ten "hepsini kabul et"e çevrilen bir kontrol. `<`'dan `<=`'ye
çevrilen bir karşılaştırma. Tamamen silinen bir güvenlik kontrolü. Sonra
test suite'i bozulmuş kodun üzerinde çalıştırılıyor.

Yalnızca iki sonuç mümkün:

- **Killed (öldü)** — bir test düşüyor. Demek ki o güvenlik özelliği
  ŞU AN, gerçek bir test tarafından gerçekten kontrol ediliyor. Bir test
  suite'inin verebileceği en güçlü kanıt bu.
- **Survived (hayatta kaldı)** — bütün testler, görünür şekilde bozulmuş
  kod üzerinde BİLE geçiyor. Bu, o özelliğin aslında hiç doğrulanmadığı
  anlamına gelir — kod bugün doğru olabilir, olmayabilir de; yarın
  bozulsa kimse fark etmez.

Her "hayatta kaldı" sonucu, belirsiz bırakılmadan, tam olarak şu üç
yoldan biriyle ele alındı:

1. **Gerçek boşluk** — yeni bir test yazıldı, önce bozulmuş kodda
   DÜŞTÜĞÜ, sonra gerçek kodda GEÇTİĞİ kanıtlandı, ardından bozulan kod
   geri alındı. Boşluk artık kalıcı olarak korunuyor.
2. **Eşdeğer mutant** — değişiklik farklı görünüyor ama davranışı
   HİÇBİR şekilde değiştiremeyeceği kanıtlanabiliyor (örn. yalnızca bir
   hata mesajında kullanılan bir sabitin adını değiştirmek). "Düzeltilmiş"
   değil, "açıklanmış" — çünkü düzeltilecek bir şey yok.
3. **Kapsam dışı** — mutasyon, kodun BİLEREK uygulamadığı bir mekanizmayı
   hedefliyor, ya da tasarımın kasıtlı olarak başka bir yere çizdiği bir
   sınırı. Varsayılmadan, gerçek koda ya da mevcut bir tasarım notuna
   dayanarak atıf verildi.

Daha nadir görülen dördüncü bir etiket — **"kontrol yok"** — hayatta
kalan mutasyonun yalnızca eksik bir TEST değil, gerçekten eksik bir
GÜVENLİK ÖNLEMİ ortaya çıkardığı anlamına gelir. Bundan altı tane
bulundu; ikisi hâlâ açık, §4'te ele alınıyor.

Her mutasyon ölçüldükten hemen sonra geri alındı (bir sonraki mutasyona
geçmeden önce `git diff` boş) — üretim kodu yalnızca bir turun kasıtlı
sonucu bir düzeltmeyse değiştirildi, hiçbir zaman yarım bırakılmadı.

---

## 2. Sayılar

Aynı yöntemle, uygulamanın tamamını kapsayan ve doğrudan
karşılaştırılabilir iki sistematik tur var:

| Tur | Mutasyon | Killed (yakalandı) | Düzeltildi (yeni test) | Eşdeğer | Kapsam dışı | Diğer |
|---|---|---|---|---|---|---|
| Elle yazılan 100 senaryolu liste (8 bölüm) | 100 | 55 | 24 | 7 | 14 | — |
| Tam kripto/güvenlik kataloğu, 4 parça (MC-M001–200) | 200 | 92 | 27 | 5 | 74 | 2 |
| **Toplam** | **300** | **147** | **51** | **12** | **88** | **2** |

Sade dille okursak: kodu kasıtlı olarak bozmaya çalıştığımız 300
denemenin,

- **198'i (%66)** ZATEN var olan testler tarafından anında yakalandı —
  o testlerin işini gerçekten yaptığının mümkün olan en güçlü kanıtı.
- **51'i (%17)** test suite'inde gerçek bir kör noktayı ortaya çıkardı.
  Her biri için, bu tur kapanmadan ÖNCE yeni ve kalıcı bir test yazıldı
  — önce bozulmuş kodda düştüğü kanıtlanarak.
- **88'i (%29)** uygulamanın ya HİÇ yapmadığı bir şeyi hedefledi
  (bozacak bir şey yoktu) ya da tasarım gereği KASITLI olarak farklı
  yapılan bir şeyi (yalnızca burada değil, kodun kendisinde de
  belgelenmiş).
- **12'si (%4)** incelendiğinde, HİÇBİR gözlemlenebilir davranışı
  değiştiremeyecek mutasyonlardı — bir şeyin kaçırıldığını değil,
  taramanın ne kadar kapsamlı olduğunu gösteren türden bir bulgu.
- **2'si** yalnızca testlerde değil, *uygulamanın kendisinde* gerçek bir
  boşluk ortaya çıkardı — yerinde düzeltilmek yerine backlog'a düşüldü,
  çünkü düzeltmesi bir ürün kararı gerektiriyordu. Bkz. §4.

İki ayrı, daha önceki tur daha fazla zemin doğruluyor: kriptografi/zaman
damgalama çekirdeği üzerinde 54 mutasyonluk bir geçiş (12 gerçek boşluk
bulundu, hepsi AYNI oturumda kapatıldı) ve ikinci, 200'lük ayrı bir
kataloğun kısmi bir çalıştırması (200 senaryodan 46'sı; askıda, yukarıdaki
turla numaralandırması ÇAKIŞMIYOR). Bugüne kadar gerçek kod üzerinde
elle çalıştırılan HER ŞEYİ sayarsak: **400 mutasyon senaryosu**, yöntem
baştan sona değişmedi.

---

## 3. Bulunan ve kapatılan en somut 10 boşluk

Bunlar resmi bir ciddiyet puanına göre değil, "ne olabilirdi" hikâyesinin
ne kadar somut olduğuna göre seçildi. Fonksiyon adları/dosya yolları her
maddenin sonundaki dipnota itildi; ana metin teknik bilgi gerektirmeden
okunabilir olsun diye.

**1. "Kalıcı olarak silinen" dosyalar aslında hiç silinmiyordu.**
İmha Odası'nın kalıcı silme düğmesi kullanıcıya dosyanın sonsuza kadar
gittiğini söylüyordu. Gerçekte yalnızca dosyanın adı klasör listesinden
kaldırılıyordu — dosyanın şifreli içeriği, disk üzerinde o alanın başka
bir şey tarafından üzerine yazılmasına kadar sıradan kurtarma
araçlarıyla tamamen okunabilir kalıyordu. Bir kasadaki TÜM dosyalar tek
bir şifreleme anahtarını paylaştığı için, silinmiş HERHANGİ bir şifreli
dosyayı ileride anahtarla birlikte kurtarmak, o dosyayı fiilen geri
getirirdi. Düzeltildi: kalıcı silme artık dosyayı kaldırmadan ÖNCE
rastgele veriyle üç kez üzerine yazıyor — uygulamanın başka yerinde
zaten kullanılan aynı güvenli silme rutini.[^1t]

**2. Kayıt sırasında yaşanacak bir çökme, tek bir dosyayı değil TÜM kasayı bozabilirdi.**
Kasa dosyasını kaydetmek (PIN değişiminde, rol değişiminde, kasa
kurulumunda olur) mevcut dosyanın DOĞRUDAN üzerine yazıyordu. Yazma
sırasında elektrik kesilse ya da uygulama çökse, dosya YARIM yazılmış
kalabilirdi — ve kasa dosyası, geri kalan HER ŞEYİN anahtar malzemesini
taşıyan tek dosya. Düzeltildi: kayıtlar artık önce geçici bir dosyaya
yazılıyor, diske aktarılması garanti ediliyor, ancak ONDAN SONRA gerçek
dosyanın yerine atomic olarak geçiyor — yani yazma ortasındaki bir çökme
ESKİ, hâlâ geçerli kasayı olduğu yerde bırakıyor.[^2t]

**3. Oturum sırasında USB değiştirmek, kara listeyi atlayabilirdi.**
HYCLEUS, kayıp/çalıntı bir USB anahtarını yöneticinin kara listeye
almasına izin veriyor. Bu engel oturumun BAŞLADIĞI her yerde
uygulanıyor — ama ÜÇÜNCÜ bir kod yolu (oturum açıkken USB çubuğunu
değiştirmek) projenin tüm geçmişi boyunca hiçbir testte gerçekten
çalıştırılmamıştı. Gerçekten sınandığında engelin bu yolda da tuttuğu
doğrulandı — ama yalnızca bunu daha önce hiçbir şey KANITLAMADIĞI için
şans eseri. O tek fonksiyona gelecekte yapılacak bir düzenleme, aylarca
kimse fark etmeden bu korumayı sessizce kırabilirdi. Artık kalıcı bir
test bu senaryoyu uçtan uca çalıştırıyor, risk de o kodu dokunan herkes
için kalıcı bir uyarı olarak belgelendi.[^3t]

**4. Salt okunur dahil HERHANGİ bir kullanıcı, kurcalamaya-dayanıklı denetim günlüğünü silebiliyordu.**
Denetim izi, her türlü kurcalamanın fark edilebilmesi için tasarlanmış —
her kayıt kriptografik olarak bir öncekine zincirleniyor. Ama tam bu
tabloda, kayıt silmeyi ENGELLEMESİ gereken veritabanı kuralı eksikti;
oturum açmış HERHANGİ bir rolün erişebildiği düz bir "hepsini sil"
komutu sessizce başarılı oluyordu. Bir sonraki bütünlük kontrolü
günlüğün gittiğini fark ederdi — ama ancak GİTTİKTEN sonra. Düzeltildi:
veritabanının kendisi artık o tabloda hangi rol/hangi yoldan gelirse
gelsin her türlü silme/içerik değişikliğini reddediyor.[^4t]

**5. Otomatik kilit sayacı sessizce hiç başlamayabilirdi.**
HYCLEUS bir süre hareketsiz kalınca kendini kilitlemesi gerekiyor. Bunu
sağlayan sayaç, pencere açıldığında kuruluyor — ama sayacın gerçekten
ÇALIŞMAYA başladığını doğrulayan hiçbir test yoktu, yalnızca
tetiklendikten SONRA kilit mantığının doğru olduğunu sınayan testler
vardı. Başlatma satırını devre dışı bırakmak 180 testten hiçbirini
kırmadı. Bu tek satır sessizce bozulsa, açık ve gözetimsiz bırakılmış
bir kasa hiçbir zaman kilitlenmezdi. Artık bir test, sayacın açılışta
gerçekten kurulduğunu doğruluyor.[^5t]

**6. Kasanın ana anahtarı kullanımdan sonra bellekten temizlenmiyordu.**
Uygulamadaki en hassas iki değer — anahtar-şifreleme anahtarı ve dosya
ana anahtarı — kullanıldıkları sürece boyunca sıradan, değiştirilemez
bellek olarak tutuluyordu; temizliğin er ya da geç Python'ın çöp
toplayıcısı tarafından yapılacağına güveniliyordu. Kasa kullanıldıktan
kısa süre sonra alınan bir bellek dökümü bu değerleri hâlâ içerebilirdi.
Düzeltildi: ikisi de artık değiştirilebilir bir arabelleğe çevriliyor ve
işleri bittiği ANDA açıkça sıfırlanıyor — şifreleme katmanının başka
yerde zaten kullandığı aynı desen.[^6t]

**7. Bir kasadaki TÜM dosyalar tek bir şifreleme anahtarını paylaşıyordu.**
Bu tek başına güvenliydi — anahtar korumalı depolamanın dışına hiç
çıkmıyor — ama tek bir hata noktası anlamına geliyordu: bir dosyanın
şifrelenme biçimindeki herhangi bir zayıflık, aralarında hiçbir izolasyon
olmadan aynı anda TÜM dosyaları etkileyebilirdi. Savunma-derinliği
katmanı eklendi: her dosya artık ana anahtardan taze türetilen,
tekrar kullanılmayan kendi tek-seferlik alt-anahtarını alıyor — yani bir
dosyanın şifrelemesindeki bir sorun artık diğerlerine yayılamıyor.[^7t]

**8. Kurtarma kâğıdı payı, gizlilik perdesi olmadan ekrana geliyordu.**
Kurulum sırasında bir kez gösterilen kurtarma kodu ("kağıt pay") zaten
ekran-yakalama engeline ve kazayla-kapatma onayına sahipti — ama pencere
açılır açılmaz QR kod ve metin TAM görünür şekilde ekrana geliyordu,
kullanıcının omzunun üstünden bakan birinin bunu okumasını engelleyen
hiçbir şey yoktu. Düzeltildi: içerik artık "göstermek için dokunun"
adımının arkasında gizli başlıyor, yalnızca kullanıcı bilerek bakmayı
SEÇTİĞİNDE görünüyor.[^8t]

**9. Uygulamayı yükleme sırasında kapatmak, dosyaları yarım işlenmiş bırakabilirdi.**
Dosya yükleme arka plan işçi (worker) iş parçacıklarında çalışıyor.
Kullanıcı yükleme devam ederken uygulamayı kapatırsa, uygulama o
işçilerin bitmesini beklemeden ANINDA kapanıyordu — bu da yarım
şifrelenmiş bir dosya, ya da veritabanında hiç karşılığı olmayan
şifreli bir dosya bırakabilirdi. Düzeltildi: uygulama artık kapanırken
bekleyen yükleme işi varsa önce (bir zaman aşımıyla) bitmesini bekliyor,
bekleyemezse yüksek sesle bir hata kaydı düşüyor.[^9t]

**10. İmha Odası'nın "bekleme süresi"nin gerçek birimi hiç kontrol edilmemişti.**
İmha Odası'na gönderilen dosyalar, kalıcı silmeye uygun hale gelmeden
önce sabit bir bekleme süresi geçiriyor — bunun saat cinsinden olması
gerekiyor. Hiçbir test bu sayının gerçekte KAÇ saati temsil ettiğini
kontrol etmemişti; yalnızca bir geri sayımın VAR olduğunu. "24 saat"i
sessizce "24 dakika"ya çeviren bir hata, mevcut testlerin hiçbirini
kırmazdı. Yeni bir test artık gerçek süreyi, küçük bir toleransla,
doğrudan sabitliyor.[^10t]

---

## 4. Hâlâ açık olanlar, ve neden

Bu on iki madde takip ediliyor, saklanmıyor. Hiçbiri bugün teslim edilen
uygulamada aktif bir açık YOLU temsil etmiyor — her biri ya
savunma-derinliği iyileştirmesi, ya düşük olasılıklı bir uç durum, ya da
bir mutasyon turuna sıkıştırılıp geçilmek yerine bilinçli bir karar
gerektirecek kadar geniş bir koda dokunan bir değişiklik.

- **Arkasında gerçek bir kriptografik zayıflık olmayan sağlamlık
  kontrolleri** (`B-127` dejenere/tüm-sıfır şifreleme anahtarları,
  `B-128` çok büyük tek bir dosyayı çözerken bellek tavanı yok) —
  AES-256'nın eski şifreleme algoritmalarındaki gibi bilinen bir "zayıf
  anahtar" sınıfı yok, ve bugün hiçbir meşru kod yolu dejenere bir
  anahtar ÜRETEMİYOR bile. Kontrolü eklemek ucuz bir savunma-derinliği
  adımı, sömürülebilir bir şeyin düzeltmesi değil; kullanılacak eşik
  henüz karara bağlanmadı.
- **Paylaşılan bir fonksiyonun sözleşmesini her çağrıldığı yerde
  değiştirmeyi gerektiren değişiklikler** (`B-130` ekran kilitliyken
  oturumun ana anahtarı sıfırlanmıyor, `B-141` TOTP kodlarında
  tekrar-oynatma penceresi koruması yok, `B-136` bir SQL `LIKE`
  deseninin teorik olarak bir cihaz kimliğindeki alt çizgiyle
  karışabilmesi, `B-138` anahtar malzemesinin kasa metadata'sına HİÇBİR
  zaman sızmadığını sabitleyen bir yapısal test henüz yok) — her biri
  gerçek ve sınırları belli, ama her biri de yaygın kullanılan bir
  fonksiyonun TÜM çağıranlarını denetlemeyi/değiştirmeyi gerektiriyor —
  tam da bir test turunun içine sessizce sıkıştırılmaması gereken türden
  bir değişiklik.
- **Geniş etkili politika kararları** (`B-131` denetim günlüğü
  kayıtlarında içerik doğrulaması yok, `B-133` yeni kullanıcı adları
  hesabı GERÇEKTEN oluşturan fonksiyonda değil, yalnızca onu bugün
  çağıran tek ekranda doğrulanıyor, `B-129` birkaç otomatik kod tarama
  uyarısı ÇÖZÜLMEK yerine belgelenmiş bir gerekçeyle susturulmuş
  durumda) — her birinin düzeltmesi HER YERDE geçerli olacak bir kural
  seçmek demek, bu da varsayılan olarak değil, bir insan tarafından
  verilmesi gereken bir karar.
- **Bu ay bulunan arayüz/kullanıcı-deneyimi boşlukları** (`B-145`
  arayüzdeki üç farklı "İmha Odası'na gönder" düğmesi, çekirdek silme
  mantığının sunduğu onay kapısından geçmiyor — yine de gerçek silme
  anındaki güvenlik kontrolü dosyayı her durumda koruyor;
  `B-146` bir dosyayı karantinadan çıkarmak, o dosyanın hiç
  taranıp taranmadığını kontrol etmiyor) — ikisi de gerçek pürüzler,
  ikisi de bugün bir güvenlik açığı DEĞİL, ve ikisi de kod değişikliğinden
  önce hedeflenen kullanıcı akışı hakkında bir ürün kararı gerektiriyor.

Bu maddelerin her biri, §3'teki on maddeyle AYNI titiz süreçle bulundu —
fark nasıl bulunduklarında değil, sorumlu bir şekilde kapatmanın tek bir
test yazmaktan fazlasını gerektirmesinde.

---

## 5. Geçerlilik ve gelecekte nasıl güncellenir

Bu belge, `da18340` commit'ine (2026-09-11) kadar tamamlanan HER mutasyon
testi turunu yansıtıyor — elle yazılan 100 senaryolu tur, tam 200'lük
kripto/güvenlik kataloğu (4 parçanın tamamı), ve §2'de atıf verilen iki
önceki kısmi tur. Her tek mutasyonun satır satır ham kaydı `BACKLOG.md`'de
"Mutasyon Araştırmaları" başlığı altında yaşıyor ve bu özetle o kayıt
herhangi bir noktada çelişirse doğru kabul edilecek kaynak odur.

**Yeni bir mutasyon turu çalıştırıldığında:** ham sonuçlar önce
`BACKLOG.md`'ye, kendinden önceki her tur gibi, aynen giriyor. Bu belge
DAHA SONRA o kayıttan tazelenir — §2'nin toplamları yeniden hesaplanır,
§3 yalnızca yeni bir bulgu gerçekten yerini aldığı maddeden daha çarpıcıysa
değiştirilir, §4'ün listesi maddeler kapandıkça ya da yenileri açıldıkça
güncellenir. Bu sayfa `BACKLOG.md`'nin bir özeti, hiçbir zaman tersi
değil — altındaki kaydın söylemediği bir şeyi söyleyecek şekilde
düzenlenmemeli.

[^1t]: `CORE/disposal.py::purge_file()`/`purge_expired_file()` artık
`CORE/secure_erase.py::shred_file()`'ı çağırıyor. Backlog: `B-134`.
[^2t]: `CORE/vault_manager.py::_rewrite_vault()`, `CORE/checkout.py`'nin
zaten kullandığı geçici dosya → `fsync` → `os.replace()` deseniyle
hizalandı. Backlog: `B-142`.
[^3t]: `UI/main_window_lock.py::_trigger_usb_reauth()`; test:
`tests/test_lock_overlay.py::test_trigger_usb_reauth_kara_listedeki_cihazi_DOGRU_pinle_bile_ACMIYOR`.
Bkz. SECURITY.md §4.1. Katalog kimliği: MC-M147.
[^4t]: `DB/migrations.py::_m27_audit_log_immutable()` — `audit_log`
üzerinde dört SQLite tetikleyicisi (`DELETE`/içerik `UPDATE`, koşulsuz).
Backlog: `B-132`.
[^5t]: `UI/main_window.py` (`self._idle_timer.start()`); test:
`test_idle_timer_gercekten_baslatiliyor`. Katalog kimliği: MC-M098.
[^6t]: `CORE/vault_manager.py`, altı çağrı noktası,
`CORE.crypto.zero_bytearray()` kullanılarak. Backlog: `B-139`.
[^7t]: `CORE/crypto.py::_derive_file_key()` — HKDF-SHA256 dosya-başına
alt-anahtar, versiyon-kapılı (eski dosyalar değişmeden okunmaya devam
ediyor). Backlog: `B-140`.
[^8t]: `UI/RecoveryShareDialog.py` — mevcut ekran-yakalama dışlamasının
etrafına göster-talep-üzerine bloğu eklendi. Backlog: `B-144`.
[^9t]: `UI/main_window.py::closeEvent()` — zaman aşımlı
`QThreadPool.waitForDone()` eklendi. Backlog: `B-143`.
[^10t]: `CORE/disposal.py::move_to_imha()`; test:
`test_ttl_sayaci_gercekten_saat_biriminde`. Katalog kimliği: MC-M180.
