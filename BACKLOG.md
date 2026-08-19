# HYCLEUS — Backlog

Planın doğrudan kapsamadığı, sonraya bırakılan bulgular.

## Numara kullanımı

B-NNN numaraları **bir kez** verilir ve geri dönüştürülmez — bir bulgu
numarasını aldıktan sonra aynı turda düzeltilse ve bu dosyaya hiç girmese
bile o numara harcanmış sayılır. Aksi hâlde commit mesajlarındaki atıflar
zamanla başka bir bulguya işaret etmeye başlar.

Harcanmış ama bu dosyada görünmeyen numaralar:

| No | Nerede | Ne oldu |
|---|---|---|
| B-005 | `5463cc9` — "added_by kaydi duzeltmesi" | `files.added_by` hiçbir kod tarafından yazılmıyordu. Numara verildi, bulgu aynı commit'te düzeltildi, backlog'a hiç girmedi. |
| B-008 | `60d6255` sonrası — B-008 düzeltmesi | Arayüzdeki imha sayacı saklama korumasını atlıyordu. İki ayrı silme uygulaması `CORE.disposal.purge_expired_file()` altında birleştirildi; ikinci bir uygulamanın geri gelmesini AST denetimi engelliyor (`tests/test_disposal.py::test_iki_akis_ayni_fonksiyonu_cagiriyor`). |
| B-012 | `3.5` turu sonu — B-012 düzeltmesi | `decrypt_file()` başlığı kendi başına ayrıştırıyor, `verify_file()`'ın dört uzunluk kontrolünün hiçbirini yapmıyordu: kesik dosyada `IndexError`, beş baytlık dosyada `struct.error` (ikincisini fuzzing buldu). İkisi de belgelenmiş kümenin dışındaydı. Kök neden eksik `if`'ler değil İKİ KOPYAYDI; `CORE.crypto._read_header()` altında birleştirildi. Her korumanın kendi mesajı var ve mesajlar testte sabitlendi — mesaj sabitlenmeden iki koruma mutasyonla ölmüyordu. İkinci bir uygulamanın geri gelmesini AST denetimi engelliyor (`tests/test_crypto.py::test_iki_okuma_yolu_ayni_basligi_kullaniyor`). |
| B-017 | `3.5` turu sonu — B-017 düzeltmesi | Sürüm dizesi beş yerde elle yazılıydı ve beşi farklı şey söylüyordu (etiket `v2.1.2`, SECURITY.md `v2.1.0`, README rozeti `2.0`, Hakkında `v1.6`, İletişim `v1.5`). Bildirim akışını kırıyordu: §6.3 "etkilenen sürüm" istiyor, kullanıcının gördüğü tek sürüm yanlıştı. `CORE/version.py` tek kaynak oldu; arayüz oradan okuyor, belgeler `tests/test_version.py` ile karşılaştırılıyor (belgeler kod okuyamıyor, ayrışmaları yine sessiz olurdu). İki sabit var ve ikisi de gerekli: `__version__` (çalıştırılan kod) ve `SON_YAYIN` (düzeltme alan etiket). Tarihsel "v2.1.0'a kadar…" atıfları toplu değiştirmeden korundu, ayrı test var. |
| B-021 | `3.5` turu sonu — B-021 düzeltmesi | `reconstruct_key()`, Lagrange sonucu `[2**256, asal)` aralığına düştüğünde `to_bytes(32)` ile `OverflowError` fırlatıyordu; docstring yalnızca `ValueError` vaat ediyor ve kurtarma akışı onu yakalıyor. Kurtarma parçası elle yazılan tek kripto girdisi olduğu için erişilebilir bir yoldu. `_sss_recover()` artık yakalayıp "parçayı kontrol edin" diyen bir `ValueError`'a çeviriyor; asıl sebep `__cause__` zincirinde kalıyor. Fuzzing bulmuştu, tohum korpusundaki girdi geri alınmayı yakalamak için yerinde bırakıldı. |
| B-011 | `①` grubu — B-011 düzeltmesi | `create_folder()`, `owner_id` `users` tablosunda yoksa uydurma bir satır yazıyordu ("yonetici", boş parola hash'i, `admin` rolü) ve aynı kaçamağın İKİNCİ kopyası `UI/main_window_table.py`'de duruyordu. Kök neden orada değildi: `main.py` `HycleusWindow`'a `user_id` hiç geçmiyordu, yani oturum kim olursa olsun sahiplik varsayılan **1**'e yazılıyordu. `CORE/session_user.py::sync_session_user()` girişte oturumu gerçek bir `users.id`'ye bağlıyor; satır yoksa açılan kayıt artık insan taklit etmiyor (`vault:<hwid>`, gerçek rol, ayrıştırılamaz parola sentinel'i) ve denetim kaydına düşüyor. Kaçamak iki yerden de kaldırıldı; `user_id` argümanının sessizce düşmesini AST denetimleri engelliyor (`tests/test_session_user.py`). |
| B-007 | `①` grubu — B-007 düzeltmesi | Mahrem etiketli (`tags.is_private = 1`) bir dosya `files_by_label()` ve `search_files()` görünümlerinde yönetici olmayandan gizlenirken `files_by_folder()`'da GÖRÜNÜYORDU; klasör görünümünde arayüz tarafında da engel yoktu. Dört görünüm de artık `include_private` alıyor ve dördü de role bağlı çağrılıyor. Kenar çubuğu engeli KALDIRILMADI — iki katman birlikte duruyor. Varsayılan bilerek `True` bırakıldı (ters çevirmek, parametre geçmeyen çağrılarda sessizce veri gizlerdi); asıl korumayı çağrı yerlerinin parametreyi açıkça vermesi sağlıyor ve bunu AST denetimi sabitliyor. İki `does_NOT` sabitleme testi bilerek kırılıp beklenen davranışa çevrildi. |
| B-009 | `①` grubu — B-009 düzeltmesi | `export_to_directory()` `aad_metadata`'yı döngü içinde dosya başına bir sorguyla okuyordu; `export_to_zip()` aynı bilgiyi zaten tek sorguda alıyordu. `aad_map()` tek `WHERE id IN (...)` ile önden okuyor, 900'lük parçalara bölüyor (SQLite'ın eski `SQLITE_MAX_VARIABLE_NUMBER` sınırı) ve tekrarlı id'leri tekilleştiriyor. Ölçüm sorgu SAYISINA bakıyor, kodun şekline değil. |
| B-010 | `①` grubu — B-010 düzeltmesi | İki indirme akışı, DB'nin `aad_metadata` sütununda hwid bulunmadığında ayrışıyordu: ZIP oturum hwid'iyle doğrulayıp dosyayı atlıyor, toplu indirme `hwid=None` geçtiği için kontrolü hiç çalıştırmıyordu. Fark yalnızca DB sütunu ile DOSYANIN AAD'ı ayrıştığında görünür (kontrol `decrypt_file` içinde ve dosyanın kendi AAD'ına bakıyor). ZIP'in davranışı doğru kabul edildi: sütunun eksilmesi "bu dosya bu cihazda mı şifrelendi" sorusunu geçersiz kılmıyor. Toplu indirme artık `hwid_fallback` alıyor. Kabul edilen risk: DB'si eksilmiş ve başka cihazda şifrelenmiş dosyalar toplu indirmede de atlanıyor — ama ZIP'te zaten atlanıyordu. |
| B-004 | `④` grubu — B-004 düzeltmesi | İmha Odası sayacını işleten tek yer `UI/main_window_table.py::_tick_expiry` idi ve o metot `if self._current_label != "Imha": return` ile başlıyordu — süresi dolmuş dosya, kullanıcı o sekmeye girmedikçe diskte kalıyordu. Zamanlayıcının `_purge_expired` görevi artık `Karantina` yanında `Imha` etiketini de işliyor; iki etiket ayrı denetim kaynağı yazıyor (`quarantine_ttl` / `imha_ttl`). Arayüz sayacı KALDIRILMADI, ikisi de aynı `purge_expired_file()`'ı çağırıyor (B-008). Saklama süpürmesiyle gelen `expires_at = NULL` satırlar korunuyor; korumanın kaynağı SQLite'ın üç değerli mantığı (`datetime(NULL) <= …` → NULL), ölçüldü. Bu maddeyi "son çalışma zamanı + kapı" deseni ÇÖZMEDİ: oradaki kapı global değil dosya başına. |
| B-015 | `④` grubu — B-015 düzeltmesi | Yedekleme özelliği vardı ama HATIRLATMASI yoktu; yedek yalnızca kullanıcının aklına geldiğinde alınıyordu. `CORE/backup_reminder.py` eklendi ve `ZamanKapisi`'nı (`backup_last_run`) kullanıyor — ④ grubunda deseni gerçekten kullanan tek madde. Damga `create_backup()` içinde yazılıyor, arayüzde değil: CLI'dan alınan yedekler de hatırlatmayı susturmalı. Uyarı ENGELLEYİCİ değil, "sonra sorma" bir eşik süresi kadar (süresiz değil) ve eşik `0` hatırlatmayı kapatıyor. "Hedef erişilemiyor" ile "hiç yedek yok" AYRI durumlar — harici disk takılı değilse yedek yok değil, görünmüyor. Negatif eşik kapatmıyor, varsayılana düşüyor. |
| B-006 | `④` grubu — B-006 düzeltmesi | Zincir doğrulaması üç yerden çağrılabiliyordu ama arayüzde düğmesi yoktu; TXT dışa aktarımı da yalnızca dört sütun yazıyor, hash/son uç/doğrulama durumu taşımıyordu. `CORE/audit_report.py` iki doğrulamayı (`verify_audit_chain` + `verify_against_anchor`) birleştirip METİN üretiyor; AdminPanel'e "Zinciri Doğrula" düğmesi eklendi (panel zaten `role != "Yönetici"` ise hiç kurulmuyor) ve sonuç `audit_chain_verified` olarak denetim kaydına düşüyor — doğrulayan kullanıcı B-011'in `users` satırından okunuyor, yan etkisiz `kullanici_bilgisi()` ile. TXT başlığı artık zincir durumunu, son hash'i, ilk kırılma id'sini ve "bu dosya imzalı DEĞİLDİR" sınırını taşıyor. Bu madde de "son çalışma zamanı + kapı" desenini KULLANMIYOR: zamanlanmış bir iş değil, kullanıcının bastığı bir düğme. |
| B-022 | `③` grubu — B-022 düzeltmesi | `hwid_probe.read_windows()` yalnızca `Win32_DiskDrive.PNPDeviceID`'yi okuyordu; o USBSTOR (depolama) düğümü ve seriye `&<n>` örnek soneki ekliyor. Onaltılık bir seri artı `&0`, "üretilmiş kimlik" desenine tam uyduğu için prototip SERİLİ token'a "serisiz" diyordu — SanDisk'te sistematik, ve B-016 kararını ters yöne itecek bir ölçüm hatası. Artık `Win32_PnPEntity` üzerinden USB düğümü de okunuyor ve seriyle eşleştiriliyor; VID/PID de oradan geliyor (eski `????:????` çıktısı bunun belirtisiydi). Eşleştirme saf bir fonksiyona (`build_windows_identity`) ayrıldı, artık WMI'siz test edilebiliyor. Yanında `normalize_serial()`'ın `.lstrip("0")`'ı kaldırıldı: `0123ABC` ile `123ABC`'yi aynı kimliğe indiriyordu — kimlik üreten bir fonksiyonda ÇAKIŞMA, kapatmaya çalıştığı (ve hiç ölçülmemiş) dolgu farkından ağır basar. İki sabitleme testi bilerek kırıldı. **2026-08-19:** gerçek bir aygıtla doğrulandı — prototip tanımlayıcı serisini okuyor, `generated=False`, VID/PID çözülüyor (eski `????:????` yok). Ölçüm SanDisk'le DEĞİL, o sırada takılı olan `30DE:6544` aygıtıyla yapıldı; mekanizma doğrulandı, özgün yanlış negatifi üreten aygıtta tekrar ölçüm hâlâ yapılmadı (bkz. B-016). |
| B-019 | `②` grubu — B-019 düzeltmesi | `.github/scripts/test_summary.py` JUnit XML'ini `xml.etree.ElementTree` ile okuyordu ("billion laughs" iç varlık genişlemesine açık). Girdi kendi CI'ımızın ürettiği dosya olduğu için bulgu bir süre bilinçli açık bırakılmıştı; kapatma kararının gerekçesi maliyetin iki satır olması ve `defusedxml`'in saf Python / bağımlılıksız / ~30 KB olması. İthalat KOŞULLU: paket yoksa stdlib'e düşüyor, çünkü betik CI dışında da elle çalıştırılıyor ve bir bağımlılık eksikliği yüzünden hiç konuşmaması raporladığı sorundan kötü olurdu. `XML_HATALARI` demeti `DefusedXmlException`'ı da yakalıyor — yoksa düşmanca XML'de betik temiz mesaj yerine izlemeyle düşerdi, yani koruma eklenirken raporlama bozulurdu. |
| B-013 | `512e7be` → düzeltme aynı seride | `setup_usb.py` İngilizce Windows konsolunda (cp1252/cp437) çöküyordu. Bir tur backlog'da durdu, sonra `CORE/console.py` yardımcısıyla düzeltildi ve madde kaldırıldı. Düzeltme: `setup_usb.py` + `recover_vault.py` artık `ensure_utf8_console()` çağırıyor; kuralı AST ile denetleyen test `tests/test_console.py` içinde. |

> Yeni madde açarken bu tabloya da bakın; yalnızca aşağıdaki en büyük
> numaraya bakmak yetmez.

---

## B-001 — Karantina dosya adı çakışması (sessiz üzerine yazma)

**Durum:** Açık — şimdilik dokunulmayacak
**Öncelik:** Orta (veri kaybı riski, kripto zafiyeti **değil**)
**İlgili:** v2.2 / 2.6 "tekrar tespiti" ile dolaylı ilişkili
**Bulundu:** 2026-08-12, kripto çekirdeği test çalışması sırasında

### Bulgu

[`CORE/crypto.py`](CORE/crypto.py) içindeki `encrypt_file()` çıktı yolunu sabit
biçimde üretiyor:

```python
dst = _QUARANTINE_DIR / f"{src.name}.hcl"
```

Aynı ada sahip iki farklı dosya şifrelendiğinde ikincisi birincisini **uyarı
vermeden** eziyor (`open(dst, "wb")`). Farklı dizinlerden gelen `rapor.pdf`
dosyaları tek bir `rapor.pdf.hcl` hedefini paylaşıyor.

### Etkisi

- İlk dosyanın şifreli içeriği geri dönülemez şekilde kayboluyor; ona ait
  anahtar/AAD artık hiçbir şeyi çözmüyor.
- DB'deki `files` kaydı (`filepath` UNIQUE) mevcut satırı gösterirken diskteki
  içerik başka bir dosyaya ait oluyor → kayıt ile içerik ayrışıyor.
- Kripto katmanı sağlam: GCM tag ve AAD doğrulaması etkilenmiyor, sızıntı yok.
  Sorun tamamen dosya yaşam döngüsünde.

### 2.6 ile ilişki

"Tekrar tespiti" zaten içerik özetine (`original_sha256`) göre aynı dosyanın
yeniden yüklenmesini yakalayacak. O mekanizma geldiğinde bu iki durumu
ayırmak gerekecek:

- **aynı ad + aynı içerik** → tekrar; yeni kayıt açma, mevcuda bağla
- **aynı ad + farklı içerik** → çakışma; ayrı hedef yol üret

### Olası çözüm (uygulanmadı)

Hedef adı çakışmaz hale getirmek — ör. `<ad>.<sha256[:12]>.hcl` veya
`<ad>.<file_id>.hcl`. Karar 2.6 tasarımıyla birlikte verilmeli; şimdi
değiştirilirse mevcut karantina dosyalarının yeniden adlandırılması için
migration gerekir.

### Doğrulama notu

Test paketi bu davranıştan etkilenmiyor: [`tests/test_crypto.py`](tests/test_crypto.py)
`_QUARANTINE_DIR`'i test başına `tmp_path`'e yönlendiriyor, dolayısıyla
çakışma testleri gizlemiyor — ama testler bu senaryoyu **kapsamıyor** da.

---

## B-002 — Lint / tip denetimi sıkılaştırması

**Durum:** **KISMİ** — ruff tarafı büyük ölçüde kapandı (2026-08-17),
mypy tarafı açık
**Öncelik:** Düşük (teknik borç, çalışma zamanı etkisi yok)
**İlgili:** 1.3 (CI kurulumu) ile birlikte açıldı; B-018 birebir aynı desen
**Bulundu:** 2026-08-13, CI kurulumu sırasında

### Kapanan kısım — ruff

Genel `ignore` listesi **boşaltıldı**. Dört kural temizlenip depo genelinde
açıldı:

| Kural | Adet | Nasıl |
|---|---:|---|
| `F401` kullanılmayan import | 13 | `ruff --fix`; her biri re-export olmadığı doğrulandıktan sonra |
| `F541` boş f-string | 2 | `ruff --fix` |
| `F841` kullanılmayan yerel | 3 | elle; biri B-011 düzeltmesinden kalan artıktı |
| `E741` belirsiz ad `l` | 1 | `etiket` olarak yeniden adlandırıldı |

Belgelenmiş sayılar (33/8/3/1/1) **güncel değildi**; gerçek sayım
2026-08-17'de yapıldı.

`E402` hâlâ susturuluyor ama artık **depo genelinde değil** — yalnızca
ihlal eden dosyalarda (`per-file-ignores`). Yeni bir dosyada E402 çıkarsa
CI söyler; ölçülerek doğrulandı.

**Belgelenen gerekçe YANLIŞTI ve düzeltildi.** Eski yorum E402'yi "sys.path
bootstrap'ı" ile açıklıyor ve `setup_usb.py`/`usb_manager.py`/
`vault_manager.py`'yi gösteriyordu. Ölçüm: UI/ ve `main.py`'de `sys.path`
bootstrap'ı **hiç yok**. Gerçek sebep importların arasına serpilmiş
`logging` ifadeleri.

### Kalan — iki iş

1. **E402'nin kendisi.** `_log = logging.getLogger(...)` satırlarını
   importların altına almak mekanik ve güvenli (11 dosya). Ama
   `main.py`'deki `logging.basicConfig(...)` öyle DEĞİL: import sırasında
   log yazan bir modül varsa taşımak çıktıyı sessizce değiştirir. Karışık
   bir işi "mekanik temizlik" diye yapmamak için ikisi de bırakıldı.
2. **mypy.** Gevşetilenler duruyor: `ignore_missing_imports = true`,
   `check_untyped_defs = false`, `strict` kapalı, `UI/` tamamen hariç.
   Sıra: önce `check_untyped_defs = true`, sonra `CORE/` için
   `disallow_untyped_defs = true` (CORE zaten büyük ölçüde tipli — en
   düşük maliyetli adım burası), en sonra `UI/` için PySide6 stub durumu.

### Not

`CORE/` ve `DB/` altında `__init__.py` yok (PEP 420 namespace paketleri).
mypy bu yüzden `explicit_package_bases` + `mypy_path = "."` ile
yapılandırıldı; bunlar olmadan `CORE/x.py` hem `x` hem `CORE.x` olarak
görülüp "Source file found twice" hatası veriyor.

---

## B-003 — Mevcut 4-5 haneli PIN kullanıcılarını 6 haneye taşıma

**Durum:** Açık — geçici köprü devrede
**Öncelik:** **Orta.** Güvenlik açığı değil, politika boşluğu: yeni kayıtlar
6 hane zorunlu ama eski hesaplar süresiz olarak 4-5 hanede kalabiliyor.
Yani politikanın koruduğu şey (kısa PIN'e karşı kaba kuvvet direnci) tam
olarak en eski — ve büyük ihtimalle en yetkili — hesaplarda geçerli değil.
Acil değil, çünkü PIN tek başına yeterli değil: fiziksel USB + TOTP de
gerekiyor. Ama "yaptık" sayılmaması gereken bir iş.
**İlgili:** PIN politikası 4 → 6 değişikliği (`f3b70cf`)
**Bulundu:** 2026-08-13

### Durum

PIN minimum uzunluğu 4'ten 6'ya çıkarıldı ([`CORE/pin_policy.py`](CORE/pin_policy.py)).
Ancak politika değişmeden önce kaydolmuş kullanıcıların PIN'i 4-5 hane
olabilir ve Argon2id hash'i uzunluktan bağımsız doğrulandığı için bu PIN'ler
hâlâ geçerlidir.

Giriş ekranındaki uzunluk kontrolü `PIN_MIN_LEN` (6) ile yapılsaydı bu
kullanıcılar kendi doğru PIN'leriyle giriş yapamazdı — **sessiz bir
lockout**, üstelik hata mesajı da yanıltıcı olurdu. Bu yüzden giriş eşiği
ayrı bir sabite alındı:

```python
PIN_MIN_LEN   = 6   # yeni PIN belirlerken
LOGIN_MIN_LEN = 4   # giriş ekranı — geçici köprü
```

> ⚠️ `LOGIN_MIN_LEN` **`PIN_MIN_LEN` ile aynı yapılmamalıdır.** İkisi
> eşitlenirse eski PIN sahipleri sessizce kilitlenir. Bu invariant
> [`tests/test_pin_policy.py`](tests/test_pin_policy.py) içinde
> `test_login_floor_stays_below_new_policy` ile korunuyor.

### Yapılacak — zorunlu PIN yenileme akışı

1. **Tespit:** Başarılı girişten sonra kullanılan PIN'in uzunluğuna bak.
   PIN düz metin olarak yalnızca o anda elde, hash'ten uzunluk çıkarılamaz —
   yani kontrol `_on_login` içinde, doğrulama başarılı olduktan hemen sonra
   yapılmalı.
2. **Yönlendirme:** `len(pin) < PIN_MIN_LEN` ise ana pencereyi açmadan önce
   zorunlu PIN değiştirme diyaloğunu göster (iptal edilemez).
3. **Uygulama:** `CORE.vault_manager.change_vault_pin(hwid, old, new)` zaten
   var; yeni PIN `validate_new_pin()` ile doğrulanır.
4. **Audit:** `db.log("pin_rotation_forced", ...)` düşülmeli.
5. **Kapanış:** Tüm kullanıcılar taşındıktan sonra `LOGIN_MIN_LEN`
   kaldırılıp giriş kontrolü de `PIN_MIN_LEN`'e çekilebilir. Bu adım
   atılmadan köprü kaldırılmamalı.

### Alternatif (daha zayıf)

Zorunlu yerine uyarı: girişte "PIN'iniz kısa, güncelleyin" bildirimi. Daha
az müdahaleci ama politika boşluğunu kapatmaz — kullanıcı süresiz erteler.
Yalnızca geçiş dönemini yumuşatmak için, zorunlu akışın öncesinde
kullanılmalı.

---

## B-014 — `files.hash_sha256` ölü sütun

**Durum:** Açık — 2.6 (tekrar tespiti) turunda fark edildi, plan dışı olduğu için dokunulmadı

`files` tablosunda iki özet sütunu var ve yalnızca biri kullanılıyor:

| Sütun | Yazan | Okuyan |
|---|---|---|
| `original_sha256` | `CORE/file_records.py` | `CORE/duplicates.py`, `CORE/file_queries.py`, arayüz |
| `hash_sha256` | **hiç kimse** | **hiç kimse** |

Depoda tek geçtiği yer şema tanımının kendisi (`DB/db_manager.py:34`).

### Etkisi

Doğrudan bir hata değil — boş bir sütun yer kaplıyor, o kadar. Asıl risk
YANILTICI OLMASI: adı, iki sütundan "dosyanın hash'i" gibi duran daha genel
olanı. Tekrar tespitini yazarken doğal refleks `hash_sha256`'ya uzanmaktı;
her satırı NULL olduğu için sorgu hiçbir zaman eşleşme bulmaz ve özellik
sessizce çalışmaz görünürdü. Bir sonraki kişi aynı tuzağa düşebilir.

İki sütunun anlam farkı da hiçbir yerde yazılı değil: `original_sha256`
DÜZ METNİN özeti (şifrelemeden önce hesaplanıyor); `hash_sha256` adından
şifreli dosyanın özeti gibi duruyor ama öyle bir şey hiç üretilmedi.

### Yapılacaklar (uygulanmadı)

1. Sütunun gerçekten hiç yazılmadığını canlı bir veritabanında doğrula:
   `SELECT COUNT(*) FROM files WHERE hash_sha256 IS NOT NULL`.
2. Boşsa `ALTER TABLE files DROP COLUMN hash_sha256` (SQLite 3.35+).
   Şema sürümü `PRAGMA user_version` ile takip ediliyor
   (`CORE/secret_migration.py`), migration oraya eklenebilir.
3. Düşürülmeyecekse en azından şemaya bir yorum: sütunun terk edilmiş
   olduğunu ve `original_sha256` kullanılması gerektiğini yaz.

Şimdilik `CORE/duplicates.py` modül docstring'i bu ayrımı açıklıyor.

---

## B-016 — Çapraz platform HWID kararı (Windows kapandı, Linux ayağı kaldı)

**Durum:** Açık — Windows tarafında sorulacak şey kalmadı; **yalnızca Linux
ölçümü bekliyor**
**Öncelik:** Düşük — ölçümler aciliyeti düşürdü (aşağıya bakın)
**İlgili:** 3.4 prototipi — [`CORE/hwid_probe.py`](CORE/hwid_probe.py),
[`docs/hwid-crossplatform.md`](docs/hwid-crossplatform.md), B-022
**Bulundu:** 2026-08-15
**Ölçüldü:** 2026-08-16 — gerçek USB token fiziksel olarak takılı halde,
**iki ayrı portta**

### Neden açık madde

3.4 turunda "USB donanım serisi üç işletim sisteminde tutarlı okunuyor mu"
sorusu araştırıldı ve rapor "hayır, dosya tabanlı token'a geçilmeli" dedi.
O rapor, HYCLEUS'un fiilen kullandığı USB takılı **değilken** yazılmıştı.

### Ölçüm sonucu — gerçek USB ile doğrulandı

Aygıt: SanDisk Cruzer Blade, `VID_0781` / `PID_5567`, 14,6 GB.

Seri numarası **var ve temiz okunuyor.** Değeri buraya yazılmıyor: `hwid`
`_derive_signing_key()` içinde HKDF girdisi ve kasa dosyasının AAD'ı
(`CORE/vault_manager.py`), yani gizli-bitişik bir değer. Biçimi:

```
20 karakter, [0-9A-F], SanDisk ön eki '4C53' + 16 hane   →  4C53XXXXXXXXXXXXXXXX
```

Okunan alanlar:

| Kaynak | Değer |
|---|---|
| `USB\VID_0781&PID_5567\<instance>` (USB yığını) | `<seri>` — üçüncü segmentte `&` yok, yani **tanımlayıcı serisi** |
| `USBSTOR\DISK&VEN_SANDISK&…\<instance>` (depolama yığını) | `<seri>&0` — aynı seri, USBSTOR'un eklediği `&0` örnek soneki |
| `Win32_DiskDrive.SerialNumber` | `<seri>` — **birebir aynı** |
| `usb_manager.get_usb_hwid()` | `<seri>` — `_sanitize_hwid()` hiçbir karakteri düşürmüyor |
| `data/usb_ids.json` | **dosya yok** — UUID fallback'ine hiç düşülmemiş |

3.4'ün korktuğu **alan belirsizliği bu aygıtta yok**: depolama yığını ile
USB tanımlayıcısı aynı dizeyi söylüyor. Linux'un `ID_SERIAL_SHORT`'u da
iSerialNumber'dan doldurduğu için aynı dizeyi vermesi bekleniyor — ama
bu **ölçülmedi**, çıkarım.

Aynı makinedeki 14 USB düğümünden (kök hublar hariç) **yalnızca 1'inde**
tanımlayıcı serisi var: o da bu token. Diğer 13'ü serisiz. Yani 3.4'ün
"çoğu aygıtta seri yok" bulgusu **doğruydu** ama yanlış popülasyonu
ölçüyordu: dahili çevre birimleri serisiz, USB *depolama* aygıtı serili.

### Buradan çıkan karar

| İddia | Ölçümden sonra |
|---|---|
| "USB spec'inde `iSerialNumber` opsiyoneldir, çoğu aygıtta yok" | **Geçerli** — 14 düğümün 13'ü |
| "Üç OS farklı yığınlardan okuyor, aynı alan garanti değil" | **Geçerli** ama bu aygıtta iki Windows yığını uyuşuyor |
| "HYCLEUS'un fiilen kullandığı USB'de seri yok" | **YANLIŞ** — seri var, temiz okunuyor, fallback'e düşülmüyor |
| "Serisiz USB başka makinede farklı HWID alır" | **Geçerli** — ama bu token serisiz değil, dolayısıyla etkilenmiyor |

Karar ağacının "**Seri VAR ve temiz okunuyorsa**" dalındayız: dosya tabanlı
token'a geçiş **aciliyetini yitirdi**. Taşınabilirlik sorunu yalnızca
serisiz aygıtlarda kalıyor ve orada nokta atışı çözüm `usb_ids.json`
eşlemesini makine yerine USB'nin kendisine taşımak — tüm mimariyi
değiştirmek değil.

**Bu madde yine de kapanmıyor**, çünkü karar tek bir aygıtın ölçümüne
dayanıyor. Seri taşımayan ucuz bir çubukla kaydolmuş bir kullanıcı hâlâ
`usb_ids.json` yoluna düşer ve o kullanıcı için taşınabilirlik kırık.

### Port bağımsızlığı — artık çıkarım değil, ölçüm (2026-08-16)

Aynı çubuk **başka bir fiziksel porta** takılıp `get_usb_hwid()` tekrar
okundu. Sonuç: **HWID birebir aynı** — iki okuma karakter karakter eşleşti,
uzunluk 20. `usb_ids.json` yine oluşmadı.

(Karşılaştırma bellekte yapıldı; ne değer ne de özeti buraya yazıldı. Seri
uzayı pratikte `4C53` + 16 hane, yani kısa bir özet öneki bile kaba kuvvete
açık bir ipucu olurdu — `hwid` `_derive_signing_key()`'in HKDF girdisi.)

Yeni porttaki konum (ileride tekrar ölçmek isteyen için taban çizgisi):

```
DEVPKEY_Device_LocationInfo  = Port_#0009.Hub_#0004
DEVPKEY_Device_Parent        = USB\ROOT_HUB30\7&dacba&0&0
```

Bu, verinin yapısıyla da tutarlı ve sebebi görünür durumda:

- USB yığını düğümünün instance ID'si **serinin kendisi** — içinde port ya
  da hub bilgisi yok, dolayısıyla taşınacak bir port bağımlılığı yok.
- USBSTOR düğümündeki `&0` soneki bir **örnek sayacı**, port numarası
  değil.

Yani "seri port yoluna bağlı değil" artık belgelenmiş kuraldan çıkarım
değil, bu aygıtta ölçülmüş bir gerçek.

> **Ölçümün sınırı:** portun gerçekten değiştiği kullanıcının beyanına
> dayanıyor. İlk ölçümde `LocationInfo` kaydedilmemişti, bu yüzden iki
> konum programatik olarak karşılaştırılamadı. Yukarıdaki taban çizgisi
> tam da bunun için yazıldı — bir sonraki port testi karşılaştırılabilir
> olacak.

### 2026-08-19 ölçümü — BAŞKA BİR AYGIT, ve yeni bir bulgu

Düzeltilmiş prototiple tekrar ölçüm istendi ("aynı USB'nin aynı serisini
doğru okuduğunu doğrula"). **Takılı aygıt yukarıdakiyle aynı değil.**
Karşılaştırma, seri değerine hiç bakmadan yapıldı:

| | 2026-08-16 (SanDisk) | 2026-08-19 (takılı olan) |
|---|---|---|
| VID:PID | `0781:5567` | `30DE:6544` |
| tanımlayıcı serisi | 20 karakter, `[0-9A-F]` | 24 karakter, harf+rakam |
| `Win32_DiskDrive.SerialNumber` | seriyle **birebir aynı** | **2 karakter, yazdırılamayan** |
| `get_usb_hwid()` | seri (20 karakter) | **36 karakter — UUID** |
| `usb_ids.json` | dosya yok | kayıt **var** |

Dört alan da ayrışıyor; bu, aynı çubuğun farklı okunması değil, farklı bir
çubuk. Dolayısıyla "aynı USB'nin aynı serisi" sorusu bu turda
CEVAPLANAMADI — SanDisk takılı değildi.

Bu makinede o an bağlı **tek** USB depolama aygıtı bu; `read_windows()` de
`get_usb_hwid()` de aynı aygıtı görüyor.

#### B-022 düzeltmesi bu aygıtta ÇALIŞIYOR

Prototip tanımlayıcı serisini okuyor (`generated=False`, `stable_id`
üretiliyor) ve VID/PID'yi çözüyor — eski hatanın belirtisi olan
`????:????` çıktısı yok. Yani mekanizma doğrulandı; ama özgün yanlış
negatifi üreten aygıtta değil, başka bir aygıtta.

#### Yeni bulgu — bu maddenin öngördüğü dal artık ÖLÇÜLDÜ

Bu madde "seri taşımayan bir çubukla kaydolmuş kullanıcı hâlâ
`usb_ids.json` yoluna düşer" diyordu ve bunu bir ihtimal olarak
yazıyordu. Takılı aygıtta o dal GERÇEKLEŞTİ, üstelik beklenenden kötü
bir biçimde: aygıtın tanımlayıcı serisi **var** (24 karakter), ama
`get_usb_hwid()` ona hiç bakmıyor — yalnızca `Win32_DiskDrive`'ı
okuyor ve orası bu aygıtta bozuk değer veriyor.

Kimliğin dosyadan türediği ölçüldü: `usb_ids.json` geçici olarak
kaldırılıp `get_usb_hwid()` yeniden çağrıldığında **farklı bir değer**
döndü. (Dosya hemen geri yüklendi, token'ın kimliği ölçümden önceki
hâline döndürüldü ve doğrulandı.)

Ayrıntı ve sonuçları B-025'te.

#### Port bağımsızlığı ölçümü etkilendi mi

Hayır. O ölçüm SanDisk ile yapıldı ve `usb_ids.json` o sırada hiç
oluşmamıştı — yani UUID yoluna düşmemişti, gerçekten seriyi ölçüyordu.
Bugünkü aygıt için aynı şey söylenemez ve onunla port testi yapmanın
anlamı da yok: UUID zaten dosyadan geliyor, portla değişmeyeceği
önceden belli.

### Kalan tek ölçüm — FİZİKSEL TEST ORTAMI GEREKTİRİYOR

> **Kod tarafı bitti (2026-08-17).** Ölçüm aracındaki hata düzeltildi
> (B-022 kapandı): prototip artık USB yığını düğümünü okuyor ve serili
> aygıta "serisiz" demiyor. Bu madde artık bir KOD işi değil, bir
> DONANIM işi bekliyor.

**Aynı çubuk Linux'ta** — `ID_SERIAL_SHORT` aynı dizeyi mi veriyor.
Çapraz platform iddiasının tek gerçek testi bu; Windows tarafında
sorulacak bir şey kalmadı.

### Dikkat

Geçiş yapılırsa gerekçe **taşınabilirlik**tir, güvenlik değil. Token
dosyası da seri numarası kadar kopyalanabilir; HWID zaten uygulama
seviyesi bir kontrol (SECURITY.md §4.5). "Daha güvenli oldu" denirse
yanlış olur.

### Dikkat

Geçiş yapılırsa gerekçe **taşınabilirlik**tir, güvenlik değil. Token
dosyası da seri numarası kadar kopyalanabilir; HWID zaten uygulama
seviyesi bir kontrol (SECURITY.md §4.5). "Daha güvenli oldu" denirse
yanlış olur.

---

## B-018 — bandit'in susturulan denetimleri temizlenmedi

**Durum:** **KISMİ** — B607 kapandı (2026-08-17), B608/B110 açık
**Kapanan kısım:** `B607` düzeltildi ve denetim depo genelinde AÇILDI:
`wmic` tam yola çevrildi (`CORE/usb_manager.py::_wmic_yolu`), `open` ve
`xdg-open` satırda gerekçeli `# nosec B607` aldı. Kazanç düzeltmenin
kendisi değil, denetimin açık kalması — YENİ bir kısmi yol çağrısı artık
CI'da yakalanıyor.
**Kalan:** `B608` (13 satır) ve `B110` (15 blok) — ikisi de incelendi ve
susturulmuş durumda; bilinçli olarak bu turda ele alınmadı.
**Öncelik:** Düşük (teknik borç) — tek "gerçek" bulgu olan B607 kapandı
**İlgili:** 3.5 (denetime hazırlık), B-002 ile birebir aynı desen
**Bulundu:** 2026-08-16, bandit'in ilk taramasında

### Bulgu

bandit devreye alınırken mevcut kodu FAIL ettirmeyecek şekilde
yapılandırıldı ([`pyproject.toml`](pyproject.toml) `[tool.bandit]`). İlk
taramada 44 bulgu çıktı; hepsi LOW/MEDIUM, hiçbiri HIGH değil.

| Denetim | Adet | Değerlendirme |
|---|---:|---|
| `B110` try/except/pass | 15 | "En iyi çaba" yolları. Bilinçli ama gerçekten geniş — `except Exception: pass` her hatayı yutuyor. |
| `B608` f-string ile SQL | 13 | **On üçü de incelendi**, hiçbirinde kullanıcı girdisi enterpolasyona girmiyor. Değerler her yerde `?` ile bağlı. |
| `B603` subprocess (shell=False) | 5 | Hepsi liste biçimi çağrı. |
| `B404` subprocess import | 4 | Bilgi amaçlı, bulgu değil. |
| `B607` kısmi çalıştırılabilir yolu | 3 | **Gerçek, düşük.** Aşağıya bakın. |
| `B101`/`B105`/`B311`/`B606` | 1'er | Satırda `# nosec <ID>` ile gerekçeli susturuldu; bu dört denetim depo genelinde AÇIK kaldı. |

### B-607 — tek gerçek bulgu

Üç çağrı çalıştırılabiliri tam yolla vermiyor:

| Yer | Komut |
|---|---|
| [`CORE/usb_manager.py`](CORE/usb_manager.py) | `wmic` |
| [`UI/main_window_open.py`](UI/main_window_open.py) | `open` (macOS) |
| [`UI/main_window_open.py`](UI/main_window_open.py) | `xdg-open` (Linux) |

Kısmi yol, `PATH` üzerinden arama demek. Saldırganın `PATH`'te önce gelen
bir dizine yazabildiği bir senaryoda kendi `wmic.exe`'si çalışır. Bu,
makineye zaten yazma erişimi gerektiriyor — yani SECURITY.md §1'in
sınırının içinde ve tek başına bir açık değil. Ama ucuz bir sertleştirme:
`wmic` için `%SystemRoot%\System32\wbem\wmic.exe` tam yolu yazılabilir.

`open` ve `xdg-open` Windows dışı yollar; HYCLEUS'un hedef platformu değil
(o dalların kendisi geliştirme ortamı için duruyor).

### Yapılacaklar (sırayla, ayrı ayrı ele alınabilir)

1. `B607` — `wmic` çağrısına tam yol ver, `skips` listesinden `B607`'yi
   çıkar. En yüksek değer/maliyet oranı burada.
2. `B608` — susturmak yerine on üç satıra tek tek `# nosec B608` yaz ve
   denetimi depo genelinde aç. Böylece YENİ bir f-string SQL yakalanır;
   bugün yakalanmıyor.
3. `B110` — `except Exception: pass` bloklarını daralt (beklenen istisna
   tipini yaz) ya da en azından `_log.debug()` ekle. Sessizce yutulan bir
   hata, olmayan bir hatadan ayırt edilemez.
4. `B404`/`B603` — kalıcı istisna sayılabilir; `subprocess` kullanımı
   bilinçli ve liste biçiminde.

### Not

`pyproject.toml`'daki gerekçe bloğunda ADETLER yazılı. Bir denetimin sayısı
değişirse yeni bir şey girmiş demektir — sayılar bilerek orada duruyor,
`tests/test_static_analysis.py::test_bandit_skips_listesi_belgeli` de her
skip'in gerekçesinin var olduğunu denetliyor.

### Kapatılmış yan bulgu — bandit'in `custom` biçimlendiricisi

Açık madde DEĞİL, kayıt: bandit 1.9'un `formatters/custom.py` dosyası,
şablonda yalnızca `{test_id}` istense bile tüm etiketleri hevesle
hesaplıyor. Bunlardan biri `os.path.relpath` ve o da sürücü sınırında
`ValueError` fırlatıyor. GitHub Windows koşucusunda çalışma alanı `D:`,
TEMP `C:` — kanarya testi bu yüzden kırıldı ve bandit "boş çıktı +
sıfırdan farklı çıkış" verdiği için "bulgu yok" ile "araç çöktü" ayırt
edilemedi. Çözüm: `-f json`. Gerekçe testin docstring'inde, yerel
üretimi `subst X:` ile yapıldı.

---

## B-020 — semgrep kural dosyasını yerel kod sayfasıyla okuyor

**Durum:** Açık — yukarı akış (upstream) sorunu, geçici çözüm devrede
**Öncelik:** Düşük (geliştirici deneyimi), ama TUZAK
**Bulundu:** 2026-08-16
**Son kontrol:** 2026-08-17 — semgrep **1.173.0** (PyPI'daki en son sürüm)
hâlâ çöküyor. `PYTHONUTF8=0` ile doğrudan yeniden üretildi:
`UnicodeDecodeError: 'charmap' codec can't decode byte 0x9e in position 506`.
Geçici çözüm yerinde kalıyor; kanarya testi de skip'e düşmedi, yani
kendi haber verme mekanizması çalışır durumda.

semgrep 1.173 `.semgrep/hycleus.yml`'yi `Path.read_text()` ile, yani
`locale.getencoding()` ile okuyor. Kural dosyası UTF-8 ve Türkçe karakter
içeriyor; Windows'ta cp1254/cp1252 locale altında çağrı çıplak bir
`UnicodeDecodeError` geri iziyle çöküyor:

```
UnicodeDecodeError: 'charmap' codec can't decode byte 0x9e in position 506
```

Bu B-013 ile **aynı sınıftan** bir hata — yalnızca bu sefer bizim kodumuzda
değil, aracın kendisinde.

### Geçici çözüm (devrede)

semgrep'i çağıran her yer `PYTHONUTF8=1` geçiyor:

| Yer | Nasıl |
|---|---|
| CI | `security` işinin `env:` bloğu |
| Testler | `tests/test_static_analysis.py::_utf8_env()` |
| Elle | `requirements-security.txt` başındaki komut satırı |

### Tuzak

`--quiet` bayrağı çöküş geri izini de bastırıyor. Yani hatalı ortamda
komut sessizce exit 2 veriyor ve "bulgu yok" gibi görünüyor. Bu tuzağa bir
kez düşüldü: kanarya testi ilk yazıldığında `--quiet` ile çalışıyordu ve
çöküşü göremeyip "sorun düzelmiş" diye ATLADI. Test artık `--quiet`
kullanmıyor; o satırın üstünde neden olduğu yazılı.

### Yapılacak

Yukarı akış düzeltirse: `PYTHONUTF8=1`'i üç yerden birden kaldır.
`tests/test_static_analysis.py::test_windows_pythonutf8_olmadan_kural_dosyasi_okunamiyor`
o gün otomatik olarak `skip`'e düşecek ve mesajında bunu söyleyecek —
yani bu maddeyi kapatma zamanını test haber verecek.

---

## B-023 — ClamAV arka ucu gerçek bir Linux kurulumunda hiç çalıştırılmadı

**Durum:** Açık — kod yazıldı ve test edildi, ÖLÇÜLMEDİ
**Öncelik:** Orta (Linux'ta tarama ya çalışıyor ya da sessizce mock)
**Bulundu:** 2026-08-17 — ClamAV entegrasyonu eklenirken, kendi kapsamı olarak

`CORE/scanner_backends.py::ClamAVBackend` `clamdscan`/`clamscan` çağırıyor
ve tüm testleri `run_tool` dikişini monkeypatch'leyerek çalışıyor. Yani
şu ana kadar doğrulanan şey **bizim eşlemelerimiz**: çıkış kodu tablosu,
`--fdpass` yerleşimi, imza adı ayrıştırma, daemon kapalıyken düşüş.

Hiç doğrulanmayan şey, ClamAV'ın GERÇEKTEN böyle davrandığı. Sahte
çalıştırıcı bizim varsayımımızı tekrar ediyor; varsayım yanlışsa test de
onunla birlikte yanlış. Bu B-016 ile aynı sınıftan bir eksik — kod tarafı
bitti, fiziksel/gerçek ortam ölçümü bekliyor.

### Ölçülmesi gerekenler (EICAR ile, sırayla)

| # | Ölçüm | Neden |
|---|---|---|
| 1 | `clamscan` temiz dosyada `rc=0`, EICAR'da `rc=1` | Eşlemenin temeli. Defender'da `2` tehdit; ters karıştırılırsa her tarama hatası "zararlı" olur |
| 2 | Bulgu satırının tam biçimi (`<yol>: <imza> FOUND`) | `parse_threat()` sondaki `": "` üzerinden bölüyor |
| 3 | `clamdscan --fdpass` kasa dizinindeki dosyayı gerçekten okuyabiliyor mu | `clamd` ayrı kullanıcı olarak çalışıyor; bayrak işe yaramazsa her tarama "Access denied" |
| 4 | Daemon KAPALIYKEN `clamdscan`'in stderr metni | Düşüş kararı `_CLAMD_ULASILAMIYOR` işaretlerine bakıyor. Metin farklıysa düşüş hiç tetiklenmez ve tarama sessizce mock'a iner |
| 5 | `clamscan` soğuk başlangıç süresi | `SCAN_TIMEOUT = 120` tahmin; imza veritabanı büyükse yetmeyebilir |

### Nasıl bakılır (kurulum gerekmeden)

```
python -m CORE.scanner              # hangi motor seçildi, araçlar nerede
python -m CORE.scanner <dosya>      # tek dosya tara, kararı yazdır
```

`4` numaralı ölçüm en sinsisi: yanlış tarafa düşerse hata **sessiz**.
Kullanıcı dosyayı yükler, tarama sütunu boş kalır, hiçbir şey bağırmaz —
bu modülün en başta düzeltmek için yazıldığı durumun aynısı.

### Kapsam notu

`ClamAVBackend` Windows dışındaki HER platformda etkin, yani macOS'ta
`clamscan` kuruluysa çalışır (komut satırı arayüzü aynı). macOS de
ölçülmedi; bugünkü davranış (her zaman mock) bundan kötü olduğu için
kapı bilerek açık bırakıldı.

---

## B-024 — Windows `.spec` dosyası iki yerden bozuk

**Durum:** KAPALI — 2026-08-19, `HYCLEUS.spec` düzeltildi
**Öncelik:** Yüksek (dağıtılan yapı eksik çalışıyor, hata sessiz)
**Bulundu:** 2026-08-17 — AppImage ayağı kurulurken, `HYCLEUS.spec` referans
alınıp aynısı Linux için yazıldığında. İkisi de ÖLÇÜLDÜ, tahmin değil.

Bulunduğu turda Windows'a bilerek dokunulmamıştı (o tur Linux paketlemesini
kurmakla ilgiliydi). Bir tur sonra düzeltme taşındı: bu bir özellik eksiği
değil, elde duran paketin gerçek bir bozukluğuydu — geciktirmek riski
büyütüyordu.

### Ölçüm — düzeltmeden önce ve sonra

Aynı makinede, `HYCLEUS.spec` ile üretilen EXE üzerinde `--selftest`:

| | Temiz ağaçta yapı | Yüklenen modül |
|---|---|---|
| Önce | `ERROR: Unable to find …\data` — hiç başlamıyor | 43/53 |
| Sonra | başarılı | **53/53** |

Ara ölçüm için `data/` elle oluşturuldu; yoksa "önce" sütununun ikinci
hücresi hiç ölçülemezdi.

### Bulgu 1 — temiz bir ağaçta yapı HİÇ başlamıyor

```
$ pyinstaller --noconfirm HYCLEUS.spec
ERROR: Unable to find 'C:\...\HYCLEUS\data' when adding binary and data files.
```

Spec `datas=[('data', 'data'), …]` istiyor ama `data/` `.gitignore`'da.
Yani yapı yalnızca o dizini zaten üretmiş bir makinede çalışıyor; taze
bir klonda ilk adımda düşüyor.

Satır ayrıca GEREKSİZ: `CORE/paths.py::data_dir()` donmuş modda EXE'nin
YANINDAKİ `data/`'yı döndürüyor, pakete kopyalanan hiç okunmuyor.

### Bulgu 2 — paket eksik bağımlılıkla çıkıyor, uygulama yine de açılıyor

Spec `CORE`/`DB`/`UI`'yı **veri** olarak kopyalıyor. Bu, `.py` dosyalarını
pakete koyar ama PyInstaller'ın onları ANALİZ etmesini sağlamaz — dolayısıyla
`main.py`'nin import etmediği her modül kendi bağımlılıkları olmadan gidiyor.

`HYCLEUS.spec` ile üretilen EXE'de ölçülen sonuç: **53 modülün 10'u yüklenemedi.**

| Eksik | Nereden | Kullanıcıya etkisi |
|---|---|---|
| `getpass` | `backup_cli`, `recover_vault`, `setup_usb` | CLI araçları çalışmıyor |
| `asn1crypto` | `timestamp`, `timestamp_verify` | RFC 3161 damgası ve doğrulaması yok |
| `reportlab` | `inventory` | KVKK envanter PDF'i alınamıyor |
| `qrcode.image.svg` | `recovery_share` | Kurtarma karekodu üretilemiyor |

Hatanın biçimi en kötüsü: **uygulama açılıyor ve normal görünüyor.** Eksiklik
ancak kullanıcı o özelliğe dokunduğunda — muhtemelen kurtarma anında —
ortaya çıkıyor.

### Düzeltme (iki spec'te de uygulandı)

`datas` yerine `hiddenimports`: modül adları `os.listdir` ile dizinden
üretiliyor, PyInstaller bağımlılık grafiğini yürüyor ve eksik dördü
kendiliğinden geliyor. `reportlab` için `collect_all` gerekli (gömülü
Type-1 yazı tipleri veri dosyası), `qrcode` için `collect_submodules`
(görüntü arka ucu çalışma anında seçiliyor).

Windows'a ÖZGÜ olan hiçbir şey değişmedi: wmi/pywin32 toplama, tek dosya
EXE, `upx=True` yerinde.

### Neden bir daha sessizce olmayacak

`main.py --selftest` paketlenmiş yapıda her modülü içe aktarıp raporluyor,
CI'ın `appimage` işi de her push'ta onu çalıştırıyor. Yukarıdaki 10 modül
zaten bu komutla bulundu — kod okunarak değil.

2026-08-19 GÜNCELLEME — kapı kapandı. `ci.yml` → `exe` işi eklendi:
windows-latest üzerinde TEMİZ bir checkout'ta derliyor (`-TemizAgac`,
`data/` varsa duruyor) ve `packaging/windows/smoke-test.ps1` ile
`--selftest` koşturuyor. Artık iki platformun da yapısı her push'ta
üretilip açılıyor.

Kapının GERÇEKTEN kapandığı iki kasıtlı bozma ile ölçüldü:

| Bozma | Sonuç | İş |
|---|---|---|
| `_uygulama_modulleri()` hiddenimports'tan çıkarıldı | 46/57 | KIRMIZI |
| Linux'un `excludes` satırı Windows spec'ine kopyalandı | 53/57 | KIRMIZI |

İkincisi bir tasarım kararını doğruladı: duman testi modül sayısını SABİT
bir sayıyla karşılaştırmıyor, "yüklenen == denenen" diye bakıyor. `wmi`
grubu elenmiş bozuk bir yapı tam olarak **53** gösteriyor — yani
`== 53` yazan bir denetim o yapıyı YEŞİL geçirirdi.

### Yan ölçüm — `console=False` ile `--selftest`

Yukarıdaki ölçüm, `console=False` ile üretilmiş bir Windows
EXE'sinde yapıldı ve çıktı BORUYA sorunsuz yazıldı. Yani `--selftest`
pencereli bir yapıda da kullanılabiliyor; ayrı bir konsollu yapı gerekmiyor.
Ölçülmeyen tek durum, çıktının yönlendirilmediği (doğrudan çift tıklanmış)
çalıştırma — orada zaten okuyacak kimse yok.

### Testler

`tests/test_packaging.py` iki spec'i AYNI parametrik testlerle denetliyor —
hata tam olarak birinden diğerine kopyalanarak yayılmıştı, ayrı ayrı
denetlemek birinin unutulmasına kapı bırakırdı.

Denetimlerin HEPSİ AST; hiçbiri metin araması değil. İlk hâlleri metindi ve
mutasyon testi ikisini birden yakaladı: `assert "upx=True" in metin`,
`upx=False`'a çevrilmiş bir spec'te bile geçiyordu çünkü dosyanın
başındaki AÇIKLAMA da "upx=True" yazıyor. Aynı sınıf hata bu depoda
dördüncü kez çıktı (bkz. B-011, B-008, B-013 testleri): bir kuralı düz
metinle denetlemek, kuralı ANLATAN metni de eşleştirir.

Modül üreticisi ayrıca SÖKÜLÜP ÇALIŞTIRILIYOR ve sonucu depoyla
karşılaştırılıyor — "fonksiyon tanımlı mı" yetmiyordu; gövdesi boş
döndürülen bir üretici tanım denetiminden geçmişti.

15 mutasyonun 15'i ölüyor.

---

## B-025 — `get_usb_hwid()` USB düğümünü hiç okumuyor; kimlik donanımdan değil DOSYADAN türüyor

**Durum:** Açık
**Öncelik:** YÜKSEK — "donanıma bağlı kasa" iddiasının doğrudan konusu
**Bulundu:** 2026-08-19 — B-022 sonrası prototip ölçümü sırasında, ÖLÇÜLDÜ

### Bulgu

`CORE/usb_manager.get_usb_hwid()` seriyi yalnızca **depolama yığınından**
okuyor: `Win32_DiskDrive.SerialNumber`, olmazsa `wmic diskdrive`. İkisi de
aynı yığın. Değer bozuksa `_sanitize_hwid()` onu atıyor ve
`_get_or_create_uuid()` `data/usb_ids.json`'a bir UUID yazıyor.

B-022 prototipe **ikinci bir kaynak** kazandırdı — `Win32_PnPEntity`
üzerinden USB düğümü, yani `iSerialNumber`'ın kendisi. Ama o kazanım
`hwid_probe.py`'de kaldı; `usb_manager.py` hâlâ tek yığına bakıyor.

2026-08-19'da takılı olan aygıtta bu fark belirleyici:

| Kaynak | Okunan |
|---|---|
| USB düğümü (`Win32_PnPEntity`) — prototipin okuduğu | 24 karakter, harf+rakam, temiz |
| Depolama yığını (`Win32_DiskDrive`) — HYCLEUS'un okuduğu | **2 karakter, yazdırılamayan** |
| `get_usb_hwid()` sonucu | 36 karakter — **UUID**, dosyadan |

Yani **kullanılabilir bir donanım serisi var ve HYCLEUS onu görmüyor.**

### Kimliğin dosyadan türediği ölçüldü

`usb_ids.json` geçici olarak kaldırılıp `get_usb_hwid()` yeniden
çağrıldı: **farklı bir değer döndü.** Dosya hemen geri yüklendi ve
token'ın kimliğinin ölçüm öncesine döndüğü doğrulandı.

### Neden yüksek öncelikli

`hwid`, `_derive_signing_key()`'in HKDF girdisi, kasa dosyasının AAD'ı,
kasa dosyasının ADI (`vaults/<hwid>.hclv`) ve keyring kaydının kullanıcı
adı (`share_2:<hwid>`). Bu aygıt sınıfında o değer bir JSON dosyasından
geliyor:

1. **Kilitlenme.** `data/usb_ids.json` silinir/bozulursa HWID değişir;
   kasa dosyası ve keyring kaydı bulunamaz. Kullanıcı kurtarma parçası
   olmadan kasasına erişemez. Dosya `.gitignore`'da ve yedekleme akışının
   kapsamında olup olmadığı AYRICA kontrol edilmeli.
2. **Donanıma bağlılık yok.** Kimlik USB'de değil diskte. `data/`'yı
   kopyalayan biri, o USB olmadan aynı HWID'yi elde eder — SECURITY.md'nin
   "kayıtlı USB cihazının fiziksel olarak mevcut olması zorunludur"
   cümlesi bu aygıt sınıfı için tam olarak doğru değil.
3. **Çakışma yüzeyi.** Eşlemenin ANAHTARI ham seri. Bu aygıtta o anahtar
   2 karakter. Aynı bozuk değeri bildiren ikinci bir aygıt **aynı UUID'yi**
   alır, yani iki farklı fiziksel token tek kimliğe düşer. Anahtar uzayının
   ne kadar dar olduğu ölçülmedi; ölçülmesi gereken ilk şey bu.

### Yapılacaklar

1. `get_usb_hwid()` USB düğümü yolunu da denesin — `hwid_probe`'daki
   `build_windows_identity()` zaten saf ve test edilebilir bir fonksiyon,
   yeniden yazmaya gerek yok. Sıra: tanımlayıcı serisi → depolama serisi →
   UUID.
2. UUID yoluna DÜŞÜLDÜĞÜNDE kullanıcı bilgilendirilsin. Bugün tamamen
   sessiz; "donanıma bağlı" olmayan bir kasa, kullanıcının bilmesi gereken
   bir şey.
3. Eşleme anahtarı olarak ham seri yerine VID+PID+seri üçlüsü kullanılsın —
   çakışma yüzeyini daraltır. Mevcut kayıtların taşınması gerekir.
4. Bu değişiklik MEVCUT KULLANICILARIN HWID'İNİ DEĞİŞTİRİR. Geçiş yolu
   olmadan yapılamaz: bugün UUID ile kayıtlı bir kasa, yarın seriyle
   açılmaya çalışılırsa açılmaz. B-003'teki (PIN taşıma) gibi bir
   migration gerekiyor.

### Kapsam notu

Bu madde B-016'nın devamı ama aynı şey değil. B-016 "hangi alanı
okumalıyız, platformlar arası uyuşuyor mu" sorusuydu. Bu madde
"okuduğumuz alan bozuk olduğunda ne oluyor" sorusu ve cevabı ölçüldü:
sessizce dosya tabanlı bir kimliğe geçiliyor.

---

## B-026 — Testler gerçek `data/usb_ids.json` dosyasına yazıyor

**Durum:** Açık
**Öncelik:** Orta (geliştirici ortamını kirletiyor; veri kaybı riski düşük)
**Bulundu:** 2026-08-19 — B-025 ölçümü sırasında, ÖLÇÜLDÜ

`tests/conftest.py` üç şeyi autouse fixture ile izole ediyor: keyring,
`totp_secret.json` ve denetim çıpası. Gerekçeleri de yazılı — "testlerin
kullanıcının gerçek kaydına dokunmaması".

`data/usb_ids.json` o listede YOK.

Ölçüm: `data/` silindi, dört test dosyası çalıştırıldı
(`test_backup_cli`, `test_recover_cli`, `test_main_window_smoke`,
`test_packaging`), 193 test geçti ve `data/usb_ids.json` **yeniden
oluşmuştu** — yeni bir UUID tahsis edilmişti.

### Etki

Bugünkü hâliyle sınırlı: eşleme anahtar bazlı ve ekleme yapıyor, yani
mevcut bir kaydın ÜZERİNE yazmıyor. Yani testler bir kullanıcının HWID'ini
değiştirmiyor — yalnızca dosya yoksa oluşturuyor.

Ama B-025 düzeltilirken bu dosyanın şeması değişecek (anahtar olarak
VID+PID+seri). O sırada izole olmayan bir test, geliştiricinin gerçek
eşlemesine yanlış şemada satır yazabilir.

### Yapılacak

`conftest.py`'ye `isolate_usb_ids` autouse fixture'ı — diğer üçüyle aynı
desen, `CORE.usb_manager._USB_IDS_FILE`'ı `tmp_path`'e taşıyacak.

Dikkat: `_USB_IDS_FILE` modül seviyesinde hesaplanıyor, yani
`monkeypatch.setattr(usb_manager, "_USB_IDS_FILE", …)` gerekiyor;
`data_dir()`'i patch'lemek yetmez.
