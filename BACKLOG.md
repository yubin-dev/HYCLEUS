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
| B-022 | `③` grubu — B-022 düzeltmesi | `hwid_probe.read_windows()` yalnızca `Win32_DiskDrive.PNPDeviceID`'yi okuyordu; o USBSTOR (depolama) düğümü ve seriye `&<n>` örnek soneki ekliyor. Onaltılık bir seri artı `&0`, "üretilmiş kimlik" desenine tam uyduğu için prototip SERİLİ token'a "serisiz" diyordu — SanDisk'te sistematik, ve B-016 kararını ters yöne itecek bir ölçüm hatası. Artık `Win32_PnPEntity` üzerinden USB düğümü de okunuyor ve seriyle eşleştiriliyor; VID/PID de oradan geliyor (eski `????:????` çıktısı bunun belirtisiydi). Eşleştirme saf bir fonksiyona (`build_windows_identity`) ayrıldı, artık WMI'siz test edilebiliyor. Yanında `normalize_serial()`'ın `.lstrip("0")`'ı kaldırıldı: `0123ABC` ile `123ABC`'yi aynı kimliğe indiriyordu — kimlik üreten bir fonksiyonda ÇAKIŞMA, kapatmaya çalıştığı (ve hiç ölçülmemiş) dolgu farkından ağır basar. İki sabitleme testi bilerek kırıldı. **2026-08-19:** gerçek bir aygıtla doğrulandı — prototip tanımlayıcı serisini okuyor, `generated=False`, VID/PID çözülüyor (eski `????:????` yok). Ölçüm hem `30DE:6544` hem de özgün yanlış negatifi üreten SanDisk `0781:5567` ile yapıldı; SanDisk'te sonuç 2026-08-16 ölçümüyle birebir aynı çıktı (uzunluk, karakter kümesi, önek, yığın-uyumu, fallback yokluğu — bkz. B-016). |
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

**Durum:** ÇÖZÜLDÜ (2026-08-21) — zorunlu yenileme akışı devrede.
Köprünün kaldırılması B-040'a devredildi; çözüm kaydı dosyanın sonunda.
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
çubuk. O an bağlı **tek** USB depolama aygıtı buydu.

#### Aynı gün, SanDisk takıldıktan sonra — SORU CEVAPLANDI

SanDisk sonradan takıldı ve karşılaştırma yapılabildi. **Sonuç: önceki
ölçümle birebir aynı.**

| Denetim | Sonuç |
|---|---|
| prototip "serisiz" diyor mu | **hayır** (B-022 öncesi "evet" diyordu) |
| tanımlayıcı serisi == depolama serisi | evet |
| tanımlayıcı serisi == `get_usb_hwid()` | evet |
| `_sanitize_hwid()` karakter düşürüyor mu | hayır |
| `normalize_serial()` değeri değiştiriyor mu | hayır (B-022'nin `lstrip("0")` kaldırması burada da zararsız) |
| uzunluk 20 mi | evet |
| tümü `[0-9A-F]` mi | evet |
| B-016'nın kaydettiği `4C53` öneki | evet |
| UUID fallback'e düştü mü | hayır |

**Ölçümün sınırı:** 2026-08-16'daki HAM DEĞER hiçbir yere yazılmamıştı
(bilinçli), dolayısıyla iki değer karakter karakter karşılaştırılamıyor.
Karşılaştırılan şey, o turda kaydedilmiş olan TÜM özellikler: aynı fiziksel
aygıt (aynı VID:PID, model, kapasite), aynı uzunluk, aynı karakter kümesi,
aynı önek, aynı yığın-uyumu, aynı fallback-yokluğu. Bu, sırrı saklayarak
elde edilebilecek en güçlü eşleşme kanıtı.

#### B-022 düzeltmesi bu aygıtta ÇALIŞIYOR

Prototip tanımlayıcı serisini okuyor (`generated=False`, `stable_id`
üretiliyor) ve VID/PID'yi çözüyor — eski hatanın belirtisi olan
`????:????` çıktısı yok. Doğrulama **özgün yanlış negatifi üreten
aygıtta da** yapıldı (aşağıdaki tablo): B-022 kapandı.

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

**Durum:** Açık — ama madde 2 (sessizlik) KAPANDI, bkz. 2026-08-28 notu
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

### 2026-08-28 — Madde 2 kapandı, ama daha sert: bilgilendirmenin ötesine geçildi

Madde 2 "kullanıcı bilgilendirilsin" diyordu; yapılan bundan fazlası oldu —
kapalı hataya (fail-closed) çevrildi:

  · `CORE/usb_manager._get_or_create_uuid()` artık ilk UUID üretiminde
    (yalnızca ilk seferinde, her takılışta değil) bir uyarı log'a düşüyor.
  · `CORE/usb_manager.is_uuid_fallback_hwid(hwid)` — canlı USB probu
    gerektirmeden, verilen bir hwid'in bu yedekten gelip gelmediğini
    söyleyen saf fonksiyon.
  · `CORE/vault_manager._reject_if_weak_binding()` bu durumu TRUST veren
    her işlemde reddediyor: `create_vault()` (taze kayıt), `open_vault()`,
    `authenticate_usb()`, `read_vault_role()`, `change_vault_role()`,
    `change_vault_pin()`. `USBAuthError` fırlatıyor, `weak_hwid_binding_
    rejected` denetim kaydı düşüyor, aynı UI yollarından (login ekranı
    hata etiketi, "USB Reddedildi" diyaloğu) görünür oluyor.
  · BİLEREK muaf: `verify_vault()` (bütünlük taraması hâlâ çalışmalı) ve
    kurtarma akışı (`recover_master_key`/`reprovision_vault`) — zayıf
    bağlı bir cihazın tek çıkış yolu bu, kesmek kullanıcıyı kalıcı
    kilitlerdi. Kara listenin aksine (o kurtarmayı da kapsıyor, çünkü
    idari bir iptal), bu yapısal bir donanım kısıtı — cezai değil.

Ayrıntılı gerekçe SECURITY.md §4.15'te. Testler:
`tests/test_usb_weak_binding.py` (CORE katmanı, 18 test) ve
`tests/test_usb_weak_binding_ui.py` (gerçek `LoginDialog`, 2 test).

**Madde 1, 3, 4 hâlâ AÇIK** — bu tur yalnızca "sessizce kabul" davranışını
düzeltti, `get_usb_hwid()`'in NEDEN bu duruma düştüğünü (yalnızca depolama
yığınına bakması) değiştirmedi. Yani bu yola düşen bir cihaz artık
sessizce çalışmıyor, ama hâlâ hiç çalışmıyor — kayıt/giriş için tek yol
donanımı değiştirmek.

### 2026-08-28 (devam) — reprovision'daki muafiyet deliği kapatıldı, denetim yazımı zincire taşındı

Bir önceki notta `reprovision_vault()`'un (create_vault()'un `anchor_share`
verilen çağrısı) TAMAMEN muaf olduğu yazılıydı — bu, kanıtlanmadan yapılmış
bir varsayımdı. Denendiğinde: zayıf bağlı bir hwid, `reprovision_vault()`'tan
sorunsuz geçip vault'u kalıcı olarak bir UUID yedeğine bağlayabiliyordu; bu,
K0-2'nin "USB kaydı reddedilsin" gereksinimini karşılamıyordu — kayıt ANINDA
engellenmesi gerekirken kayıt SONRASI kullanılamaz hâle geliyordu (çünkü
`open_vault()`/`authenticate_usb()` zaten reddediyordu).

Düzeltme: `create_vault()` içindeki iki alt-işlem ayrıştırıldı.
`recover_master_key()` (eski payı/PIN'i OKUYUP `master_key`'i yeniden
üretmek) BİLEREK muaf kaldı — zayıf bağlı bir cihazın verisine erişmenin
tek yolu bu. Ama `reprovision_vault()`'un kendisi (kurtarılan `master_key`'i
YENİ bir hwid'e YAZMASI) artık muaf DEĞİL — bu, taze kayıtla aynı sınıfta
bir TRUST kararı. `create_vault()` artık her iki dalda da
`_reject_if_weak_binding()`'i çağırıyor.

Ayrıca: `_get_or_create_uuid()`'in ilk-atama uyarısı yalnızca uygulama
logundaydı, denetim zincirinde DEĞİLDİ — sistem delil-değeri iddia eden TEK
bir zincire güveniyor, o zincirin dışında kalan bir iz zincir bozulmadan
silinebilirdi. Artık `weak_hwid_uuid_assigned` denetim satırı da düşüyor
(best effort — DB bağlı değilse yutuluyor, hardware probu çökmemeli).

Ayrıntılı gerekçe ve yeni testler SECURITY.md §4.15'te
(`test_reprovision_YAZMA_zayif_hwid_icin_REDDEDILIR`,
`test_kurtarma_OKUMA_zayif_hwid_icin_MUAF`,
`test_reprovision_GUCLU_hwid_ile_calismaya_devam_eder`,
`test_get_or_create_uuid_ilk_uretim_denetim_zincirine_de_dusuyor`).
Madde 1, 3, 4 hâlâ AÇIK — bu değişmedi.

### Kapsam notu

Bu madde B-016'nın devamı ama aynı şey değil. B-016 "hangi alanı
okumalıyız, platformlar arası uyuşuyor mu" sorusuydu. Bu madde
"okuduğumuz alan bozuk olduğunda ne oluyor" sorusu ve cevabı ölçüldü:
sessizce dosya tabanlı bir kimliğe geçiliyor.

### Etkilenen aygıt tespit edildi (2026-08-19)

UUID yoluna düşen aygıt **KIOXIA TransMemory** (`30DE:6544`, 31 GB) —
sıradan bir USB bellek. SanDisk (`0781:5567`) etkilenmiyor, onun depolama
serisi temiz.

Yani sorun tek bir bozuk çubuğa özgü değil, **satıcıya göre değişen** bir
davranış: aynı makinede iki USB belleğin biri depolama yığınına temiz seri
veriyor, diğeri 2 karakterlik bozuk değer. İkisinin de USB düğümünde
kullanılabilir seri VAR.

### Mali mühür / akıllı kart token'ları — HİÇ görünmüyor

Aynı ölçümde makinede bir **mali mühür** de takılıydı: `08E6:3438`
"USB Key Smart Card Reader" (+ `SmartCard` sınıfında bir kart). USB
düğümünde 8 karakterlik bir serisi var.

`get_usb_hwid()` yalnızca `Win32_DiskDrive`'ı geziyor, akıllı kart
okuyucusu orada YOK. Yani bugün bir mali mühür ya da e-imza token'ı
HYCLEUS'a token olarak KAYDEDİLEMEZ — uygulama onu hiç göremez.

Bu, yukarıdaki düzeltmenin (USB düğümü yolunu da denemek) ikinci
kazanımı olurdu. Ama ayrı bir tasarım sorusu açıyor ve bu madde onu
kapsamıyor: mali mühür sertifikası 1-3 yılda bir yenileniyor ve fiziksel
token DEĞİŞİYOR. Kasa kimliği ona bağlanırsa yenileme günü kullanıcı
kasasından kilitlenir. Bir token'ın kasa için uygun olması, seri
taşımasından ibaret değil.

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

---

## B-027 — Birden fazla USB bellek takılıyken `get_usb_hwid()` İLKİNİ seçiyor

**Durum:** Açık
**Öncelik:** Orta-Yüksek (kayıtlı token takılıyken açılışın reddedilmesi)
**Bulundu:** 2026-08-19 — iki USB bellek aynı anda takılıyken ölçüm sırasında

`CORE/usb_manager.get_usb_hwid()` `Win32_DiskDrive`'ı geziyor ve
`InterfaceType == "USB"` olan **ilk** aygıtın serisini döndürüp çıkıyor.
Hangi aygıtın KAYITLI token olduğuna bakmıyor — o bilgi veritabanında ve
bu fonksiyon veritabanını hiç görmüyor.

### Ölçülen durum

İki USB bellek birden takılıyken:

| Sıra | Aygıt | Sonuç |
|---|---|---|
| 1 | SanDisk Cruzer Blade (`0781:5567`) | **seçildi** |
| 2 | KIOXIA TransMemory (`30DE:6544`) | kullanılmadı |

Beş çağrının beşi de aynı değeri döndürdü, yani tek oturumda sıra kararlı.
Bu turda kayıtlı token zaten birinci sıradaydı — yani hata GÖRÜLMEDİ,
yalnızca yolu ölçüldü.

### Neden sorun

Sıra, numaralandırmadan geliyor; hangi çubuğun önce geleceğini kod
belirlemiyor. Kayıtsız bir çubuk önce gelirse:

`get_usb_hwid()` onun serisini döndürür → `DBManager().connect(hwid=…)`
`HWIDMissingError` fırlatır → `main.py` "Hata" kutusu gösterip
`sys.exit(1)` yapar.

Yani **kayıtlı token TAKILIYKEN uygulama açılmayı reddeder** ve kullanıcıya
gösterilen mesaj sebebi söylemez. Kullanıcının yapması gereken şey (diğer
çubuğu çıkarmak) hiçbir yerde yazmıyor.

Bu bir güvenlik açığı DEĞİL — yanlış aygıtla açılmıyor, hiç açılmıyor.
Ama teşhisi zor bir kilitlenme ve tetiklemesi çok kolay: yanında telefon
şarj eden ya da harici disk takılı bir kullanıcı yeter.

### Yapılacak

`get_usb_hwid()` tek bir değer yerine ADAY LİSTESİ döndürsün; kayıtlı
olanı seçme işi çağırana (veritabanını gören katmana) geçsin. Hiçbiri
kayıtlı değilse mesaj "USB bulunamadı" değil "takılı N aygıttan hiçbiri
kayıtlı değil" olsun.

B-025 ile birlikte ele alınmalı: ikisi de aynı fonksiyonun aynı döngüsünü
değiştiriyor ve ikisi de `get_usb_hwid()`'in tek değer döndüren imzasını
zorluyor.

---

## B-028 — Rol karşılaştırması üç farklı biçimde, 19 karar noktasında

**Durum:** KAPALI — 2026-08-19, `CORE/roles.py` tek karar noktası oldu
**Öncelik:** YÜKSEK — erişilebilir bir yetki kaybı yolu vardı (aşağıda)
**Bulundu:** 2026-08-19 — "aynı iş için birden fazla uygulama" sistematik taraması

### Ölçüm

`role` karşılaştırması UI genelinde **üç farklı normalizasyonla** yapılıyor:

| Biçim | Adet | Nerede |
|---|---|---|
| katı literal `== "Yönetici"` | **11** | AdminPanel:100,526 · login_dialog:904 · main_window:276,370,389 · main_window_tree:107,210,368,443 · RegisterDialog:385 |
| `.strip().lower()` | **7** | main_window_files:72 · main_window_table:407,429,518 · main_window_tree:219,398 · TagDialog:89 |
| `.strip().lower().replace("_"," ")` | **1** | main_window:191 |

Biri (`main_window_table.py:518`) üç yazımı birden kabul ediyor:
`in ("yönetici", "yonetici", "admin")`. Yani birisi bu sorunla ZATEN
karşılaşmış ve tek bir çağrı yerini yamamış.

### Erişilebilir kusur — kurtarma sonrası yönetici sessizce düşüyor

`CORE/recover_vault.py:175` satırı rolü şöyle alıyor: `input()` sonucu
boşsa varsayılan **ASCII** `Yonetici` — Türkçe `ö` yok. Zincir:

```
recover_vault (Enter'a basıldı)  ->  reprovision_vault(hwid, pin, "Yonetici")
  ->  kasaya "Yonetici" yazılır
  ->  login: role, key = open_vault(...)      (normalize EDİLMEDEN)
  ->  HycleusWindow(role="Yonetici")
  ->  11 katı karşılaştırmanın hepsi False
```

Sonuç: kasa kurtarma işleminden sonra yönetici, yönetici olmayan gibi
davranılıyor — AdminPanel hiç kurulmuyor (`AdminPanel.py:100`), mahrem
etiketli dosyalar gizleniyor, arayüz kısıtlanıyor. Üstelik **aynı oturum
içinde tutarsız**: `main_window_table.py:518` toleranslı olduğu için
tekrar tespiti kullanıcıyı yönetici saymaya devam ediyor.

**Yön:** kapanma yönünde (yetki KAYBI, genişlemesi değil) — güvenlik açığı
değil. Ama kilitlenme sınıfı bir hata ve en kötü anda, kurtarmadan hemen
sonra ortaya çıkıyor; kullanıcı AdminPanel'e erişemediği için rolü
düzeltemez de.

### Yapılacaklar

1. Tek karar noktası: `CORE/roles.py::yonetici_mi(role)` (ve
   `salt_okunur_mu`). Normalizasyon TEK yerde — `.strip().lower()` +
   `_` yerine boşluk + ASCII/Türkçe eşdeğerliği.
2. 19 çağrı yeri ona bağlansın.
3. `recover_vault.py` varsayılanı ya kaldırılsın (rol zorunlu sorulsun) ya
   da kanonik biçime normalize edilsin.
4. AST denetimi: kanonik modül dışında `"Yönetici"` sabitiyle `Compare`
   düğümü YASAK (bkz. B-033).

**Dikkat:** rol dizesi KASADA saklanıyor. Kanonik biçime geçmek, mevcut
kasalardaki ASCII değerleri okuma anında normalize etmeyi gerektirir —
kasayı yeniden yazmak PIN ister, yani migration DEĞİL okuma-anı
normalizasyonu doğru çözüm.

---

## B-029 — `_EXCLUDE_PRIVATE` iki kopya, VARSAYILANLARI ters

**Durum:** Açık — DÜZELTİLMEDİ, önce rapor
**Öncelik:** Orta-Yüksek (görünürlük filtresi; B-007 ile aynı sınıf)
**Bulundu:** 2026-08-19 — aynı tarama

`CORE/file_queries.py` ve `CORE/duplicates.py` **bayt bayt aynı** SQL
parçasını ayrı ayrı tanımlıyor (`_EXCLUDE_PRIVATE`): mahrem etiket taşıyan
dosya id'lerini `NOT IN` ile eleyen alt sorgu.

Ve varsayılanları TERS:

| Modül | `include_private` varsayılanı |
|---|---|
| `file_queries.*` (4 görünüm) | `True` |
| `duplicates.find_duplicates_by_hash` | `False` |

İkisinin de gerekçesi kendi docstring'inde yazılı ve ikisi de kendi
bağlamında savunulabilir (B-007 varsayılanı bilerek `True` bıraktı;
`duplicates` bilerek `False`). Sorun varsayılanlar değil, **kuralın iki
kopyası**: mahremiyet tanımı bir gün değişirse (ör. klasör bazlı gizleme
eklenirse) bir kopya güncellenir, diğeri sessizce eski semantikte kalır.

B-007 dört görünümü birleştirmişti ama `duplicates.py` o ailenin dışında
kaldı — tarama bunu buldu.

### Yapılacak

SQL parçası tek yerde (`CORE/file_queries.py` ya da yeni bir
`CORE/privacy.py`), iki modül oradan alsın. Varsayılanlar bilerek farklı
kalabilir — paylaşılması gereken KURAL, tercih değil.

---

## B-030 — Arayüz rolü → `users.role` eşlemesi üç ayrı yerde

**Durum:** KAPALI — 2026-08-19, B-028 ile birlikte
**Öncelik:** Orta (B-011 ile aynı sınıf)
**Bulundu:** 2026-08-19 — aynı tarama

| Yer | Uygulama |
|---|---|
| `CORE/session_user.py:87` + `db_role()` | `_ROL_ESLEMESI` sözlüğü, bilinmeyen rol → `user` (belgeli) |
| `UI/login_dialog.py:904` | satır içi `"admin" if role == "Yönetici" else "user"` |
| `UI/RegisterDialog.py:385` | satır içi, aynı ifade |

B-011 tam olarak bu sorunu çözmek için `session_user.db_role()`'ü tek karar
noktası yapmıştı; iki kayıt akışı ona hiç bağlanmadı.

Bugün **aynı sonucu** veriyorlar, yani görünür bir hata yok. Risk ileriye
dönük: `db_role()`'e bir eşleme eklendiği gün (ör. "Salt Okunur" için ayrı
bir DB rolü) iki UI yolu eskisini yazmaya devam eder ve `users.role`
sütununda CHECK kısıtını geçen ama YANLIŞ bir değer oluşur.

Ayrıca ikisi de B-028'in katı literal karşılaştırmasını kullanıyor, yani
ASCII `Yonetici` ile kaydolan bir kullanıcı `user` olarak yazılır.

### Yapılacak

İki UI çağrı yeri `session_user.db_role()`'ü çağırsın. AST denetimi:
`users` tablosuna `role` yazan bir INSERT'in yakınında literal
`"admin"` / `"user"` YASAK.

---

## B-031 — `is_admin` adı iki farklı soruyu cevaplıyor

**Durum:** Açık — büyük ihtimalle YALNIZCA BELGELEME işi
**Öncelik:** Düşük
**Bulundu:** 2026-08-19 — aynı tarama

| Yer | Kaynak | Güç |
|---|---|---|
| `CORE/disposal.py:217` `is_admin(db, user_id)` | **veritabanı** (`users.role`) | yetkili karar |
| `UI/main_window.py:192` `is_admin` | oturum dizesi | görünürlük ipucu |
| `UI/TagDialog.py:90` `_is_admin` | oturum dizesi | görünürlük ipucu |

Bu ayrım **kasıtlı ve doğru**: `disposal.is_admin` docstring'i "onay,
çağıranın gönderdiği bayrağa değil VERİTABANINA sorulur" diyor. UI'nınki
bir yetki kapısı değil, bir çizim kararı.

Yine de aynı ad üç yerde iki farklı anlam taşıyor. Yeni bir geliştiricinin
UI'daki `is_admin`'i yetki kontrolü sanması kolay. Öneri: UI'dakiler
`_yonetici_gorunumu` gibi bir ada geçsin, `disposal.is_admin` olduğu gibi
kalsın. Kod davranışı değişmiyor.

---

## B-032 — PIN üst sınırı yalnızca `setup_usb`'de uygulanıyor

**Durum:** Açık
**Öncelik:** Düşük (UX tutarsızlığı, güvenlik etkisi yok)
**Bulundu:** 2026-08-19 — aynı tarama

`CORE/pin_policy.validate_new_pin()` yalnızca ALT sınırı uyguluyor ve bunu
docstring'inde açıkça söylüyor. Beş çağrı yerinin dördü (login_dialog ×2,
ProfileDialog, RegisterDialog) sadece bunu çağırıyor.

`CORE/setup_usb.py:144` ise ayrıca üst sınırı denetliyor.

Sonuç: 40 karakterlik bir PIN arayüzden KABUL edilir, `setup_usb`'den
REDDEDİLİR. Argon2id uzun girdiden etkilenmiyor, yani güvenlik sorunu yok;
tutarsız olan kullanıcıya söylenen kural.

### Yapılacak

Üst sınır `validate_new_pin()`'e taşınsın (tek karar noktası) ve
`setup_usb`'deki kopya silinsin. Mevcut uzun PIN'ler etkilenmez — kontrol
yalnızca YENİ PIN belirlerken çalışıyor.

---

## B-033 — "Tek karar noktası" denetimlerini genelleştir

**Durum:** Açık — araç önerisi
**Öncelik:** Orta (bu kusur sınıfı 8 kez çıktı)
**Bulundu:** 2026-08-19 — aynı tarama

Depoda bu sınıftan **sekiz** bulgu var: B-004/B-008, B-007, B-010, B-011,
pay ayrıştırıcı, ve bu turda B-028, B-029, B-030. Beş tanesi için elle
yazılmış AST denetimi mevcut (`test_disposal.py`, `test_session_user.py`,
`test_crypto.py`, `test_audit_report.py`, `test_layering.py`).

Her biri ayrı yazılmış, ortak bir iskelet yok.

### Neyi genelleştirmek MÜMKÜN

**1. Yasak-desen kaydı (uygulanabilir, yüksek değer).** Veri tablosu:

```python
KararNoktasi(
    ad="rol → yönetici kararı",
    kanonik="CORE.roles",
    yasak=SabitKarsilastirma("Yönetici"),   # ast.Compare + ast.Constant
)
```

Beş bespoke testi tek tabloya indirir; yeni bir madde eklemek bir satır olur.

**2. Tekrarlanan sabit dedektörü (ÖLÇÜLDÜ, hemen yazılabilir).**
CORE/ ve DB/ altındaki 40+ karakterlik modül seviyesi string sabitlerini
normalize edip karşılaştıran ~15 satırlık bir test denendi:

```
40+ karakterlik modül sabiti  : 8
birden fazla yerde AYNI olan  : 1   ->  _EXCLUDE_PRIVATE (B-029)
yanlış pozitif                : 0
```

Yani B-029'u mekanik olarak, sıfır gürültüyle yakalıyor.

### Neyi genelleştirmek MÜMKÜN DEĞİL

"Aynı işi yapan iki bağımsız uygulama" genel hâlde tespit edilemez —
B-010 (iki indirme akışının AAD davranışı) ya da B-028'in ASCII/Türkçe
ayrışması hiçbir sözdizimsel imza taşımıyor. Bu turdaki bulguların çoğu
ELLE okumayla çıktı ve öyle çıkmaya devam edecek.

Dolayısıyla öneri "otomatik dedektör" değil: **bilinen karar noktalarının
kayıt defteri** artı iki mekanik tarayıcı. Kayıt defterinin değeri, bir
maddeyi kapatırken denetimini de eklemeyi ucuzlatması.

### Taramanın TEMİZ çıkanları

Negatif sonuçlar da kayda değer — bu kategoriler gerçekten birleştirilmiş:

| Kategori | Durum |
|---|---|
| Güvenli silme (`shred`) | 5 çağrı yerinin 5'i de `secure_erase.shred_file()` |
| TTL/imha silme | UI ve zamanlayıcı, ikisi de `purge_expired_file()` (B-004/B-008 tuttu) |
| Saklama koruması | `is_retention_protected` → `check_disposal`'a devrediyor |
| Pay ayrıştırma | `_parse_share` belgeli darboğaz; `decode_share` dahil üç giriş de oradan geçiyor |
| PIN alt sınırı | 5 çağrı yerinin 5'i de `validate_new_pin()` |

---

## B-028 / B-030 — çözüm kaydı (2026-08-19)

`CORE/roles.py` eklendi ve 19 karar noktasının tamamı ona bağlandı.
Beş commit: modül → CORE tarafı → main_window ailesi → diyaloglar →
AST denetimi.

### Ölçülen: sorun sanılandan genişti

Tarama raporu "ASCII `Yonetici` tanınmıyor" diyordu. Ölçünce
`.strip().lower()` kullanan yedi çağrı yerinin de kırık olduğu çıktı:

```
"YÖNETİCİ".lower()          ->  'yöneti̇ci̇'   (10 karakter, 8 değil)
"YÖNETİCİ".lower() == "yönetici"  ->  False
```

Sebep `İ` (U+0130): küçük harfi `i` + U+0307 BİRLEŞEN NOKTA. Yani
Türkçe büyük harfle yazılmış bir rol, "toleranslı" sanılan yolda da
tanınmıyordu. `normalize_role()` NFKD ayrıştırması + birleşen işaretleri
atarak çözüyor; `ı` (U+0131) atomik olduğu için elle eşlendi (ölçüldü:
`NFKD("ı") == "ı"`).

### Saf refactor kuralının bilerek yapılan tek istisnası

`can_write()`. Eski kod `not is_readonly` diyordu, yani BİLİNMEYEN bir rol
yazabiliyordu. Yeni hâli yalnızca tanınan iki role izin veriyor. Kanonik
üç rol için davranış aynı; değişim yalnızca bilinmeyen rollerde ve
daraltma yönünde. Testte açıkça yazılı.

Gözden geçirmede ayrıca işaretlendi ve **2026-08-19'da onaylandı**. Kayda
geçiriliyor çünkü bu, "davranış değişmeyecek" kuralının bilerek delindiği
tek yer; ileride biri farkı görüp hata sanabilir.

### Kaldırılan "ikinci cevaplar"

| Nerede | Neydi |
|---|---|
| `main_window_table.py` | `in ("yönetici","yonetici","admin")` — bu hatanın tek yere yamanmış hâli |
| `main_window.py` | `is_readonly` ara değişkeni — tek kullanıcısı `can_write` hesabıydı |
| `TagDialog.py` | `_role_norm` ara değişkeni |
| `session_user.py` | `_ROL_ESLEMESI` sözlüğü (uygulama `roles.db_role()`'e taşındı) |

### Grep'in kaçırdığı, AST'nin bulduğu

`_ROLE_BADGE` (`main_window_palette.py`) ve `_ROLE_COLOR`
(`ProfileDialog.py`) rolü SÖZLÜK ANAHTARI olarak kullanıyordu. Kasada
ASCII `Yonetici` yazan bir kullanıcı rozetsiz kalıyordu — B-028'in
görünür ama zararsız yüzü. Anahtarlar kanonik değere çevrildi,
aramalar `normalize_role()`'den geçiyor.

### Denetim ve mutasyon testi

`tests/test_role_decision_point.py` (85 test). Mutasyon testi denetimi
İKİ KEZ düzeltti:

1. İlk hâl yalnızca `ast.Compare` arıyordu ve
   `{"Yönetici": "admin"}.get(...)` mutasyonu HAYATTA KALDI — oysa
   B-030'un düzeltilen şekli tam olarak buydu. Üçüncü kalıp eklendi:
   anahtarı rol adı olan sözlük sabiti.
2. Kanonik modül için yazılan muafiyet GEREKSİZ çıktı: `roles.py` rol adı
   sabitleriyle değil `ROL_YONETICI` gibi adlandırılmış sabitlerle
   karşılaştırıyor, yani denetimden kendi başına temiz geçiyor. Muafiyet
   kaldırıldı — kuralın artık hiçbir istisnası yok.

Son ölçüm: 10 mutasyonun 10'u ölüyor.

### Yan bulgu — semgrep yanlış pozitifi

`hycleus-hardcoded-key-material` kuralı `ROL_SALT_OKUNUR` adını
işaretledi: Türkçe **"salt"** (yalnızca) sözcüğü kriptografik `salt` ile
çakışıyor. Kuralı gevşetmek yerine o satır gerekçeli susturuldu.

### Kapanmayan

`recover_vault.py` artık kanonik yazıyor ve okuma tarafı her yazımı
tanıyor, yani ESKİ kasalar da düzeliyor — migration gerekmedi. Ama bu
yalnızca ROL dizesi için geçerli; kasadaki başka alanların benzer bir
normalizasyon sorunu olup olmadığı BAKILMADI.

---

## B-034 — Salt okunur rol damgayı doğrulayamıyor

**Durum:** Açık — DÜZELTİLMEDİ, kapsam dışı bırakıldı
**Öncelik:** Düşük-Orta (yetki KAYBI; güvenlik açığı değil)
**Bulundu:** 2026-08-20 — 3.1 "Damgayı Doğrula" turu

`UI/main_window_files.py::_on_context_menu` ilk satırında salt okunur
rolde tüm sağ tık menüsünü kapatıyor:

```python
if is_readonly_role(self._role):
    return
```

Bu tur eklenen **Damgayı Doğrula** maddesi o menünün içinde, dolayısıyla
salt okunur kullanıcı damga doğrulayamıyor.

### Neden bir sorun

Doğrulama saf bir OKUMA: dosyayı değiştirmiyor, anahtar istemiyor, ağa
çıkmıyor, veritabanına yalnızca denetim kaydı yazıyor. "Yazamaz" rolünün
bir okumayı engellemesi kavramsal olarak yanlış. Salt okunur rol tipik
olarak denetçiye verilir — damga doğrulamasının BİRİNCİL kitlesi.

### Neden bu turda düzeltilmedi

Menüyü bu rol için açmak, yıkıcı maddelerin (İndir, İmha, Taşı) sızmadığını
AYRICA kanıtlamayı gerektirir. Bu deponun beş kez yakaladığı kusur sınıfı
tam olarak budur — B-007'de dört görünümden ikisi mahrem filtresizdi ve
sebebi yeni bir görünüm eklenirken filtrenin unutulmasıydı. Rol kapısını
tek maddelik bir istisnayla delmek, aynı hatanın yeni bir yüzeyini açar.

Mevcut davranış `tests/test_timestamp_ui.py::test_SALT_OKUNUR_rol_menuyu_
hic_acmiyor` ile SABİTLENDİ: değişirse test düşer, yani değişiklik
bilinçli olmak zorunda.

### Öneri

Salt okunur rol için AYRI bir menü kurulsun — "yıkıcı olanları çıkar"
değil, "okuma maddelerini ekle" yönünde. Yön önemli: çıkarma listesi
yeni bir madde eklendiğinde sessizce eksik kalır, ekleme listesi kalmaz.
Yanına AST denetimi: salt okunur dalında `addAction` çağrılan maddelerin
kümesi beyaz listeye bağlı olsun.

Alternatif (daha ucuz): doğrulama menüden bağımsız bir yerden de
çağrılabilsin — dosya çift tıklandığında açılan ayrıntı görünümü ya da
AdminPanel. Ama AdminPanel yalnızca yöneticiye açık, yani salt okunur
rolü için çözüm DEĞİL.

### Güncelleme (2026-08-21) — önerilen alternatif KURULDU, kapı açılmadı

Yukarıdaki "alternatif (daha ucuz)" öneri bu turda gerçekleşti:
`UI/GuvenlikView.py` — damga, yedek ve zincir doğrulamasını toplayan
ayrı bir üst seviye görünüm. Yani doğrulama artık sağ tık menüsünden
BAĞIMSIZ bir yerden de çağrılabiliyor.

**Bu maddenin düzeltilmeme gerekçesi o yüzeyde GEÇERSİZ.** Yukarıda
yazan itiraz, menüyü açmanın yıkıcı maddeleri (İndir, İmha, Taşı)
sızdırma riskiydi. Güvenlik sayfasında yıkıcı madde YOK — üçü de saf
okuma, hiçbiri dosyayı değiştirmiyor, anahtar istemiyor, ağa çıkmıyor.
"Okuma maddelerini ekle" yönü de sağlanmış durumda: sayfaya ne
eklendiğini `GuvenlikView._KARTLAR` tek yerde sayıyor.

**Yine de kapı AÇILMADI ve bu bilinçli.** Sayfa bugün salt okunur rolde
gizli; seçim, mevcut kısıtlamayla TUTARLILIK için yapıldı, bir karar
olarak değil. Karar kullanıcıya bırakıldı.

Açmak tek satır: `UI/GuvenlikView.py::GUVENLIK_SALT_OKUNURA_ACIK = True`.
Mevcut davranış `tests/test_guvenlik_view.py::
test_salt_okunura_KAPALI_sabitleniyor` ile sabitlendi — değiştirmek
testi düşürür, yani bilinçli olmak zorunda.

Açılırsa geriye kalan tek soru: salt okunur kullanıcının seçtiği dosyanın
`files` satırını okuyabilmesi gerekiyor mu (denetim kaydının `target_id`
alanı için). Doğrulamanın kendisi o satıra ihtiyaç duymuyor.

---

## B-035 — Hiçbir kullanıcı akışı damga ATMIYOR; doğrulama boşa çalışıyor

**Durum:** Açık — DÜZELTİLMEDİ, önce rapor
**Öncelik:** **Yüksek** (özellik zinciri tamamlanmamış)
**Bulundu:** 2026-08-20 — 3.1 turu, doğrulama düğmesi bağlanırken

`CORE/timestamp.py` iki damgalama fonksiyonu sunuyor:

```
timestamp_file()   → 1 dosya, 1 TSA çağrısı, fragman v1
timestamp_batch()  → N dosya (+ çıpa), 1 TSA çağrısı, fragman v2
```

**İkisinin de testler dışında hiçbir çağıranı yok.** Ölçüldü:

```
$ grep -rn "timestamp_file\|timestamp_batch" --include=*.py . | grep -v "^./tests/"
./CORE/timestamp.py:724:def timestamp_file(
./CORE/timestamp.py:930:def timestamp_batch(
```

(Kalan eşleşmeler docstring'ler.) Ne arayüzde bir düğme, ne zamanlanmış
bir iş, ne bir CLI. `CORE/scheduled_checks.py` damgalamayı çağırmıyor.

### Sonucu

Kasadaki gerçek dosyaların **hiçbiri** damgalı değil. Bu turda eklenen
"Damgayı Doğrula" maddesi, bugünkü hâliyle her dosyada "Bu dosyada zaman
damgası yok" diyecek. Doğru çalışıyor — söyleyecek başka bir şey yok.

Yani şu an elde:

| Parça | Durum |
|---|---|
| Damga ÜRETME (`timestamp_file`/`_batch`) | Yazıldı, test edildi, **bağlanmadı** |
| Damga SAKLAMA (`.hcl` fragmanı v1/v2) | Çalışıyor |
| Damga DOĞRULAMA (çevrimdışı, CLI) | Çalışıyor |
| Damga DOĞRULAMA (arayüz) | Bu turda eklendi |

Zincirin ilk halkası eksik. Doğrulama tarafına yatırılan iş
(`timestamp_verify.py`, `timestamp_report.py`, CLI, diyalog, ~200 test)
kullanıcı için henüz karşılıksız.

### Neden bu turda düzeltilmedi

İstenen iş doğrulama düğmesiydi ve damgalama akışı ayrı bir karar
gerektiriyor — kapsamı bu turun dışında:

* **Ne zaman damgalanacak?** Yüklemede mi (her dosya bir TSA çağrısı),
  yoksa toplu ve zamanlanmış mı (`timestamp_batch` bunun için yazıldı)?
* **Ağ erişimi.** Damgalama, doğrulamanın aksine ağ İSTİYOR. TSA
  erişilemezse yükleme başarısız mı sayılacak, yoksa damga sonraya mı
  bırakılacak? İkincisi bir kuyruk gerektirir.
* **Hangi dosyalar?** Hepsi mi, yalnızca `Kritik` mi, kullanıcı seçimi mi?
* **Maliyet.** freetsa.org ücretsiz ama hız sınırlı; kurumsal bir TSA
  çağrı başına ücretli olabilir.

### Öneri

`timestamp_batch()` zaten toplu iş için tasarlanmış (N dosya, tek TSA
çağrısı, Merkle kökü) ve `current_anchor_hash()` denetim çıpasını da
yaprak olarak katıyor. En düşük riskli ilk adım: `CORE/scheduled_checks.py`
içine günlük bir toplu damgalama görevi, `ZamanKapisi` deseniyle
(`timestamp_last_run`), ve AdminPanel'de bir "Şimdi damgala" düğmesi.
Ağ hatası görevi düşürmeli ama uygulamayı DEĞİL.

### 2026-08-28 (devam) — bu bulgu kalıcı bir testle sabitlendi, tek seferlik ölçüm olmaktan çıktı

`merkle.py`/`hclx.py`'nin (B-043) gerçekten üretimden çağrılıp
çağrılmadığı soruldu. Bu maddedeki `grep` ölçümü doğruydu ama tek
seferlikti — kod tabanı büyüdükçe biri fark ettirmeden bağlayabilir ya da
biri "zaten kullanılmıyor" diye yanlışlıkla silebilir, ikisi de sessiz.

`tests/test_deneysel_bagli_degil.py` eklendi: `ast` ile CORE/, UI/, DB/ ve
`main.py`'yi tarayıp `timestamp_file()`/`timestamp_batch()`'in (bu madde)
ve `create_package()`/`open_package()`'ın (B-043) hâlâ testler dışında
sıfır çağırana sahip olduğunu her koşuda yeniden kanıtlıyor — biri
bağlarsa test KIRILIYOR, sessizce eskimiyor. Ayrıca `verify_merkle_path()`
zincirinin (`CORE/timestamp_verify.py` → `UI/main_window_files.py`
"Damgayı Doğrula") GERÇEKTEN bağlı olduğunu da ayrı bir testle kanıtlıyor
— `merkle.py`'yi `hclx.py` ile aynı kefeye koymamak için: okuma tarafı
çalışıyor, sadece hiç girdi görmüyor (ağacı KURACAK tek yol olan
`timestamp_batch()` bağlı olmadığı için).

`CORE/hclx.py` ve `CORE/merkle.py`'nin modül docstring'lerine
EXPERIMENTAL/NOT-WIRED notu eklendi; SECURITY.md §4.9 ve §4.14 (EN+TR)
bu kalıcı testi anıyor. Ayrıntı SECURITY.md §4.9/§4.14'te.

---

## B-036 — USB fiziksel olarak kaybolduğunda çalışan bir kurtarma yolu YOK

**Durum:** Açık — DÜZELTİLMEDİ, karar gerekiyor
**Öncelik:** **Yüksek** (kurtarma şemasının kapatmayı vaat ettiği senaryo)
**Bulundu:** 2026-08-20 — kullanıcı rehberi yazılırken

Kurtarma şeması 2-of-3 ve gerekçesi SECURITY.md §4.4'te yazılı: üç
paydan herhangi biri kaybolsa kalan ikisi yeterli. Ama `--recover`
**takılı ve kayıtlı bir USB olmadan hiç başlamıyor**:

```python
def _require_hwid() -> str:
    hwid = get_usb_hwid()
    if hwid is None:
        _abort("USB tespit edilemedi. ...")
```

Sebebi teknik olarak doğru: kalan iki payın **ikisi de HWID ile
adresleniyor** — `share_1` `data/vaults/<hwid>.hclv` içinde,
`share_2` işletim sistemi anahtar kasasında `hwid` anahtarıyla. USB
yoksa hangi kaydın okunacağı bilinmiyor.

### Sonucu

| Kaybolan | Kurtarılabilir mi |
|---|---|
| Basılı parça (share_3) | ✅ Evet — normal giriş çalışıyor, `--export` yenisini üretiyor |
| PIN (share_1'e erişim) | ✅ Evet — `--recover`, seçenek 2 |
| Anahtar kasası / makine (share_2) | ✅ Evet — `--recover`, seçenek 1 |
| **USB'nin kendisi** | ❌ **Hayır** — araç başlamıyor |

Yani şema üç paydan birinin kaybını tolere ediyor gibi görünüyor ama
pratikte USB, payların hepsine erişimin ÖN KOŞULU. USB dördüncü ve
yedeksiz bir bileşen.

### Neden acil

Kullanıcının bu noktada bulacağı tek "çözüm" `setup_usb.py --reset` ve o
komut bütün `.hcl` dosyalarını kalıcı olarak açılamaz hâle getiriyor.
Yani çalışan bir yolun yokluğu, kullanıcıyı veri kaybına iten bir
boşluk — sadece bir eksik özellik değil.

`docs/kullanici-rehberi.md` şu an sınırı açıkça yazıyor ("kendi başınıza
yapabileceğiniz bir şey yok, yöneticinize başvurun") ve
`tests/test_kullanici_rehberi.py::test_kayip_USB_icin_calismayan_bir_yol_
ONERILMIYOR` bu notun silinmesini engelliyor. Ama bu bir çözüm değil,
dürüst bir kayıt.

### Karar gerektiren nokta

Bir "yeni USB'ye taşı" akışı eklenecek mi? Eklenirse tasarımı düşünmek
gerekiyor:

* `share_2` kasada HWID ile anahtarlanmış. Yeni HWID'e taşımak, eski
  kaydı **HWID olmadan bulmayı** gerektiriyor — ya kasada bir dizin
  tutulacak ya `usb_tokens` tablosu kullanılacak.
* `share_1` vault dosyasında; dosya adı HWID'den geliyor ama içerik PIN
  ile açılıyor. Dosyayı yeni HWID adına kopyalamak yeterli olabilir —
  ÖLÇÜLMEDİ, AAD'de hwid bağı olup olmadığı kontrol edilmeli.
* Böyle bir akış, USB'yi çalan birinin işine yaramamalı: yeni USB'ye
  taşıma **basılı parça + PIN** istemeli (yani yine 2-of-3).
* B-025 ile kesişiyor: HWID bazı aygıtlarda `usb_ids.json`'dan
  türüyor, yani "USB'nin kimliği" her zaman donanımdan gelmiyor.

Alternatif karar: akış EKLENMEZ ve sınır belgelenir. O durumda kurulum
akışı kullanıcıya **iki USB kaydettirmeli** (yedek anahtar gibi) —
bugün böyle bir şey yok.

---

## B-037 — Kurtarma ve yedek CLI'ları dağıtılan pakete GİRMİYOR

**Durum:** Açık — DÜZELTİLMEDİ, önce rapor
**Öncelik:** Orta-Yüksek (kurtarma yolunun ulaşılabilirliği)
**Bulundu:** 2026-08-20 — kullanıcı rehberi yazılırken

`HYCLEUS.spec` ve `HYCLEUS-linux.spec` yalnızca `main.py`'yi paketliyor
(ölçüldü: her iki spec'te tek bir `EXE(` bloğu, `Analysis(['main.py'])`).

Yani son kullanıcıya giden EXE/AppImage şunları **içermiyor**:

* `CORE/recover_vault.py` — kurtarma parçası, PIN sıfırlama
* `CORE/backup_cli.py` — yedek doğrulama ve geri yükleme
* `CORE/setup_usb.py` — ilk kurulum
* `CORE/verify_timestamp_cli.py` — damga doğrulama

### Çelişki

Bu araçların CLI olmasının gerekçesi her dosyanın docstring'inde aynı:
"grafik arayüz tam ihtiyaç duyulan anda açılmıyor, o yüzden kurtarma
komut satırında." Gerekçe doğru — ama araçlar **dağıtılan pakette hiç
yok.** Elinde yalnızca EXE olan bir kullanıcı için kurtarma yolu
UI'dakinden bile uzak: hiç yok.

Çalıştırmak için kaynak depo + kurulu Python gerekiyor. Bu, hedef
kitlenin (KVKK sorumlusu, denetçi, büro personeli) sahip olduğu bir şey
değil.

### Öneri

Spec'e ikinci bir konsol hedefi eklemek düşük maliyetli: PyInstaller tek
bir `Analysis`/`EXE` çiftinden fazlasını destekliyor. Bir `hycleus-kurtar`
konsol EXE'si, dört CLI'ı alt komut olarak toplayabilir
(`hycleus-kurtar recover`, `... verify-backup`, `... verify-timestamp`).

Dikkat: `console=True` olmalı — `main.py` penceresel derleniyor ve o
kipte `print()` çıktısı hiçbir yere gitmiyor.

Ölçülmesi gereken: paket boyutu artışı (PySide6 ikinci kez girmemeli;
kurtarma CLI'ları Qt kullanmıyor, `excludes` ile dışarıda tutulabilir).

---

## B-038 — Bütünlük taramasının sonucu arayüzde HİÇBİR YERDE gösterilmiyor

**Durum:** Açık — DÜZELTİLMEDİ, önce rapor
**Öncelik:** Orta
**Bulundu:** 2026-08-20 — kullanıcı rehberi yazılırken

Haftalık bütünlük taraması gerçekten çalışıyor: `main.py`
`start_scheduler(key_provider=...)` çağırıyor, zamanlayıcı
`maybe_run_weekly_sweep()`'i koşturuyor. Bozuk dosya bulursa sonuç
**yalnızca iki yere** gidiyor:

1. `logger.warning(...)` — konsola; pencereli EXE'de hiçbir yere.
2. `db.log("integrity_check_failed", ...)` — denetim kaydına.

`files.integrity_status` sütunu da doldurulmuş durumda ve indeksi var
(`DB/db_manager.py`), ama **hiçbir arayüz kodu onu okumuyor** (ölçüldü:
`UI/` altında `integrity_status` geçmiyor).

### Sonucu

Kullanıcının bozulmayı öğrenmesinin tek yolu, Denetim Günlüğü'nü açıp
`integrity_` ile başlayan kayıtları elle aramak. Rehber şu an bunu
adım adım anlatıyor — ama bu, bir bildirimin yerine geçen bir arama
talimatı.

Dosya tablosunda zaten bir "tarama" rozeti sütunu var
(`_VERDICT_BADGE`, antivirüs sonucu için). Bütünlük durumu için aynı
desen kullanılabilir; veri hazır, eksik olan yalnızca gösterim.

Daha önemlisi: `SweepReport.clean` False döndüğünde kullanıcıya bir
kere, açıkça söylenmeli. Sessizce denetim kaydına yazılan bir bozulma,
aylar sonra fark edilir.

---

## B-039 — pip-audit gevşek kapı; sertleştirme kriteri

**Durum:** Açık — karar bekliyor (araç KURULDU ve çalışıyor)
**Öncelik:** Düşük (bugün bulgu yok; madde kapının kendisi hakkında)
**Bulundu:** 2026-08-20 — pip-audit'in CI'a eklendiği tur

### İlk tarama sonucu: TEMİZ

```
49 paket çözümlendi (geçişli bağımlılıklar dahil)
 0 zafiyet — PyPI kaynağı
 0 zafiyet — OSV kaynağı (çapraz kontrol)
```

Taranan: `requirements.txt` + `requirements-dev.txt`, geçişli bağımlılıklar
dahil (`shiboken6`, `charset-normalizer`, `idna`, `urllib3`, `cffi` …).
İki ayrı zafiyet kaynağıyla çapraz kontrol edildi çünkü PyPI ve OSV her
zaman aynı şeyi bildirmiyor.

Yani **düzeltilecek bir bulgu yok** ve bu maddenin konusu bulgular değil,
kapının sertliği.

### Kapı neden GEVŞEK

Alışıldık gerekçe ("mevcut bulgular CI'ı kırmasın") burada GEÇERSİZ —
bulgu yok, sert kapı bugün hiçbir şeyi kırmazdı.

Gevşek bırakılmasının sebebi başka ve daha kalıcı: **bu adım, depodaki
hiçbir şey değişmeden kırılabilen tek adım.** Yukarıda bir CVE yayınlandığı
an, tamamen ilgisiz bir PR kırmızıya döner ve yazarının o bulguyla hiçbir
ilgisi olmaz.

Semgrep kayıt defteri adımında aynı gürültü bilerek kabul edilmişti
("bulgu kaçırmaktansa gürültü"). Fark şu: orada tetikleyici bizim kodumuz
ve düzeltme aynı PR'da yapılabilir. Burada tetikleyici bizim dışımızda ve
düzeltme çoğu zaman bir sürüm yükseltmesi — ayrı bir iş, ayrı bir test
turu.

Bulgu **görünmez değil**: iş özetine markdown tablo olarak yazılıyor ve
`pip-audit-raporu` artifact'ı olarak (kısa tablo + açıklamalı JSON)
yükleniyor.

### Sertleştirme kriteri

Kapı şu ikisinden biri sağlandığında sertleştirilmeli:

1. **Sürüm sabitleme geldiğinde.** Bugün `requirements.txt` sürüm
   sabitlemiyor (`PySide6`, `cryptography`, `requests` … hepsi serbest).
   Sabitlenmiş bir dosyada yeni bir CVE, biz bir şey değiştirene kadar
   ortaya çıkmaz; yani "ilgisiz PR kırmızıya döner" riski büyük ölçüde
   kalkar ve sert kapının bedeli düşer.
2. **`--ignore-vuln` listesi kurulduğunda.** Bilinen ve bilerek kabul
   edilen bulgular gerekçeleriyle listelenirse, sert kapı yalnızca YENİ
   bulgularda çalar. Bu, gevşek kapıdan kesin olarak daha iyi: gevşek
   kapıda kabul edilen bulgu ile fark edilmemiş bulgu ayırt edilemez.

İkincisi tercih edilmeli. Bugün liste BOŞ olacağı için maliyeti bir satır.

Kapının sessizce kalıcılaşmasını `tests/test_packaging.py::
test_pip_audit_GEVSEK_kapi_ve_bu_bilerek` engelliyor: adım gevşekse
gerekçe ve bu madde numarası ci.yml'de anılmak ZORUNDA.

### Yan bulgu — B-020 birebir tekrarladı

pip-audit'in requirements ayrıştırıcısı (`pip_requirements_parser`)
dosyaları **yerel kod sayfasıyla** açıyor:

```python
data.decode(locale.getpreferredencoding(False) or sys.getdefaultencoding())
```

Bizim requirements dosyalarımız Türkçe yorum taşıyor. Türkçe bir
Windows'ta (cp1254) ÖLÇÜLDÜ:

```
UnicodeDecodeError: 'charmap' codec can't decode byte 0x9e in position 506
decoding with 'cp1254' codec failed
```

`PYTHONUTF8=1` ile sorun kayboluyor. Bu, B-020'nin (semgrep + Türkçe kural
dosyası + UTF-8 olmayan locale) birebir aynısı — aynı sınıf üçüncü kez
çıkıyor.

Linux koşucusu zaten UTF-8, yani **CI'da hiç görünmezdi.** Görünmemesi
düzeltmeyi gereksiz yapmıyor: belgelenen elle çalıştırma komutu Türkçe bir
Windows'ta kırılırdı ve geliştirici "bulgu yok" değil bir yığın izleme
görürdü — yani aracın sessizce yanlış cevap verdiğini sanırdı.

`requirements-security.txt`'teki elle çalıştırma komutu ve ci.yml'in iş
düzeyi `env` bloğu ikisi de `PYTHONUTF8=1` taşıyor;
`test_pip_audit_PYTHONUTF8_altinda_kosuyor` ikisini birden denetliyor.

### Kapsanmayan

* **`requirements-build.txt` (PyInstaller) taranmıyor.** Yalnızca paketleme
  makinesinde kurulu ve ürüne girmiyor; yine de bir yapı aracının zafiyeti
  tedarik zinciri riski. Ayrı bir değerlendirme konusu.
* **Sistem/Qt kütüphaneleri taranmıyor.** pip-audit yalnızca Python
  paketlerine bakıyor; AppImage'in `apt` ile kurduğu `libegl1` ve
  arkadaşları kapsam dışında.
* **Bağımlılıklar SABİTLENMİYOR.** Bugünkü tarama "bugün çözümlenen
  sürümler" hakkında; yarın farklı sürümler çözümlenebilir. Sabitleme ayrı
  bir karar (bkz. yukarıdaki 1. kriter).

---

## B-003 — çözüm kaydı (2026-08-21) + köprünün kaldırılması B-040'a devredildi

Zorunlu PIN yenileme akışı eklendi. Kısa PIN'le giren kullanıcı, ana
pencere açılmadan önce PIN'ini yenilemek zorunda.

### Ne yapıldı

| Parça | Nerede |
|---|---|
| Tespit + uygulama + denetim | `CORE/pin_rotation.py` (yeni) |
| Zorunlu ekran | `UI/PinRotationDialog.py` (yeni) |
| Kapı | `UI/login_dialog.py::_zorunlu_pin_yenileme()` |
| İsteğe bağlı akış da aynı yere bağlandı | `UI/ProfileDialog.py` |

### Asıl kapı diyalogda DEĞİL

Diyalog kapatılamaz (iptal düğmesi yok, `reject()` ve `closeEvent`
yutuluyor) ama bu bir **kullanılabilirlik** tercihi. Güvenlik kararını
`_on_login()` veriyor: `dlg.rotated` False ise `accept()` HİÇ
çağrılmıyor. Pencere yöneticisi diyaloğu dışarıdan kapatsa bile
kullanıcı içeri giremiyor.

Ayrım bilinçli: kapatılamaz bir pencere, kullanıcıyı uygulamayı görev
yöneticisinden öldürmeye iten bir tuzağa dönüşebilir. Uygulamadan ÇIKMAK
her zaman mümkün; engellenen tek şey PIN yenilenmeden İÇERİ GİRMEK.

### İkinci bir uygulama yazılmadı

`UI/ProfileDialog.py` PIN değiştirmeyi zaten uyguluyordu. Zorunlu akış
için ikinci bir kopya, bu deponun beş kez ürettiği kusurun altıncısı
olurdu. İkisi de `rotate_pin()` çağırıyor ve AST denetimi
(`test_change_vault_pin_UI_katmanindan_dogrudan_cagrilmiyor`)
`change_vault_pin()`'in UI'dan doğrudan çağrılmasını yasaklıyor.

Yan etki: `rotate_pin()` "yeni PIN eskisiyle aynı olamaz" kuralını
getiriyor. ProfileDialog'da bu YENİ bir kısıt — eskiden aynı PIN'e
"değiştirmek" sessizce kabul ediliyor, kasa boşuna yeniden şifreleniyor
ve denetim kaydı yanıltıcı oluyordu.

### Mutasyon testi

19/20 → düzeltme → **19/19**. Hayatta kalan iki mutasyon:

1. `reject()`'i `super().reject()` yapmak. Testim `result()`'a bakıyordu
   ve `QDialog.Rejected == 0` — başlangıç değeriyle AYNI, yani gerçekten
   reddedilmiş bir diyalog hiç dokunulmamış olandan ayırt edilemiyordu.
   Test artık GÖRÜNÜRLÜĞE bakıyor.
2. `keyPressEvent`'teki Esc kancası. Kaldırmak hiçbir davranışı
   değiştirmedi — `QDialog` Esc'i zaten `reject()`'e yönlendiriyor, yani
   ikinci katman bağımsız olarak gözlenemiyordu. **Katman kaldırıldı**:
   gözlenemeyen bir koruma, zamanla "bu neden burada" diye sorulan ölü
   koda dönüşür.

### Kapsanmayan: kasasız yol

`change_vault_pin()` bir kasa dosyası istiyor. DEV_MODE ve kasa öncesi
kurulumlarda PIN ayrı bir hash dosyasında duruyor ve yenilenemiyor. O
yolda giriş ENGELLENMİYOR — engellemek, çıkış yolu olmayan bir
kilitlenme üretirdi. Durum `_log.warning("pin_rotation_skipped", …)`
ile kayda geçiyor.

Bu yol DEV_MODE ve eski kurulumlara özgü; dağıtılan yapıda
(`sys.frozen`) kasa zorunlu.

---

## B-040 — `LOGIN_MIN_LEN` köprüsü: kaldırma kriteri ve geçiş süresi

**Durum:** Açık — KALDIRILMADI, bilinçli
**Öncelik:** Düşük (köprü zararsız; B-003 kapandıktan sonra yalnızca artık)
**Bulundu:** 2026-08-21 — B-003 çözüm turu

B-003 kapandı ama `LOGIN_MIN_LEN = 4` DURUYOR. Kaldırılmadı ve hemen
kaldırılmamalı.

### Neden hemen kaldırılamaz

Köprü, henüz giriş yapmamış kısa PIN'li kullanıcılar için tek erişim
yolu. Bugün 6'ya çekilirse o hesaplar KENDİ DOĞRU PIN'leriyle giriş
ekranını geçemez — yani B-003'ün kapattığı sessiz kilitlenme, tam da
onu düzelten turda geri gelir.

Sıra kaçınılmaz: önce herkes girip yenileyecek, sonra köprü kalkacak.

### "Herkes göç etti" ÖLÇÜLEBİLİR mi — evet, dolaylı olarak

İlk bakışta hayır: PIN uzunluğu Argon2id hash'inden çıkarılamaz, yani
"kaç hesap hâlâ kısa PIN'de" diye sorulamıyor. `pin_rotation_forced`
kaydı yalnızca GÖÇ EDENLERİ sayıyor; göç etmeyenler görünmez.

Ama sorunun eşdeğeri ölçülebilir: **B-003 akışı yayına girdikten sonra
giriş yapan her hesap zaten uyumludur** — ya PIN'i 6+'ydı ya da
yenilemeye zorlandı. Yani soru "kim kısa PIN'de" değil, "kim akıştan
sonra hiç giriş yapmadı".

`users.last_login` bu soruyu yanıtlıyor:

```sql
-- Köprü hâlâ gerekli olan hesaplar
SELECT u.id, u.username, u.last_login
FROM   users u
JOIN   usb_tokens t ON t.hwid = u.hwid
WHERE  t.blacklisted = 0
  AND  (u.last_login IS NULL OR u.last_login < '<AKIŞ_YAYIN_TARİHİ>');
```

Bu sorgu BOŞ dönüyorsa köprü kaldırılabilir.

### Önerilen geçiş

1. **Gözlem penceresi — en az 90 gün.** Gerekçe: bu bir kurum içi
   belge kasası; bir kullanıcı izinde, raporlu ya da başka bir projede
   olabilir. Üç ay, "aktif ama seyrek" bir kullanıcının en az bir kez
   giriş yapması için makul bir alt sınır. Bir çeyrek dönemi de kapsıyor.
2. **Pencere boyunca ölçüm.** Yukarıdaki sorgu AdminPanel'e bir satır
   olarak eklenebilir ("N hesap henüz PIN göçünü tamamlamadı"). Bugün
   böyle bir gösterge YOK ve elle SQL çalıştırmayı gerektiriyor.
3. **Pencere sonunda kalan hesaplar için karar.** Boş değilse iki
   seçenek: (a) o hesapları elle devre dışı bırakıp kullanıcıyı
   kurtarma akışına yönlendirmek, (b) pencereyi uzatmak. Köprüyü
   kalanları görmezden gelerek kaldırmak, onları kilitlemek demektir.
4. **Kaldırma.** `LOGIN_MIN_LEN` silinir, giriş kontrolü `PIN_MIN_LEN`'e
   çekilir, `test_login_floor_stays_below_new_policy` kaldırılır ve
   yerine "iki eşik artık AYNI" testi yazılır.

### Dikkat — invariant hâlâ geçerli

`tests/test_pin_policy.py::test_login_floor_stays_below_new_policy`
`LOGIN_MIN_LEN < PIN_MIN_LEN` şartını koruyor ve bu test 4. adıma kadar
KALDIRILMAMALI. Bugün ikisini eşitlemek, göç etmemiş hesapları sessizce
kilitler.

### Kapsanmayan

* **Göç göstergesi yok.** Yukarıdaki sorgu hiçbir arayüzde görünmüyor;
  2. adım onu AdminPanel'e bağlamayı öneriyor ama bu tur yapılmadı.
* **Akış yayın tarihi kayıtlı değil.** Sorgu bir eşik tarih istiyor ve o
  tarih şu an yalnızca git geçmişinde. Bir `settings` satırı
  (`pin_rotation_deployed_at`) bunu ölçülebilir kılardı.

---

## B-041 — SECURITY.md'de saldırgan modeliyle ÇELİŞEN beş iddia (okuma turu bulgusu)

**Durum:** BEŞTE DÖRDÜ ÇÖZÜLDÜ (2026-08-21) — 4. madde (§5 "device binding")
kullanıcı kararıyla KAPSAM DIŞI bırakıldı, açık kalmaya devam ediyor
**Öncelik:** Orta (hiçbiri kod hatası değil; hepsi belge doğruluğu)
**Bulundu:** 2026-08-21 — üç saldırgan modeli eklendikten sonraki okuma turu

### Çözüm kaydı (2026-08-21)

| Madde | Durum | Ne yapıldı |
|---|---|---|
| 1 — §2 bütünlük satırı ✅ vs ⚠️ | ÇÖZÜLDÜ | Karar `⚠️ Bulunur, ama kararı silinebilir` oldu; gerekçe kopyalanmadı, §4.7'ye atıf verildi |
| 2 — §4.7 "anahtarı olmayan" koşulsuz | ÇÖZÜLDÜ | Kilitli/kilitsiz oturum ayrımı açıkça yazıldı; §3'ün bellek itirafına bağlandı |
| 3 — §2 `share_2` satırı | ÇÖZÜLDÜ | `✅ güncel bir kurulumda` + migration öncesi ham kopya istisnası, §1.3'e atıf |
| 4 — §5 "device binding" | **AÇIK** | Kullanıcı kararıyla kapsam dışı; satırlara DOKUNULMADI (parmak izleriyle doğrulandı) |
| 5 — §5 "en az 6 karakter" | ÇÖZÜLDÜ | Geçiş penceresi ve `LOGIN_MIN_LEN = 4` yazıldı, B-040'a atıf |

**2. madde bir yan tutarsızlık üretti ve o da kapatıldı.** Koşul §4.7'nin
giriş paragrafına yazılınca, altı satır aşağıdaki madde imi (`*Dosya*
taklit edilemez`) aynı mutlak ifadeyi tekrarlar hâle geldi — yani düzeltme
kendi içinde yeni bir çelişki doğurdu. Hem o madde imi hem §1.2
matrisindeki aynı ifade koşula bağlandı.

**Belge sayıyı yazdığı için bir denetim eklendi.** §5 artık
`LOGIN_MIN_LEN = 4` diyor ve bu elle yazılmış bir sayı — B-017'nin sınıfı.
`tests/test_pin_policy.py::test_SECURITY_md_giris_esigini_DOGRU_yaziyor`
sabiti belgeyle karşılaştırıyor ve iki dilde de arıyor. B-040 köprüyü
kaldırdığında bu test düşecek ve belgeyi güncellemeye zorlayacak.

### Özgün bulgular (kayıt için)

M1/M2/M3 modelleri eklenip her iddia etiketlenince, daha önce görünmeyen
beş yer görünür oldu: iddianın kendisi doğru ama **hangi saldırgana karşı
doğru olduğu** söylenmiyor ve modele göre okununca fazlasını vaat ediyor.

Talimat gereği hiçbiri düzeltilmedi. Beşi de tek bir soruya bakıyor:
§2/§5'in kısa ifadeleri mi genişletilsin, yoksa §1.2 matrisi tek doğruluk
kaynağı sayılıp §2/§5 özet olarak mı bırakılsın.

### 1. §2'nin bütünlük satırı ✅ diyor, §1.2 ve §4.7 ⚠️ diyor

| Yer | Ne diyor |
|---|---|
| §2, "diskte sessizce bozulma" satırı | **✅** Dosya açılmadan bulunur |
| §1.2, bütünlük taraması satırı | **⚠️** dosya sahtelenemez, KARAR sahtelenebilir |
| §4.7 | "`UPDATE files SET integrity_status = 'ok'` bulguyu siler" |

Satır M3 etiketli ve M3 kurcalayanın kendisiyse taramanın kararını da geri
alabiliyor. §4.7 bunu zaten söylüyor ve satır §4.7'ye atıf veriyor — yani
belge kendi içinde tutarsız değil, ama ✅ ile ⚠️ yan yana konduğunda
denetçinin göreceği ilk şey bu.

Seçenekler: (a) §2'nin kararını "⚠️ Bulunur, ama karar silinebilir — bkz.
§4.7" yapmak, (b) satırı ikiye bölmek — saldırgansız nedenler (bit çürümesi,
yarım kopya) ✅, M3 kurcalaması ⚠️.

### 2. §4.7'nin "anahtarı olmayan hiç kimse" ifadesi koşulsuz

§4.7: "GCM tag'i ana anahtar altında hesaplanıyor, yani anahtarı olmayan
hiç kimse bir dosyayı değiştirip doğrulanan bir tag üretemez."

Doğru — ama M3 açısından eksik: oturum KİLİTLİ DEĞİLKEN ana anahtar süreç
belleğinde ve §3'ün "Bellek" paragrafı bir bellek dökümünün düz metin
içerebileceğini zaten kabul ediyor. Yani anahtarlı denetim, M3'ün kilitsiz
bir oturum yakalamadığı sürece dayanıyor.

Bu turda §1.2 ve §1.3 koşulu AÇIKÇA yazdı; §4.7 hâlâ koşulsuz. İki yer aynı
şeyi farklı kesinlikte söylüyor.

### 3. §2'nin "`share_2` artık veritabanında değil" satırı GÜNCEL kurulum için doğru

Satır: "`share_2` veritabanından okundu → ✅ Artık orada değil".

Migration ÖNCESİ alınmış ham bir `data/` kopyası için yanlış: `share_2` o
kopyada `usb_tokens.share_2` sütununda düz metin. Kırılmış bir PIN'le
birleştiğinde ana anahtarı gerçekten yeniden kuruyor.

`CORE/secret_migration.py` canlı kopyanın üzerine yazıp temizliyor ama
makineden çıkmış bir kopyaya ulaşamıyor — §4.4'ün "hiçbir şey
döndürülmüyor" ısrarının aynısı. §4.6 tam bu şekli ("zincir yükseltmede
başlıyor") açıkça işaretliyor; §2'nin bu satırı işaretlemiyor.

Bu tur §1.3'e bir istisna paragrafı olarak yazıldı. §2 satırının kendisi
DEĞİŞTİRİLMEDİ.

### 4. §5'in "device binding" ifadesi B-025 aygıt sınıfında geçerli değil

§5: "Vault sealing: AES-256-GCM, AAD = HWID (**device binding**)".

B-025'te ölçüldü: depolama yığını kullanılamaz seri bildirdiğinde HWID
`data/usb_ids.json`'daki bir UUID'den geliyor. O aygıt sınıfında bağ cihaza
değil DOSYAYA. §4.2 HWID'nin sır olmadığını zaten söylüyor ama "device
binding" ifadesi ayrı bir şey vaat ediyor: cihazın VARLIĞINI.

Kapsam notu: §5, kullanıcının taradığımı söylediği §1–§4.12 aralığının
DIŞINDA, o yüzden dokunulmadı. §1.3 bu turda B-025'e açık atıf verdi.

### 5. §5'in "yeni PIN'ler için en az 6 karakter" ifadesi giriş eşiğinden söz etmiyor

§5: "PIN storage: Argon2id hash; **minimum 6 characters for new PINs**".

Literal olarak doğru. Eksik olan, `LOGIN_MIN_LEN = 4` köprüsünün hâlâ
duruyor olması (B-040): giriş ekranı 4 haneli bir PIN'i kabul ediyor ve
B-003 akışı onu ancak kullanıcı GİRDİKTEN sonra yeniliyor. "En az 6 karakter"
diyen bir güvenlik belgesi, kaba kuvvet direncini değerlendiren bir denetçi
için burada eksik konuşuyor.

SECURITY.md `LOGIN_MIN_LEN`'den hiçbir yerde söz etmiyor. B-040 kapanınca bu
madde kendiliğinden düşer; kapanana kadar bir cümle hak ediyor.

### Bu turda YAPILAN — kayıt için

Çelişkiler düzeltilmedi ama bu turda YAZILAN metin kendi içinde tutarlı
tutuldu: §1.2 matrisinin GCM satırı ⚠️'ye çekildi (madde 2), §2'nin iki
kurcalama satırı yalnızca **M2** etiketlendi (M3 iddiası §1.2'ye bırakıldı),
ve §1.3'e migration öncesi kopya istisnası (madde 3) ile B-025 atfı
(madde 4) yazıldı.

---

## B-042 — TPM mühürlemesinin kapsamadıkları

**Durum:** Açık — ama madde 1 (asıl eksik) KAPANDI, bkz. 2026-08-28 notu
**Öncelik:** ~~Orta (1. madde)~~ ÇÖZÜLDÜ, Düşük (kalan 2-4)
**Bulundu:** 2026-08-21 — TPM 2.0 mühürlemesi eklenirken

`CORE/tpm_sealing.py` eklendi ve SECURITY.md §4.13'te belgelendi. Bilerek
YAPILMAYAN dört şey burada; hiçbiri gizlenmiyor.

### 1. Mevcut kayıtlar geriye dönük mühürlenmiyordu — ASIL EKSİK (KAPANDI, bkz. 2026-08-28)

Mühürleme yalnızca YAZMA anında oluyordu. `share_2` ise yalnızca kasa
kurulurken ya da yeniden sağlanırken yazılıyor. Sonuç, bu düzeltmeden önce:

> **TPM'li bir makinedeki YERLEŞİK bir kurulum, kasa yeniden sağlanana
> kadar bu özellikten hiçbir kazanım görmüyordu.**

Ve bunu hiçbir arayüz söylemiyordu. Kullanıcı Hakkında kutusunda "TPM
mühürlemesi ETKİN" görüyor — ki doğru, mühürleme etkin — ama KENDİ
`share_2` kaydı hâlâ mühürsüz olabiliyordu. Bu, B-025'in şeklinin bir tık
yumuşamış hâli: katman açık, ama o kayda uygulanmamış.

O zaman bu turda yapılmama gerekçesi iki göç yolunun da "saf ekleme"
sınırını aştığı düşünülmesiydi:

  (a) **Okurken yeniden mühürle.** `load()` mühürsüz bir kayıt görünce
      mühürleyip geri yazar. Ucuz ama `open_vault()` bir OKUMA işlemine
      yazma ekler — kasa açma akışının davranışı değişir.
  (b) **Açılışta göç adımı.** `DB/migrations.py` iskeleti hazır ama o
      defter SQLite şeması için; anahtar kasası kayıtları şema değil.
      Ayrı bir göç noktası gerekir.

**2026-08-28 — (a) uygulandı.** `CORE/secret_store.py::load()` artık
mühürsüz okuduğu bir kaydı, TPM şu an kullanılabiliyorsa hemen yeniden
mühürlüyor (`_reseal_firsatci()`) — kullanıcı ayrıca bir şey yapmadan,
İLK açılışta (`open_vault()`). "Okuma işlemine yazma ekleniyor" endişesi
aşıldı: yeniden mühürleme başarısız olsa bile OKUMA yine de değeri
döndürüyor (zaten başarıyla okunmuş bir değeri arkadaki iyileştirme
denemesi patladı diye vermemek yeni bir kilitlenme yüzeyi açardı) — ama
sessiz de değil: başarı `tpm_reseal_completed`, başarısızlık
`tpm_reseal_failed` olarak denetim zincirine düşüyor. TPM kararı
(`.kullanilabilir`) `tpm_sealing.py` dışında TEKRARLANMIYOR —
`belki_muhurle()`'nin döndürdüğü değerin mühürlü olup olmadığına bakarak
çıkarım yapılıyor (`tests/test_tpm_sealing.py::
test_kullanilabilir_karari_baska_modulde_TEKRARLANMIYOR` bunu zaten
koruyordu, yeni kod da ihlal etmiyor).

Test: `tests/test_tpm_sealing.py::
test_ESKI_kurulum_ILK_ACILISTA_otomatik_yeniden_muhurleniyor` (sahte TPM,
eski/mühürsüz bir kurulumu simüle ediyor, ilk `open_vault()`'un share_2'yi
yeniden mühürlediğini VE yeni mührün doğru anahtarı verdiğini VE tek bir
denetim kaydı düştüğünü doğruluyor) ve
`test_gercek_TPM_ile_ESKI_kayit_ilk_okumada_yeniden_muhurleniyor`
(`gercek_tpm` fixture'ıyla, bu geliştirme makinesindeki GERÇEK AMD fTPM
üzerinde aynı iddia). Ayrıntı SECURITY.md §4.13'te.

AdminPanel'e "bu kasa TPM'e mühürlü: evet/hayır" satırı eklemek hâlâ
YAPILMADI — artık bir düzeltme önkoşulu değil (mühürleme kendiliğinden
oluyor), ama görünürlük için hâlâ faydalı olurdu; ayrı, düşük öncelikli
bir iyileştirme olarak burada not düşülüyor.

### 2. CI'da TPM yolu HİÇ çalışmıyor (B-023 sınıfı)

`gercek_tpm` fixture'ı isteyen testler CI'da ATLANIYOR: ne Linux ne de
Windows koşucusunda TPM sağlayıcısı var. Yani mühürleme yolunun yeşil
kalması TEK bir geliştirici makinesinin ölçümüne dayanıyor.

Ölçüldüğü ortam, kayıt için: AMD fTPM 2.0, Level 0, Revision 1.59,
Firmware 393248.6, Windows 11 Pro 26200, 2026-08-21.

Seçenek: GitHub'ın Windows koşucularında vTPM yok; kendi barındırılan bir
koşucu ya da Hyper-V vTPM'li bir sanal makine gerekir. Maliyeti bu projenin
ölçeğine göre yüksek — madde şimdilik "biliniyor ve yazılı" durumunda.

### 3. Tek bir TPM üreticisi görüldü

Yalnızca AMD fTPM denendi. Intel PTT, ayrık TPM yongaları (Infineon,
Nuvoton) ve sanal TPM'ler DENENMEDİ.

Somut bilinmezlik: OAEP'in reddedilmesi (`NCryptEncrypt` → `NTE_BAD_FLAGS`,
0x80090009) BU sağlayıcıda ölçüldü. Kod zaten PKCS#1'e sabitlendiği için
başka bir üreticide davranış değişmez — ama "OAEP hiçbir TPM'de
çalışmıyor" DENMEDİ ve denmemeli.

İkinci bilinmezlik: `NCryptDecrypt`, KURCALANMIŞ bir PKCS#1 sarmalını hata
vermeden çözüp BOŞ tampon döndürdü (ölçüldü). Bu davranışın üreticiye
bağlı olup olmadığı bilinmiyor. Kod artık DEK uzunluğunu denetliyor, yani
her iki davranışta da `TpmSealingError` çıkıyor.

### 4. TPM temizleme senaryosu fiziksel olarak denenmedi

"TPM silinirse mühür kalıcı olarak açılamaz" iddiası mantıksal. BIOS'tan
Clear TPM yapılıp doğrulanmadı — o işlem ölçüm makinesindeki BitLocker ve
Windows Hello kayıtlarını da yok ederdi.

Yerine aynı HATA YOLU testte üretiliyor (`test_tpm_sealing.py::
test_muhurlu_kayit_TPM_yokken_None_DONMUYOR` ve
`test_TPM_li_kasa_TPM_gidince_ACILMIYOR`): kasada mühürlü kayıt varken TPM
kapatılıyor ve istisnanın gerçekten fırladığı, `None` DÖNMEDİĞİ ölçülüyor.
Ölçülmeyen tek şey, gerçek bir Clear TPM'in CNG'den hangi hata kodunu
döndürdüğü.

---

## B-043 — `.hclx` teslim paketinin kapsamadıkları

**Durum:** Açık — bilinçli kapsam sınırları
**Öncelik:** Orta (1–2), Düşük (3–4)
**Bulundu:** 2026-08-21 — `.hclx` formatı kurulurken

`CORE/hclx.py` eklendi, SECURITY.md §4.14'te belgelendi. Bilerek YAPILMAYAN
şeyler burada.

### 1. Arayüz bağlantısı YOK — format var, düğme yok

`create_package()` ve `open_package()` çalışıyor ve test ediliyor, ama
hiçbir menüden çağrılmıyor. Bugün `.hclx` yalnızca koddan erişilebilir.

Bu B-035'in ("hiçbir kullanıcı akışı damga ATMIYOR") ve B-038'in ("bütünlük
taramasının sonucu arayüzde görünmüyor") aynı sınıfı: çalışan ama
erişilemeyen bir özellik.

Gerekenler: gönderme akışı (dosya seç → pencere seç → kaydet), açma akışı
(dosya seç → doğrula → nereye çıkaracağını sor), ve reddedilen paket için
`_pencere_mesaji()` metnini gösteren bir diyalog.

### 2. Kullanıcı düzeyinde kaynak kanıtı YOK

İmza kasa master key'i altında, yani "bu kasadan çıktı" kanıtlanıyor,
"bunu KİM üretti" kanıtlanmıyor. Kasaya erişimi olan herkes aynı anahtarı
paylaşıyor; `sender_user_id` kurcalanamaz ama bir BEYAN.

Asimetrik bir kimlik gerekir. TPM anahtarı (B-042 turunda eklendi) bunun
için kullanılamaz: bilerek yalnızca ÇÖZME yetkili
(`NCRYPT_ALLOW_DECRYPT_FLAG`) ve makine başına, kullanıcı başına değil.

Bu, "yeni imza şeması icat etme" kısıtıyla bilinçli olarak çelişmiyor —
kısıt gereği mevcut mekanizma kullanıldı ve SINIRI YAZILDI. Asimetrik
kimlik ayrı bir tasarım kararı ve bu maddenin konusu.

### 3. Üretim zamanı BEYAN — RFC 3161 damgası yok

`created_at` üreten makineden geliyor. Pencere hesabı `valid_from`/
`valid_until`'e bakıyor ve ikisi de aynı beyandan türüyor.

`timestamp.py` zaten RFC 3161 damgası atabiliyor ve gövde bir `.hcl`, yani
damgalanabilir. Yapılmadı çünkü B-035 hâlâ açık: hiçbir akış damga atmıyor,
yani damgalama önce KENDİ ayakları üzerinde durmalı.

Damga eklense pencerenin BAŞLANGICI güvenilir bir alt sınır kazanırdı. Ama
"şimdi"yi hâlâ çözmezdi (bkz. 4. madde).

### 4. Pencere YEREL SAATE bakıyor — saati geri almak paketi açar

SECURITY.md §4.14 bunu açıkça yazıyor ve §3 aynı çekinceyi giriş kilidi
için zaten kabul ediyor. Çevrimdışı bir uygulamada güvenilir bir "şimdi"
yok; çözüm bir zaman sunucusu ya da çevrimiçi anahtar dağıtımı ister ve
ikisi de HYCLEUS'un çevrimdışı olma kararını bozar.

Kayda geçiyor çünkü pencere bir GÜVENLİK özelliği gibi okunabiliyor;
değil — uygulama seviyesi bir kontrol (§4.5 sınıfı).

### 5. Boyut sınırı 64 MB ve bellekte ~%33 fazlası duruyor

Gövde base64 taşıyan kanonik JSON ve `decrypt_file()` tamamını belleğe
alıyor. Sınır aşılırsa net bir hata veriliyor ve kullanıcı yedeklemeye
yönlendiriliyor.

Akış tabanlı bir gövde (base64 yerine uzunluk önekli ikili çerçeveleme)
sınırı kaldırırdı ama ikinci bir ayrıştırıcı demek. Belge teslimi için
gerekli görülmedi; gerekirse sürüm `0x02` ile gelir — `SUPPORTED_VERSIONS`
o gün için hazır.

### 2026-08-28 (devam) — madde 1'in "hiçbir menüden çağrılmıyor" iddiası kalıcı bir testle sabitlendi

`merkle.py` ile birlikte sorulan: `.hclx` gerçekten üretimden çağrılıyor
mu? Madde 1'deki bulgu doğruydu ama tek seferlik bir gözlemdi.
`tests/test_deneysel_bagli_degil.py` eklendi — `create_package()`/
`open_package()`'ın CORE/, UI/, DB/ ve `main.py` genelinde testler
dışında hâlâ sıfır çağırana sahip olduğunu her koşuda `ast` ile yeniden
kanıtlıyor; biri bunu bir menüye/CLI'a bağlarsa (madde 1'in önerdiği
gönderme/açma akışı gibi) test KIRILIR ve bu maddenin, SECURITY.md
§4.14'ün, README'nin ve `CORE/hclx.py`'nin kendi EXPERIMENTAL/NOT-WIRED
docstring notunun bilinçli olarak güncellenmesi gerekir — sessiz drift
yerine. Ayrıntı SECURITY.md §4.14'te, aynı yaklaşım B-035'e de uygulandı.

---

## B-044 — Güvenilir kök deposu makine DIŞINA taşınamıyor

**Durum:** Açık — bilinçli kapsam sınırı
**Öncelik:** Orta (kazanımın tavanını belirliyor)
**Bulundu:** 2026-08-21 — kurumsal güvenilir kök deposu eklenirken

`CORE/trusted_roots.py` güven kökünü doğrulanan DOSYANIN DIŞINA çıkardı —
SECURITY.md §4.9'un yıllardır yazdığı sınır bu turda kapandı. Ama liste
`settings` tablosunda, yani **şifresiz veritabanında** (§3).

### Sınır

Veritabanına yazabilen biri (M3) kendi kökünü ekleyip sahte bir damgayı
"tam geçerli" gösterebilir. Bir `INSERT` yeter.

Kazanım yine de gerçek ve ölçülebilir: kurcalayanın artık İKİ yeri birden
tutarlı tutması gerekiyor (dosyadaki fragman + veritabanındaki liste) ve
ikincisi denetim kaydına düşen bir eylem (`tsa_root_added`). Ama bu, §4.5'in
tarif ettiği sınıftan bir kontrol — maliyeti yükseltiyor, kapatmıyor.

### Çözüm: çıpanın deseni

`CORE/audit_chain.py` aynı sorunu `HYCLEUS_AUDIT_ANCHOR` ile çözüyor: çıpa
dosyasının yolu ortam değişkeniyle bir USB'ye, ağ paylaşımına ya da salt
okunur bir konuma yönlendirilebiliyor. SECURITY.md §4.6 bunu açıkça
"özelliğin gerçek olduğu yer" diye anlatıyor.

Kök deposu için aynısı gerekir: `HYCLEUS_TSA_ROOTS` gibi bir değişken, ya
da bir dizin yolu ayarı. O zaman liste M3'ün yazamayacağı bir güven
alanına taşınabilir.

Yapılmadı çünkü bu tur "settings'te bir ayar" olarak istendi ve iki kaynağı
aynı anda kurmak "tek karar noktası" sınırını bulanıklaştırırdı: hangi
listenin kazandığı, çakışınca ne olacağı ve hangisinin denetim kaydına
gireceği ayrı kararlar.

### İlgili, ama AYRI: CLI bilerek depoyu kullanmıyor

`CORE/verify_timestamp_cli.py` kayıtlı listeyi okumuyor ve okumamalı —
denetçi tam olarak bu makineyi denetliyor. Bu bir eksik değil, karar;
`CORE/trusted_roots.py` docstring'inde ve §4.9'da yazılı,
`tests/test_trusted_roots.py::test_CLI_kok_deposunu_KULLANMIYOR` sabitliyor.

### Kapsanmayan diğer şey: kök GEÇERLİLİĞİ kontrol edilmiyor

Depoya eklenen sertifikanın süresi dolmuş olabilir, iptal edilmiş olabilir,
CA olmayabilir. `der_coz()` yalnızca "geçerli bir X.509 mu" diye bakıyor.

Bilinçli: §4.9 zaten iptal kontrolü yapılmadığını (OCSP/CRL ağ ister,
uygulama çevrimdışı) ve kendinden imzalı bir kökün öz-imzasının bir güven
beyanı OLMADIĞINI yazıyor. Kökün uygunluğu, onu ekleyen yöneticinin
kararı — araç o kararı taklit etmemeli.

---

## B-045 — Görünüm tercihleri için kullanıcı başına ayar altyapısı yok

**Durum:** Açık — bilinçli kapsam sınırı
**Öncelik:** Düşük (kozmetik; veri ya da yetki etkisi yok)
**Bulundu:** 2026-08-21 — Güvenlik sekmesi Basit/Gelişmiş anahtarı eklenirken

Güvenlik sekmesinin Basit/Gelişmiş anahtarı OTURUM İÇİ tutuluyor
(`GuvenlikView._gelismis`), kalıcı ayara yazılmıyor.

### Neden kalıcı YAPILMADI

`settings` tablosu KURULUM GENELİ, kullanıcı başına değil. Anahtar oraya
yazılsaydı bir kullanıcının görünüm tercihi, aynı makineyi kullanan diğer
kullanıcıların gördüğünü de değiştirirdi — bir tercih değil, bir hata.

Kullanıcı başına tercih altyapısı yok ve kozmetik bir anahtar için onu
kurmak orantısız: `users` tablosuna sütun eklemek ya da ayrı bir
`user_settings` tablosu açmak bir şema göçü demek (`DB/migrations.py`).

### Ne zaman gerekir

İkinci bir kullanıcı başına tercih ortaya çıktığında. O gün tek bir
`user_settings(user_id, key, value)` tablosu doğru cevap olur ve bu anahtar
da oraya taşınır. Tek bir tercih için tablo açmak, tablo açmadan iki
tercihi `settings`'e sıkıştırmaktan iyi DEĞİL — ikisi de erken karar.

### Bugünkü maliyet

Kullanıcı uygulamayı her açtığında anahtar Gelişmiş'e dönüyor. Varsayılan
bilerek Gelişmiş: diyalogların bugünkü hâli o ve Basit'i varsayılan
yapmak, mevcut kullanıcıların gördüğü bilgiyi habersiz azaltırdı.

---

## B-046 — `85c6dcc` ubuntu kırmızısının GERÇEK sebebi hâlâ bilinmiyor

**Durum:** Açık — teşhis yarım, sebep belirlenemedi
**Öncelik:** YÜKSEK (CI kırmızı)
**Bulundu:** 2026-08-21 — CI teşhis turu

Run `32489529229`, job `96793665685` (`ubuntu-latest · Python 3.11`),
adım "Test (pytest)". Beş test düştü, hepsi `AdminPanel` kuran testler:

```
tests.test_trusted_roots::test_panel_bos_depoyu_ANLASILIR_gosteriyor
tests.test_trusted_roots::test_panel_eklenen_koku_LISTELIYOR
tests.test_trusted_roots::test_panel_silme_dugmesi_KOK_SECILINCE_aciliyor
tests.test_trusted_roots::test_panel_silmeyi_UYGULUYOR
tests.test_trusted_roots::test_panel_ONAY_verilmezse_silmiyor
```

Aynı dosyadaki diğer 28 test — gerçek freetsa token'ıyla çalışan uçtan uca
kök eşleşmesi dâhil — Linux'ta GEÇTİ. Yani kök deposu mantığı sağlam;
düşen tek şey `AdminPanel` yüzeyi.

### ELENEN sebep: eksik `QT_QPA_PLATFORM`

İlk hipotez buydu ve **yanlış çıktı**. İki bağımsız ölçüm:

1. Pytest bütün modülleri koşudan ÖNCE topluyor. Tam pakette
   `test_backup_verify_ui.py` (alfabetik olarak önce) modül seviyesinde
   `setdefault` çalıştırıyor, yani koşu başladığında değişken ZATEN
   `offscreen`. Ölçüldü — izole koşuda `None`, tam pakette `'offscreen'`.
2. Yüklenemeyen bir platformda `QApplication([])` **yakalanabilir istisna
   vermiyor**, `qFatal` ile süreci öldürüyor (ölçüldü: çıktı hiç
   basılmadı). Öyle olsaydı pytest hiç bitmez ve JUnit XML üretilmezdi —
   oysa `test-results-ubuntu-latest-py3.11` artifact'i 32 KB ve içinde
   2200+ geçen test var.

Eksik satır yine de gerçek bir kusurdu (izole koşu Linux'ta çökerdi) ve bu
turda düzeltildi + AST denetimi eklendi. Ama CI'ı kıran şey O DEĞİL.

### Neden sebep okunamıyor

`UI/AdminPanel.py` bugüne kadar hiçbir Linux koşusunda kurulmadı: onu
kuran tek yer bu testler, `main.py --selftest` listesi yalnızca CORE/DB
modüllerini içeriyor ve `test_layering.py` UI dosyalarını AST ile okuyup
içe aktarmıyor. Yerelde Linux yok (WSL kurulu değil, Docker yok).

Yetkisiz API ile log (403) ve artifact (401) indirilemiyor; annotation'lar
bu tura kadar yalnızca test ADINI taşıyordu.

### Sıradaki adım — DENENDI, SONUC ALINAMADI

`render_annotations` genişletildi: annotation artık `<failure message=...>`
ilk satırını da taşıyor. Ama bir sonraki koşuda **bu beş test hiç
çalışmadı** — araya toplama (collection) hatası girdi ve pytest daha ilk
saniyede durdu. Bkz. B-047.

Yani bu madde açık kalmakla kalmıyor, artık **maskelendi**: B-047
çözülmeden beş testin sebebi ölçülemez.

**2026-08-22 güncelleme:** B-047 çözüldü, maske kalktı. Bir sonraki
push'ta ubuntu ayağı koşu evresine geçebilecek ve beş `test_panel_*`
testinin gerçek hata mesajı annotation'da görünecek — ama B-048 yüzünden
yalnızca `<failure message=...>` taşıyan koşu başarısızlıkları için.

### Güncelleme — 2026-08-21 21:00, run `32526378278` (`89826bd`)

Ölçülenler (yetkisiz GitHub API; log 403, artifact indirme 401 — yalnızca
metadata ve annotation okunabildi):

| | `85c6dcc` / run 32489529229 | `89826bd` / run 32526378278 |
|---|---|---|
| Çıkış kodu | **1** (test başarısızlığı) | **2** (toplama hatası) |
| "Test (pytest)" adımı | 21:00:38 → 21:01:23, **45 s** | 21:00:38 → 21:00:41, **3 s** |
| İş toplamı | 1 dk 09 sn | 34 sn |
| JUnit artifact | 32 230 bayt, 2200+ geçen | **935 bayt** |
| Annotation | 5 adet, `test_panel_*` | 1 adet, `collection failure` |

Kullanıcının fark ettiği "45 s → 34 s" farkının kaynağı budur: koşu
hızlanmadı, **hiç başlamadı**. 935 baytlık XML tek bir toplama hatasından
başka hiçbir şey içermiyor.

Annotation'ın harfi harfine metni:

```
::error title=Basarisiz test (ubuntu-latest · Python 3.11)::tests.test_guvenlik_view — collection failure
```

Beş `test_panel_*` testi bu koşuda **hiç görünmüyor** — çünkü pytest
toplama hatasında oturumu `Interrupted` ile bitiriyor, koşu evresine hiç
geçmiyor.

---

## B-047 — `test_guvenlik_view.py` Qt'yi korumasız içe aktarıyor: ubuntu'da toplama hatası

**Durum:** ÇÖZÜLDÜ — 2026-08-22, kalıcı denetimle birlikte
**Öncelik:** —
**Bulundu:** 2026-08-22 — annotation okuma turu

`89826bd` koşusunda ubuntu ayağını kıran şey `tests/test_guvenlik_view.py`
dosyasının **toplanamaması**. Çıkış kodu 2, pytest 3 saniyede durdu.

### Neden bu dosya

Deponun Qt test dosyalarında yerleşik bir desen var ve bu dosya onu
uygulamıyor. AST ile ölçüldü (modül seviyesinde, `try` bloğunun dışında
`PySide6`/`UI`/`shiboken6` içe aktaran test dosyaları):

```
korumali test_backup_verify_ui.py    korumali test_pin_rotation_ui.py
korumali test_checkout_ui.py         korumali test_timestamp_ui.py
korumali test_duplicate_prompt.py    korumali test_lock_overlay.py
korumali test_main_window_smoke.py
CIPLAK   test_guvenlik_view.py  ->  PySide6.QtWidgets, UI.GuvenlikView,
                                     UI.main_window_files
```

Sekiz dosyadan **yalnızca biri** korumasız ve annotation'ın adlandırdığı
dosya tam olarak o. `tests/test_trusted_roots.py` bu listede hiç yok —
modül seviyesinde Qt içe aktarmıyor, AdminPanel'i test gövdelerinin içinde
kuruyor. Bu yüzden Linux'ta sorunsuz TOPLANDI ve `85c6dcc`'de koşu
evresinde düştü (B-046). İki kırılma ayrı mekanizma.

### Deponun kendi kayıtlı içtihadı

`tests/test_lock_overlay.py` başındaki yorum bu hatayı adıyla anlatıyor:

> `importorskip("PySide6")` YETMİYOR: paket kurulu olsa bile alt modüller
> sistem kütüphanelerine bağlı (libEGL.so.1, libxkbcommon) ve çıplak bir
> Linux runner'ında `from PySide6.QtGui import ...` ImportError veriyor.
> Modül seviyesinde patlayan bir import, pytest'te ATLAMA değil TOPLAMA
> HATASI olur (çıkış kodu 2) ve CI'ı kırar — nitekim 297327f'te Ubuntu
> ayağı tam olarak böyle kırıldı.

Aynı üç imza bu koşuda da var: çıkış kodu 2, toplama hatası, ubuntu.
`.github/workflows` içinde ubuntu **test** işinde Qt sistem kütüphanesi
adımı yok — AppImage işinde var ("Sistem kütüphaneleri (Qt)", adım 4),
test işinde yok.

### ÖLÇÜLEMEYEN: traceback'in kendisi

Hangi satırın `ImportError` verdiği (`PySide6.QtWidgets` mi, zincirin
ilerisindeki `UI.main_window_files` mi) **okunmadı**. Traceback 935
baytlık JUnit XML'in içinde ve indirmek yetki istiyor. Yukarıdaki teşhis
"hangi dosya" sorusunu ölçümle yanıtlıyor, "hangi satır" sorusunu
yanıtlamıyor.

### Düzeltme — uygulandı

`tests/test_guvenlik_view.py`, diğer yedi dosyadaki blokla **birebir aynı**
desene sarıldı: Qt ve UI içe aktarmalarının hepsi tek bir `try` altında,
`except ImportError` -> `pytest.skip(..., allow_module_level=True)`.
`CORE.crypto`/`CORE.timestamp` bloğun dışında bırakıldı — Qt'ye bağlı
değiller ve referans dosyaların hiçbiri onları sarmıyor.

Üstteki `os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")` **yerinde
bırakıldı**: iki ayrı arıza, iki ayrı önlem. `setdefault` Qt
yüklenebildiğinde hangi platformun seçileceğini belirler; `try` bloğu Qt
hiç yüklenemediğinde toplamanın çökmesini engeller. Birinin diğerinin
yerine geçtiğini sanmak bu maddeyi tekrar üretirdi.

### Yerel kanıt — Linux arızası canlandırıldı

`sys.path`'in başına, içe aktarılınca `ImportError` fırlatan sahte bir
`PySide6` paketi konarak çıplak runner koşulu yerelde üretildi:

```
A) DÜZELTMELİ        -> çıkış kodu 5 · "collected 0 items / 1 skipped"
B) MUTASYON (koruma yok) -> çıkış kodu 2 · "Interrupted: 1 error during collection"
```

B, CI'daki imzanın aynısı. Yani düzeltmenin doğru arızayı hedeflediği
varsayım değil, ölçüm.

### Kalıcı denetim — `test_layering.py`

Aynı ailenin üçüncü kuralı eklendi: **hiçbir test modülü, modül
seviyesinde korumasız Qt/UI içe aktaramaz.** AST tabanlı, `tests/*.py`'nin
tamamını (conftest.py dâhil) geziyor, ihlalde dosya adı + satır numarası
veriyor.

Kapsam kararları:

| | Kapsam | Gerekçe |
|---|---|---|
| Modül seviyesi import | **içinde** | Toplama anında çalışır → paketi durdurur |
| `if`/`with`/`for` gövdesindeki modül seviyesi import | **içinde** | O da toplama anında çalışır; `if True:` kuralı atlatmamalı |
| Fonksiyon/sınıf gövdesindeki import | dışında | Koşu anında patlar → tek test düşer, paket durmaz |
| `except`/`finally` gövdesindeki import | **içinde** | Onu yakalayacak başka bir şey yok |

Koruma sayılmak için **iki koşul birden** gerekiyor: `ImportError`
yakalanacak VE `pytest.skip(..., allow_module_level=True)` çağrılacak.
Yarım koruma (`except ImportError: pass`) toplamayı geçirir ama testleri
`NameError`'a boğar — kusuru çözmez, yerini değiştirir.

Denetim yük taşıyor: korumayı geri almak iki testi birden kırıyor
(parametrik denetim + desen tanıma meta-testi), mesajda üç ihlal satırı
adıyla listeleniyor.

---

## B-048 — Toplama hatalarında annotation "neden"i taşımıyor

**Durum:** Açık
**Öncelik:** Orta
**Bulundu:** 2026-08-22 — annotation okuma turu

`89826bd` turunda eklenen zenginleştirme çalıştı ama işe yaramadı:

```
tests.test_guvenlik_view — collection failure
```

`— collection failure` kısmı gerçekten `_ilk_satir()`'in ürettiği ek.
Sorun şu: pytest **toplama** hatalarında `<error message="collection
failure">` yazıyor — nitelik sabit ve bilgisiz; asıl traceback düğümün
METNİNDE. `_ilk_satir()` ise `dugum.get("message") or dugum.text` diyor,
yani metne hiç bakmıyor.

Koşu başarısızlığı (`<failure message="AssertionError: ...">`) için
nitelik doğru kaynak. Toplama hatası için değil. Ayrım gerekiyor:
niteliğin bilgisiz olduğu durumda düğüm metninin **son** anlamlı satırına
düşülmeli (traceback'te istisna satırı sondadır).

Bugünkü maliyet: CI kırmızıyken sebep hâlâ yetkisiz API'den okunamıyor —
B-046'yı kapatmak için eklenen mekanizma tam da bu yüzden B-047'de
işlemedi.

---

## B-049 — Ekran yakalama koruması yalnızca Windows'ta var

**Durum:** Açık — Windows'ta ÇÖZÜLDÜ, diğer platformlarda boşluk
**Öncelik:** Orta
**Bulundu:** 2026-08-22 — kurtarma parçası modalı turu

`UI/RecoveryShareDialog.py` ekranın en tehlikeli içeriğini gösteriyor:
kurtarma parçası, kalan tek payla birlikte kasadaki her dosyanın
anahtarını veriyor. `WARNING_TEXT` kullanıcıya "ekran görüntüsü almayın"
diyor ama bunu YALNIZCA rica ediyordu.

### Windows'ta çözüldü — ölçüldü

`SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)` uygulanıyor.
Gerçek bir pencerede doğrulandı:

```
platform: windows
koruma  : True
GetWindowDisplayAffinity -> 1  (0x11 = WDA_EXCLUDEFROMCAPTURE)
```

Win10 2004 öncesinde bu bayrak reddediliyor; kod o zaman `WDA_MONITOR`'a
düşüyor (yakalamada pencere SİYAH çıkar — içerik yine korunur).

### Açık kalan

Linux ve macOS'ta karşılığı **yok**: Qt'nin platformdan bağımsız bir
"beni yakalama" API'si yok, X11'de kavramsal olarak da yok (herhangi bir
istemci ekranı okuyabilir). Wayland'de kısıtlama derleyiciye bağlı ve
uygulamanın isteyebileceği bir bayrak değil.

macOS'ta `NSWindow.sharingType = .none` karşılığı var ama PySide6'dan
erişmek PyObjC gerektirir — bugün bir bağımlılık değil ve yalnızca bu
ekran için eklemek orantısız.

### Bugünkü davranış — sessiz DEĞİL

Koruma kurulamadığında modal bunu **yazıyor**:

> ⚠ Ekran yakalama ENGELLENEMEDİ — bu pencere ekran görüntüsüne ve ekran
> kaydına düşebilir. Bu özellik yalnızca Windows'ta var (platform: linux).

Ve kurulduğunda da yazıyor. Yalnızca sorun varken yazmak, "yazmıyorsa her
şey yolunda" diye okunurdu ve o çıkarım sessiz bir düşüşte yanlış olurdu
(B-025).

### Not — numaralandırma

Bu madde istekte "B-045" olarak anılmıştı ama B-045 (görünüm tercihleri
için kullanıcı başına ayar altyapısı) zaten dolu. Numaralar yeniden
kullanılmıyor; sıradaki boş numara verildi.

---

## B-050 — PDF bayt karşılaştırması Linux'ta sessizce atlanıyor

**Durum:** Açık
**Öncelik:** Düşük
**Bulundu:** 2026-08-22 — CI 71/72 teşhisi

`test_PDF_bayt_bayt_yeniden_uretilebiliyor`, PDF'i üreten reportlab
sürümü kurulu sürümden farklıysa `pytest.skip` ediyor (bilinçli tasarım —
bayt yeniden üretilebilirlik sürüme bağlı, bkz. `CORE/rehber.py` başlığı).

### Çıkarım — ölçüm değil

CI 71/72'de gömülü özet ayrışmıştı, yani o test koşsaydı **düşmesi
gerekirdi**: yeniden üretilen PDF'in `/Subject` alanı farklı olurdu ve
bayt karşılaştırması tutmazdı. Ubuntu'da dört test düştü, bu beşinci
düşmedi. Tek tutarlı açıklama: ubuntu runner'ında reportlab sürümü
farklı ve test atlandı.

Bu bir ÇIKARIM; logu okunamadı (yetkisiz API log vermiyor). Doğrulaması
kolay: CI çıktısındaki skip sayısı ya da `pip freeze | grep reportlab`.

### Bugünkü maliyet

Gövde denetimi yalnızca Windows'ta koşuyor. Gömülü özet denetimi
(`test_PDF_kaynakla_GUNCEL`) her iki platformda koşmaya devam ediyor,
yani PDF'in hangi kaynaktan üretildiği korunuyor; korunmayan şey PDF
GÖVDESİNİN elle düzenlenmemiş olması.

### Seçenekler

1. `requirements.txt`'te reportlab'ı sabitlemek — testi her yerde
   çalıştırır ama bir bağımlılık politikası kararı; bu turda alınmadı.
2. Atlamayı görünür kılmak: CI özetinde skip sayısını raporlamak.
3. Olduğu gibi bırakmak — Windows asıl hedef platform ve denetim orada
   koşuyor.

---

## B-051 — bandit B608 dokümante tabanı güncel değil: 13 → 17

**Durum:** ÇÖZÜLDÜ — 2026-08-22, `pyproject.toml` güncellendi
**Öncelik:** —
**Bulundu:** 2026-08-22 — CLAUDE-SECURITY-RESULTS.md tam depo taraması

`pyproject.toml`'daki `[tool.bandit]` yorumu 2026-08-16 taramasından beri
"B608 · 13× · f-string ile SQL, hepsi incelendi" diyor. Bu turun ham
bandit taraması (susturmasız) **17** buldu — dördü 2026-08-16'dan sonra
eklenmiş:

| Yer | Enterpolasyona giren |
|---|---|
| `CORE/audit_chain.py:312,519` | `_SELECT_FIELDS` (modül sabiti) |
| `DB/migrations.py:452,550` | `LEDGER_TABLE` (modül sabiti) |
| `CORE/export.py:150` | yalnızca `?` — zaten `# nosemgrep` gerekçeli |
| `CORE/scheduler.py:103` | yalnızca `?` — zaten `# nosemgrep` gerekçeli |
| `UI/TagDialog.py:240` | `len(self._file_ids)` (tamsayı) |

Elle doğrulandı: 17'sinin de değerleri `?` ile bağlı, enterpolasyona giren
yalnızca sabit tanımlayıcılar ya da bir tamsayı. **İstismar edilebilir
değil** — bu bir güvenlik açığı değil, dokümante sayının koddan geride
kalması.

`CORE/secure_erase.py:62,74,81` (tablo/sütun DİNAMİK ama tek çağıran sabit
literal geçiyor) ayrıca doğrulandı, zaten dokümante edilmiş desenin içinde.

### Karar — kullanıcı

> "Dört yeni satırı ayrı belgeleyelim, sayıyı '13×' olarak sabit bırakma
> — dokümanın koddan geri kalması B-052'deki tutarsızlık deseniyle aynı
> sınıf, bir sonraki kişi yanlış sayıya güvenir."

İki şey birden yapıldı, tek başına hiçbiri yeterli olmazdı:

1. **Üst toplam güncellendi:** `B608 · 13×` → `B608 · 17× TOPLAM (13
   özgün + 4 sonradan)`. Yalnızca ikinci adımı yapıp üst satırı "13×"te
   bırakmak, dokümanın kendi içinde çelişmesi demek olurdu — bir sonraki
   okuyucu hangi sayıya güveneceğini bilemezdi.
2. **Dört yeni satır AYRI bir blokta, kendi tarihiyle** belgelendi
   (`pyproject.toml`, "B608 — 2026-08-22 taramasında EKLENEN 4×")  —
   eski 13'ün açıklamasına (`_FILE_COLUMNS`, `RESTORABLE_TABLES`,
   `retention.update_profile`) anonim eklenmedi. Böylece bir sonraki
   tarama "17 neyin toplamı" sorusunu tek bakışta yanıtlayabiliyor.

Dosya/satır listesi ve güvenli olduklarının gerekçesi artık
`pyproject.toml`'un kendisinde; ayrıntılı tarama kaydı
`CLAUDE-SECURITY-RESULTS.md`'de değişmeden duruyor.

---

## B-052 — `CORE/scanner.py`: aynı hata iki çağrıda farklı görünürlükte

**Durum:** Açık
**Öncelik:** Düşük (gözlemlenebilirlik, istismar edilebilir değil)
**Bulundu:** 2026-08-22 — CLAUDE-SECURITY-RESULTS.md tam depo taraması

`scan_file()` ve `scan_by_hash()` aynı `_save_to_db()` çağrısını aynı
şekilde sarmalıyor ama biri logluyor, diğeri sessizce yutuyor:

```python
# scan_file()  (~satır 117) — GÖRÜNÜR
except Exception:
    _log.exception("scan_db_error  file_id=%d", file_id)

# scan_by_hash() (satır 136) — SESSİZ
except Exception:
    pass
```

İstismar edilebilir değil: her iki durumda da yalnızca tarama sonucunun
quarantine tablosuna YAZILMASI etkileniyor, tarama sonucunun kendisi
(zaten üretilip çağırana dönen `ScanResult`) etkilenmiyor.

Yine de bu depo tam olarak bu sınıftan bir hatayı önceki bir turda
yaşadı: `audit_log` FK ihlali `_kaydet()` içinde sessizce yutuluyordu ve
denetim kayıtları görünmeden kayboluyordu. Aynı fonksiyonun iki çağrı
yerinin farklı davranması "hangisi doğru davranış" sorusunu açık
bırakıyor — B-011/roles.py tarzı tek karar noktası burada yok.

### Düzeltme (bu turda uygulanmadı)

`scan_by_hash()`'teki `pass`'i `scan_file()`'daki `_log.exception(...)`
ile aynı desene getirmek — tek satırlık değişiklik, ama bu tur yalnızca
rapor.

---

## B-053 — `fuzz.yml`: `workflow_dispatch` girdisi tırnaksız `run:` bloğuna giriyor

**Durum:** Açık
**Öncelik:** Düşük (sertleştirme — bugün istismar edilebilir bir yol yok)
**Bulundu:** 2026-08-22 — CLAUDE-SECURITY-RESULTS.md tam depo taraması

```yaml
python tests/fuzz/fuzz_${{ matrix.hedef }}.py \
  -max_total_time=${{ inputs.sure }} \
```

`inputs.sure` (`type: string`, serbest metin) doğrudan `run:` bloğuna
enjekte ediliyor — klasik GitHub Actions script-injection deseni.

**Ama güven sınırı aşılmıyor:** `fuzz.yml` yalnızca `workflow_dispatch`
ile tetikleniyor, bu da depoya YAZMA yetkisi gerektiriyor; o yetkiye
sahip biri zaten dosya değiştirip push edebilir. Depoda ayrıca
`pull_request_target` ya da `issue_comment` tetikleyicisi YOK — yani
yetkisiz bir PR'dan gelen script-injection yüzeyi hiç yok. `ci.yml` ve
`fuzz.yml`'nin tamamı tarandı, `github.event.*` interpolasyonu da yok.

### Düzeltme (bu turda uygulanmadı)

`env:` bloğuna alıp ortam değişkeni olarak kullanmak — savunma derinliği
için, bugünkü tetikleyici modeliyle acil değil:

```yaml
env:
  SURE: ${{ inputs.sure }}
run: |
  python tests/fuzz/fuzz_${{ matrix.hedef }}.py -max_total_time="$SURE"
```

---

## B-054 — "Mavi" (varsayılan) temanın açık modunda `subtext` kontrastı AA sınırının altında

**Durum:** KAPANDI (2026-08-24)
**Öncelik:** Düşük (kozmetik — okunmuyor değil, WCAG AA büyük-metin eşiğinin hafif altında)
**Bulundu:** 2026-08-22 — tema preset-registry'si turu (`tests/test_tema_kontrasti.py` yazılırken)

`UI/main_window_palette.py::_LIGHT["subtext"]` (`#9CA3AF`) `_LIGHT["bg"]`
(`#F9FAFB`) üzerinde **2.43:1** kontrast veriyor; WCAG AA'nın büyük
metin/UI bileşeni eşiği (3:1) bile karşılanmıyor. Bu renk çifti bu
turdan ÖNCE de aynıydı — yeni preset'ler eklenirken tesadüfen ölçüldü,
bu turun ürettiği bir bozulma değil.

O turda düzeltilmedi çünkü "mavi" preset'ini **birebir** korumayı
istedi (geriye dönük uyumluluk) — rengi değiştirmek görev kapsamının
dışına çıkardı. `tests/test_tema_kontrasti.py` bunu bilerek
`_ONCEDEN_VAR_OLAN_ISTISNALAR` ile atlıyordu; sessizce yutmuyordu,
kaydını tutuyordu.

### Düzeltme — UYGULANDI (2026-08-24)

`_LIGHT["subtext"]` `#9CA3AF` → `#898F9A`. Aynı gri tonun en yakın
biraz koyu tonu — hue/doygunluk değişmedi, yalnızca parlaklık AA
eşiğini geçecek kadar düşürüldü. `accent`, `bg`, `text`'e dokunulmadı;
"mavi" preset ekran görüntüsü düzeyinde tanınabilir kaldı.

- Öncesi: `subtext`/`bg` = **2.43:1**
- Sonrası: `subtext`/`bg` = **3.11:1** (eşik: 3.0)

`_ONCEDEN_VAR_OLAN_ISTISNALAR`'dan `("mavi","light","subtext_bg")`
kaldırıldı — artık istisna değil, gerçek kontrast testinden geçiyor.
Yeni `test_b054_mavi_acik_subtext_duzeltildi` testi hem yeni değerin
AA'yı geçtiğini HEM eski değerin (`#9CA3AF`, sabit referans) hâlâ
AA'nın altında kaldığını doğruluyor — biri subtext'i eski griye
geri döndürürse bu test (ve genel `test_ikincil_metin_ayirt_edilebilir`)
düşer. Elle doğrulandı: değer geçici olarak eskiye döndürülüp iki
testin de beklendiği gibi kırmızı verdiği görüldü.

Not: bu düzeltme `subtext`/`search_bg` (B-057) veya `accent`/`search_bg`
(B-057) kombinasyonlarını KAPSAMIYOR — search_bg (`#F3F4F6`) bg'den
(`#F9FAFB`) biraz daha koyu bir yüzey, yeni `#898F9A` orada hâlâ AA'nın
altında (~2.85:1). B-057 ayrı madde olarak açık kalıyor.

**Güncelleme (2026-08-25):** Bu düzeltmenin KENDİSİ yanlış eşiği
hedeflemiş çıktı. `subtext`'in gerçek kullanım yerleri tarandı — hepsi
11-12px düz etiket metni, WCAG'ın büyük-metin eşiğine (3.0) değil normal
küçük metin eşiğine (4.5:1) tabi. `#898F9A` (3.11:1) bu yüzden hâlâ
yetersizdi; `#64707C`'ye çekilip 4.84:1'e çıkarıldı. Bkz. B-057'nin
güncellenmiş kapanışı — bu ikinci düzeltme B-057'nin ilk maddesini de
yan etki olarak kapattı.

---

## B-055 — AdminPanel / GuvenlikView / RecoveryShareDialog tema preset sistemine bağlı değil

**Durum:** KAPANDI — 2026-08-22 (aynı gün açılıp aynı gün kapandı)
**Öncelik:** Orta (tutarlılık — okunabilirlik sorunu değil, üç ekran zaten kendi sabit paletleriyle okunabilir)
**Bulundu:** 2026-08-22 — tema preset-registry'si turu (Claude Design senkronu)

Ana pencere artık 5 preset arasında geçiş yapabiliyor
(`UI/main_window_theme.py::register_theme`), ama `UI/AdminPanel.py`
(kendi sabit `QDialog { background: #1e1e2e; color: #cdd6f4; }`
bloğu), `UI/GuvenlikView.py` ve `UI/RecoveryShareDialog.py` hiçbiri
`self._T`/`main_window_palette` kullanmıyor — üçü de ortam/sabit
renklerle çiziliyor. Kullanıcı "Aurora Borealis" ya da "Grafit &
Kehribar" seçse bile bu üç ekran görünüşte hiç değişmiyor.

Bu, ayrı bir kararla ZATEN kapsam dışı bırakılmıştı: bu üç ekran aynı
zamanda dialog→slide-over dönüşümünün adayı (AdminPanel `QDialog`,
ayrı pencere) ve o dönüşüm bilinçli olarak ayrı bir aşamaya
ertelendi. Bu madde o kararın BACKLOG'daki kalıcı kaydı — konuşma
geçmişi kaybolsa bile iz kalsın diye.

### Düzeltme — UYGULANDI (aynı gün)

Beklenenden erken ele alındı: dialog→slide-over dönüşümü BEKLENMEDEN
üçü de `self._T`'a bağlandı — mimari değişmeden de mümkün olduğu
ortaya çıktı (AdminPanel/RecoveryShareDialog `T` parametresi alıyor,
GuvenlikView `main_window_theme.py`'nin merkezi QSS'inden cascade
ediyor). İki yeni token eklendi (`red_tint`, `green_tint`, 5 preset'in
hepsinde tanımlı). `UI/dialog_kit.py`'nin `RAPOR_STILI`/
`VARSAYILAN_GORUNUM` sabitleri de aynı turda fonksiyona çevrildi —
TimestampDialog/BackupVerifyDialog/PinRotationDialog'un üçü de tek
kaynaktan besleniyordu, ikisi düzeltilip biri (dialog_kit tüketicisi
olduğu için) sessizce bozulmasın diye üçü de güncellendi.

`tests/test_tema_kontrasti.py` genişletildi: gerçek preset değerleriyle
WCAG AA + "iki farklı preset'le çağrılan stil fonksiyonu FARKLI çıktı
üretmeli" mutasyon kanıtı (AdminPanel'in `_stil`/`_btn_stil`/instance
metotları, `dialog_kit.rapor_stili`, gerçek `AdminPanel`/
`RecoveryShareDialog`/`HycleusWindow` nesneleri üzerinden).

Dialog→slide-over dönüşümü hâlâ AYRI, ele alınmadı — bu madde yalnızca
renk/tema bağlanmasını kapsıyordu.

---

## B-056 — README'nin `--selftest` modül sayısı zaten yanlıştı, bu turdan önce de

**Durum:** KAPANDI (2026-08-25) — kalıcı çözüm (sabit sayının README'den
tamamen kaldırılması) uygulandı, bir daha sürüklenmesi yapısal olarak
imkânsız.
**Öncelik:** Düşük (kozmetik — `--selftest` kendi doğru sayısını basıyor, README'ninki yalnızca örnek metin)
**Bulundu:** 2026-08-22 — Bireysel/Kurumsal mod turu, `CORE/app_mode.py`'yi
`main.py::_SELFTEST_MODULLERI`'ye eklerken

README.md (EN+TR) "57 on Windows — 53 plus the wmi/pywin32 group" diyor.
Ölçüldü: bu turdan ÖNCEKİ commit'te (`git stash` ile) gerçek sayı
**61 (Windows dışı) / 65 (Windows)** idi — 53/57 hiçbir zaman doğru
değildi, bu tur bunu bozmadı, yalnızca fark etti.

`CORE.app_mode` eklendikten sonra gerçek sayı **62 / 66**. Sayı elle
tutulan bir liste (`_SELFTEST_MODULLERI` + `_SELFTEST_UCUNCU_TARAF` +
platform grubu) olduğu için her yeni modülde tekrar kayacak —
`tests/test_packaging.py::test_selftest_listesi_depodaki_her_modulu_
kapsiyor` listenin EKSİKSİZ olduğunu zorluyor ama README'deki SAYIYI
hiç doğrulamıyor.

### Düzeltme — KISMEN UYGULANDI (2026-08-25)

Seçenek (1) uygulandı: `python main.py --selftest` yeniden çalıştırılıp
ölçüldü — B-060/B-061/B-059 turlarında eklenen `CORE.registration` ve
diğer modüllerle gerçek sayı artık **63 (Windows dışı) / 67 (Windows)**
(53 temel + 10 üçüncü taraf + Windows'ta 4 platform modülü — `wmi`,
`pythoncom`, `win32api`, `win32con`). README.md'nin EN+TR iki satırı
buna güncellendi.

Bu, B-056'nın kendi teşhis ettiği sorunu ÇÖZMEDİ: sayı yine elle
tutulan bir liste, bir sonraki yeni modülde YİNE eskiyecekti — bu zaten
turun İKİNCİ sürüklenmesiydi (61/65 → 62/66 → 63/67).

### Kalıcı çözüm — UYGULANDI (2026-08-25, kapanış turu)

Seçenek (2): sabit sayı README'nin EN+TR "Verifying a build without a
GUI" / "Yapıyı GUI açmadan doğrulama" bölümlerinden TAMAMEN kaldırıldı.
Yerine konan, `--selftest`'in ZATEN bastığı `"Modüller : N/N yüklendi"`
satırının kendisi doğrulama ölçütü olarak açıklandı — N'in platforma
bağlı olduğu ve modül eklendikçe büyüdüğü, dolayısıyla burada sabit
tutulmaya değmediği yazıldı. Böylece belge bir daha koddan bağımsız bir
sayı taşımıyor: sürüklenme artık yalnızca yavaşlatılmadı, YAPISAL olarak
imkânsız hale geldi — güncellenecek ikinci bir yer kalmadı.

Doğrulama: `grep`'le README.md'de `--selftest` civarında sabit bir
sayı (`\d+ on Windows`, `Windows'ta \d+` gibi) kalmadığı teyit edildi.

---

## B-057 — "Mavi" temasının `subtext`/`accent` renkleri search_bg üzerinde de AA sınırının altında

**Durum:** KAPANDI (2026-08-25)
**Öncelik:** Düşük (kozmetik — B-054 ile aynı sınıf, aynı gerekçeyle düzeltilmedi)
**Bulundu:** 2026-08-22 — B-055 turu, `tests/test_tema_kontrasti.py`'yi
AdminPanel/GuvenlikView/RecoveryShareDialog'u kapsayacak şekilde
genişletirken

B-054, "mavi" temasının `subtext` renginin (`#9CA3AF`) kendi `bg`sine
karşı AA'nın altında olduğunu kaydetmişti. B-055 aynı `search_bg`
token'ını (önceden yalnızca arama çubuğu gibi dar bir girdi kutusunda
kullanılıyordu) AdminPanel'in tablosu ve GuvenlikView'in kartları için
"metin taşıyan bir yüzey" olarak YENİDEN kullanınca, iki ölçüm daha AA
sınırının altında çıktı:

- `subtext` / `search_bg` (mavi, açık mod) — **2.31:1**
- `accent` / `search_bg` (mavi, koyu mod) — **2.70:1** (AdminPanel'in
  kendi HWID satırını vurgulaması bu zeminde metin olarak yazılıyor)

B-054 ile aynı gerekçeyle düzeltilmedi: bu tur "mevcut mavi"yi birebir
korumayı istedi, renk değiştirmek kapsamın dışına çıkardı.
`tests/test_tema_kontrasti.py::_ONCEDEN_VAR_OLAN_ISTISNALAR` bu ikisini
topluyor (B-054'ün `subtext_bg`'si artık burada değil — bkz. altı).

**Güncelleme (2026-08-24):** B-054 kapatıldı, `subtext` `#9CA3AF` →
`#898F9A` oldu — ama bu ikisini KAPATMADI, yalnızca hafifletti:

- `subtext` / `search_bg` (mavi, açık mod): 2.31:1 → **2.95:1** (hâlâ
  eşiğin altında, eşiğe çok yakın ama geçmiyor)
- `accent` / `search_bg` (mavi, koyu mod): değişmedi, `accent`'e hiç
  dokunulmadı — hâlâ **2.70:1**

Yani aşağıdaki "muhtemelen birden çözer" tahmini YANLIŞ çıktı: B-054
bilerek en küçük/en yakın düzeltmeyi seçti (yalnızca `bg` eşiğini
geçecek kadar), `search_bg`'nin biraz daha koyu yüzeyi için yetmedi.
Bu iki ölçüm hâlâ açık, ayrı bir renk kararı gerektiriyor.

### Düzeltme — UYGULANDI (2026-08-25)

İki nokta AYRI kararlarla kapatıldı, aynı turda, aynı dosyada (sıra
önemli — B-054 takibi ÖNCE uygulandı, ikinci noktayı YAN ETKİ olarak
kendiliğinden kapattı):

**1. `subtext`/`search_bg` (mavi, açık mod)** — B-054 takibinin (bkz. o
madde) yan etkisi. B-054'ün orijinal düzeltmesi `subtext`'i yalnızca
3.0 eşiğini (`bg`'ye karşı) geçecek kadar koyultmuştu; bu turda gerçek
kod kullanımı tarandı (`UI/AdminPanel.py`, `UI/dialog_kit.py`,
`UI/main_window_theme.py`, `UI/main_window_tree.py`,
`UI/RecoveryShareDialog.py`) ve HEPSİNİN 11-12px düz etiket metni
olduğu, yani WCAG'ın büyük-metin eşiğine hiç girmediği görüldü — gerçek
eşik 3.0 değil 4.5:1 olmalıydı. `subtext` `#898F9A` → `#64707C`'ye
çekilince (`UI/main_window_palette.py::_LIGHT`) `search_bg` üzerindeki
kontrast da (dokunulmadan) 2.95:1 → **4.60:1**'e çıktı — B-057'nin ilk
maddesi ayrı bir renk kararı gerektirmeden kapandı.

**2. `accent`/`search_bg` (mavi, koyu mod)** — ayrı, doğrudan bir
düzeltme: `accent`'e (birçok başka geçen kontrastın bağlı olduğu token)
HİÇ dokunulmadı, yalnızca `_DARK["search_bg"]` `#2C2C2E` → `#222224`
koyultuldu (`UI/main_window_palette.py`). Sonuç: 2.70:1 → **3.07:1**.
`topbar`/`hover`/`row_hover` (önceden `search_bg` ile aynı tondaydı)
KASITLI olarak değişmedi — yalnızca `search_bg` artık onlardan bir tık
koyu, en az yan etkili seçenek buydu.

`tests/test_tema_kontrasti.py::_ONCEDEN_VAR_OLAN_ISTISNALAR` artık BOŞ
— üç istisnanın (B-054'ün `subtext_bg`'si zaten önceden kapanmıştı) hiçbiri
kalmadı. `test_b057_mavi_koyu_accent_search_bg_duzeltildi` ve B-054
takibinin `test_b054_takibi_subtext_gercekte_kucuk_metin_4_5_esigini_geciyor`
testleri her iki eski değeri de referans olarak sabit tutup mutasyonla
doğrulandı (değerler geçici olarak eskiye döndürülüp testlerin kırmızı
verdiği, sonra aynen geri getirilip yeşile döndüğü görüldü).

Not: bu düzeltme yalnızca "mavi" preset'i kapsıyor — diğer 4 preset'in
`subtext`'i de aynı 11-12px küçük-metin gerçekliğine tabi ama
denetlenmedi (bkz. B-063).

---

## B-063 — `subtext`'in 3.0 eşiği yalnızca "mavi" preset'te düzeltildi, diğer 4 preset denetlenmedi

**Durum:** KAPANDI (2026-08-25)
**Öncelik:** Düşük (kozmetik — B-054/B-057 ile aynı sınıf)
**Bulundu:** 2026-08-25 — B-054 takibi turu, `subtext`'in gerçek
kullanım yerlerini (11-12px düz etiket metni) tarayıp yalnızca "mavi"
preset'i (`_LIGHT`) 4.5:1'e çekerken

`tests/test_tema_kontrasti.py`'nin genel `_AA_MUTED` (3.0) eşiği
`subtext`/`nav_text` gibi renkler için TÜM preset'lerde (Teal & Gold,
Grafit & Kehribar, Aurora Borealis, Midnight — isimler yaklaşık, bkz.
`UI/main_window_palette.py`) hâlâ geçerli. Ama gerçek kod kullanımı
(`UI/AdminPanel.py`, `UI/dialog_kit.py` vb.) preset'e bakmaksızın aynı
11-12px düz etiket metni — yani teorik olarak bu 4 preset'in `subtext`'i
de gerçekte 4.5:1 gerektiriyor olabilir, yalnızca ÖLÇÜLMEDİ.

Bu turun kapsamı dışında bırakıldı çünkü görev açıkça `_LIGHT["subtext"]`
(yani "mavi" preset) ile sınırlıydı ve diğer 4 preset'e dokunmak ayrı bir
onay gerektirir (her birinin kendi tanınabilirlik/görünüm dengesi var).

### Düzeltme — UYGULANDI (2026-08-25)

Kalan 4 preset'in tamamı aynı yöntemle tarandı: `subtext`'in kullanıldığı
yerler yine `UI/AdminPanel.py`, `UI/dialog_kit.py`, `UI/main_window_theme.py`
gibi PAYLAŞILAN bileşenler — hiçbiri preset'e göre font-size dallanmıyor,
yani "mavi"de doğrulanan 11-12px düz-etiket gerçeği VARSAYILMADI, her
preset için de aynı kod okunarak teyit edildi. Sonra her preset'in gerçek
`subtext`/`bg` ve `subtext`/`search_bg` oranı ölçüldü:

| Preset/varyant | subtext/bg (önce) | subtext/search_bg (önce) | Sonuç |
|---|---|---|---|
| mavi/koyu | 6.70:1 | 6.26:1 | Zaten geçiyordu, DOKUNULMADI |
| teal_gold/koyu | 6.29:1 | 5.53:1 | Zaten geçiyordu, DOKUNULMADI |
| teal_gold/açık | 4.43:1 | 4.20:1 | `#6b7280`→`#606773` (5.22/4.95) |
| aurora_borealis/koyu | 5.66:1 | 5.45:1 | Zaten geçiyordu, DOKUNULMADI |
| abyssal_blue/koyu | 4.88:1 | 4.28:1 | `#6A86A6`→`#7891AE` (5.66/4.96) |
| graphite_amber/koyu | 3.84:1 | 3.71:1 | `#6B7280`→`#7C8492` (4.93/4.77) |

Üç preset'te düzeltme gerekti (teal_gold/açık, abyssal_blue/koyu,
graphite_amber/koyu) — üçünde de yalnızca `subtext` değişti, `accent`/
`bg`/`text`'e dokunulmadı, aynı renk ailesinde kalındı (koyu zeminlerde
AÇIKLAŞTIRMA, açık zeminde KOYULAŞTIRMA — ışık/karanlık yönü ters).

`tests/test_tema_kontrasti.py`'nin `test_ikincil_metin_ayirt_edilebilir`
ve `test_search_bg_yuzeyinde_metin_okunabilir` testleri artık `subtext`
için `_AA_MUTED` (3.0) değil `_AA_TEXT` (4.5) kullanıyor — tüm 5 preset ×
tüm varyantlar (8 kombinasyon) parametrize, tek bir istisna yok. Üç
düzeltmenin üçü de mutasyonla doğrulandı: değerler geçici olarak eskiye
döndürülüp ilgili preset/varyant kombinasyonlarının (5 test) kırmızı
verdiği, sonra aynen geri getirilip 65 testin tamamının yeşile döndüğü
görüldü.

`nav_text` kapsam dışı bırakıldı — ayrı bir denetim gerektiriyor,
görev yalnızca `subtext`'i kapsıyordu.

---

## B-058 — Giriş ekranındaki self-servis kayıt, YÖNETİCİ USB'sini hiç doğrulamıyor

**Durum:** KISMEN KAPANDI (2026-08-24) — kök neden (onaysız admin
oluşturma) DÜZELTİLDİ; aşağıdaki orijinal bulgu (`_on_register()`'ın
bilgi kutusu metniyle çelişmesi) hâlâ AÇIK, ayrıca ele alınmalı.
**Öncelik:** Düşük (yükseltilmişti — 2026-08-24'ün ikinci güncellemesi
asıl ciddi kısmı, onaysız `role='admin'` oluşturma + TOTP ezme yan
etkisini, kapattı; kalan yalnızca metinsel/kozmetik uyuşmazlık)
**Bulundu:** 2026-08-24 — kayıt ekranının mod'a göre ayrılması turu,
`UI/login_dialog.py::_on_register()` okunurken

`UI/login_dialog.py`'nin "Kayıt Ol" sekmesi (giriş ekranı, HENÜZ
kimlik doğrulanmamış) "Kayıt için Yönetici USB'si takılı olmalıdır"
bilgi kutusu gösteriyor ve "Yönetici USB: Bağlı / Bekleniyor" durumunu
(`current == self._hwid`) yazıyor — ama bu kontrol yalnızca GÖRÜNTÜ.
`_reg_btn` bu duruma göre hiç `setEnabled(False)` olmuyor ve
`_on_register()` yalnızca şunu kontrol ediyor:

1. Takılı USB `users` tablosunda zaten kayıtlı mı (evetse reddet),
2. kullanıcı adı benzersiz mi.

Takılı USB'nin GERÇEKTEN bir yöneticiye ait olup olmadığı hiç
sorulmuyor — herhangi bir boş/yeni USB ile giriş ekranından, HİÇBİR
kimlik doğrulaması yapmadan, `create_vault()` (gerçek kripto malzemesi
+ keyring yazımı) tetiklenip `users` tablosuna `status='pending'` bir
satır eklenebiliyor.

Ciddiyeti sınırlayan şey: `status='pending'` girişi `_on_login()`da
engelliyor (satır 854 — "Hesabınız yönetici onayı bekliyor"), yani bu
tek başına bir yetki yükseltmesi DEĞİL. Yine de: (a) gerçek vault
dosyası + keyring kaydı oluşuyor (kimliği doğrulanmamış biri tarafından
tetiklenen disk/kasa yazımı), (b) bilgi kutusunun iddiası ("yönetici
USB'si takılı olmalı") koddaki gerçek davranışla ÇELİŞİYOR — kullanıcıyı
var olmayan bir kontrole inandırıyor, tıpkı bu turda kaçınılan "sahte
doğrulama" riski gibi.

`UI/AdminPanel.py`'den açılan `RegisterDialog.py`'de aynı desen var
ama ORADA zararsız: o ekrana ulaşmak zaten oturum açmış bir yöneticiyi
gerektiriyor (AdminPanel rol kontrolü), yani "admin USB" ayrıca
doğrulanmasa da çağıran taraf zaten yönetici. Giriş ekranındaki kopya
bu ön koşula sahip DEĞİL — orası tam olarak kimliği doğrulanmamış
tarafın erişebildiği tek yer.

Bu turda düzeltilmedi: kapsam mockup'ın kurumsal alanlarının mod'a
göre gizlenmesiydi, bu ayrı bir kimlik doğrulama boşluğu.

### Düzeltme (bu turda uygulanmadı)

En basit seçenek: bilgi kutusunun iddiasını gerçek davranışla
eşleştirmek — ya `_reg_btn`'i `current == self._hwid` DEĞİLKEN devre
dışı bırakmak (ama bu, giriş ekranından self-servis kaydı fiilen
İMKANSIZ kılar — çünkü kayıt olan kişinin USB'si TANIM GEREĞİ henüz bir
yöneticiye ait DEĞİL), ya da metni gerçeğe uydurmak ("bu USB ile bir
hesap oluşturulacak, bir yönetici onaylayana kadar giriş yapamazsınız"
gibi, "yönetici USB'si" iddiasını kaldırarak). İkinci seçenek daha
tutarlı: akışın kendisi zaten "kimse doğrulamadı, onay bekliyor" modeli
üzerine kurulu, metnin yalan söylememesi yeterli.

**Güncelleme (2026-08-24) — ilk admin nasıl oluşuyor, ve asıl bulgu daha ciddi**

Yukarıdaki analiz "Kayıt Ol" sekmesinin `_on_register()`'ını konu alıyordu.
Bu turda soru genişletildi: taze bir kurulumda (users tablosu boş) ilk
kayıt "Kayıt Ol"dan mı geçiyor, ve öyleyse onu kim onaylıyor? Ölçüldü
(`tests/test_b058_ilk_kurulum.py`, 3 test, hepsi GEÇTİ):

1. **İlk kullanıcı "Kayıt Ol"dan HİÇ geçmiyor.** TOTP sırrı yokken
   (`CORE.secret_store.load_totp_secret() is None`) `LoginDialog`
   `_build_main_ui()` (Giriş/Kayıt sekmeleri) DEĞİL, `_build_setup_ui()`
   ("İlk Kurulum" sihirbazı) açıyor. O sihirbaz `users` tablosuna HİÇ
   dokunmuyor — satırı `main.py`'nin `dialog.exec()` SONRASI çağırdığı
   `sync_session_user()` (`CORE/session_user.py`) yazıyor, doğrudan
   `status='approved'`, `role='admin'` ile. Yani "ilk kullanıcı da
   pending düşer, onaylayacak kimse yoktur" korkusu ASILSIZ — ilk
   kullanıcı otomatik onaylı. Bu, görevin 1. sorusuna (a) cevabı.

2. **Ama bu yol "İLK" ile SINIRLI DEĞİL — asıl bulgu bu.** `_first_run`
   hesabı (`main.py` + `login_dialog.py`) iki şeye bakıyor: TOTP sırrının
   varlığı (**GLOBAL** — tek bir `keyring` girdisi,
   `CORE/secret_store.py::TOTP_USERNAME`) VE vault dosyasının varlığı
   (**HWID BAŞINA**, `CORE/vault_manager.py::_read_vault_path`). Sır BİR
   KEZ kaydedildikten SONRA bile, DAHA ÖNCE HİÇ GÖRÜLMEMİŞ herhangi bir
   USB takıldığında (o HWID için vault dosyası yok) `_first_run` YİNE
   `True` çıkıyor. Sonuç: kurulu bir sistemde ikinci/üçüncü/n'inci bir
   USB, "Kayıt Ol" (pending onay) sekmesine değil, İLK KURULUM
   SİHİRBAZINA yeniden düşüyor — rolü SERBEST seçtiriyor (varsayılan
   "Yönetici", işaretli geliyor) ve `_on_setup_confirm()` `status='pending'`
   yazmıyor, `sync_session_user()` üzerinden yine doğrudan `'approved'`
   üretiyor. **"Kayıt Ol" sekmesinin `status='pending'` yazan tek satırı,
   yalnızca ZATEN bir vault'u olan (yani daha önce bu yoldan ya da
   RegisterDialog'dan geçmiş) bir HWID için çalışabiliyor** — gerçekten
   yeni, hiç görülmemiş bir USB o kod yoluna hiç uğramıyor.

3. **Yan etki: paylaşılan TOTP sırrı EZİLİYOR.** `_on_setup_confirm()`
   sonunda her zaman `_save_secret(self._secret)` çağrılıyor —
   `self._secret` o oturum için `pyotp.random_base32()` ile TAZE
   üretilmiş bir değer. TOTP sırrı global olduğundan, ikinci bir USB'nin
   İlk Kurulum'dan geçmesi TÜM MEVCUT kullanıcıların paylaştığı sırrı
   değiştiriyor — ilk kullanıcının authenticator uygulaması o andan
   itibaren geçerli kod ÜRETMEZ HALE geliyor (test 3 bunu `pyotp` ile
   doğrudan doğruluyor: eski sırla üretilen kod, yeni sırla artık
   GEÇERSİZ).

Bu üçü birlikte: kurulu bir HYCLEUS makinesine daha önce hiç
kullanılmamış bir USB takan biri, HİÇBİR onay olmadan `status='approved'`
`role='admin'` bir hesap açabiliyor VE bunu yaparken mevcut tüm
kullanıcıların TOTP'sini kalıcı olarak bozuyor. Bu ne salt "(a)" ne salt
"(b)" — ilk kullanıcı gerçekten otomatik onaylanıyor (a'ya benziyor) ama
"onaysız admin oluşturma" sorunu İLK kullanıcıyla SINIRLI değil, sistemin
ÖMRÜ boyunca her yeni USB için tekrarlıyor. **Prompt 1'in ("İlk kurulum
sihirbazına yeni soru eklenmeyecek") kararıyla doğrudan GERİLİM
içinde**: bu bulgunun akla gelen düzeltmelerinin çoğu (aşağı bakınız)
sihirbaza bir soru/kontrol eklemeyi gerektiriyor — karar kullanıcıya
bırakılıyor, bu turda hiçbir kod yazılmadı.

### Düzeltme (bu turda uygulanmadı — yalnızca seçenekler)

Görev, var olan İKİ giriş noktasından (RegisterDialog / login_dialog'un
Kayıt Ol'u) birine bağlanmayı, ÜÇÜNCÜ bir yol açılmamasını istiyor. İkisi
de zaten `status='pending'` yazıyor — asıl sorun onlara hiç UĞRANMAMASI.
Olası yönler (hiçbiri uygulanmadı):

- **`_first_run`ı "gerçekten hiç kurulmamış" ile "bu HWID'i hiç görmedim"
  ayırt edecek şekilde yeniden tanımla** — ör. `users` tablosunda HİÇ
  satır yoksa gerçek ilk kurulum, satır VARSA (TOTP sırrı zaten
  kaydedilmiş) yeni bir HWID İlk Kurulum'a değil "Kayıt Ol"a
  yönlendirilsin. Bu, Prompt 1'in sihirbaza soru eklenmemesi kararını
  BOZMAZ (sihirbazın kendisi değişmiyor, sihirbaza NE ZAMAN
  girildiğinin kararı değişiyor) — ama `main.py` + `login_dialog.py`nin
  iki ayrı `_first_run` hesaplamasının İKİSİNİN de güncellenmesi
  gerekir (bkz. "iki kopya" riskine bu depronun hassasiyeti).
- **TOTP sırrını HWID başına yap** (şu an global) — hem bu ezilme yan
  etkisini hem de "herkesin authenticator kodu aynı" tuhaflığını
  çözer, ama bu daha büyük bir migration (mevcut kullanıcıların QR'ı
  yeniden taranması gerekir).
- Asgari/acil önlem: `_on_setup_confirm()`'ün `users` tablosu BOŞ
  DEĞİLKEN çağrılmasını engellemek (bir tür kapı) — sihirbaza soru
  EKLEMEZ, yalnızca YOLU kapatır; ikinci bir USB için akış "Kayıt Ol"a
  DÜŞMEZ hâlâ, yalnızca sihirbaza da düşemez hâle gelir (kilitli kalır)
  — bu da kendi başına bir kullanılabilirlik sorunu, ayrı bir karar.

**Güncelleme (2026-08-24, aynı gün ikinci tur) — kök neden DÜZELTİLDİ**

Yukarıdaki seçeneklerin ilki (`_first_run`ı sistem bazlı kontrole
çevirme) UYGULANDI. `CORE/session_user.py::sistem_kurulmus_mu(db)` eklendi
— "sistemde en az bir `status='approved'` kayıt var mı" sorusu, TEK
fonksiyon, HEM `main.py` HEM `UI/login_dialog.py`'nin kendi `first_run`
fallback hesabı bunu çağırıyor (iki ayrı tanım yerine tek kaynak — bu
deponun B-028/B-030/B-033'te defalarca kapattığı "aynı kararın iki
kopyası" kusuru burada da açılmadı).

`main.py`'de `DBManager().connect()` çağrısı `_first_run` hesabından
ÖNCEye taşındı (eskiden sonraydı) — hesap artık `users` tablosunu
okuyabilsin diye. Vault dosyasının (HWID başına) veya TOTP sırrının
(global) varlığına bakan eski soru TAMAMEN kaldırıldı, "hangi HWID
olursa olsun" ilkesine sadık kalınarak.

Savunma derinliği: `_on_setup_confirm()`'ün başına AYNI kontrolle bir
guard eklendi — `sistem_kurulmus_mu()` `True` döndürürken bu fonksiyon
çağrılırsa `RuntimeError` fırlatıyor (B-058 referansıyla). `_first_run`
hesabı ileride bir yerde atlanırsa (ör. `first_run=True` sabitlenmiş
yeni bir çağrı yolu), sessizce onaysız ikinci bir admin üretmek yerine
görünür şekilde çöküyor. Bu, tasarım brief'inin B-007 tarzı "iki katman
birlikte duruyor" ilkesiyle tutarlı: TEK bir kontrol fonksiyonu, İKİ
bağımsız noktada uygulanıyor.

TOTP sırrının HALA global olması bilerek DOKUNULMADI (B-059'un konusu,
ayrı ve öncelikli). Bu turun kapattığı şey yalnızca "ikinci bir USB
sihirbaza girip sırrı ezebiliyor muydu" sorusu — cevap artık hayır,
çünkü ikinci bir USB sihirbaza hiç GİRMİYOR (`tests/test_b058_ilk_kurulum.py`
bunu doğrudan doğruluyor). Sırrın kendisinin HWID başına olup olmaması
ayrı, daha büyük bir migration kararı.

`tests/test_b058_ilk_kurulum.py` yeniden yazıldı (7 test): ilk kullanıcı
hâlâ otomatik onaylı (değişmedi); iki farklı, daha önce hiç görülmemiş
HWID artık sihirbaza HİÇ düşmüyor, "Kayıt Ol" üzerinden her zaman
`status='pending'` üretiyor, asla `approved`/`admin` değil; ikinci USB
artık paylaşılan TOTP sırrına dokunmuyor; guard onaylı kullanıcı varken
zorla çağrılırsa patlıyor, yokken aynı zorlama patlamıyor (mutasyon
kontrastı — guard'ın kör bir `raise` olmadığı, gerçekten KOŞULA bağlı
olduğu kanıtlanıyor). Elle doğrulandı: `sistem_kurulmus_mu()` geçici
olarak `return False`'a sabitlenip 6/7 testin beklendiği gibi kırmızı
verdiği görüldü, sonra geri alındı.

Kalan (aşağıdaki orijinal bulgu — hâlâ AÇIK): `_on_register()`'ın kendisi
hâlâ takılı USB'nin gerçekten bir yöneticiye ait olup olmadığını
sormuyor; bilgi kutusu metni hâlâ gerçek davranışla çelişiyor. Bunun
ciddiyeti bu turla büyük ölçüde AZALDI (en kötü sonuç — onaysız admin
oluşturma — artık mümkün değil, `_on_register()` her zaman `pending`
yazıyor), ama metin/davranış uyuşmazlığının kendisi düzeltilmedi.

**Düzeltme notu (2026-08-23, B-058 sınıfı tarama turu):** Bu maddenin
en üstteki "mevcut davranış" listesindeki 1. kalem — "Takılı USB
`users` tablosunda zaten kayıtlı mı (evetse reddet)" — YANLIŞTI.
`login_dialog.py::_on_register()`'ın git geçmişinin TAMAMI tarandı
(`git log -p`) — bu fonksiyon hiçbir sürümde HWID'i sorgulamamış,
yalnızca kullanıcı adını sorgulamış. Yani "zararı sınırlayan" ikinci
katman hiç var olmadı. Bunun gerçek, çok daha ciddi sonucu B-060'ta —
takılı USB zaten onaylı bir kullanıcıya aitse ne olduğu bu turda ilk
kez ölçüldü ve tam bir hesap devralma çıktı.

---

## B-059 — TOTP sırrı GLOBAL/paylaşılan, kullanıcı bazlı değildi

**Durum:** KAPANDI (2026-08-23, aynı gün üçüncü tur)
**Öncelik:** Yüksek — RBAC'ı anlamsızlaştıran bir kimlik doğrulama açığı
**Bulundu:** 2026-08-23 — B-058 sınıfı yetkilendirme/durum-geçiş taraması
sırasında adı geçti (bkz. B-058'in "kurulumdan sonra ikinci bir USB
paylaşılan TOTP sırrını eziyordu" bulgusu); bu numarayla ayrıca ele
alınmak üzere işaretlenmişti.

`CORE/secret_store.py::TOTP_USERNAME = "totp_secret"` altında TEK bir
global keyring kaydı vardı ve TÜM kullanıcılar aynı authenticator kodunu
üretiyordu — `pyotp.TOTP(secret).verify(code)` her girişte, her indirme
onayında AYNI `secret`'e bakıyordu. Sonuç: herhangi bir onaylı kullanıcı
(Standart, Salt Okunur, admin fark etmeden) başka HERHANGİ bir
kullanıcının 2FA kodunu üretebiliyordu — ikinci faktör PIN'e ek bir
"bunu SEN mi giriyorsun" garantisi vermiyordu, yalnızca "authenticator
uygulamasına sahip birileri" garantisi veriyordu. RBAC'ın (Yönetici /
Standart / Salt Okunur ayrımı) üstüne kurulduğu ikinci katman, kimlik
ayrımı yapmayan tek bir paylaşılan sırra indirgeniyordu.

### Seçilen yön: HWID başına saklama, `users.id` başına DEĞİL

`CORE/secret_store.py`'nin kendi eski notu "`totp_secret:<user_id>`
biçimine genişletilmeli" diyordu — ama bu turda **HWID başına**
(`totp_secret:<hwid>`) seçildi, gerekçe:

1. `users.hwid` artık kısmi UNIQUE (B-060) — HWID ve kullanıcı kimliği
   birebir örtüşüyor, iki şema arasında GÜVENLİK farkı yok.
2. HWID, akışın HER noktasında (İlk Kurulum sihirbazının QR'ı dahil)
   herhangi bir DB sorgusu gerekmeden ZATEN elde. `user_id` ise yalnızca
   bir `users` satırı YAZILDIKTAN sonra biliniyor — sihirbaz QR'ı
   kullanıcı henüz onaylanmadan, satır yokken göstermek zorunda; `user_id`
   başına saklamak bunu bir tavuk-yumurta sırasına çevirirdi.
3. `CORE/secret_store.py`'nin zaten `share_2:<hwid>` için kullandığı
   desenle simetrik kalıyor — modülde üçüncü bir adlandırma şeması
   açılmadı.

Tam gerekçe `CORE/secret_store.py` ve `CORE/secret_migration.py`'nin
modül docstring'lerinde.

### Uygulanan değişiklik

- **`CORE/secret_store.py`**: `totp_username(hwid)`,
  `load_totp_secret_for_hwid()`, `store_totp_secret_for_hwid()`,
  `erase_totp_secret_for_hwid()` eklendi. Eski `load_totp_secret()`/
  `store_totp_secret()` KALDIRILMADI ama docstring'leri "YENİ KOD
  BUNU ÇAĞIRMAMALI" diye işaretlendi — yalnızca migration'ın eski
  kaydı okuması ve DEV_MODE'un kasa-öncesi (tek operatörlü, RBAC
  kapsamı dışı) yolu için kalıyor.
- **`CORE/registration.py::register_new_user()`**: artık her kayıt
  KENDİ rastgele TOTP sırrını üretip HWID'ine kaydediyor ve
  `RegistrationResult(user_id, totp_secret)` döndürüyor — eskiden
  self-servis kayıt HİÇ TOTP sırrı üretmiyordu, onaydan sonra
  paylaşılan global sırra güveniyordu (B-059'un ikinci, daha az
  belgelenmiş yüzü). `users` INSERT'i başarısız olursa
  (`vault_manager.discard_vault()`) TOTP sırrı da vault'la BİRLİKTE
  geri alınıyor.
- **`UI/totp_enrollment.py`** (yeni): `show_totp_enrollment_dialog()` —
  yeni kayıt sonrası QR + manuel anahtarı gösteren TEK gövde; hem
  `login_dialog.py`'nin self-servis "Kayıt Ol" sekmesi hem
  `RegisterDialog.py` buraya bağlanıyor.
- **`UI/login_dialog.py`**: `__init__` artık `use_vault` yolunda
  `load_totp_secret_for_hwid(hwid)` çağırıyor (global `_load_secret()`
  DEĞİL). `_on_setup_confirm()` (İlk Kurulum sihirbazı) sırrını artık
  `store_totp_secret_for_hwid(self._hwid, ...)` ile kaydediyor.
  `_on_login()`'da `self._secret` artık `None` OLABİLİR (bu HWID hiç
  enroll olmamış); `totp_ok` hesaplaması `pyotp.TOTP(None)`
  çökmesine karşı korunuyor ve PIN doğruyken sır yoksa ayrı, açık bir
  mesaj gösteriliyor ("Bu USB için authenticator kaydı bulunamadı —
  yöneticinize başvurun") — bkz. aşağıdaki bilinçli ödünleşim notu.
- **`UI/main_window_files.py` / `main_window_tree.py` / `main_window_bulk.py`**:
  indirme öncesi ikinci TOTP doğrulaması artık `load_totp_secret_for_hwid(self._hwid)`
  kullanıyor — eskiden buradaki üç nokta da global sırra bakıyordu, yani
  giriş dışında dosya indirirken de RBAC'ı delen aynı açık vardı.
- **`CORE/vault_manager.py::discard_vault()`**: artık TOTP sırrını da
  siliyor — bir USB kaydı tamamen kaldırıldığında (`AdminPanel._on_delete()`/
  `_on_reject()`) ya da yarım kalan bir kayıt geri alındığında (B-061)
  yetim bir TOTP kaydı kalmıyor.
- **Migration (`CORE/secret_migration.py`, `PRAGMA user_version` 2→3,
  `migrate_totp_to_per_hwid()`)**: eski global sır, sistemdeki EN ESKİ
  onaylı kullanıcının (`ORDER BY id LIMIT 1` — muhtemelen ilk admin)
  HWID'ine devrediliyor; global kayıt siliniyor.

### Geriye dönük uyumluluk — KIRILIYOR, sessizce DEĞİL

Migration sonrası **yalnızca devri alan (en eski onaylı) kullanıcı**
authenticator uygulamasını yeniden taramadan çalışmaya devam ediyor.
**Diğer TÜM onaylı/bekleyen kullanıcılar** kendi TOTP kaydına sahip
DEĞİL — bir sonraki girişlerinde "Bu USB için authenticator kaydı
bulunamadı" mesajıyla karşılaşıp GİREMEYECEKLER, yeniden enrollment
gerekiyor. Bu SESSİZCE olmuyor: `migrate_totp_to_per_hwid()` etkilenen
kullanıcı adlarını `MigrationReport.notes`'a yazıyor, `main.py` bunu
hem log'a hem `audit_log`'a (`secret_migration_warning`) düşürüyor —
bir yönetici açılış loglarına bakarak kimlerin etkilendiğini görebilir.

**Neden EN ESKİ onaylı kullanıcıya devir, HERKESİ zorla sıfırlamak
DEĞİL:** alternatif (sırrı kimseye devretmeden silmek, herkesi
enrollment'a zorlamak) bu turda YAPILMADI çünkü yeniden-enrollment
AKIŞI (arayüzden "sırrımı sıfırla, yeni QR göster" diyen bir ekran)
henüz YOK — yalnızca aşağıda ÖNERİLİYOR. Kimseye devretmeden silmek,
göç sonrası HİÇ KİMSENİN (bir admin bile) giremediği bir sistem
üretirdi; bu "sessizce kırıp kullanıcıyı sistem dışında bırakma"
riskinin EN KÖTÜ hâli olurdu. En eski onaylı kullanıcıyı ayrıcalıklı
tutmak en azından BİR kişinin (tipik olarak sistemi yöneten kişi)
diğerlerinin yeniden enrollment'ını yönetebilmesini sağlıyor.

**Bilinçli ödünleşim (`_on_login()`):** "authenticator kaydı bulunamadı"
mesajı, PIN doğruyken gösteriliyor — bu dolaylı olarak "PIN doğruydu"
bilgisini sızdırıyor (rate limit'e rağmen). Kabul edildi çünkü (a)
saldırgan zaten fiziksel USB'ye sahip olmalı (uzaktan saldırılabilir
bir yüzey değil), (b) bu tek başına GİRİŞ SAĞLAMIYOR (`totp_ok` hâlâ
`False`, fonksiyon orada dönüyor) — yalnızca "PIN doğru" bilgisini
biraz erken açığa çıkarıyor. Karşılığında: bu geçici duruma (göç sonrası
yeniden enrollment bekleyen meşru bir kullanıcı) düşen gerçek kullanıcı
neden giremediğini anlıyor, "kod yanlış" sanıp sonsuza kadar denemiyor.

### Önerilen yeniden-enrollment akışı (bu turda UYGULANMADI — yalnızca öneri)

Görev tanımı bunu açıkça bu turun dışında bıraktı. Öneri: Admin
Paneli'ne "TOTP Sıfırla" eylemi eklenmeli — seçili bir USB için yeni bir
rastgele sır üretip `store_totp_secret_for_hwid()` ile kaydeden ve
kullanıcıya (ör. `UI/ContactDialog.py`'nin auth-code akışına benzer
şekilde, ya da doğrudan admin ekranında) yeni QR'ı gösteren bir akış.
Yetki kontrolü zaten var olan `is_admin_role()` deseniyle
(`AdminPanel.__init__`) örtüşür; yeni bir yetkilendirme kararı
gerektirmez. Bu, göç sonrası "yeniden enrollment gerekiyor" durumuna
düşen her kullanıcı için TEK, yönetici-onaylı bir çözüm yolu olurdu —
bugün o kullanıcıların literal olarak hiçbir giriş yolu yok (kasıtlı,
yukarıda gerekçelendirildi, ama kalıcı olmamalı).

### Test

`tests/test_authz_invariants.py`'ye eklenen/değiştirilen testler:
`test_totp_sirri_iki_kullanici_arasinda_bagimsiz` (iki kaydın TOTP
kodları birbirini doğrulamıyor — B-059'un ta kendisinin artık mümkün
olmadığının doğrudan kanıtı), `test_migration_eski_global_sir_ilk_onayli_kullaniciya_devrediyor`
(göç sonrası ilk onaylı kullanıcının eski kodu hâlâ doğrulanıyor),
`test_migration_digerleri_yeniden_enrollment_gerektiriyor_sessizce_degil`
(diğerlerinin etkilendiği rapora sessizce değil AÇIKÇA yazılıyor),
`test_migration_onayli_kullanici_yokken_sir_kimseye_devredilmeden_silinir`
+ `test_migration_global_sir_YOKSA_hicbir_sey_yapmiyor` (mutasyon
kontrastları). `tests/test_secret_migration.py::test_run_migrations_reaches_current_version`
uçtan uca share_2+TOTP+TOTP-per-HWID'i tek akışta doğruluyor.
`tests/test_b058_ilk_kurulum.py`/`tests/test_pin_rotation_ui.py`/
`tests/test_kayit_ekrani.py` yeni per-HWID sır yükleme yoluna uyacak
şekilde güncellendi (fixture'lar artık `load_totp_secret_for_hwid`'i de
sabitliyor/susturuyor).

Mutasyon kanıtı: `migrate_totp_to_per_hwid()`'deki devir satırı geçici
olarak kaldırılıp ilgili migration testinin kırıldığı (devralan HWID'in
eski kodu artık doğrulayamadığı) görüldü, sonra tam geri alındı.

Tam takım: 2554 geçti, 4 atlandı, 0 kırıldı, 0 xfail (önceki turun
`test_totp_sirri_kullanici_basina_bagimsiz` xfail testi bu turda GERÇEK
bir geçen teste dönüştü).

---

## B-060 — Kayıt Ol sekmesinde HWID benzersizlik kontrolü YOK: PIN bilmeden hesap devralma

**Durum:** KAPANDI (2026-08-23, aynı gün ikinci tur)
**Öncelik:** Kritik — bu turun en ciddi bulgusu
**Bulundu:** 2026-08-23 — B-058 sınıfı yetkilendirme/durum-geçiş taraması
(kullanıcı talebi: "B-058 sınıfı açıkları depo genelinde ara")

`UI/login_dialog.py::_on_register()` ("Kayıt Ol" sekmesi, kimlik
doğrulaması YAPILMAMIŞ giriş ekranından erişilir) yeni bir kayıt kabul
etmeden önce yalnızca şunlara bakıyor:

1. kullanıcı adı boş/kısa değil,
2. PIN politika kurallarına uyuyor ve iki alan eşleşiyor,
3. `get_usb_hwid()` `None` değil,
4. **kullanıcı adı** `users` tablosunda tekil.

Takılı USB'nin **HWID'i** `users` veya `usb_tokens` tablosunda zaten
kayıtlı mı diye HİÇBİR sorgu yok. `git log -p -- UI/login_dialog.py`
ile tüm geçmiş tarandı — bu kontrol bu dosyanın hiçbir sürümünde
olmamış (B-058'in bunu "var" sanan eski notu yanlıştı, düzeltmesi
yukarıda).

Sonrasında çağrılan `CORE.vault_manager.create_vault(hwid, pin, role)`
da bir varlık kontrolü yapmıyor: `_new_vault_path(hwid)` doğrudan
`_VAULT_DIR/{hwid}.hclv` yolunu döndürüyor ve `_rewrite_vault()` orayı
KOŞULSUZ üzerine yazıyor; `_save_usb_token()` da
`INSERT OR REPLACE INTO usb_tokens (hwid, ...)` kullanıyor — var olan
kaydı sessizce değiştiriyor. Üstüne `DB/migrations.py::_m07_users_hwid`
`hwid` sütununu **UNIQUE olmadan** ekliyor, yani aynı HWID için birden
fazla `users` satırı bir arada durabiliyor.

**Kanıtlanan saldırı zinciri** (PoC:
`poc_hwid_takeover.py`, depoya YAZILMADI — yalnızca doğrulama amaçlı
çalıştırıldı, kod tabanında hiçbir değişiklik yok):

1. Kurban zaten kayıtlı ve onaylı: `hwid=V`, PIN bilinmiyor,
   `status='approved'`.
2. Saldırgan bu USB'ye (V) fiziksel erişim sağlar — **PIN'i bilmesine
   gerek YOK**. Giriş ekranından "Kayıt Ol"a geçer, yeni bir kullanıcı
   adı ve kendi seçtiği bir PIN girer, kaydı gönderir.
3. `create_vault(V, saldirgan_pin, "Standart")` hiçbir engelle
   karşılaşmadan çalışır ve kurbanın vault dosyasını + `usb_tokens`
   kaydını SESSİZCE ÜZERİNE YAZAR. Kurbanın eski PIN'i artık vault'u
   AÇMIYOR.
4. `db.execute(INSERT INTO users ... VALUES (..., 'pending', V))`
   BAŞARIYLA çalışır (UNIQUE yok) — artık aynı HWID için iki satır var:
   kurbanınki (`approved`) ve saldırganınki (`pending`).
5. Saldırgan aynı USB ile "Giriş Yap"a geçer. `open_vault(V,
   saldirgan_pin)` kendi PIN'iyle açılır (vault zaten onun). `_on_login()`
   dakiTEK yetki kapısı: `SELECT status FROM users WHERE hwid = ?`
   + `fetchone()` — `ORDER BY` YOK. Sorgu iki satırdan HANGİSİNİ
   döndüreceğini garanti etmiyor; ölçülen SQLite davranışında (index
   yok, tam tablo taraması) İLK eklenen satır (kurbanın `approved`
   satırı) dönüyor. Sonuç: `pending` kontrolü hiç tetiklenmiyor, giriş
   BAŞARILI.
6. `main.py`'nin çağırdığı `sync_session_user(db, hwid=V, role=...)`
   `ORDER BY id LIMIT 1` ile YİNE kurbanın (en eski) satırını buluyor —
   oturum kurbanın `user_id`/`username`'i ile eşleniyor. Saldırgan artık
   kurbanın kimliğiyle, kurbanın klasör sahipliğiyle, `approved`
   statüsüyle sistemde.

Ölçülen sonuç (`poc_hwid_takeover.py` çıktısı): kurbanın eski PIN'i
vault'u açamıyor, saldırganın PIN'i açıyor, DB satırı
`status='approved'` kalıyor, giriş engellenmiyor.

**Kapsam/sınırlama:** "Kayıt Ol" sekmesinin rol seçimi yalnızca
Standart/Salt Okunur sunuyor (bkz. `_SETUP_ROLES` değil,
`self._reg_role.addItems(["Standart","Salt Okunur"])`), yani bu yolla
doğrudan `role='admin'` üretilemiyor — ama kurbanın KENDİ rolü/kimliği
zaten `admin` olabilir; saldırgan o durumda `sync_session_user()`'ın
"mevcut satırı bul" dalına düşer ve DB'deki `role` sütunu HİÇ
değişmez (yalnızca `last_login` güncellenir) — yani kurban zaten
admin ise saldırgan onun ADMIN kimliğini de devralır. Bu, adım 6'daki
`ORDER BY id LIMIT 1` bulgusunun doğal sonucu.

TOTP hâlâ GLOBAL bir sır olduğundan (B-059) ve makineye zaten fiziksel
erişimi olan bir saldırgan onu da elde edebileceğinden, TOTP bu
zincirde ek bir engel oluşturmuyor.

`UI/AdminPanel.py` üzerinden açılan `RegisterDialog.py` bu açığa KAPALI
— `_on_detect()` (satır ~314) yeni HWID'i `usb_tokens` tablosunda arar
ve zaten kayıtlıysa formu devre dışı bırakır. Yani düzeltme deseni
depoda zaten var, yalnızca `login_dialog.py`'nin bağımsız
reimplementasyonuna hiç taşınmamış — bu projenin kendi "iki çağıran,
tek gövde" ilkesinin ihlali (iki farklı gövde, biri eksik).

### Düzeltme (bu turda uygulanmadı — yalnızca yön)

- `_on_register()`'ın en başına `RegisterDialog._on_detect()`'teki
  gibi bir `SELECT hwid FROM usb_tokens WHERE hwid = ?` (ya da
  `users`) kontrolü eklenmeli — zaten kayıtlı bir HWID sessizce
  üzerine yazılmamalı.
- `create_vault()`/`_save_usb_token()` seviyesinde de bir savunma
  katmanı düşünülebilir (B-058'in "tek kontrol, iki bağımsız nokta"
  desenine benzer) — çağıran tarafın kontrolü atlaması ihtimaline
  karşı.
- `users.hwid`'e UNIQUE kısıtı eklemek ayrı, daha büyük bir migration
  (mevcut kurulumlarda zaten çakışan satır olup olmadığı önce
  denetlenmeli) ama kök nedenin bir parçası: bu kısıt olmadan
  `_on_login()`'daki `fetchone()` sorgusu tanım gereği belirsiz.
- `_on_login()`'daki pending kontrolü `ORDER BY id` eksikliğinden
  bağımsız olarak da kırılgan; birden fazla satır ihtimali
  engellenirse bu sorgunun kendisi de düzelir.

**Güncelleme (2026-08-23, aynı gün ikinci tur) — DÜZELTİLDİ, B-061 ile birlikte**

Yukarıdaki dört yön TEK bir düzeltme katmanında birleştirildi (kullanıcı
talebi: "ikisi aynı akışın farklı katmanlarında aynı sonuca çıkıyor —
ayrı yamalama, tek katman düzeltmesi").

1. **`users.hwid`'e kısmi UNIQUE indeks** — `DB/migrations.py::_m23_users_hwid_unique`
   (`Migration(23, ...)`, `TEMEL_SURUM`'un üstünde, gerçekten çalışıyor).
   Çakışan bir kurulumda (aynı HWID'e bağlı birden fazla satır) indeks
   SESSİZCE atlanmıyor: hangi HWID'lerin çakıştığı adıyla listelenerek
   `RuntimeError` fırlatılıyor ve göç damgalanmıyor (bir sonraki açılışta
   yeniden denenir) — operatör elle çözmeden uygulama açılmayı reddediyor.
2. **Seçilen yön: (a)** — HWID zaten bir `users` satırına bağlıyken
   (pending ya da approved fark etmez) yeni kayıt hiç satır/vault
   oluşturmadan REDDEDİLİYOR. Gerekçe: (1)'deki UNIQUE kısıt fiziksel
   olarak (b)'yi (aynı HWID'e ikinci bir pending satır) imkânsız kılıyor,
   yani tutarlı tek seçenek (a) kalıyor. Meşru yeniden-kayıt senaryosu
   TAMAMEN kilitlenmiyor: `UI/AdminPanel.py::_on_delete()` artık yalnızca
   `usb_tokens`/kasa değil, `users` satırını ve per-HWID vault dosyasını
   da temizliyor (eskiden `users` satırını yetim bırakıyordu — bu, UNIQUE
   kısıt eklenince aynı HWID'i KALICI olarak kilitlerdi, o yüzden bu
   fonksiyon da bu turda düzeltildi); `_on_reject()` zaten pending
   satırlar için aynısını yapıyordu, o da aynı yardımcıya
   (`vault_manager.discard_vault()`) bağlandı. Yani bir HWID'in yeniden
   kullanılması artık her zaman bir yöneticinin AÇIK kararı.
3. **Tek gövde: `CORE/registration.py::register_new_user()`** — hem
   `UI/login_dialog.py::_on_register()` hem `UI/RegisterDialog.py::_on_save()`
   artık kendi `INSERT INTO users`'ını yazmıyor, ikisi de buraya
   bağlanıyor. Fonksiyon: önce kullanıcı adı/HWID çakışma kontrolü
   (`UsernameTakenError` / `HwidAlreadyRegisteredError`), sonra
   `create_vault()`, sonra `users` INSERT'i — INSERT başarısız olursa
   (B-061) az önce yazılan vault `vault_manager.discard_vault()` ile
   GERİ ALINIYOR (usb_tokens satırı + kasadaki share_2 + per-HWID vault
   dosyası), yarım bir HWID bırakılmıyor. Ayrıca savunma derinliği:
   `role` "Yönetici"ye normalize oluyorsa `RuntimeError` — kayıt
   akışından hiçbir koşulda admin üretilemez (B-058 ile aynı disiplin).
4. **Belirsiz sorgu düzeltmesi** — `CORE/session_user.py::tekil_hwid_satiri()`
   eklendi: `WHERE hwid = ?` sorgusunu TEKİL sonuç varsayımıyla
   çalıştırıyor, birden fazla satır dönerse (UNIQUE kısıt bir şekilde
   atlanmışsa) sessizce ilkini kabul etmek yerine `RuntimeError`
   fırlatıyor. `login_dialog.py::_on_login()`'daki pending kontrolü,
   `sync_session_user()`'ın "mevcut satırı bul" sorgusu ve
   `kullanici_bilgisi()` üçü de bu TEK fonksiyona bağlandı (`ORDER BY id
   LIMIT 1` ile sessizce "birini seçmek" yerine).

**Mutasyon kanıtı** (`tests/test_authz_invariants.py`): `register_new_user()`'daki
`discard_vault(hwid)` satırı geçici olarak kaldırılıp
`test_kesinti_sonrasi_ne_approved_satir_ne_yarim_vault_kaliyor`'un
kırıldığı (usb_tokens yetim kaldığı) doğrulandı; `_m23_users_hwid_unique`'in
çakışma tespiti geçici olarak devre dışı bırakılıp
`test_migration_cakisan_hwid_varsa_sessizce_atlamiyor_raporluyor`'un
kırıldığı (ham `sqlite3.IntegrityError`'a düştüğü, okunabilir
`RuntimeError` yerine) doğrulandı. İkisi de sonra tam olarak geri
alındı.

Eski PoC'lar (`poc_hwid_takeover.py`, `poc_torn_write.py`) artık
`tests/test_authz_invariants.py::test_b060_eski_hesap_devralma_poc_artik_basarisiz`
ve `test_kesinti_sonrasi_ne_approved_satir_ne_yarim_vault_kaliyor` olarak
kalıcı regresyon testleri hâline geldi — PoC'ların kendisi depoya hiç
girmedi.

TOTP'nin hâlâ GLOBAL olması (B-059) bu turda da BİLEREK dokunulmadı —
kapsam dışı, ayrı ve öncelikli.

Tam takım: 2548 geçti, 4 atlandı, 1 xfail (B-059'a bağlı, bkz.
`test_totp_sirri_kullanici_basina_bagimsiz`), 0 kırıldı.

---

## B-061 — Kayıt akışı atomik değil: create_vault() ile users INSERT'i arasında kesinti, onaysız 'approved' üretir

**Durum:** KAPANDI (2026-08-23, aynı gün ikinci tur) — B-060 ile BİRLİKTE,
aynı `CORE/registration.py::register_new_user()` düzeltmesiyle. Ayrıntı
yukarıda B-060'ın "Güncelleme" bölümünde (madde 3: `discard_vault()` ile
geri alma).
**Öncelik:** Yüksek
**Bulundu:** 2026-08-23 — B-058 sınıfı yetkilendirme/durum-geçiş taraması

Hem `UI/login_dialog.py::_on_register()` hem `UI/RegisterDialog.py::_on_save()`
aynı iki adımlı, ATOMİK OLMAYAN deseni bağımsız olarak tekrarlıyor:

```
create_vault(hwid, pin, role)                    # (1) disk + usb_tokens
db.execute("INSERT INTO users ... 'pending' ...") # (2) ayrı, sonraki commit
```

`create_vault()` kendi içinde `_save_usb_token()` ile `usb_tokens`
tablosuna YAZAR VE COMMIT EDER (`DBManager.execute()` her çağrıda
`conn.commit()` çağırıyor — `DB/db_manager.py:472`); `users` INSERT'i
TAMAMEN AYRI, sonraki bir `db.execute()` çağrısı. İkisini saran bir
transaction yok. (1) başarılı olup (2) hiç çalışmadan araya bir
kesinti girerse (çökme, güç kesintisi, beklenmeyen `Exception`, USB'nin
erken çıkarılması) diskte GERÇEK bir vault dosyası + `usb_tokens`
kaydı kalıyor ama `users` tablosunda o HWID için HİÇBİR satır yok.

Bu, tam olarak `CORE/session_user.py::sync_session_user()`'ın
"vault'u olup `users` kaydı olmayan oturumlar GERÇEK" varsayımıyla
(DEV_MODE ve kayıt-akışı-öncesi vault'lar için yazılmış, bkz. modül
docstring'i) çakışıyor: o HWID bir sonraki girişte `open_vault()`'u
BAŞARIYLA geçiyor (vault gerçek), `_on_login()`'daki pending kontrolü
`row is None` olduğu için hiç tetiklenmiyor, ve `main.py`'nin çağırdığı
`sync_session_user()` "satır yok → vault oturumu için oluştur" dalına
düşüp doğrudan `status='approved'` bir satır YAZIYOR — B-058'in kök
nedeniyle (kurulum sihirbazının aynı hatası) AYNI SONUCA, farklı bir
tetikleyiciden (kasıtlı sihirbaz çağrısı yerine, sıradan kayıt
akışındaki bir kesinti) ulaşıyor.

**Kanıtlandı** (PoC: `poc_torn_write.py`, depoya YAZILMADI — yalnızca
doğrulama amaçlı çalıştırıldı): sistemde zaten onaylı bir admin varken,
`create_vault()` çağrısı yapılıp `users` INSERT'i BİLEREK atlanınca,
o HWID'in bir sonraki "girişi" `status='approved'`, `role='user'`
üretiyor — hiçbir onay adımı yaşanmadan.

**Kapsam/sınırlama:** Bu, B-060'ın aksine fiziksel HWID çakışması
GEREKTİRMİYOR — kendi (gerçek, ilk kez görülen) USB'siyle kayıt olan
sıradan bir kullanıcının kaydı yarıda kesilirse de aynı sonuç oluşuyor.
Tetiklenme ihtimali B-060'tan daha düşük (kasıtlı sömürü için ya bir
çökme/kesinti ya da DB hatası indüklemek gerekir) ama TAMAMEN
saldırgan kontrolü dışında da (gerçek bir güç kesintisi, uygulama
çökmesi) kendiliğinden gerçekleşebilir — üstelik iki bağımsız dosyada
(`login_dialog.py`, `RegisterDialog.py`) aynı hata tekrarlanmış.

### Düzeltme (uygulandı — bkz. B-060'ın "Güncelleme" bölümü)

Üç seçenekten "asgari" olanı (telafi/geri alma) uygulandı:
`CORE/registration.py::register_new_user()` `users` INSERT'i
BAŞARISIZ olursa `vault_manager.discard_vault(hwid)` ile az önce
yazılan vault dosyasını + `usb_tokens` kaydını geri alıyor. Diğer iki
seçenek (gerçek transaction — dosya+DB birlikte atomik yapılamadığı
için zaten mümkün değildi; `sync_session_user()`'ın varsayımını
sıkılaştırma) uygulanmadı, çünkü telafi yaklaşımı kök nedeni (yarım
HWID hiç oluşmasın) B-060'ın HWID-çakışma kontrolüyle BİRLİKTE tam
kapatıyor: artık normal yoldan iki kez aynı HWID'e yazılamıyor
(B-060), VE tek seferlik yazımın kendisi kesintiye uğrarsa da iz
bırakmıyor (B-061). Mutasyon kanıtı ve tam test sonucu B-060'ın
"Güncelleme" bölümünde.

---

## B-062 — ContactDialog: rol ayrımı yok + `auth_codes` üretiliyor ama hiçbir yerde doğrulanmıyor

**Durum:** KAPANDI (2026-08-25)
**Öncelik:** Düşük — bilgi ifşası + ölü kod, doğrudan yetki yükseltmesi DEĞİL
**Bulundu:** 2026-08-23 — B-058 sınıfı yetkilendirme/durum-geçiş taraması
(taramanın kapsamı dışında ama giderken görüldü)

`UI/ContactDialog.py`, `main_window.py::_on_open_contact()` üzerinden
AÇILIYOR ve bu çağrı `AdminPanel` gibi bir `is_admin_role()` kontrolüne
sahip DEĞİL — Standart/Salt Okunur dahil HERHANGİ bir oturum açabiliyor.
Diyalog `_load_users()` ile `status='approved'` TÜM kullanıcıları
(kullanıcı adı + rol) listeliyor ve `_on_generate_code()` ile SEÇİLEN
HERHANGİ BİR kullanıcı (yalnızca kendisi değil) için `auth_codes`
tablosuna 8 haneli bir kod yazıyor.

Bu iki şey kendi başına bir yetki yükseltmesi değil çünkü:
`auth_codes` tablosu depo genelinde TARANDI (`grep -rn "auth_codes"`,
`FROM auth_codes`) — hiçbir yerde bu kod OKUNUP DOĞRULANMIYOR; giriş
akışının (`login_dialog.py`) hiçbir dalı bu tabloya bakmıyor.
`CORE/backup.py::EXCLUDED_TABLES` onu "geçici durum" diye yedeğin
dışında tutuyor. Yani şu an bu ölü/yarım bir özellik gibi görünüyor —
muhtemelen bir destek hattı çalışanının telefonda okuyacağı bir kod
üretmek için tasarlanmış ama doğrulama tarafı hiç yazılmamış.

Yine de iki gerçek sorun var: (1) herhangi bir düşük yetkili kullanıcı
sistemdeki TÜM onaylı kullanıcıların adını ve rolünü görebiliyor
(bilgi ifşası — küçük, güvenilir bir kurulum için önemsiz olabilir ama
belgelenen tehdit modeliyle karşılaştırılmalı), (2) eğer `auth_codes`
ileride bir doğrulama yoluna bağlanırsa (ör. bir "PIN unuttum" akışı),
BUGÜNKÜ hâliyle rol kontrolü olmadığı için herhangi bir kullanıcı
BAŞKA bir kullanıcı (potansiyel olarak bir admin) için kod üretebilir
hale gelir — o türden bir bağlama YAPILMADAN ÖNCE bu dosyaya bir rol
kapısı eklenmesi gerekir.

### Doğrulama turu (2026-08-25) — ek bulgu

Yeniden tarandığında B-062'nin orijinal tespiti güncel çıktı, ayrıca BİR
ek giriş noktası bulundu: `main_window.py::_on_open_contact()` sidebar/
hamburger yoluyla `_support_btn` üzerinden ZATEN admin'e kısıtlıydı
(`_apply_role_restrictions()`, `main_window.py:224-226`) — ama
`ProfileDialog.py::_open_contact()` ("İletişim" sayfasındaki "Destek ve
İletişim Penceresini Aç" düğmesi) HİÇ rol kısıtı taşımıyordu ve
`ProfileDialog` kendisi de her role açık (herkesin profili var). Yani
gerçek zafiyet buradaydı: admin-only sidebar yolu değil, herkese açık
Profil yolu.

### Düzeltme — UYGULANDI (2026-08-25)

Kullanıcıyla birlikte karar verildi: `auth_codes` hiçbir yerde
doğrulanmadığı (repo genelinde tarandı, yalnızca INSERT/UPDATE var,
hiçbir SELECT/okuma yok) doğrulanan bir ölü/yarım özellik olduğu için
canlı bir özelliğe rol kapısı eklemek yerine ÖZELLİĞİN TAMAMI kaldırıldı:

- `UI/ContactDialog.py`: "Auth Kodu Paylaş" sekmesi, kullanıcı listesi,
  kod üretimi/kopyalama, ilgili QSS kuralları ve `is_admin_role`
  denemesi tamamen silindi — dialog artık tek sayfalı (yalnızca
  "İletişim": sistem bilgileri + sorun bildirme), hiçbir zaman
  ayrıcalıklı içerik göstermiyor, `role` parametresi gerekmiyor.
- `UI/main_window.py` ve `UI/ProfileDialog.py`: çağrılar
  `ContactDialog(self)`'e geri döndü (turun ortasında geçici olarak
  eklenen `role=` argümanı, özellik kaldırılınca anlamsızlaştı).
- `auth_codes` tablosu DB'den de kaldırıldı: `DB/migrations.py`
  Migration 24 (`_m24_auth_codes_kaldir`, `DROP TABLE IF EXISTS`) +
  `DB/db_manager.py::_apply_schema()`'daki tabloyu YENİDEN yaratan raw
  SQL bloğu silindi (yalnızca göç eklemek YETMEZDİ — `_apply_schema()`
  her açılışta tabloyu `CREATE TABLE IF NOT EXISTS` ile sessizce geri
  yaratıp göç bir daha çalışmayacağı için tablo ikinci açılıştan
  itibaren kalıcı olarak geri gelirdi). 13 numaralı tarihsel göç
  (`_m13_auth_codes`) DEĞİŞTİRİLMEDİ — MIGRATIONS demeti değişmez
  kuralı gereği, yalnızca `sifirdan_kur()` test yolunun gerçek
  `_apply_schema()` geçmişini üretebilmesi için olduğu gibi duruyor.
- `CORE/backup.py::EXCLUDED_TABLES` güncellendi — artık var olmayan
  bir tabloya referans vermiyor.

Test: `tests/test_contact_dialog.py` "referans yok" testleriyle (AST
taraması, modül docstring'i hariç) ContactDialog.py'nin gövdesinde Auth
Kodu Paylaş'a ait hiçbir isim kalmadığını doğruluyor; ayrı bir test
`sifirdan_kur()` ile TÜM göçleri gerçekten uygulayıp `auth_codes`'un
şemada olmadığını kanıtlıyor. Migration 24'ün gövdesi geçici olarak
devre dışı bırakılıp bu testin kırmızı verdiği, sonra aynen geri
getirilip yeşile döndüğü görüldü (mutasyon kanıtı).

---

## B-068 — Windows EXE'sinin dosya özellikleri (sürüm bilgisi) tamamen boş

**Durum:** Açık — DÜZELTİLMEDİ, önce rapor
**Öncelik:** Düşük — kozmetik, işlevi etkilemiyor
**Bulundu:** 2026-08-26 — B-065/B-067 sonrası EXE yeniden derleme +
gerçek paket doğrulama turu

Windows Gezgini'nde `dist\HYCLEUS.exe` üzerinde sağ tık → Özellikler →
Ayrıntılar sekmesi tamamen boş: Dosya sürümü, Ürün sürümü, Ürün adı,
Açıklama, Telif hakkı — hiçbiri dolu değil. `Get-Item ... | Select
VersionInfo` ile doğrulandı:

```
FileVersionRaw    : 0.0.0.0
ProductVersionRaw : 0.0.0.0
FileDescription   :
CompanyName       :
ProductName       :
LegalCopyright    :
```

Sebep `HYCLEUS.spec`'in `EXE(...)` çağrısında (satır 94-113) `version=`
parametresinin hiç bulunmaması — PyInstaller bu alan verilmeden PE
kaynağına bir VERSIONINFO bloğu gömmüyor. Karşılaştırma: `CORE/version.py`
uygulamanın kendi `__version__`'ını zaten biliyor (`--version` bayrağı ve
`--selftest` çıktısı doğru "2.3.0" gösteriyor) — eksik olan yalnızca bu
bilginin PyInstaller'ın `version=` alanına (bir `pyi-grab_version`/elle
yazılmış `VSVersionInfo` dosyası yoluyla) aktarılması.

### Yapılacak

`HYCLEUS.spec`'e bir `version_info.txt` (PyInstaller'ın `VSVersionInfo`
formatı) eklenip `EXE(..., version='version_info.txt')` ile bağlanması;
`FileVersion`/`ProductVersion`'ın `CORE/version.py::__version__`'dan tek
kaynaktan türetilmesi gerekiyor (elle senkronize edilen ikinci bir kopya
açmamak için — bkz. B-056'daki benzer "tek kaynak" dersi).

---

## B-069 — "Kurtarma parçasıyla giriş" ekranı — wontfix

**Durum:** Kapalı — wontfix, kod DEĞİŞTİRİLMEDİ
**Öncelik:** —
**Bulundu:** 2026-08-26 — Arayüz güncellemesi (BÖLÜM B) mockup taraması,
Giriş ekranı restyle turu

Mockup'ta bir "Kurtarma parçasıyla gir" ekranı var: kullanıcı kâğıda
bastığı `share_3`'ü (Base32/QR) doğrudan Giriş ekranından girip PIN'i
sıfırlayarak kasayı açabiliyor. Gerçek kodda bu ekranın karşılığı yok —
`login_dialog.py`'de "kurtarma"/"recovery"/"share_3" geçen tek bir satır
bile yok. Restyle turunda bu yüzden atlandı; bu madde neden EKLENMEYECEĞİNİ
kayda geçiriyor.

Gerçek kurtarma mekanizması (`CORE/recovery_share.py`,
`python CORE/recover_vault.py --recover`) yalnızca AdminPanel'den,
yönetici oturumu İÇİNDEN bir payın (`share_3`) DIŞA AKTARILMASINI
sağlıyor — kullanım rehberi bunu açıkça "USB takılıyken" senaryosu olarak
tanımlıyor, çünkü `--recover` payı hangi HWID'e ait olduğunu bilmek için
kayıtlı USB'nin fiziksel olarak takılı olmasını ZORUNLU kılıyor. Yani
mekanizma yalnızca "USB elimde, PIN'i unuttum" senaryosunu çözüyor —
"USB gerçekten kayıp" senaryosunu CLI'da bile çözmüyor, oraya yalnızca bir
yönetici müdahalesiyle (USB kaydını silip yeniden kayıt) çıkılabiliyor.

İki sebeple bu ekran eklenmeyecek:

1. **Kullanıcının asıl ihtiyacını karşılamıyor.** Mockup'taki "kurtarma
   parçasıyla giriş" senaryosu tam olarak "USB kayıp" durumunda çekici
   görünüyor, ama gerçek `--recover` akışı bu senaryoyu ZATEN çözmüyor
   (HWID'i bilmek için USB gerekiyor). UI'a bu ekranı eklemek, çözmediği
   bir sorunu çözüyormuş gibi görünen sahte bir kapı açardı.
2. **USB'siz gerçek bir kurtarma yolu kurmak güvenlik amacını bozar.**
   HWID kilidinin var oluş sebebi "sahip olunan şey" (fiziksel USB)
   faktörü — bunu atlayan bir kurtarma yolu (yalnızca `share_3` + PIN ile
   HWID doğrulaması olmadan açılan bir kasa) bu faktörü tamamen ortadan
   kaldırır. Mockup'ın gösterdiği ekranı gerçek yapmak, restyle kapsamının
   çok ötesinde bir mimari değişiklik olurdu.

Test: yok — yalnızca belge girişi, kod değişikliği yapılmadı.

---

## B-070 — Windows Credential Manager, üzerine yazılan eski kaydı silmiyordu — bulundu ve aynı turda kapatıldı

**Durum:** Kapalı
**Öncelik:** Yüksek (TPM mühürlemesinin M2 iddiasını kısmen zayıflatıyordu)
**Bulundu ve kapatıldı:** 2026-08-28 — TPM re-seal'in (bkz. bir önceki
tur) yan etkilerinin denetimi sırasında

Re-seal'in atomiklik denetimi istenmişti (`_reseal_firsatci()`'nin write'ı
create-then-delete mi, yerinde mi güncelliyor). Kod OKUNARAK doğrulandı:
tek bir `set_password()` çağrısı, ayrı bir silme adımı yok — bu, MY kod
seviyesinde zaten atomik. Ama denetim orada durmadı: `set_password()`'ün
ALTINDA, `keyring` kütüphanesinin Windows arka ucunun (`keyring.backends.
Windows.WinVaultKeyring`) NASIL çalıştığı da okundu, ve GERÇEK Windows
Credential Manager'a karşı doğrudan bir betikle ölçüldü.

### Bulgu

Native Windows `CredWrite`, yalnızca `TargetName`'e göre anahtarlıyor —
kullanıcı adı diye bir kavramı yok. `keyring`'in Windows arka ucu, "aynı
serviste birden fazla kullanıcı adı" fikrini bir hileyle simüle ediyor: bir
"çıplak" (bare) hedef (`{service}`) ve gerektiğinde bir "compound" hedef
(`{username}@{service}`). `set_password(service, username, value)` şöyle
çalışıyor:

1. Çıplak hedefte O AN duran kredi neyse (kime ait olursa olsun) OKUNUR.
2. Duran bir şey varsa, o kendi (`existing_username`) compound hedefine
   TAŞINIR (yeniden yazılır).
3. YENİ değer HER ZAMAN çıplak hedefe yazılır.

Sorun: adım 3, YAZILAN kullanıcı adının KENDİ ÖNCEKİ compound kopyasına
HİÇ dokunmuyor. Yani `username`'i BİRDEN FAZLA KEZ yazmak (ki reseal TAM
OLARAK bunu yapıyor — aynı kullanıcı adına yeniden yazma) o kullanıcının
ESKİ değerini, `get_password()`'ün asla bakmadığı bir compound hedefte,
SONSUZA KADAR kasada bırakabiliyor.

Doğrudan ölçüldü (gerçek `WinVaultKeyring`, bellek-içi test taklidi DEĞİL):

```
u1 yazıldı (bare'i aldı)                    → bare=u1
u2 yazıldı (u1 compound'a taşındı)          → bare=u2, u1@HYCLEUS=u1(eski)
u1 TEKRAR yazıldı (reseal'in şekli)         → bare=u1(yeni), u1@HYCLEUS=u1(eski) — DEĞİŞMEDİ
```

`get_password(service, "u1")` doğru (yeni) değeri döndürüyor — ama
`u1@HYCLEUS`'taki ESKİ değer hâlâ orada, silinmemiş.

### Neden önemli

TPM mühürlemesinin (§4.13) M2 iddiası: "mühürlü kayıt, o TPM olmadan
açılamaz." Bu iddia YALNIZCA `get_password()`'ün gördüğü kopya için doğru.
Bir reseal'den sonra, aynı sırrın ESKİ, MÜHÜRSÜZ hâli — TPM'e hiç ihtiyaç
duymadan okunabilir bir kopya — kasada, farklı bir ad altında, sessizce
hayatta kalmaya devam ediyordu. Windows kimlik bilgileri konum fark
etmeksizin DPAPI ile korunuyor (bkz. §4.13), yani bu M1/uzak bir saldırgana
hiçbir şey vermiyor; ama DPAPI'nin kendisi çevrimdışı kırılırsa (bilinen
bir saldırı sınıfı, oturum açmış kullanıcı olmaktan farklı bir yetenek)
yetim kopya, mühürlemenin kaldırmak için var olduğu tam garantiyi geri
veriyordu.

Reseal bunu İCAT ETMEDİ — `set_password()`'ün bu şekli her zaman
böyleydi, mevcut bir kullanıcı adının üzerine yazan HERHANGİ bir kod (ör.
`setup_usb.py --reset` ile aynı hwid'in yeniden kaydı) aynı boşluğu
üretirdi. Ama reseal, tam olarak bu üzerine-yazma örüntüsünün yeni ve
düzenli bir kaynağı olduğu için, denetim bunu şimdi buldu.

### Düzeltme

`CORE/secret_store.py::_windows_golge_sil(username)` — yalnızca Windows'ta
VE yalnızca aktif backend gerçekten `WinVaultKeyring` İSE (ada bakarak,
farklı yapılandırılmış bir backend'e dokunmuyor) çalışıyor. Hedef compound
adı (`{username}@{SERVICE}`) doğrudan hesaplanıp `win32cred.CredDelete` ile
siliniyor — `keyring.delete_password()` KULLANILMIYOR, çünkü o hem çıplak
hem compound konumda AYNI kullanıcı adını arayıp İKİSİNİ DE siler; bu, az
önce güvenle yazılmış YENİ değeri de silme riski taşırdı.

`store()`'un round-trip doğrulamasından SONRA ve `_reseal_firsatci()`'nin
kendi doğrulamasından SONRA çağrılıyor — yani temizlik yalnızca YENİ değer
GÜVENDE olduğu kanıtlandıktan sonra denenir. Best-effort: başarısız olursa
yalnızca eski gölge kalmaya devam eder (bu düzeltmeden ÖNCEki durumla
aynı), yeni değer asla riske girmiyor.

Test: `tests/test_tpm_sealing.py::
test_windows_golge_kopya_gercek_kasada_TEMIZLENIYOR` — GERÇEK
`WinVaultKeyring` kullanıyor (`use_keyring_backend` fixture'ıyla), Windows
dışında/pywin32 yokken atlanıyor. Tahliyeyi yeniden üretiyor, gölgenin
GERÇEKTEN var olduğunu doğruluyor, temizlik yolunu tetikliyor, gölgenin
gittiğini VE canlı değerin dokunulmadığını doğruluyor. Ayrıca reseal'in
kendi atomiklik/audit-ayrım testleri de bu turda eklendi:
`test_reseal_yazimi_KESILIRSE_ESKI_kayit_hala_okunabilir` (kesintiye
uğrayan reseal yazımı eski kaydı bozmuyor),
`test_reseal_ile_TAZE_kayit_denetim_zincirinde_AYIRT_EDILEBILIYOR` (taze
kayıt ile reseal denetim zincirinde asla karışmıyor),
`test_share_2_DISI_cagri_yerinde_reseal_TETIKLENMIYOR_TAZE_yazimda` (TOTP
gibi share_2 dışı bir çağrı yerinde reseal sahte tetiklenmiyor). Ayrıntı
SECURITY.md §4.13'te.

### 2026-08-28 (devam) — düzeltme-öncesi kod bu makinede GERÇEKTEN gölge bırakmış mı, ölçüldü

Varsayılmadı: bu makinenin GERÇEK Credential Manager'ı
`win32cred.CredEnumerate` ile tarandı. Düzeltmeden ÖNCEye ait 10 gerçek
kayıt bulundu (5× `share_2:<hwid>`, 5× `totp_secret:<hwid>`) — hiçbirinde
ŞU AN bir gölge yok (çıplak `HYCLEUS` yuvası boş, her biri tek bir
compound konumda, hepsi zaten mühürlü). `6c748dd`'deki reseal testi
(`test_gercek_TPM_ile_ESKI_kayit_ilk_okumada_yeniden_muhurleniyor`)
yalnızca `gercek_tpm` istiyor, `use_keyring_backend` DEĞİL — yani gerçek
Credential Manager'a hiç dokunmadı, orada bir şey bırakmış olamaz.

Diğer 10 kaydın gölge göstermemesinin nedeni doğrudan yeniden üretilip
kanıtlandı: `main.py` her başlangıçta `ensure_available()`'ı, o oturumdaki
herhangi bir `store()`'dan ÖNCE çağırıyor; onun sonda yazımı, çıplak
yuvayı işgal edeni compound hedefine tahliye ederken bunu bir EKLEME değil
TAM ÜZERİNE YAZMA olarak yapıyor — yani hiçbir gölge-farkında kod
olmadan, o kullanıcı adının eski gölgesini KENDİLİĞİNDEN iyileştiriyor.
Bu, GERÇEK bir düzeltme-öncesi gölge sentetik olarak üretilip
`ensure_available()` bir kez çağrılarak DOĞRUDAN gösterildi (compound
değer "OLD-VALUE"'dan "NEW-VALUE"'ya değişti).

Bu genel bir garanti DEĞİL — yalnızca bu makinenin "yazım, sonra yeniden
başlatma" örüntüsünde işliyor; bir üzerine-yazma ile bir sonraki
başlatma ARASINDA incelenen bir gölge hâlâ B-070'in tarif ettiği kadar
sömürülebilir kalırdı. Şu an iyileşmemiş bir gölge BULUNAMADIĞI için ayrı
bir başlangıç göçü/temizlik geçişi bu turda YAZILMADI — asıl düzeltme
zaten `store()`/`_reseal_firsatci()` içinde (`91a4e21`) ve
`ensure_available()`'ın bir daha çalışmasına bağlı değil. Ayrıntı
SECURITY.md §4.13'te.

### 2026-08-28 (2. devam) — yukarıdaki not fazla iddialıydı: "gölge yok" ile "hiç yazılmadı" ayırt edilemiyordu

Yukarıdaki not "10 kaydın hepsi düzeltme-öncesi çift yazıldı ve iyileşti"
gibi okunuyordu. Bu iddia GÖLGE OLMAMASINDAN çıkarılmıştı — ama gölgenin
olmaması "bir kez yazıldı, hiç iyileşmeye gerek yoktu" durumunun da TAM
OLARAK aynı görünüşü. `create_vault()` taze kayıtta hiçbir denetim satırı
yazmıyor ve bu veritabanının `usb_tokens` tablosu (2 satır) keyring'de
görülen 5 farklı `share_2` hwid'inin çok gerisinde — yani en az bir kez
sıfırlanmış, tam yazım geçmişine tanıklık edemiyor. Ondan DOKUZU için
gerçekte hiç çift yazım olup olmadığı BİLİNMİYOR.

Onuncusu (`USB-PROBE-TOKEN-ID`) farklı ve GERÇEKTEN doğrulandı:
`audit_log`'daki tek `vault_reprovisioned` satırı (`2026-08-28T12:32:05Z`,
`kaynak=share_1+share_3`) yapısal olarak bir ÖNCEKİ `share_2`'nin var
olmasını gerektiriyor (PIN dalı `share_1`'i MEVCUT bir vault dosyasından
okuyor) — yani gerçek, çift bir yazım oldu, ve bu düzeltmenin commit'inden
(`91a4e21`, yerel 19:31) SAATLER önce (reprovision yerel 15:32). Ama bu
kaydın kendisi artık kasada YOK (`CredRead` ne çıplak ne compound'da
buluyor) — muhtemelen daha önceki bir soruşturmadan kalan bu tek kullanımlık
hwid'in `secret_store.erase()` ile temizlenmesi sırasında (o, hem çıplak
hem compound'u koşulsuz siliyor). Gölge bırakıp bırakmadığı artık kontrol
EDİLEMİYOR — kanıt, soru sorulmadan önce yok edilmişti.

O yüzden asıl soru mekanizmanın KENDİSİNE kaydırıldı, belirli bir kaydın
kaderinden bağımsız: gerçek backend'e karşı doğrudan denendi, İKİ gölge
AYNI ANDA var olabiliyor mu? Cevap HAYIR — YAPISAL OLARAK olamıyor. Tek
çıplak yuva demek, ikinci bir gölge oluşmadan ÖNCE, farklı bir kullanıcı
adı için yapılan BİR SONRAKİ yazımın, o an var olan (en fazla TEK) gölgeyi
her zaman iyileştirmesi demek —
`tests/test_tpm_sealing.py::test_AYNI_ANDA_IKI_golge_YAPISAL_OLARAK_var_olamiyor`
bunu adım adım kanıtlıyor. Yani healing garantisi, geçerli olduğu yerde,
"bazılarını iyileştirir bazılarını kaçırır" değil — TAM. Ama hâlâ evrensel
değil: gölge yaratan yazım servisin aldığı SON yazımsa (bir daha hiç
`store()`/`ensure_available()` çağrısı olmazsa) tek gölge süresiz kalır,
İYİLEŞMEMİŞ. SECURITY.md §4.13 bu turda buna göre düzeltildi.

### 2026-08-28 (3. devam) — `erase()`'in kendisi de aynı iki-hedef sorununu taşıyordu, TERSİNE bir riskle

Yukarıdaki notlarda geçen bir cümle ("`secret_store.erase()`
`keyring.delete_password()`'i çağırıyor, o da her iki konumu da koşulsuz
temizliyor") SONUÇ olarak doğruydu ama SÜREÇ hiç incelenmemişti —
`erase()`'in kendi atomikliği bu turda ayrıca sorgulandı.

**Bulgu.** Kod okunarak doğrulandı: `keyring.backends.Windows.
WinVaultKeyring.delete_password()`'ün kendi kaynağı
(`site-packages/keyring/backends/Windows.py`) tek bir atomik işlem DEĞİL —
`for target in service, compound: ... self._delete_password(target)`
şeklinde İKİ AYRI `CredDelete` çağrısı, SIRAYLA: önce çıplak (bare) hedef,
SONRA compound. Aralarında doğrulama yok, kesinti olursa geri alma yok.

Doğrudan ölçüldü (gerçek `WinVaultKeyring`, taklit değil): bir gölge
kurulup (`u1` iki kez yazılıp), kütüphanenin kendi silmesinin yalnızca
İLK yarısı elle yapıldı — yalnızca bare hedef silindi, compound'a hiç
dokunulmadan (tam olarak iki `CredDelete` arasında bir çökmenin
bırakacağı durum). Sonuç: `get_password(service, "u1")`, bare'i
bulamayınca `_resolve_credential()` compound'a düştüğü için, silinmiş
sanılan ESKİ değeri (`"OLD-VALUE"`) sessizce GERİ VERDİ. Bu, yukarıdaki
`store()` gölgesinden DAHA KÖTÜ bir risk: o yalnızca görünmezdi (kimse
bakmıyordu), bu ise GÖRÜNÜYOR ve YANLIŞ — "silindi" denen bir kayıt hâlâ
eski veriyle cevap veriyor, K0-3'ün tam tarif ettiği "korunduğunu sanıp
korunmuyor olma" durumu.

### Düzeltme

`CORE/secret_store.py::erase()` artık Windows + `WinVaultKeyring`'de
`keyring.delete_password()`'e hiç uğramıyor — `_windows_erase()`'e
yönlendiriliyor. O da iki hedefi TEK TEK, her birini `CredRead` ile
geri okuyarak GERÇEKTEN yok olduğunu doğrulayarak siliyor (bir hedef
hâlâ duruyorsa üç denemeye kadar tekrar dener, son denemede de
başarısızsa `KeyringUnavailableError` fırlatır — sessizce "silindi"
denmiyor). Idempotent: bir hedef zaten yoksa ya da bize ait değilse
(UserName farklı) dokunulmuyor, hata sayılmıyor.

SIRA BİLEREK TERS ÇEVRİLDİ — önce compound (gölge), SONRA bare
(asıl/güncel kopya), kütüphanenin kendi sırasının tersi. Bunun nedeni:
iki adım arasında bir kesinti olursa, hangi konumun kaldığı sonucu
belirliyor. Bare önce silinirse (kütüphanenin kendi sırası), kesinti
sonrası `get_password()` ESKİ/yanlış bir değer döndürür (yukarıdaki
bulgu). Compound önce silinirse, kesinti sonrası bare hâlâ yerinde durur
ve `get_password()` GÜNCEL değeri döndürmeye devam eder — `erase()`
yalnızca YARIM kalmış olur (secret hâlâ okunabilir, tıpkı erase() hiç
çağrılmamış gibi), ama ASLA yanlış bir değer dönmez. Yarım kalan bir
`erase()` bir sonraki çağrıda (idempotent) tamamlanır.

### Test

`tests/test_tpm_sealing.py`'e üç test eklendi, hepsi GERÇEK
`WinVaultKeyring`'e karşı (`use_keyring_backend`), Windows dışında/pywin32
yokken atlanıyor:

- `test_erase_KUTUPHANENIN_KENDI_silmesi_KESINTIYE_UGRARSA_eski_deger_GERI_DONUYOR`
  — yukarıdaki riski ÖNCE kanıtlıyor: kütüphanenin kendi sırasıyla
  (bare önce) kesintiyi simüle edip `get_password()`'ün ESKİ değeri
  geri verdiğini doğruluyor.
- `test_erase_WINDOWS_kesintiye_dayanikli_asla_ESKI_deger_DONDURMUYOR` —
  aynı kesintiyi DÜZELTİLMİŞ `_windows_erase()`'in kendi akışına
  enjekte ediyor (gerçek silme başarıyla biter bitmez fırlayan
  monkeypatch'lenmiş bir `CredDelete` ile) ve `get_password()`'ün ASLA
  eski değeri döndürmediğini, yarım kalan çağrının sessizce "başarılı"
  DEMEYİP fırlattığını, ikinci bir `erase()` çağrısının işi idempotent
  biçimde tamamladığını doğruluyor.
- `test_erase_gercek_kasada_HER_IKI_hedef_de_TEMIZLENIYOR_ve_IDEMPOTENT`
  — sıradan (kesintisiz) yolda hem bare hem compound'un gerçekten
  silindiğini, `load()`'un `None` döndüğünü, ve zaten silinmiş bir
  kullanıcı adını tekrar silmenin hata değil `False` olduğunu
  doğruluyor.

Bu turda kullanılan test credential'ları (`HYCLEUS-ERASE-*` servis
adları) doğrulanmış `erase()`/`_sil()` yardımcılarıyla temizlendi ve
gerçek Credential Manager'da `win32cred.CredEnumerate` ile bağımsızca
teyit edildi — geriye hiçbir kalıntı kalmadı. Ayrıntı SECURITY.md
§4.13'te.

### 2026-08-28 (4. devam) — `_windows_erase()`'in sahiplik kontrolü doğrulandı, üretim credential'larına karşı bağımsızca teyit edildi

Bir önceki notta `_windows_erase()`'in iki hedefi (compound, sonra bare)
sildiği anlatılıyordu ama bare'de O AN duran kaydın GERÇEKTEN silinmek
istenen kullanıcıya ait olup olmadığı — yani `store()`'un normal
işleyişinde bare'i sürekli işgal eden BAŞKA kullanıcıların kayıtlarına
`erase()`'in dokunup dokunmadığı — ayrıca sorgulandı.

**Kod incelemesi.** `CORE/secret_store.py::_windows_hedefi_dogrulayarak_sil()`
her hedef için, herhangi bir `CredDelete` denemeden ÖNCE, `CredRead` ile
okuyup `UserName`'i karşılaştırıyor: `if mevcut.get("UserName") !=
username: return False` (satır ~642-643). Kontrol ZATEN vardı — hem
compound hem bare hedef için aynı şekilde, `_windows_erase()`'in ilk
yazıldığı turdan beri. Eklenecek bir şey yoktu.

**Sentetik çapraz-sahiplik testi.** Gerçek Credential Manager'a karşı:
`A` yazıldı (bare'i aldı), `B` yazıldı (`A` compound'a tahliye edildi,
`B` bare'i aldı) — `store()`'un HER sıradan ikinci yazımda ürettiği
durumun aynısı. `erase(A)` çağrıldı. Doğrulandı: `B`'nin bare kaydı
sonradan bayt bayt aynı (`UserName`, `CredentialBlob` değişmedi),
`keyring.get_password(service, B)` hâlâ `B`'nin değerini döndürüyor,
`A`'nın compound kopyası gerçekten silinmiş, `secret_store.load(A)`
`None`. Kalıcı test: `tests/test_tpm_sealing.py::
test_erase_CAPRAZ_SAHIPLIK_bare_yuvasindaki_BASKA_kullanicinin_
kaydina_DOKUNMUYOR`.

**Üretim verisi bütünlük denetimi.** Bu makinedeki 10 gerçek HYCLEUS
credential'ının (5× `share_2:<hwid>`, 5× `totp_secret:<hwid>`)
`TargetName`/`UserName`/credential-blob-SHA-256 anlık görüntüsü bu
turun test koşusundan ÖNCE ve tam suite (2713 test, bkz. yukarı)
BİTTİKTEN SONRA ayrı ayrı alındı ve karşılaştırıldı: sayı aynı (10),
her kayıt için `UserName` aynı, her kayıt için hash aynı — sıfır
silinen, sıfır eklenen, sıfır değişen. Regresyon YOK. Bu turda kullanılan
sentetik test credential'ları (`HYCLEUS-CAPRAZ-SAHIPLIK-*` servis
adları) `win32cred.CredEnumerate` ile bağımsızca teyit edilerek
temizlendi. Ayrıntı SECURITY.md §4.13'te.

---
