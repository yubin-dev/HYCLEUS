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

### 2026-08-29 — yeniden doğrulama denendi: bu ortamda donanım yok, karşılaştırma bir araca çevrildi

Görev "hwid_probe.py'nin sonucunu doğrula, üç platformda (veya elindeki
platformlarda) test et" idi. Bu oturumun ortamında **hiçbir platform**
elde değil: `python -m CORE.hwid_probe` çalıştırıldı, çıktı `USB depolama
aygıtı bulunamadı.` — takılı USB depolama yok, ve yalnızca Windows'a
erişilebiliyor (Linux/macOS makinesi yok). "Kalan tek ölçüm" (Linux'ta
`ID_SERIAL_SHORT` okuması) bugün de alınamadı — üstteki tespiti
zayıflatmıyor, yalnızca bu turun onu tekrarlayamadığını söylüyor.

Bunun yerine yapılan: "aynı çubuğu üç OS'a takıp elle karşılaştır" adımı
çalıştırılabilir bir araca çevrildi. `CORE/hwid_probe.py`'ye `--json`
(bu platformun okumasını dosyaya serileştirir) ve `--compare A.json
B.json` (iki dosyayı karşılaştırır, `backup_cli.py` ile aynı çıkış kodu
deseniyle: 0 eşleşti, 1 eşleşmedi, 2 kullanım hatası) eklendi;
`to_dict`/`from_dict`/`dump_json`/`load_json`/`compare_all` yardımcıları
ve `tests/test_hwid_probe.py`'ye bunları sınayan 15 yeni test (§7)
eklendi — mutasyon kanıtıyla: `--compare`'in çıkış kodu satırı geçici
olarak her zaman `0` dönecek şekilde bozuldu,
`test_cli_compare_ESLESMEZSE_cikis_kodu_1` beklendiği gibi kırıldı, geri
alındı. Ayrıntı ve tam gerekçe: `docs/hwid-crossplatform.md`'nin
"2026-08-29" bölümü, SECURITY.md §4.19 (EN+TR).

Ayrı bir mimari madde açılmadı — dosya tabanlı token'a geçiş önerisi
zaten `docs/hwid-crossplatform.md`'de var ve bu maddenin (B-016) gerçek
donanım ölçümüyle daralttığı kapsamla hâlâ tutarlı.

Tam test suite: 2871 passed, 4 skipped (bir önceki turdan +12). Ruff/mypy/
bandit temiz.

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

### 2026-08-28 (devam) — bu maddenin "teknik olarak doğru" dediği öncül, B-069'un gerekçe düzeltmesinde netleştirildi

B-069'un wontfix gerekçesi koddan yeniden doğrulanırken bu maddenin de
konusu olan soru netleşti: yukarıdaki "Sebebi teknik olarak doğru... USB
yoksa hangi kaydın okunacağı bilinmiyor" ifadesi hâlâ doğru ama eksik —
bilgi (hwid dizesi) fiziksel cihaza kilitli DEĞİL, `data/vaults/<hwid>.
hclv` dosya adında, `keyring`deki `share_2:<hwid>` kullanıcı adında ve
`usb_tokens.hwid` sütununda düz metin olarak zaten duruyor; `--recover`
onu yalnızca USB'den OKUMAYI kabul ediyor, başka bir girişe İZİN
VERMİYOR. Ayrıca yukarıdaki "AAD'de hwid bağı olup olmadığı kontrol
edilmeli, ÖLÇÜLMEDİ" notu artık ölçüldü: EVET, `_decrypt_vault()`
(`CORE/vault_manager.py:1260`) hwid'i GCM AAD'i olarak kullanıyor — ama
bu bir SIR değil, yalnızca doğru DİZENİN verilmesini istiyor. Tam analiz
ve satır referansları **B-069**'da. Bu maddenin kendi kararı
(bir "yeni USB'ye taşı" akışı eklenip eklenmeyeceği) DEĞİŞMEDİ — hâlâ
açık, hâlâ karar bekliyor.

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

### 2026-08-29 — yeniden doğrulandı, ikinci bir uygulama YAZILMADI

Görev metni ("`PinRotationDialog`'u ekle/etkinleştir") akışın hâlâ eksik
olduğunu varsayıyordu. `git log -- UI/PinRotationDialog.py CORE/pin_
rotation.py tests/test_pin_rotation*.py` incelendi: akış `a94d1f1`
("B-003 kapandı") ile 2026-08-21'de TAMAMLANMIŞ ve `origin/main`'e
işlenmiş (`git merge-base --is-ancestor a94d1f1 origin/main`) durumda —
`login_dialog.py::_on_login()` zaten kısa PIN'i tespit edip
`_zorunlu_pin_yenileme()` üzerinden `PinRotationDialog`'u açıyor,
`tests/test_pin_rotation.py` + `tests/test_pin_rotation_ui.py` (47 test)
tam olarak istenen senaryoyu (kısa PIN'le giriş → diyalog tetiklenir →
yenilenmeden `accept()` hiç çağrılmaz) zaten kapsıyor. Bu turda yeni bir
uygulama YAZILMADI — B-003/B-004/B-007/B-008/B-010/B-011'in beş kez
tekrarladığı "ikinci bir kopya" kusurunun altıncısını üretmemek için.

Bunun yerine `_on_login()`'deki gerçek kapı satırı (`if not self.
_zorunlu_pin_yenileme(pin): return`) bugünün tarihiyle YENİDEN mutasyon
kanıtıyla doğrulandı: satır geçici olarak `if False and ...` ile devre
dışı bırakıldı — `tests/test_pin_rotation_ui.py`'den 5 test **BAŞARISIZ**
oldu (`test_kisa_PINLI_kullanici_YONLENDIRILIYOR`,
`test_yenileme_yapilmazsa_GIRIS_ENGELLENIYOR`,
`test_yenileme_yapilirsa_giris_SURUYOR`,
`test_yenileme_sonrasi_oturum_anahtari_GECERLI`,
`test_engellenen_giriste_denetim_kaydi_var`) — yani kapı bugün de
gerçekten çalışıyor, eski bir test kaydının güncelliğini yitirmiş olma
ihtimali ELENDİ. Satır geri alındı, `git diff --stat` temiz döndü, 47/47
tekrar yeşile döndü.

`LOGIN_MIN_LEN` köprüsü (**B-040**, açık) hâlâ kasıtlı duruyor: B-003
2026-08-21'de kapandı, bugün 2026-08-29 — B-040'ın önerdiği 90 günlük
gözlem penceresinin sekizinci günündeyiz, kaldırma kriterinin ("kim
akıştan sonra hiç giriş yapmadı" sorgusu boş dönüyor mu) çok erisinde.
Bu turda B-040'a dokunulmadı.

Tam test suite: 2859 passed, 4 skipped (değişiklik yok — bu tur yalnızca
doğrulama, kod eklemedi). Ruff/mypy/bandit temiz.

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

### Güncelleme (B-105): "dış depo" fikri denenmedi, DAR kapsamlı bir başka çözüm eklendi

Yukarıdaki "dış güvenli depo" (`HYCLEUS_AUDIT_ANCHOR` deseni) önerisi
sonradan değerlendirildi ve fazla karmaşık bulunarak reddedildi — bkz.
B-105. Onun yerine uygulamanın kendi varsayılan TSA'sının kökü ikili
dosyaya gömüldü (`CORE/trusted_roots_builtin.py`), ama bu SINIRLI bir
kazanım: yalnızca K4-20'nin denetim raporu mührü için, genel dosya
doğrulaması hâlâ yukarıdaki sınırı AYNEN taşıyor. Kurumun kendi/özel bir
TSA'sı için kök hâlâ buradaki mutable, M3'e açık depodan ekleniyor.

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

**Durum:** Kapalı — wontfix NİHAİ (2026-08-29), kod DEĞİŞTİRİLMEDİ;
gerekçe 2026-08-28'de koddan yeniden doğrulanıp düzeltildi, 2026-08-29'da
kalıcı bir testle korunmaya alındı (bkz. altta)
**Öncelik:** —
**Bulundu:** 2026-08-26 — Arayüz güncellemesi (BÖLÜM B) mockup taraması,
Giriş ekranı restyle turu

Mockup'ta bir "Kurtarma parçasıyla gir" ekranı var: kullanıcı kâğıda
bastığı `share_3`'ü (Base32/QR) doğrudan Giriş ekranından girip PIN'i
sıfırlayarak kasayı açabiliyor. Gerçek kodda bu ekranın karşılığı yok —
`login_dialog.py`'de "kurtarma"/"recovery"/"share_3" geçen tek bir satır
bile yok. Restyle turunda bu yüzden atlandı; bu madde neden EKLENMEYECEĞİNİ
kayda geçiriyor.

### Gerekçe koddan yeniden doğrulandı (2026-08-28) — önceki metnin merkezi iddiası YANLIŞTI

Önceki metin şöyle diyordu: "`--recover` payı hangi HWID'e ait olduğunu
bilmek için kayıtlı USB'nin fiziksel olarak takılı olmasını ZORUNLU
kılıyor" — yani USB gereksinimini KRİPTOGRAFİK/YAPISAL bir zorunluluk gibi
sunuyordu. `CORE/recover_vault.py` ve `CORE/vault_manager.py` satır satır
okunarak bu **YANLIŞ** bulundu: kalan payların hiçbiri hwid'i fiziksel
cihazdan OKUMAYA ihtiyaç duymuyor, hwid'i yalnızca bir dize olarak
BİLMEYE ihtiyaç duyuyor — ve o dize USB olmadan da makinede birden fazla
yerde açık biçimde duruyor.

**1. `recover_master_key()`'in hiçbir dalı hwid'i donanımdan türetmiyor**
(`CORE/vault_manager.py:1326-1376`):

* Seçenek 1 (share_2 kayıp, PIN + share_1): `_read_share_1()` →
  `_decrypt_vault()` (`vault_manager.py:1214`) hwid'i YALNIZCA iki yerde
  kullanıyor — `_read_vault_path(hwid)` ile dosya adını hesaplamak için
  (`vault_manager.py:143-148`: `data/vaults/<hwid>.hclv`) ve GCM'in AAD'i
  olarak (`vault_manager.py:1260`: `authenticate_additional_data(hwid.
  encode())`). AAD gizli DEĞİLDİR — yalnızca doğru dizenin verilmesini
  ister, cihazdan okunmasını değil. Anahtarın kendisi PIN'den türüyor
  (`_derive_kek(pin, salt)`, `vault_manager.py:1258`), hwid'den değil.
* Seçenek 2 (share_1 kayıp, share_2 kasadan): `_load_share_2(hwid)`
  (`vault_manager.py:478-496`) hwid'i yalnızca `keyring` kullanıcı adının
  bir parçası olarak kullanıyor (`share_2:<hwid>`) — yine bir ADRESLEME
  dizesi, cihazdan okunan bir sır değil. **Ve bu dalda PIN de İSTENMİYOR**
  (`recover_vault.py:143`: `pin = ... if secim == "1" else None`) — yani
  bu dalda master_key'i yeniden kurmak için gereken TEK şey doğru hwid
  dizesi + elde bulunan `share_3`.

**2. hwid dizesi USB olmadan zaten açıkça makinede duruyor.** Aynı vault'u
oluşturan kayıt işlemi onu üç ayrı düz-metin konuma yazıyor: vault
DOSYA ADI (`data/vaults/<hwid>.hclv`), `keyring`'deki kullanıcı adı
(`share_2:<hwid>`), ve DB'nin `usb_tokens.hwid` sütunu. Makineye erişimi
olan biri (`data/vaults/` dizinini listeleyerek ya da DB'yi okuyarak) bu
dizeyi USB'ye hiç dokunmadan öğrenebilir. B-036'nın "USB yoksa hangi
kaydın okunacağı bilinmiyor" ifadesi de aynı ölçüde gevşetilmeli — bilgi
FİZİKSEL olarak cihaza kilitli değil, yalnızca aracın bugünkü arayüzü
başka bir yoldan girilmesine İZİN VERMİYOR.

**3. USB gereksinimini fiilen dayatan TEK şey, `_require_hwid()`'in
bilinçli reddi — kriptografik bir zorunluluk değil, uygulama seviyesi
bir kapı.** `_require_hwid()` (`recover_vault.py:59-67`) ve `main()`'in
kendi `DBManager().connect(hwid=hwid, key=None)` çağrısı
(`recover_vault.py:248-252`, hwid `None` ise `DB/db_manager.py:152-156`
`HWIDMissingError` fırlatıyor) `get_usb_hwid()` `None` dönerse programı
`--export`/`--recover`/`--status` FARK ETMEKSİZİN daha başlamadan
durduruyor. (İkisi de aynı koşulu kontrol ediyor — `main()`'in kendi
kapısı zaten `None` iken önce patladığı için `_cmd_recover()` içindeki
`_require_hwid()` çağrısı pratikte hiç tetiklenmiyor, yedek/vestigial.)
Program hwid'i BAŞKA bir yoldan (komut satırı argümanı, `data/vaults/`
listesinden otomatik bulma, elle giriş) kabul edecek biçimde
yazılabilirdi — kriptografi buna itiraz etmez.

**4. Sonuç: eski metnin 1. maddesi (mekanizma zaten "USB kayıp"
senaryosunu çözmüyor, o yüzden ekran sahte bir kapı) TEKNİK OLARAK
YANLIŞ öncüle dayanıyordu — bir "kurtarma parçasıyla giriş" ekranı,
hwid'i USB yerine diskten/DB'den otomatik bularak, GERÇEKTEN çalışacak
biçimde inşa EDİLEBİLİRDİ. Ama tam da bu yüzden eski metnin 2. maddesi
düzeltilmiş haliyle TEK BAŞINA yeterli ve daha da güçlü bir gerekçe:**
böyle bir ekran `_require_hwid()`'in bugün sağladığı fiziksel-sahiplik
kapısını KALDIRMAK zorunda kalırdı — ve Seçenek 2'nin PIN istemediği
gerçeğiyle birleşince (madde 1), bu tam olarak SECURITY.md §4.4'ün zaten
belgelediği saldırı yolunu üretir: **basılı kurtarma parçası + makineye
erişim (USB YOK, PIN YOK) → master_key.** §4.4 bunu "disk erişimi"
(oturum açmış OS kullanıcısı olarak `keyring`'den `share_2` okumak)
üzerinden anlatıyor; buradaki bulgu onu tamamlıyor — o saldırı yolunun
BUGÜN çalışmamasının TEK nedeni, `--recover`'ın USB'siz çalışmayı hiç
kabul etmemesi. `_require_hwid()`, göründüğünden farklı olarak, bu
belirli saldırı yolu için FİİLEN devrede olan tek savunma.

**Karar DEĞİŞMEDİ — wontfix kalıyor, ama artık daha net bir zeminde:**
mockup'taki ekranı gerçek koda dönüştürmek, teknik olarak "çözülemeyen
bir sorunu çözüyormuş gibi görünen sahte bir kapı" değil, "bugün fiilen
duran tek savunmayı bilerek kaldıran, §4.4'ün zaten uyardığı saldırı
yolunu açan gerçek bir mimari gerileme" olurdu. Restyle kapsamının çok
ötesinde bir karar, ve kapsam dışı kalmaya devam ediyor.

### 2026-08-28 (devam 2) — `_require_hwid()`'in TAM OLARAK nerede uygulandığı sorgulandı: kapı KISMEN atlanabiliyor, "fiili tek savunma" ifadesi düzeltildi

Yukarıdaki 3. madde "USB gereksinimini fiilen dayatan TEK şey
`_require_hwid()`'in bilinçli reddi" diyordu ama HANGİ katmanda
uygulandığını ayırt etmiyordu. İki ayrı katman var, doğrudan çağrı ile
denendi (`tests/test_kurtarma_usb_kapisi.py`):

**Katman 1 — `CORE/recover_vault.py::_cmd_export`/`_cmd_recover`/
`_cmd_status` (satır 105/127/215): kapı fonksiyonun KENDİ gövdesine
gömülü, `main()`'in dispatch'ine değil.** `main()` hiç çalıştırılmadan,
modül doğrudan içe aktarılıp bu üç fonksiyon tek tek çağrıldığında
(`get_usb_hwid()` `None` dönecek şekilde) üçü de `SystemExit` ile
duruyor — kanıtlandı, kapı bu katmanda ATLANAMIYOR.

**Katman 2 — `CORE/vault_manager.py::recover_master_key()`: kapı hiç
YOK.** Fonksiyonun kaynağında (`inspect.getsource()`) `get_usb_hwid` ya
da `_require_hwid` geçen TEK satır bile yok. Doğrudan kanıtlandı: gerçek
bir vault kurulup, hwid USB'ye HİÇ dokunmadan yalnızca `data/vaults/`
dizin listesinden okunup, `recover_master_key()` `CORE/recover_vault.py`'ye,
`main()`'e, `_require_hwid()`'e hiç uğramadan doğrudan çağrıldı —
Seçenek 2'de (share_1 kayıp dalı) **PIN bile verilmeden** — ve doğru
master_key GERİ GELDİ.

**Sonuç: "kapı atlanabiliyor mu" sorusunun tek bir cevabı yok — katmana
göre değişiyor.** `python CORE/recover_vault.py --recover` standart
giriş noktasından çağrıldığında kapı sağlam. Ama bu makineye Python kod
çalıştırma erişimi olan biri — bu depoda zaten M2/M3'ün varsayılan
yeteneği, §4.5'in "uygulama arayüzünü değil, dosyaları/kodu doğrudan
işleten saldırganı sınırlamaz" dediği tam o sınıf — `CORE.vault_manager.
recover_master_key()`'i doğrudan içe aktarıp çağırarak kapıyı TAMAMEN
atlayabilir.

**Kapı `recover_master_key()`'e BİLEREK TAŞINMADI.** Bunun mimari bir
sebebi var: B-069'un bu maddesi zaten kapıyı kaldırmanın riskini
tartışıyor, ama B-036 (açık, karar bekliyor) tam olarak "USB fiziksel
kaybolduğunda basılı parça + PIN ile" bir kurtarma akışı EKLEME
olasılığını değerlendiriyor. `recover_master_key()`'in kendisine
koşulsuz bir fiziksel-USB kontrolü gömmek, B-036'nın öngördüğü o
gelecekteki tasarımı YAPISAL OLARAK imkânsız kılardı — çekirdek
fonksiyon kasıtlı olarak "hwid'i BİLEN çağıranın" ne yoldan bildiğine
karışmıyor; hangi girdinin GÜVENİLİR sayılacağına dış katman
(`recover_vault.py` bugün, olası bir B-036 akışı yarın) karar veriyor.

**Düzeltme — "fiili tek savunma" ifadesi daraltıldı:** yukarıdaki 3. ve
4. maddelerdeki "`_require_hwid()` bu saldırı yolu için fiilen devrede
olan TEK savunma" ifadesi, "`_require_hwid()`, YALNIZCA standart CLI
giriş noktasından (`python CORE/recover_vault.py --recover`) olağan
şekilde çağrıldığında geçerli olan bir savunma — kod çalıştırma erişimi
olan bir saldırgana karşı hiçbir koruma sağlamıyor" şeklinde okunmalı.
Bu, §4.5'in zaten kurduğu çerçeveyle TUTARLI: uygulama seviyesi
kontroller uygulamanın arayüzünü sınırlar, dosya/kod erişimi olan
saldırganı değil — `_require_hwid()` de bir istisna değil, aynı sınıfın
bir örneği.

**Karar YİNE DE DEĞİŞMEDİ.** Katman 1'in (CLI script) sağlam olması,
mockup'taki ekranın Katman 1'e (yani `_cmd_recover()`'ın KENDİSİNE, USB
kontrolünü atlamadan) eklenmesi hâlâ mümkün OLMADIĞI anlamına gelmiyor
— tam tersi, tam da bu yüzden hâlâ eklenmeyecek: böyle bir ekran, tanım
gereği, Katman 1'in USB kontrolünü YOKSAYAN yeni bir giriş noktası
olurdu (aksi hâlde "USB kayıp" senaryosunu hiç çözmezdi), yani Katman
2'nin zaten sahip olduğu USB'siz erişimi UYGULAMANIN KENDİ ARAYÜZÜNE
taşırdı — bugün yalnızca kod çalıştırma erişimi gerektiren bir şeyi,
uygulamayı normal şekilde kullanan HERKESE açardı.

SECURITY.md §4.4 bu ayrıma göre güncellendi.

Test: `tests/test_kurtarma_usb_kapisi.py` — 5 test, ikisi Katman 1'in
sağlam olduğunu (üç `_cmd_*` fonksiyonu doğrudan çağrıldığında bile
`SystemExit`), ikisi Katman 2'de kapının YOKLUĞUNU (kaynak taraması +
uçtan uca gerçek kurtarma, PIN'siz dal dahil) kanıtlıyor.

### 2026-08-29 (nihai) — karar onaylandı; "bilinçli olarak yok" artık kalıcı bir testle korunuyor

Bir sonraki turda net bir soru soruldu: mockup'taki "Kurtarma parçasıyla
gir" ekranı (Base32/QR ile `share_3` girişi, Giriş ekranından doğrudan
erişim) gerçek uygulamaya eklenecek mi, eklenmeyecek mi — B-003'ün
"kullanıcıyı hapsetme" dersiyle çelişebileceği endişesiyle birlikte.

**Karar: eklenmiyor, wontfix NİHAİ.** Yukarıdaki iki tur zaten teknik
sonucu kurmuştu: böyle bir ekran B-003'ün dersine aykırı OLMAZDI (onay
kutusu / hapsetme meselesi değil — `RecoveryShareDialog`'un KENDİSİ
zaten Esc ile kapanabiliyor, bkz. §4.4'ün "onay kutusu bir güvenlik
kontrolü değil" paragrafı), gerçek engel BAŞKA: böyle bir ekran, bugün
yalnızca Katman 1'in (`recover_vault.py` CLI'ı) `_require_hwid()`
kapısının arkasında duran bir yeteneği (USB YOK + PIN YOK →
master_key, Seçenek 2/share_1-kayıp dalında) UYGULAMANIN KENDİ
ARAYÜZÜNE, yani normal şekilde uygulamayı kullanan HERKESE açardı —
bugün bunu yapmak için Python kod çalıştırma erişimi (M2/M3) gerekiyor.
B-003 farklı bir sorunun (kullanıcıyı bir pencerede TUTMAK) dersiydi; bu
madde bambaşka bir sorun (kimin bu yeteneğe ERİŞEBİLDİĞİ). İkisini
karıştırmak yanlış bir gerekçeye varırdı — bu yüzden karar B-003'e değil,
yukarıdaki iki turun kod-kanıtlı analizine dayanıyor.

**Boşluk: karar vardı, kalıcı bir KORUMA yoktu.** 2026-08-26'nın "tek
bir satır bile yok" ölçümü elle yapılmış bir grep'ti — `login_dialog.py`
ileride (ör. mockup'a yeniden bakan bir restyle turunda) bu ekranı
sessizce geri alsa hiçbir test kırılmazdı. İki dosya eklendi/genişletildi:

- `tests/test_kurtarma_usb_kapisi.py`'ye YENİ bir bölüm (3, YAPISAL):
  - `test_login_dialog_KAYNAGINDA_kurtarma_giris_terimi_YOK` —
    `login_dialog.py`'nin kaynağı `decode_share`/`recover_master_key`/
    `export_recovery_share`/`share_3`/`RecoveryShareDialog`/"Kurtarma
    parça..." gibi terimler için taranıyor (B-071/B-076'nın aynı deseni).
  - `test_tarayici_enjekte_edilen_kurtarma_terimini_YAKALIYOR` —
    denetimin kendisi çalışıyor mu (B-024 dersi), `tmp_path` ile.
- YENİ dosya `tests/test_login_dialog_kurtarma_ekrani_yok.py`
  (DAVRANIŞSAL): `test_login_dialog_TAM_IKI_sayfali_UCUNCU_kurtarma_
  sayfasi_YOK` — gerçek `LoginDialog`, `_stack.count() == 2` (Giriş Yap +
  Kayıt Ol) — üçüncü bir sayfa eklenirse bu test kırılır. AYRI dosyada,
  kasıtlı: `test_kurtarma_usb_kapisi.py` modül seviyesinde Qt/UI ithal
  ETMİYOR ve öyle kalmalı — `tests/test_layering.py` bu depo genelinde
  korumasız bir modül-seviyesi Qt ithalinin TÜM paketi (Qt'siz bir
  ortamda) toplama hatasıyla durdurabileceğini zorunlu kılıyor; ilk
  yazımda ikisini TEK dosyada birleştirmek denendi ve tam da bu kuralı
  ÇİĞNEDİ (`test_layering.py::test_test_modulu_TOPLAMA_HATASI_uretemiyor`
  kırmızıya döndü) — düzeltme, davranışsal testi diğer yedi UI test
  dosyasıyla AYNI standart `try/except ImportError: pytest.skip(...,
  allow_module_level=True)` korumasına sahip ayrı bir dosyaya taşımaktı.

**Mutasyon kanıtı (üçü de bu turda, gerçek dosyada, sonra geri
alındı):** `login_dialog.py`'ye geçici bir `_MUTASYON_KANITI_B069 =
"share_3"` satırı eklenip yapısal test çalıştırıldı — **BAŞARISIZ**
oldu, doğru terimi (`share_3`) rapor ederek. Ayrı olarak `self._stack`'e
üçüncü bir `QWidget()` eklenip davranışsal test çalıştırıldı —
**BAŞARISIZ** oldu (`3 == 2` diff'i ile) — dosya bölündükten SONRA
tekrarlanıp aynı sonucu verdiği doğrulandı. Üçü de geri alındıktan sonra
`git diff --stat UI/login_dialog.py` boş döndü (dosya orijinal hâline
birebir döndü) ve tüm paket (`test_layering.py` dahil) tekrar yeşile
döndü.

Tam test suite: 2808 passed, 4 skipped (bir önceki turdan +5 — 2 yapısal
test + 1 davranışsal test + `test_layering.py`'nin YENİ dosyayı otomatik
kapsayan parametrizasyonlarından +2).

### 2026-08-29 (devam) — kapsam DÜZELTİLDİ: login_dialog.py'ye özel değil, UI/'nin tamamı (K0-6'nın aynı dersi)

Bir sonraki turda yukarıdaki yapısal korumanın (bölüm 3) TAM OLARAK
neyi taradığı sorgulandı — sonuç, tam da B-056/K0-6'nın öğrettiği sınıf
sorunun tekrarıydı: `test_login_dialog_KAYNAGINDA_kurtarma_giris_
terimi_YOK` yalnızca `UI/login_dialog.py`'yi TEK dosya olarak
tarıyordu, glob/rglob YOKTU. Korunması gereken şey "login ekranına
üçüncü bir sayfa eklenmesin" değil, "kurtarma-yeniden-inşa yeteneği
`_require_hwid()` kapısı olmadan `UI/`'nin HİÇBİR yerinden
tetiklenmesin" — biri bu ekranı `UI/RecoveryEntryDialog.py` gibi başka
bir dosyaya yazıp `main_window.py`'den bir menü öğesiyle ya da
`AdminPanel.py`'den ayrı bir düğmeyle bağlasa, ne yapısal tarama ne de
`LoginDialog._stack`'in sayfa-sayısı kilidi bunu görürdü.

**Düzeltme — K0-6'nın `rglob("*.py")` desenine geçildi, TÜM `UI/`
ağacı.** `tests/test_kurtarma_usb_kapisi.py`'nin 3. bölümü yeniden
yazıldı: `_ui_dosyalari()` artık `UI/`'nin tamamını (`__pycache__`
hariç, alt dizinler dahil) tarıyor.

**Ölçülen gerçek yanlış-pozitif riski — eski terim listesi çok
genişti.** İlk yazımdaki liste (`decode_share`, `recover_master_key`,
`export_recovery_share`, `share_3`, `RecoveryShareDialog`, "Kurtarma
parça...") `UI/`'nin TAMAMINA karşı çalıştırıldığında `UI/AdminPanel.py`'nin
MEŞRU dışa-aktarım ekranında (SEKİZ isabet: `export_recovery_share`
ithali/çağrısı, `RecoveryShareDialog` ithali/çağrısı, yerel değişken
`share_3`, "Kurtarma Parçasını Göster…" düğmesi, "Kurtarma Parçası"
diyalog başlıkları) ve `UI/RecoveryShareDialog.py`'nin kendi sınıf
adında/başlığında PATLADI — ölçüldü, gerçek bir false-positive, K0-6'nın
"çevrimdışı doğrular" ile yaşadığı sorunun aynı sınıfı. Ayrım netleştirildi:
tehlikeli olan payı DIŞARI vermek (`export_recovery_share`/`build_export`/
`RecoveryShareDialog` — `AdminPanel.py`'de zaten var, PIN'le korunan,
test edilmiş MEŞRU bir akış) değil, payı İÇERİ alıp master_key'i YENİDEN
KURMAK. Yasaklı liste bu yüzden İKİ ayrı, dar taramaya bölündü:

1. **Çağrı/ithal taraması** (`ast.Call`/`ast.Import`/`ast.ImportFrom`,
   YALNIZCA fonksiyon/ithal HEDEFLERİ): `recover_master_key`,
   `decode_share` — `UI/`'de bugün hiçbir meşru kullanımları yok.
   `share_3` BİLEREK bu listede DEĞİL: yalnızca bir DEĞİŞKEN adı,
   Python bir değişkenin adına önem vermez — tehlikeli olan hangi
   FONKSİYONUN çağrıldığı, değerin hangi isimle tutulduğu değil;
   `AdminPanel.py`'nin meşru kodu da bu adı kullanıyor.
2. **Metin taraması** (`ast.Constant`, K0-6'nın yöntemi — yorumlar hiç
   AST'ye girmediği için otomatik dışarıda): yalnızca mockup'ın "gir/
   giriş" fiilini TAŞIYAN spesifik biçimler ("Kurtarma parçasıyla",
   "Kurtarma ile Gir" ve büyük/küçük harf varyantları) — yalın "Kurtarma
   parça(sı/sını)" KÖKÜ BİLEREK YOK, tam da `AdminPanel.py`'nin meşru
   metniyle çakışan kısım.

**Gerçek kanıt — enjeksiyon, login_dialog.py DIŞINDA bir dosyada.**
Görevin istediği kanıt için `UI/ProfileDialog.py`'ye (giriş akışıyla
hiçbir ilgisi olmayan, kurtarma kodu barındırmayan temiz bir dosya)
geçici olarak eklendi:

- `from CORE.vault_manager import recover_master_key` — çağrı/ithal
  taraması **YAKALADI**: `UI/ProfileDialog.py:20 — recover_master_key`.
- `_MUTASYON_KANITI_B069 = "Kurtarma parçasıyla gir"` (modül docstring'i
  altına) — metin taraması **YAKALADI**:
  `UI/ProfileDialog.py:2 — 'Kurtarma parçasıyla'`.

İkisi de ayrı ayrı geri alındı, `git diff --stat UI/ProfileDialog.py`
boş döndü, tüm paket tekrar yeşile döndü. Bu tek kanıt aynı zamanda
davranışsal testin (`test_login_dialog_kurtarma_ekrani_yok.py`) neden
TEK BAŞINA yeterli olmadığının da kanıtı: `ProfileDialog.py`'ye eklenen
bu import `LoginDialog._stack`'e hiç dokunmaz, o test onu HİÇ görmezdi
— yalnızca genişletilmiş yapısal tarama görüyor. Davranışsal test
KALDIRILMADI (login akışına özgü, ucuz, ikinci bir savunma katmanı
olarak duruyor), ama artık BİRİNCİL koruma genişletilmiş yapısal tarama;
davranışsal test dosyasının kendi docstring'i bunu netleştirecek şekilde
güncellendi.

**Testler — `test_kurtarma_usb_kapisi.py`'nin 3. bölümü 2 testten 7'ye
çıktı (dosyanın toplamı 12):** eski `test_login_dialog_KAYNAGINDA_
kurtarma_giris_terimi_YOK` ve `test_tarayici_enjekte_edilen_kurtarma_
terimini_YAKALIYOR`, yerlerini `test_UI_agacinda_kurtarma_yeniden_insa_
cagrisi_YOK` (asıl çağrı/ithal taraması) ve `test_UI_agacinda_kurtarma_
giris_metni_YOK`'a (asıl metin taraması) bıraktı; ayrıca YENİ:
`test_ui_dizini_taranacak_dosya_iceriyor` (B-024 dersi — denetim boş
kümeyi denetlemiyor mu), `test_mevcut_UI_dosyalarindaki_mesru_
kullanimlar_YANLIS_POZITIF_URETMIYOR` (`AdminPanel.py`/
`RecoveryShareDialog.py`'nin gerçek içeriği hiçbir taramada
YAKALANMIYOR — yukarıdaki false-positive'in artık kapatıldığının kalıcı
kanıtı), iki enjeksiyon testi (çağrı + metin, `tmp_path` ile), ve
`test_tarayici_ALT_DIZINDEKI_dosyayi_da_yakaliyor` (K0-6'nın aynı
`rglob` regresyon kanıtı).

SECURITY.md §4.4 (EN+TR) bu kapsam düzeltmesini yansıtacak şekilde
güncellendi; `test_belge_dil_paritesi.py` (27/27) ile doğrulandı.

Tam test suite: 2813 passed, 4 skipped (bir önceki turdan +5).

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

## B-071 — "AIR-GAPPED"/"ÇEVRİMDIŞI" UI'ye İKİ KEZ sızdı — tek dosyalı düzeltme B-056'nın dersini tekrar öğretti, tek bir kapsamlı tarama ile kapatıldı

**Durum:** Kapalı
**Öncelik:** Orta (yanlış bir mimari iddia; kırılan bir şey değil ama
SECURITY.md ile ÇELİŞEN bir güvenlik iddiası kullanıcıya ulaşabilirdi)
**Bulundu ve kapatıldı:** 2026-08-28 — aynı turda

### Olay geçmişi

"HYCLEUS v2.5 · AIR-GAPPED" ve "● ÇEVRİMDIŞI" — SECURITY.md §1.1'in M1
(zaman damgası otoritesine AĞ üzerinden ulaşılıyor) ile doğrudan çelişen,
doğrulanmamış mimari iddialar — bu koda İKİ KEZ girdi:

1. Tema portlama turunda mockup'ın "v2.5 / AIR-GAPPED" metni BİLEREK
   taşınmadı (`UI/main_window_palette.py`'nin `_AURORA_BOREALIS`
   üstündeki yorum bunu kayda geçiriyor).
2. İki-sütunlu giriş ekranı restyle turunda (2026-08-26), aynı mockup'ın
   sol paneli tasarlanırken "HYCLEUS v2.5 · AIR-GAPPED" ve "● ÇEVRİMDIŞI"
   metni bu kez GERÇEKTEN `UI/login_dialog.py`'ye kopyalandı — 1.
   maddedeki karar unutulmuştu.

2. maddeyi yakalayan düzeltme (`tests/test_login_dogrulanmamis_iddia.py`)
   **TEK bir dosyayı** (`login_dialog.py`) tarıyordu, elle tutulan bir
   terim listesiyle. Bu tam olarak B-056'nın "README'nin `--selftest`
   modül sayısı" bulgusuyla aynı sınıf sorun: dosyaya-özgü, elle tutulan
   bir kontrol, YENİ bir UI dosyasında aynı iddia sızarsa onu YAKALAMAZ
   — üçüncü bir sızıntı için üçüncü bir dosyaya-özgü test yazılması
   gerekirdi, sessizce sürüklenmeye açık.

### Kalıcı çözüm — B-056'nın yapısal hamlesinin aynısı

`tests/test_login_dogrulanmamis_iddia.py` SİLİNDİ, yerine
`tests/test_ui_yasakli_iddia_terimleri.py` eklendi — `UI/*.py` altındaki
**HER** dosyadaki **her** string sabitini `ast` ile ayrıştırıp yasaklı
terim listesine karşı kontrol ediyor. Yeni bir UI dosyası eklendiğinde
elle güncellenecek bir liste YOK; tarama `UI/` glob'unu takip ediyor.

**Neden `ast`, neden ham metin taraması değil.**
`main_window_palette.py`'nin kendi yorumu ("... 'air-gapped'
doğrulanmamış bir güvenlik iddiası...") YASAKLI TERİMİN kendisini, onu
NEDEN yasakladığını açıklarken içeriyor. Ham bir `terim in dosya_metni`
taraması (önceki testin yaptığı gibi, ama o zaman tek dosyaya bakıyordu)
bu yorumu da bir ihlal SANIRDI — kanıtlandı: `UI/` genelinde ham metin
taraması denendiğinde bu tam olarak oldu. `ast.Constant` (yalnızca gerçek
string DEĞERLERİ) taramasına geçilince Python yorumları hiç AST'ye
girmediği için bu yanlış pozitif ortadan kalktı.

**Yasaklı terim listesi — SECURITY.md §6.8'de tam gerekçesiyle belgeli:**

| Terim | Bağlam |
|---|---|
| `AIR-GAPPED` / `air-gapped` | Koşulsuz yasak |
| `ZERO-TRUST` / `zero-trust` | Koşulsuz yasak |
| `ÇEVRİMDIŞI` / `çevrimdışı` | Yalnızca "çevrimdışı doğrula-" bigramı içinde izinli (RFC 3161 doğrulaması, §4.9 ile doğrulanmış GERÇEK bir yetenek); başka her bağlamda yasak |

"ÇEVRİMDIŞI" bağlama bağlı ele alındı çünkü `UI/GuvenlikView.py` ve
`UI/main_window_files.py`'de MEŞRU, doğru kullanımları var ("zaman
damgasını çevrimdışı doğrular" — gerçekten ağsız, ölçüldü). Koşulsuz
yasaklansa bu ikisi yanlış pozitif üretirdi; izin verilen bigram listesi
metinden çıkarılıp KALAN kısımda hâlâ bir "çevrimdışı" varyantı var mı
diye bakılarak ayrım yapılıyor.

Türkçe'nin noktalı/noktasız I sorunu ("İ".lower() tek bir "i" değil,
"i" + BİRLEŞTİRİCİ NOKTA üretiyor — ölçüldü) yüzünden `.lower()/.upper()`
kullanılmadı; tüm terimler ve izinli bigramlar büyük/küçük harf
varyantlarıyla ELLE listelendi (önceki testle aynı desen).

### Test

`tests/test_ui_yasakli_iddia_terimleri.py` — 7 test:

- `test_ui_stringlerinde_yasakli_mimari_iddia_YOK` — asıl tarama, tüm
  `UI/*.py`.
- `test_ui_dizini_taranacak_dosya_iceriyor` — denetimin kendisi boş
  kümeyi denetlemiyor mu (B-024 dersi, bkz. `test_tpm_sealing.py`).
- `test_mevcut_UI_dosyalarindaki_mesru_kullanimlar_YANLIS_POZITIF_
  URETMIYOR` — `GuvenlikView.py`/`main_window_files.py`'deki gerçek,
  meşru "çevrimdışı doğrular" kullanımları yanlışlıkla yakalanmıyor.
- 4 tane "denetimin kendisi çalışıyor mu" testi (`tmp_path` ile, gerçek
  dosyalara HİÇ dokunmadan): enjekte edilen AIR-GAPPED yakalanıyor,
  terim kaldırılınca yeşile dönüyor, enjekte edilen ZERO-TRUST
  yakalanıyor, bağımsız "● ÇEVRİMDIŞI" rozeti yakalanırken aynı dosyadaki
  "çevrimdışı doğrular" cümlesi yakalanmıyor (tam olarak sızan örüntü).

Ayrıca GERÇEK bir dosyaya (`UI/RecoveryShareDialog.py`) geçici olarak
`"Bu kasa AIR-GAPPED calisir"` eklenip asıl taramanın onu doğru dosya/
satır bilgisiyle yakaladığı, sonra geri alınınca yeşile döndüğü elle
doğrulandı (kalıcı teste dahil edilmedi — `tmp_path` testleri aynı
kanıtı gerçek dosyalara dokunmadan sağlıyor).

Tam test suite: 2735 passed, 4 skipped (bir önceki turdan +6: yeni
dosyanın 7 testi eksi silinen dosyanın 1 testi).

### 2026-08-29 (devam) — kapsam kanıtlandı ve genişletildi: alt dizinler + CORE/DB exception mesajları

Bir sonraki turda taramanın KENDİSİNİN kapsam iddiası (§ "Kalıcı çözüm")
iki yönden sınandı — kanıtlanmadan varsayılmaması istendi:

**1. `UI/` alt dizinleri.** `UI/*.py` glob'u yalnızca üst düzeydi.
`UI/` bugün alt dizin içermiyor (yalnızca `__pycache__`), ama gerçek bir
kanıt gerekiyordu: geçici `UI/_gecici_altdizin_kaniti/sahte.py` dosyasına
bir `AIR-GAPPED` dizesi ekilip tarama çalıştırıldı — 7/7 test YEŞİL
kaldı, yani desen bir alt dizindeki dosyayı SESSİZCE atlıyordu. `glob`
`rglob`'a (`__pycache__` hariç) çevrildi; aynı ekili dosya bu kez
yakalandı. Geçici dosya/dizin kanıttan hemen sonra silindi; kalıcı bir
`tmp_path` regresyon testi (`test_tarayici_ALT_DIZINDEKI_dosyayi_da_
yakaliyor`) düzeltmeyi koruyor.

**2. CORE/DB exception mesajları.** `USBAuthError`, `VaultTamperedError`,
`AuthenticationError`, `BackupError`, `CheckoutError`, `TrustedRootError`,
`PinRotationError` gibi CORE/DB'de tanımlı exception sınıflarının
mesajlarının `str(exc)` yoluyla UI'ye HAM ulaşıp ulaşmadığı grep ile
izlendi. Sonuç: ULAŞIYOR — `AdminPanel.py:729,1282`,
`main_window_open.py:131,237,342`, `main_window_lock.py:230,234,258`,
`ProfileDialog.py:355,358`, `main_window_files.py:313`,
`login_dialog.py:1094`, `PinRotationDialog.py:207` hepsi bir exception'ı
doğrudan `QMessageBox`'a geçiriyor. Bu yüzden bir CORE/DB exception mesajı
da bir UI string'i kadar kullanıcıya açık — tarama genişletildi.

CORE/DB'nin TÜM string sabitlerini (UI/'deki yöntemin aynısıyla) taramak
önce denendi. Sonuç 8 ihlal, 7'si YANLIŞ POZİTİF: `backup.py`, `hclx.py`,
`rate_limit.py`, `timestamp.py`, `timestamp_verify.py`'nin modül
docstring'leri "çevrimdışı kaba kuvvet" (saldırganın yapabileceği) ve
"ÇEVRİMDIŞI DOĞRULANMASI" (isim-fiil, konu tanıtımı) gibi hiçbir
kullanıcının görmediği, izinli listenin kapsamadığı biçimlerde metin
içeriyordu. Tarama bunun yerine yalnızca `raise SinifAdi(...)`
çağrılarının İÇİNDEKİ string sabitlerine daraltıldı
(`_raise_mesaj_sabitlerini_topla`) — CORE/DB'nin `str(exc)` yoluyla
gerçekten sızabilecek TEK kaynağı. Bu yedi yanlış pozitifi ortadan
kaldırdı ve tek gerçek isabeti korudu: `CORE/timestamp.py:672`'nin
`"...bu damga sonradan çevrimdışı doğrulanamaz."` mesajı — bir SINIRLAMA
bildirimi (sertifika gömülmemişse doğrulama YAPILAMAZ), bir mimari iddia
değil; izin verilen bağlam listesine "çevrimdışı doğrulanamaz" olarak
eklendi.

**Yeni testler (5, dosyanın toplamı 13'e çıktı):**
`test_mevcut_CORE_dosyalarindaki_docstring_mesru_kullanimlar_YANLIS_
POZITIF_URETMIYOR`, `test_raise_icindeki_enjekte_edilen_terim_CORE_
taramasinda_yakalaniyor`, `test_raise_DISINDAKI_docstring_CORE_
taramasinda_YAKALANMIYOR`, `test_core_db_dosyasi_mi_yol_ayrimi_dogru`,
`test_gercek_CORE_timestamp_dosyasinin_raise_mesaji_UYGUN_ALLOWLIST_ile_
GECIYOR` — artı alt dizin kapsamı için `test_tarayici_ALT_DIZINDEKI_
dosyayi_da_yakaliyor`. Toplam 13 test, hepsi yeşil.

SECURITY.md §6.8 (EN+TR) 2026-08-29 tarihli bir paragrafla güncellendi;
`test_belge_dil_paritesi.py` (27/27) ile doğrulandı.

Tam test suite: 2741 passed, 4 skipped (bir önceki turdan +6 — bu dosyaya
eklenen 6 yeni test: yukarıda sayılan 5 + alt dizin kapsamı testi).

### 2026-08-29 (devam 2) — `raise Sinif(degisken)` atlatması ölçüldü ve kapatıldı

Bir sonraki turda, bir önceki maddedeki `raise`-yalnızca CORE/DB
taramasının KENDİSİNİN bir boşluk bırakıp bırakmadığı sorgulandı: tarama
yalnızca `raise Sinif(...)` çağrısının İÇİNDEKİ `ast.Constant`
düğümlerini arıyordu (kod satırıyla teyit:
`tests/test_ui_yasakli_iddia_terimleri.py`'nin o zamanki `_raise_mesaj_
sabitlerini_topla`'sı, `ast.walk(dugum.exc)` içinde `Constant` arıyordu).
Argüman bir `ast.Name` (değişken) olduğunda o alt ağaçta HİÇ `Constant`
düğümü yok — geri izleme YOKTU.

**Sentetik kanıt.** CORE/'ye geçici olarak eklendi:

```python
msg = "AIR-GAPPED doğrulama modu etkin"
raise USBAuthError(msg)
```

Tarama çalıştırıldı: **TOPLAM İHLAL: 0**. Atlatma gerçekti. Geçici dosya
kanıttan hemen sonra silindi. (Gerçek üretim kodunda bu kalıbın kullanılıp
kullanılmadığı grep ile ayrıca kontrol edildi — kullanılmıyor, ama boşluk
yine de kapatılması gereken gerçek bir yapısal zayıflıktı.)

**Uygulanan seçenek — (a): taramayı genişlet.** Görevin izin verdiği
"basit tek-seviye geri izleme" uygulandı, tam bir veri akışı analizi
DEĞİL: `_govde_icinde_raise_ve_atamalari_coz` her fonksiyon/modül gövdesini
SIRAYLA gezip `ad = "literal"` atamalarını bir sözlükte takip ediyor,
`raise Sinif(ad)` görüldüğünde o ana kadar bilinen en son atamayı
kullanıyor. Kapsam kuralları:

- İç içe `if`/`for`/`while`/`try`/`with` blokları AYNI kapsam (sözlük
  PAYLAŞILIYOR — dallanma doğruluğundan çok, kaçırmamak önceliklendirildi,
  bir güvenlik taraması için doğru yön: fazla-yakalama zararsız, az-yakalama
  tehlikeli).
- İç içe bir `def`/`class` YENİ bir kapsam (boş sözlükle işleniyor,
  dışarıdan miras almıyor) — başka bir fonksiyondaki aynı isimli bir
  değişkenle YANLIŞLIKLA eşleşmemesi için.
- Sıra önemli: bir atama `raise`'den SONRA yazılmışsa "en yakın ÖNCEKİ"
  tanımına uymadığı için çözülmüyor.

Sentetik kanıt tekrar çalıştırıldı, bu kez geri izlemeyle: **TOPLAM
İHLAL: 1**, doğru dosya/satır (`raise`'in satırı, atamanınki değil) ile
yakalandı. Gerçek CORE/DB ağacına karşı da çalıştırıldı — geri izleme
eklendikten sonra hâlâ sıfır ihlal (yeni mantık yeni bir yanlış pozitif
üretmedi).

**Yeni testler (4, dosyanın toplamı 17'ye çıktı):**
`test_raise_DEGISKEN_uzerinden_gecirilen_enjekte_terimi_yakaliyor` (pozitif
kanıt), `test_raise_DEGISKEN_atamasi_BASKA_FONKSIYONDA_ise_COZULMUYOR` ve
`test_raise_DEGISKEN_atamasi_RAISE_DEN_SONRA_ise_COZULMUYOR` (kapsam/sıra
sınırları), `test_gercek_CORE_DB_dosyalarinda_degisken_uzerinden_gecen_
ihlal_YOK` (gerçek ağaçta yeni yanlış pozitif yok).

SECURITY.md §6.8 (EN+TR) 2026-08-29 "devam" paragrafıyla güncellendi;
`test_belge_dil_paritesi.py` (27/27) ile doğrulandı.

Tam test suite: 2745 passed, 4 skipped (bir önceki turdan +4 — bu dosyaya
eklenen 4 yeni test).

### 2026-08-29 (devam 3) — ÇOK-HOP zincirleme atama atlatması ölçüldü ve kapatıldı

Bir sonraki turda, bir önceki maddedeki tek-seviye geri izlemenin
KENDİSİNİN kaç hop derinliğinde çalıştığı sorgulandı (kod satırıyla teyit
istendi, henüz düzeltme yapılmadan). Kod incelemesi: `atamalar[hedef] =
stmt.value.value` satırı yalnızca `isinstance(stmt.value, ast.Constant)`
olduğunda çalışıyordu — `ad = baska_degisken` biçimindeki bir atama
(`stmt.value` bir `ast.Name`, `ast.Constant` DEĞİL) bu koşulu hiç
sağlamıyordu, yani sözlüğe HİÇ girmiyordu. Derinlik tam olarak **1 hop**.

**Sentetik kanıt (bu turda tekrarlandı, aynı sonuç).** CORE/'ye geçici
olarak eklendi:

```python
tmp = "AIR-GAPPED doğrulama modu etkin"
msg = tmp
raise USBAuthError(msg)
```

Tarama çalıştırıldı: **TOPLAM İHLAL: 0**. Atlatma teyit edildi. Geçici
dosya kanıttan hemen sonra silindi.

**Uygulanan düzeltme — iki aşamalı kayıt + zincir çözümü.**
`_govde_icinde_raise_ve_atamalari_coz`'ün atama kaydı ikiye ayrıldı:
`atamalar[hedef] = ("literal", deger)` (RHS bir string literal) ya da
`("isim", baska_ad)` (RHS başka bir isim) — hangisi olursa olsun HAM
olarak kaydediliyor, henüz çözümlenmeden. Yeni bir `_isim_zincirini_coz`
fonksiyonu, bir `raise Sinif(ad)` görüldüğünde bu HAM haritayı `ad`'den
başlayıp bir literal'e ulaşana kadar takip ediyor:

- **Azami derinlik:** `_MAKS_ZINCIR_DERINLIGI = 10` hop. Aşılırsa
  `warnings.warn` ile bildirilip `None` (ihlal yok) dönülüyor —
  SESSİZCE yutulmuyor.
- **Döngü koruması:** zincirde aynı ismin İKİNCİ kez görünmesi (`a = b; b
  = a` gibi) sonsuz döngüye girmeden tespit ediliyor, yine `warnings.warn`
  ile bildiriliyor.
- **Bayat kayıt temizliği:** bir hedef izlenemez bir değere (ör. bir
  fonksiyon çağrısı sonucu) yeniden atanırsa, eski kaydı `atamalar`'dan
  SİLİNİYOR — aksi halde stale bir literal'e yanlışlıkla çözülebilirdi.

**Doğrulama — 4 sentetik senaryo, sonuca göre raporlandı:**

1. İki-hop zincir (`tmp = "..."; msg = tmp; raise X(msg)`) — CORE/'ye
   tekrar eklendi, düzeltmeden SONRA çalıştırıldı: **TOPLAM İHLAL: 1**,
   doğru satırda (`raise`'in satırı) yakalandı.
2. Üç-hop zincir (`a = "..."; b = a; c = b; raise X(c)`) — aynı şekilde
   **TOPLAM İHLAL: 1**, yakalandı.
3. Döngüsel atama (`a = b; b = a; raise X(a)`) — tarama ÇÖKMEDEN,
   ASILI KALMADAN tamamlandı; `warnings.warn` ile döngü uyarısı üretti;
   sonuç 0 ihlal (beklenen — hiçbir isim bir literal'e çözülmüyor).
4. Gerçek CORE/DB ağacına karşı: çok-hop çözümü etkinken hâlâ **sıfır
   ihlal** (yeni mantık yeni bir yanlış pozitif üretmedi).

Her sentetik kanıt sonrası geçici dosyalar hemen silindi;
`git status --porcelain` her adımda temiz olduğu doğrulandı.

**Yeni testler (5, dosyanın toplamı 22'ye çıktı):**
`test_raise_IKI_HOP_zincirleme_atamayi_cozuyor`,
`test_raise_UC_HOP_zincirleme_atamayi_cozuyor`,
`test_raise_DONGUSEL_atama_COKMEDEN_ve_ASILI_KALMADAN_tamamlanir`
(`warnings.catch_warnings` ile uyarının GERÇEKTEN üretildiğini de
doğruluyor, yalnızca çökmediğini değil),
`test_isim_zincirini_coz_azami_derinlik_asilinca_uyarir_ve_None_doner`
(yapay 15-hop zincir — azami derinlik sınırının döngü korumasından
BAĞIMSIZ çalıştığının kanıtı), `test_gercek_CORE_DB_dosyalarinda_
cok_hop_sonrasi_ihlal_YOK`.

SECURITY.md §6.8 (EN+TR) 2026-08-29 "devam, yine" paragrafıyla
güncellendi; `test_belge_dil_paritesi.py` (27/27) ile doğrulandı.

Tam test suite: 2750 passed, 4 skipped (bir önceki turdan +5 — bu dosyaya
eklenen 5 yeni test).

### 2026-08-29 (devam 4) — f-string (`ast.JoinedStr`) kapsamı ölçüldü; `+`-birleştirmesi kontrol edildi, bugün gerekmiyor

Bir sonraki turda taramanın f-string'lere (`raise X(f"...")`) karşı
davranışı sorgulandı — iki senaryo, CORE/'ye geçici kod eklenerek ayrı
ayrı ölçüldü:

**Senaryo 1 — doğrudan f-string:**
```python
raise USBAuthError(f"AIR-GAPPED doğrulama modu: {hwid}")
```
Tarama çalıştırıldı: **TOPLAM İHLAL: 1**, doğru yakalandı, **hiçbir kod
değişikliği gerekmedi**. Sebep: `_raise_mesaj_sabitlerini_topla`'nın
doğrudan-literal taraması `ast.walk(dugum.exc)` ile TÜM alt ağacı geziyor
— bir `ast.JoinedStr`'ın `values` listesindeki `ast.Constant` parçaları da
bu genel gezinmeyle bulunuyor, `ast.FormattedValue` (interpolasyon)
düğümleri zaten `ast.Constant` OLMADIĞI için otomatik olarak atlanıyor.

**Senaryo 2 — değişkene atanmış f-string (zincir üzerinden):**
```python
msg = f"AIR-GAPPED doğrulama modu: {hwid}"
raise USBAuthError(msg)
```
Tarama çalıştırıldı: **TOPLAM İHLAL: 0**. Atlatma gerçekti — `_govde_
icinde_raise_ve_atamalari_coz`'ün atama kaydedicisi yalnızca `ast.Constant`
(doğrudan literal) ve `ast.Name` (isimden-isme) durumlarını tanıyordu;
`stmt.value` bir `ast.JoinedStr` olduğunda `else: atamalar.pop(hedef,
None)` dalına düşüp "izlenemez" sayılıyordu. Her iki senaryonun geçici
dosyaları kanıttan hemen sonra silindi.

**Uygulanan düzeltme.** Yeni bir `_joinedstr_literal_kismini_coz(dugum)`
fonksiyonu, bir `JoinedStr`'ın `values` listesindeki YALNIZCA düz literal
(`ast.Constant`, str) parçalarını sırayla birleştiriyor, `ast.FormattedValue`
düğümlerini (interpolasyonun kendisini) atlıyor. Atama kaydedicisine
üçüncü bir dal eklendi: `ad = f"..."` artık `("literal",
_joinedstr_literal_kismini_coz(...))` olarak kaydediliyor — normal bir
literal atama gibi, sonraki hop'lar tarafından şeffafça takip edilebiliyor
(ayrı bir kod yolu değil, mevcut `_isim_zincirini_coz` ile birleşik).

Senaryo 2 düzeltmeden SONRA tekrar çalıştırıldı: **TOPLAM İHLAL: 1**,
doğru satırda yakalandı.

**`+`-birleştirmesi (`ast.BinOp`, `ast.Add`) kontrolü.** Görevin istediği
hızlı kontrol yapıldı: kod tabanında GERÇEKTEN kullanılıyor mu?
`raise` çağrıları İÇİNDE 3 gerçek kullanım bulundu (`CORE/timestamp.py:988,
998, 1041` — literal + `", ".join(...)` + literal), ama ÜÇÜ DE doğrudan
`raise` argümanı, bir değişkene atanıp SONRA raise edilen bir `BinOp`
DEĞİL — bu yüzden zaten aynı `ast.walk` mekanizmasıyla (f-string'lerle
aynı sebepten) hiçbir ek kod olmadan yakalanıyorlar (doğrulandı:
`_raise_mesaj_sabitlerini_topla` bu üç satırın tüm literal parçalarını
doğru döndürüyor). CORE/DB genelinde (`raise` dışında dahil) string-içeren
8 `BinOp(+)` ataması daha bulundu, ama hepsi byte-paketleme
(`tpm_sealing.py`, `vault_manager.py`), SQL sorgu kurma (`duplicates.py`)
ya da sayaç aritmetiği (`rate_limit.py`) — hiçbiri bir exception mesajı
değil, hiçbiri bir `raise`'e akmıyor. Sonuç: `+`-birleştirmesi ZİNCİR
üzerinden (`msg = "a" + "b"; raise X(msg)`) bugün kod tabanında
KULLANILMIYOR, o yüzden görevin izin verdiği ikinci seçenek uygulandı —
kod değişikliği YAPILMADI, SECURITY.md §6.8'e bilinen bir sınır olarak not
düşüldü.

**Yeni testler (4, dosyanın toplamı 27'ye çıktı):**
`test_raise_DOGRUDAN_fstring_yakalaniyor`,
`test_raise_DEGISKEN_uzerinden_gecen_fstring_yakaliyor`,
`test_fstring_interpolasyon_kismi_TARANMIYOR_ve_HATAYA_YOL_ACMIYOR`
(interpolasyondaki bir değişken adının kendisi bir terim İÇERSE bile
yanlış pozitif üretmediğini VE hataya yol açmadığını kanıtlıyor),
`test_gercek_CORE_DB_dosyalarinda_fstring_sonrasi_ihlal_YOK` (gerçek
`CORE/tpm_sealing.py`'deki GERÇEK bir f-string tabanlı raise mesajıyla
sınanıyor) — artı birim düzeyinde `test_joinedstr_literal_kismini_coz_
interpolasyonu_atlar`.

SECURITY.md §6.8 (EN+TR) 2026-08-29 "devam, bir kez daha" paragrafıyla
güncellendi (hem f-string desteği hem `+`-birleştirmesinin bilinen sınırı);
`test_belge_dil_paritesi.py` (27/27) ile doğrulandı.

Tam test suite: 2755 passed, 4 skipped (bir önceki turdan +5 — bu dosyaya
eklenen 5 yeni test).

### 2026-08-29 (devam 5 — K0-6 teyidi: kod tabanı temiz, ama mockup artifact'ı HÂLÂ eski rozeti taşıyor)

Bir sonraki turda (K0-6 listesindeki temizlik/teyit maddesi), yukarıdaki
taramanın bugün hâlâ doğru sonuç verdiği yeniden koşuldu — kod
değişmedi, yalnızca teyit: `pytest tests/test_ui_yasakli_iddia_
terimleri.py -q` → **27/27 geçti**, `UI/`+`CORE/`+`DB/` genelinde
`AIR-GAPPED`/`ZERO-TRUST`/bağlam-dışı `ÇEVRİMDIŞI` iddiası **YOK**.
`login_dialog.py` dahil hiçbir gerçek kod dosyasında bu rozetler kalmadı.

**Ayrı bulgu — mockup artifact'ı kaynağı hâlâ eski.** Bu B-071'in
kaynağı olan tasarım mockup'ı (bkz. üstteki "Olay geçmişi" — Claude
Design/Artifact platformunda yayınlı "UI Mockup Tasarımı Projesi",
`https://claude.ai/code/artifact/f348a8a1-4ab9-4dfc-bb71-795f61ce09af`)
okunup terim taraması yapıldı: **hâlâ** "HYCLEUS v2.5 · AIR-GAPPED"
metnini VE bağımsız bir "● ÇEVRİMDIŞI" durum rozetini VE genel bir
"tamamen çevrimdışı" mimari iddiasını (RFC 3161 "çevrimdışı doğrulanır"
bigramının İZİN VERİLEN kullanımından AYRI, bağımsız bir cümle olarak)
taşıyor — üçü de kod tabanından SİLİNEN, aynı üç iddia.

**Kaynak orada güncellenmedi — kasıtlı, gerekçeli karar.** Artifact,
`<script type="__bundler/template">` içinde çift-kaçışlı (JSON içinde
JS-string içinde HTML), ~660 KB'lık TEK satırlık minified bir bundle
olarak saklanıyor — okunabilir/elle düzenlenebilir bir HTML kaynağı
DEĞİL. Bayt düzeyinde bir `\"`/`\\n` kaçış dizisini yanlış kurgulamak
bundle'ı sessizce bozabilirdi VE bu ortamda sonucu görsel olarak
render edip DOĞRULAMANIN bir yolu yok (B-024'ün "denetimin kendisi
çalışıyor mu" dersiyle aynı sınıf risk: doğrulanamayan bir değişiklik
yapmaktansa yapmamak tercih edildi). Görevin izin verdiği ikinci
seçenek uygulandı:

**ESKİ-REFERANS NOTU:** Bu mockup artifact'ı 2026-08-26 tema/restyle
turlarının GİRDİSİYDİ, o turlardan sonra GERÇEK karşılığı YOK —
"HYCLEUS v2.5 · AIR-GAPPED" metni, "● ÇEVRİMDIŞI" rozeti ve "tamamen
çevrimdışı" iddiası kasıtlı olarak koda taşınmadı (1. madde) ya da
taşınıp sonra B-071'in asıl düzeltmesiyle kaldırıldı (2. madde). Bu
artifact'a bakan biri bu üç öğeyi güncel bir özellik/durum sanmamalı;
tek otorite `SECURITY.md` + gerçek koddur (`UI/login_dialog.py`,
`tests/test_ui_yasakli_iddia_terimleri.py`).

Test eklenmedi — bu bir kod değişikliği değil, mockup harici bir
tasarım varlığı üzerine düşülen bir doküman notu; `tests/test_ui_
yasakli_iddia_terimleri.py`'nin 27 testi zaten kod tabanının temiz
kaldığını sürekli doğruluyor.

Tam test suite: değişmedi (2801 passed, 4 skipped — bu turda kod/test
dosyası değişmedi, yalnızca bu doküman notu eklendi).

---

## B-072 — Önerilen WAL checkpoint hiçbir şey düzeltmiyordu; gerçek boşluk `_dump_tables()`'ın tablolar-arası tutarlılığıydı, bulundu ve kapatıldı

**Durum:** Kapalı
**Öncelik:** Orta (ölçülebilir tetikleyici koşul gerektiriyor — eşzamanlı
yazma; ama tetiklendiğinde sonuç geri yüklendiğinde `FOREIGN KEY
constraint failed` ile patlayan ya da yetim referans taşıyan bir yedek)
**Bulundu ve kapatıldı:** 2026-08-29 — aynı turda

### İstek ve ilk bulgu

"Yedekleme akışına `PRAGMA wal_checkpoint(TRUNCATE)` çağrısını, kopyalama
başlamadan hemen önce ekle — checkpoint yapılmadan alınan bir yedek eksik
olabilir" isteğiyle başladı. Kod incelemesi önce yapıldı: `create_backup()`
([CORE/backup.py](CORE/backup.py)) ham `hycleus.db` dosyasını HİÇ
kopyalamıyor — `.hcl` kasa dosyalarını `shutil.copy2` ile kopyalıyor
(SQLite değil, WAL'la ilgisi yok) ve veritabanı içeriğini
`db.fetchall(f"SELECT * FROM {tablo}")` ile CANLI bağlantı üzerinden
çekiyor. WAL modunda bir bağlantı üzerinden yapılan `SELECT`, checkpoint
durumundan TAMAMEN bağımsız olarak her zaman tam COMMIT edilmiş durumu
döndürür — bu SQLite'ın kendisinin garantisi. Checkpoint eklemek bu
mekanizma için gerçek bir boşluğu KAPATMAZDI.

Kullanıcıya bu bulgu sunuldu (`AskUserQuestion`); yanıt: checkpoint
eklenmesin, gerekçe belgelensin — ama asıl soruyu çöz: `_dump_tables()`
tüm tabloları TEK bir tutarlı anlık görüntüde mi okuyor?

### Gerçek boşluk — cross-table tutarlılık

`_dump_tables()`, `RESTORABLE_TABLES` (`files, folders, tags, file_tags,
retention_profiles, quarantine`) için tablo başına AYRI bir `SELECT`
çalıştırıyordu, aralarını bağlayan hiçbir transaction yoktu. Doğrudan
`sqlite3` ile (kod değiştirmeden ÖNCE) ölçüldü: iki bağlantılı bir
senaryoda, ilk tablo okunduktan SONRA ama son tablo okunmadan ÖNCE gelen
bir COMMIT, ikinci okumaya YANSIYORDU — yani dump iki tabloyu FARKLI
zaman noktalarında dondurabiliyordu (`python -c` ile: sarmalayıcısız
okuma "torn? True", `BEGIN`...`COMMIT` sarmalı okuma "torn? False").

`DBManager` bir singleton (`DB/db_manager.py`) ve `UI/main_window_open.py`
`_on_create_backup()`'ta `create_backup(DBManager(), ...)` çağırıyor —
yani yedekleme uygulamanın GERÇEK, PAYLAŞILAN bağlantısı üzerinden
çalışıyor; eşzamanlı bir yazma (başka bir thread, gelecekte eklenecek bir
arka plan işi) bu iki okuma arasına gerçekten girebilir.

**Somut sonuç:** eşzamanlı eklenen bir dosyaya karşılık gelen bir
`quarantine` satırı, o dosyayı hiç içermeyen bir `files` dökümüyle
BİRLİKTE dump'a girebiliyordu — restore edildiğinde kendi foreign-key
kısıtını ihlal edecek bir veritabanı.

### Düzeltme

`create_backup()`'ta `_dump_tables(db, RESTORABLE_TABLES)` ve
`_dump_tables(db, REFERENCE_TABLES)` çağrıları artık açık bir
`db.conn.execute("BEGIN")` ... `db.conn.execute("COMMIT")` (try/finally
ile) içine alınıyor — WAL'ın anlık-görüntü izolasyonunu TÜM okuma
dizisine yayıyor. `_dump_tables()`'ın kendi docstring'i, bu garantiyi
KENDİSİNİN vermediğini, çağıranın sarmalaması gerektiğini artık açıkça
belirtiyor.

### İkinci, bağımsız bulgu — `apply_metadata()`'nın FK sırası

Round-trip testi yazılırken (aşağıda) ikinci bir hata ortaya çıktı:
`RESTORABLE_TABLES`'ta `files`, kendisinin foreign key ile bağlı olduğu
`folders` ve `retention_profiles`'tan ÖNCE listeleniyordu. `apply_metadata()`
bu sırayla `INSERT OR REPLACE` yapıyor ve `PRAGMA foreign_keys = ON`
altında bu, TAMAMEN BOŞ bir veritabanına geri yüklerken
`sqlite3.IntegrityError: FOREIGN KEY constraint failed` ile patlıyordu.
Mevcut testler bunu hiç yakalamamıştı çünkü hepsi ZATEN DOLU bir
veritabanına (folders/retention_profiles silinmeden) geri yüklüyordu —
gerçek "yeni makineye geri yükleme" senaryosu hiç sınanmamıştı.

`RESTORABLE_TABLES` bağımlılık-güvenli sıraya alındı:
`folders, retention_profiles, tags, files, file_tags, quarantine` —
önce bağımlılığı olmayanlar, sonra onlara bağımlı `files`, en son
`files`'a bağımlı `file_tags`/`quarantine`. Sabitin üstüne bu bağımlılık
zincirini ve ölçülen hatayı belgeleyen bir yorum eklendi.

### Testler

`tests/test_backup.py`'a yeni bölüm "7. Eşzamanlı yazma altında
tutarlılık", 3 yeni test:

- `test_dump_tables_building_block_is_torn_by_a_concurrent_write_if_unwrapped`
  — KALICI regresyon kilidi: `_dump_tables()`'ı sarmalamadan (düzeltmeden
  ÖNCEki `create_backup()`'ın yaptığı gibi) iki kez çağırıp, aradaki
  eşzamanlı yazmanın yırtık bir görüntü ürettiğini kanıtlıyor — birisi
  `create_backup()`'taki `BEGIN`...`COMMIT`'i yanlışlıkla kaldırırsa bu
  test hemen kırılır.
- `test_create_backup_dump_is_a_single_consistent_snapshot` — ANA TEST:
  gerçek `create_backup()`'ı, `quarantine` (son tablo) okunmak ÜZEREYKEN
  tetiklenen bir eşzamanlı yazmayla çalıştırıp, dump'ın TAMAMEN eski
  hâli yansıttığını (ne `files`'ta ne `quarantine`'de yeni satır)
  doğruluyor.
- `test_restored_backup_has_no_orphaned_quarantine_reference` —
  ROUND-TRIP: tutarlı yedeği AYRI, boş bir `DBManager` örneğine
  (`conftest.py`'nin `db` fixture'ıyla AYNI desenle, singleton elle
  sıfırlanarak) `apply_metadata()` ile geri yükleyip hiçbir
  `quarantine.file_id`'nin restore edilmemiş bir `files.id`'ye işaret
  etmediğini doğruluyor. Bu test, `db` fixture'ını doğrudan parametre
  alarak YANLIŞ kuruldu ilk taslakta — `dolu_db(db, vault)` onu zaten
  sarmaladığı için ikisi AYNI singleton'a işaret ediyordu; düzeltme testin
  kendi docstring'inde belgeli.

SECURITY.md §4.11 (EN+TR) iki yeni paragrafla güncellendi: (a) checkpoint
neden eklenmedi, (b) gerçek boşluk ve düzeltmesi + FK sırası hatası.
`test_belge_dil_paritesi.py` (27/27) ile doğrulandı.

Tam test suite: 2758 passed, 4 skipped (bir önceki turdan +3 — bu dosyaya
eklenen 3 yeni test).

---

## B-073 — Yırtık-okuma riski kod tabanı genelinde tarandı: KVKK envanter raporunda gerçek bir isabet bulundu ve kapatıldı, hata yolu doğrulandı

**Durum:** Kapalı
**Öncelik:** Orta (tetikleyici koşul — rapor üretimi sırasında eşzamanlı
yazma — gerektiriyor; ama tetiklendiğinde kendi içinde ÇELİŞEN, uyum
kanıtı olarak sunulabilecek bir rapor satırı üretiyor)
**Bulundu ve kapatıldı:** 2026-08-29 — aynı turda

### İstek

B-072'nin `create_backup()` düzeltmesinin ardından: aynı deseni (birden
fazla tabloyu ardışık, sarmalanmamış SELECT'lerle okuyan fonksiyonlar)
kod tabanı genelinde, özellikle export/rapor/CSV/PDF üretimiyle ilgili
kodda tara; gerçek risk taşıyan her fonksiyona aynı `BEGIN`...`COMMIT`
düzeltmesini uygula; `create_backup()`'ın hata dayanıklılığını da
doğrula.

### Tarama sonucu

`CORE/`'daki export/rapor üreticilerinin tümü kontrol edildi:

| Fonksiyon | Çok tablolu mu | Sarmalanmamış mı | Risk |
|---|---|---|---|
| `CORE/export.py::aad_map()` | Hayır (tek tablo, `files`) | — | Yok |
| `CORE/audit_chain.py::verify_audit_chain()` | Evet (`settings`+`audit_log`×2-3) | Evet | Yok — `audit_log` yalnızca-ekleme, ekstra okumalar bilgilendirici sayaçlar, hash-zincir matematiği bunlara bağlı değil |
| `CORE/inventory.py::generate_retention_inventory()` | Evet (temel JOIN + satır başına 4 ek sorgu) | Evet (düzeltmeden ÖNCE) | **GERÇEK — düzeltildi** |
| `UI/AuditLogDialog.py::_export_txt()` | Evet ama FARKLI biçimde (Qt tablo önbelleği + taze DB sorgusu) | — | Gerçek ama transaction-sarmalamayla düzeltilemez, ayrı madde (aşağıda) |

### Gerçek isabet — `generate_retention_inventory()`

`CORE/inventory.py`'nin KVKK saklama envanteri: `files` + `retention_
profiles` + `users` + `audit_log` alt sorgusu üzerinde TEK bir JOIN
(`_BASE_QUERY`) ile başlıyor, ama HER satır için `_row_status_and_date()`
→ `check_disposal()` `files`/`retention_profiles`'ı DÖRT KEZ DAHA, ayrı
ayrı, sarmalanmadan yeniden okuyor (modülün kendi "Bu N+1 sorgu demektir"
notu). Bu tam olarak B-072'nin backup'ta bulduğu YAPISAL kalıp.

**Neden özellikle ciddi.** Modülün kendi docstring'i: *"Tutarlılık
güvencesi — rapor ile uygulama ayrışamaz."* Bu güvence MANTIK
tutarlılığı içindi (rapor, gerçek silmeyi kapı gibi kullanan AYNI
fonksiyonu çağırıyor) ama ZAMANSAL tutarlılığı KAPSAMIYORDU. Envanter,
`export_inventory_csv()`/`export_inventory_pdf()` ile bir düzenleyiciye
uyum KANITI olarak sunulması AÇIKÇA amaçlanan bir rapor.

**Ölçüldü.** Aynı 10 yıllık profildeki iki dosyadan ikincisi, tam
`check_disposal()`'ı onun `retention_profile_id`'sini okumak ÜZEREYKEN
ikinci bir bağlantıyla 1 yıllık bir profile yeniden atandı. Sonuç:
`profile_name` (ilk JOIN'den, ESKİ) `status`'ün (YENİ profile göre
hesaplanmış) YANINDA — kendi içinde çelişen bir satır. 400 gün önce
eklenmiş bir dosya: 10 yıllık profilde AKTİF, 1 yıllık profilde SÜRESİ
DOLMUŞ — iki profil arasındaki fark gözle görülür biçimde farklı bir
`status` üretiyor, torn-read'i saklamayan bir kurulum.

**Düzeltme.** `generate_retention_inventory()`'de temel JOIN VE per-satır
`check_disposal()` döngüsünün TAMAMI `db.conn.execute("BEGIN")` ...
`db.conn.execute("COMMIT")` (try/finally ile) içine alındı — B-072'deki
AYNI düzeltme. Fonksiyonun docstring'i bu değişikliği ve gerekçesini
belgeliyor.

**Bugün istismar edilebilir değil.** `generate_retention_inventory()`
hiçbir UI'dan çağrılmıyor — `UI/AdminPanel.py`'de yalnızca yorum
satırına alınmış bir kullanım örneği var. Ama `BACKLOG.md`'nin
PyInstaller maddesi (yukarıda, "Bulgu 2") onu gerçek, paketlenmiş
(`reportlab` gömülü), test edilmiş bir özellik olarak zaten takip
ediyor — bağlanmamış olması hatanın gerçekliğini değiştirmiyor, yalnızca
aciliyetini düşürüyor. Şimdi düzeltmek, özellik bir UI düğmesine
bağlandıktan SONRA yeniden keşfetmekten ucuz.

### İlişkili ama düzeltilmeyen bulgu — `AuditLogDialog._export_txt()`

Dışa aktarılan satır listesi `self._table`'dan (önceki bir `_load()`
sorgusundan) geliyor; başlık satırının kayıt sayısı ve zincir durumu ise
dışa aktarım ANINDA çağrılan TAZE bir `zincir_raporu()`'dan. Diyalog
açık kaldığı sürece (denetim kaydı sürekli yazıldığından) ikisi
ayrışabilir. Bu bir transaction sorunu DEĞİL — bayat taraf bir Qt
widget'ı, ikinci bir DB sorgusu değil — bu yüzden `BEGIN`...`COMMIT`
düzeltmesi burada UYGULANMADI; farklı bir düzeltme gerektiriyor (dışa
aktarım anında TEK sorgudan türetme). `txt_basligi()` zaten dışa
aktarımın imzalı OLMADIĞINI söylüyor, bu da riski sınırlıyor. Takip
maddesi olarak burada belgelendi, sessizce bırakılmadı.

### Hata dayanıklılığı — `create_backup()` VE `generate_retention_inventory()`

`_dump_tables()`'ın (backup) ve `_row_status_and_date()`'in (envanter)
KENDİLERİ zaten belirli hataları İÇERİDE yutuyor (`_dump_tables()`
tablo başına `except Exception`, `_row_status_and_date()` yalnızca
`RetentionError`) — yani dış `try/finally`'yi GERÇEKTEN sınamak için
hata, bu iç yakalamaların KAPSAMADIĞI bir noktadan enjekte edildi
(`_dump_tables`'ın kendisini ya da `db.fetchone`'ı KAPSAMLI olmayan bir
noktada patlatarak).

Her iki fonksiyon için doğrudan doğrulandı: yapay bir exception `BEGIN`
edilmiş transaction ORTASINDA fırlatıldı, exception çağırana YANSIDI
(yutulmadı), VE hemen ardından `sqlite3.Connection.in_transaction`
`False` bulundu — transaction asılı kalmadı. Bağlantının hâlâ
kullanılabilir olduğu da (basit bir `SELECT` ile) doğrulandı. Açık kalan
bir transaction'ın önemi tek bir rapor/yedekle sınırlı değil: sonraki bir
`PRAGMA wal_checkpoint`'i bloklayabilir.

### Testler

`tests/test_inventory.py`'e yeni sınıf `TestEszamanliYazmaAltindaTutarlilik`,
3 yeni test: `test_building_block_is_torn_by_a_concurrent_profile_reassignment`
(kalıcı regresyon kilidi — sarmalanmamış ham çağrı yırtığı üretiyor),
`test_generate_retention_inventory_is_a_single_consistent_snapshot` (ANA
TEST — gerçek fonksiyon tutarlı kalıyor), `test_transaction_closes_even_
if_a_row_check_raises` (hata dayanıklılığı).

`tests/test_backup.py`'a yeni bölüm "8. Hata dayanıklılığı", 2 yeni test:
`test_create_backup_transaction_closes_even_if_the_dump_raises`,
`test_create_backup_transaction_closes_normally_when_nothing_raises`
(karşılaştırma kaydı — `finally` HER İKİ yolda da çalışıyor).

SECURITY.md'ye yeni bölüm **§4.16** (EN+TR) eklendi: tarama sonucu tablo,
`generate_retention_inventory()` bulgusu ve gerekçesi, `AuditLogDialog`
bulgusu (düzeltilmedi, takip maddesi), hata-yolu doğrulaması.
`test_belge_dil_paritesi.py` (27/27) ile doğrulandı.

Tam test suite: 2763 passed, 4 skipped (bir önceki turdan +5 — bu dosyaya
eklenen 5 yeni test: 3 envanter + 2 backup hata dayanıklılığı).

### 2026-08-29 (devam) — AuditLogDialog takip maddesi sorgulandı, gerçek çıktı, kapatıldı

Bir sonraki turda yukarıdaki "İlişkili ama düzeltilmeyen bulgu" madde
sorgulandı — kod okunarak DEĞİL, canlı bir senaryoyla: gerçek bir
`AuditLogDialog` örneği kuruldu, üç önceki denetim kaydı yüklendi, sonra
`audit_log`'a DOĞRUDAN (diyaloğu YENİLEMEDEN) dördüncü bir kayıt eklendi
— çalışan uygulamanın başka bir yerinin, diyalog açıkken arka planda bir
işlem kaydettiği taklit edildi — ve dışa aktarım tetiklendi.

**Sonuç, ölçüldü:** dönen dosyanın başlığı `Doğrulanan : 5 kayıt` ve
`Son kayıt : id=5` diyordu (dışa aktarım anında TAZE çalışan
`zincir_raporu()`'dan), hemen ardından yalnızca 4 satırlık bir tablo ve
`Bu dışa aktarımdaki kayıt sayısı: 4` yazan bir altyazı geliyordu (BAYAT
`self._table`'dan) — beşinci kayıt listeden TAMAMEN eksikti. Tutarsızlık
gerçekti, teorik değil.

**Düzeltme.** `UI/AuditLogDialog.py::_export_txt()`'e, dosya yolu
seçildikten hemen sonra bir `self._load()` çağrısı eklendi. Böylece satır
listesi VE başlığı üreten `zincir_raporu()` çağrısı ARKA ARKAYA, aralarına
hiçbir kullanıcı kodu (diyaloğun açık kalması, dosya seçici penceresinin
beklenmesi) girmeden çalışıyor — iki ayrı kaynağı senkron TUTMAYA
çalışmak yerine ikisini TEK bir andan üretmek. Aynı canlı senaryo
düzeltmeyle tekrar çalıştırıldı: başlık ve altyazı ikisi de `5` okudu,
beşinci satır ("arka_planda_olusan_islem") listede göründü, ekrandaki
tablo da (yan etki olarak, bilerek kabul edildi) yenilendi.

**Testler (3 yeni, `tests/test_audit_log_dialog_export.py` — yeni
dosya):**

- `test_export_dosyasi_arkaplanda_eklenen_kaydi_HEM_baslikta_HEM_
  satirlarda_gosterir` — ANA TEST: başlıktaki "Doğrulanan" sayısı,
  altyazıdaki kayıt sayısı ve fiilen listelenen satır sayısı ÜÇÜNÜN de
  gerçek DB durumuyla eşleştiğini doğruluyor. Düzeltmeden ÖNCEki kod
  üzerinde ÇALIŞTIRILDI (`git stash` ile geçici olarak geri alınıp):
  test tam olarak `{'dogrulanan': 5, 'altyazi': 4}` ile BAŞARISIZ oldu —
  elle yapılan canlı tekrarla TAM eşleşen bir sonuç — düzeltme geri
  konunca yeşile döndü.
- `test_export_tabloyu_da_yeniliyor` — yan etkiyi (ekran tablosunun da
  güncellenmesi) doğruluyor.
- `test_export_iptal_edilirse_tablo_yenilenmiyor` — kullanıcı dosya
  seçimini iptal ederse `_load()`'ın HİÇ çağrılmadığını doğruluyor
  (sessiz bir yan etki olmamalı).

Testler, bu depoda `UI/*.py` için daha önce kurulmuş Qt test desenini
(`os.environ["QT_QPA_PLATFORM"]="offscreen"`, module-scope `qapp`
fixture'ı, `QFileDialog`/`QMessageBox` monkeypatch'i — bkz.
`tests/test_backup_verify_ui.py`) izliyor.

SECURITY.md §4.16 (EN+TR) güncellendi: `AuditLogDialog` maddesi
"düzeltilmedi, takip maddesi" yerine canlı doğrulanmış bulgu +
düzeltme + test anlatımıyla değiştirildi. `test_belge_dil_paritesi.py`
(27/27) ile doğrulandı.

Tam test suite: 2768 passed, 4 skipped (bu dosyaya eklenen 3 yeni test
dahil).

---

## B-074 — RBAC yalnızca UI'da uygulanıyordu: db_manager.py yazma fonksiyonları hiçbir rol kontrolü yapmıyordu, düzeltildi

**Durum:** Kapalı
**Öncelik:** Yüksek (listenin en önemli maddesi olarak talep edildi — DB
katmanı, UI'ı atlayan hiçbir yoldan geçilemeyen SON çare)
**Bulundu ve kapatıldı:** 2026-08-29 — aynı turda

### İstek

RBAC kontrolünün yalnızca UI seviyesinde (buton gizleme) değil,
`db_manager.py` seviyesinde de uygulandığından emin ol. Salt-okunur rollü
bir kullanıcının yazma girişimi, UI'ı atlayan hiçbir yoldan (CLI,
doğrudan fonksiyon çağrısı, olası bir bug) geçmemeli —
`db_manager.py`'deki her yazma fonksiyonu, çağıran kullanıcının rolünü
kontrol etmeli ve yetkisizse reddetmeli. Test: UI'ı tamamen atlayıp
doğrudan `db_manager` fonksiyonlarını salt-okunur bir kullanıcı
context'iyle çağır, reddedildiğini doğrula.

### Sorgu — gerçekliği ölçmek

`CORE/roles.py::can_write()` kod tabanının rol karşılaştırmasına tek
karar noktası (B-028/B-030), ama çağıranları taranınca hepsinin
`UI/main_window*.py` içinde olduğu görüldü — düğme gizleme/pasifleştirme,
sürükle-bırak kabulü, sekme görünürlüğü. `DB/db_manager.py::execute()`
çağıranın rolünden HİÇ haberdar değildi; kendisine verilen SQL'i
sorgusuz sualsiz çalıştırıyordu.

Boşluğun teorik olmadığı bu kod tabanında somut olarak kanıtlandı:
`UI/TagDialog.py` taranınca içinde `is_readonly_role`/`can_write`'a
HİÇBİR çağrı olmadığı görüldü (`tests/test_db_manager_rbac.py::
test_UI_katmaninin_kendisi_boslugu_kanitliyor_TagDialog_rol_kontrolu_yok`
bunu AST taramasıyla sabitliyor) — yalnızca kendisini açan "+ Yeni
Etiket" düğmesinin salt okunur rolde gizlenmesine güveniyor.

Canlı bir script ile doğrulandı — hiç UI kurulmadan, doğrudan
`DBManager().execute()`: Salt Okunur rol aktifken `INSERT INTO files`,
`INSERT INTO folders`, `INSERT INTO tags` üçü de dokunulmadan geçti.

### Tasarım kararı — neden ambient rol + tablo bazlı gate

`DBManager` zaten bir tekil örnek (singleton) ve `_hwid`/`_key` gibi
bağlantı-ömürlü durumu üzerinde tutuyor; aynı desen `_role` için de
uygulandı. Ama iki gerçek karşı-örnek bu tasarımı BASİT bir "her
non-SELECT'i rolle kontrol et" kuralından uzaklaştırdı:

1. **Aynı tabloya hem kullanıcı hem sistem yazıyor.**
   `CORE/disposal.py::purge_expired_file()` (süresi dolmuş sayaç) ve
   `sweep_retention_expired()` (saklama süpürmesi) `files`'a yazıyor —
   ama giriş yapmış kullanıcı ADINA değil, "kimseye sormadan" davranan
   otomatik temizleyiciler olarak (kendi docstring'leri). İkisinin de
   çağıranlarından biri `CORE/scheduler.py`'nin APScheduler arka plan
   iş parçacığı; bir "ana iş parçacığı DEĞİLSE atla" kısayolu
   denenebilirdi ama `UI/main_window_table.py::_FileRunnable` — dosya
   EKLEMEYİ fiilen yapan, korunması GEREKEN yazının ta kendisi — bir
   `QThreadPool` işçi iş parçacığında çalışıyor; yani "ana iş parçacığı
   değil" kuralı tam olarak korunması gereken yazıyı da muaf tutardı.
   Çözüm: iş parçacığı kimliğine değil, AÇIK bir işaretlemeye dayanan
   `DBManager.system_write()` — thread-local bir sayaç (paylaşılan
   olsaydı bir iş parçacığının bypass'ı diğerine sızardı).
2. **Bazı tablolar rolden bağımsız yazılabilir olmak ZORUNDA.** `users`
   (`CORE/session_user.py::sync_session_user()` — giriş VE reauth'ta,
   rol henüz oturuma tam bağlanmadan önce, reauth'ta ise hâlâ ÖNCEKİ
   oturumun rolünü taşıyorken), `login_attempts`
   (`CORE/rate_limit.py` — hız sınırlama her rolde çalışmalı) ve
   `settings` (karışık: `imha_ttl_hours` gibi anahtarlar zaten
   `is_admin_role` ile ayrı korunuyor, ama
   `CORE/backup_reminder.py::ertele()` "Yedek Al…" menüsünden HER rol
   tarafından tetiklenebiliyor — `UI/main_window.py`'nin Görünüm menüsü
   okunarak doğrulandı, orada `can_write` kontrolü YOK). Bu üçü
   `_RBAC_KORUMALI_TABLOLAR` kümesinin DIŞINDA bırakıldı — boşluk değil,
   ölçülüp belgelenen bir sınır.

Gate'lenen küme: `files`, `folders`, `tags`, `file_tags`, `quarantine`,
`retention_profiles` — UI'ın bugün zaten düğme gizleyerek kısıtladığı
YÜZEYLERİN DB karşılığı.

### Düzeltme

`DB/db_manager.py`:

- `DBManager.set_active_role(role)` — etkileşimli oturumun rolünü
  tekil örnek üzerinde saklıyor (`None` varsayılan = kısıtlama YOK —
  açılış, göç, testler etkilenmiyor).
- `DBManager.system_write()` — thread-local bypass context manager
  (yalnızca yukarıdaki 2 otomatik temizleyici kullanıyor).
- `execute()` artık her çağrıda `_yazma_yetkisini_dogrula(sql)`
  çağırıyor: SQL'in hedef tablosunu regex ile ayrıştırıp
  (`_YAZMA_HEDEFI_DESENI`), tablo korunanlar kümesindeyse
  `can_write(self._role)`'u kontrol ediyor, değilse yeni
  `YazmaYetkisiYokError` (PermissionError alt sınıfı) fırlatıyor.

`UI/main_window.py::_apply_role_restrictions()` — kod tabanının rol her
değiştiğinde (girişte, reauth'ta, `reload_app_mode()`'da) zaten tek
yerden geçirdiği fonksiyon — artık `DBManager().set_active_role(role)`'ü
de çağırıyor. İkinci bir "rolü DB'ye bildir" yolu İCAT EDİLMEDİ.

`CORE/disposal.py::purge_expired_file()` / `sweep_retention_expired()`
— `db.execute()` çağrıları `with db.system_write():` içine alındı.

### Testler

`tests/test_db_manager_rbac.py` (yeni dosya, 16 test):

- 6 gate'lenmiş tablonun (`files`, `folders`, `tags`, `file_tags`,
  `quarantine`, `retention_profiles`) HER biri için: Salt Okunur rolde
  ham `db.execute()` reddediliyor mu (parametrize).
- Standart/Yönetici rollerinde aynı yazılar geçiyor mu (mutasyon
  kontrastı — kısıtlama role özgü, tabloya değil).
- Rol hiç ayarlanmamışsa (`None`) kısıtlama yok mu.
- Bilinmeyen rol de reddediliyor mu.
- SELECT sorguları rolden bağımsız her zaman çalışıyor mu.
- `CORE.folders.create_folder()` — GERÇEK bir üretim fonksiyonu, ham SQL
  değil — engelleniyor mu (yalnızca regex'in yakaladığı izlenimini
  gidermek için).
- `users`/`login_attempts`/`settings` Salt Okunur rolde de YAZILABİLİYOR
  mu (bilinçli sınırın kanıtı).
- `purge_expired_file()`/`sweep_retention_expired()` Salt Okunur bir
  oturum ORTASINDA da tamamlanıyor mu (`system_write()`'ın gerçekten
  çalıştığının kanıtı).
- Mutasyon kontrastı: `_yazma_yetkisini_dogrula()` monkeypatch'le devre
  dışı bırakılırsa aynı yazı GERÇEKTEN geçiyor mu.
- AST taraması: `UI/TagDialog.py`'de hâlâ rol kontrolü YOK mu (bu
  düzeltmenin gerekçesinin hâlâ geçerli olduğunun kanıtı).

**Doğrulama — `git stash` ile.** `DB/db_manager.py`, `CORE/disposal.py`
ve `UI/main_window.py` düzeltmeden ÖNCEki hâllerine geçici olarak geri
alındı; test modülü çalışmadı bile — `YazmaYetkisiYokError` import
edilemedi (`ImportError`). Bu, "bu paket kazayla geçemez"in mümkün olan
EN GÜÇLÜ biçimi: bir assertion başarısızlığı değil, modülün hiç
toplanamaması. Sonra `git stash pop` ile düzeltme geri getirildi.

SECURITY.md'ye yeni bölüm **§4.17** (EN+TR) eklendi: bulgu, tasarım
kararının gerekçesi (hangi tablolar neden dışarıda bırakıldı, iki
otomatik temizleyicinin neden thread-local bypass gerektirdiği),
kapsam dışı bırakılan Yönetici-vs-Standart ekseni notu.
`test_belge_dil_paritesi.py` (27/27) ile doğrulandı.

Tam test suite: 2785 passed, 4 skipped (bu dosyaya eklenen 16 yeni test
dahil), `ruff check .` temiz.

### 2026-08-29 (devam) — K1-14: system_write() bypass'ı incelendi (sızıntı yok), ama audit boşluğu bulundu ve kapatıldı

Ayrı bir turda, `system_write()`'ın kendisi CANLI incelendi — düzeltme
yapılmadan önce yalnızca kanıt toplandı. Üç soru sorgulandı:

1. **Implementasyon:** `system_write()` bir `@contextmanager`,
   `try`/`finally` ile thread-local bir sayaç (`derinlik`) artırıp
   azaltıyor. Bayrak `role`'ü geçici olarak "yazabilir" yapmıyor —
   `can_write()` kontrolüne hiç ULAŞMADAN erken `return` ediyor (önemli
   ek gözlem: bu erken dönüş tabloya özgü değil, `derinlik > 0`
   olduğunda o thread'deki HERHANGİ bir tabloya yazı kontrolsüz geçer —
   bugün pratikte dar çünkü yalnızca iki tek-satırlık `execute()`
   çağrısını sarmalıyor). Kapsam fonksiyonun tamamı değil, yalnızca
   `with` bloğu. İç içe çağrı bir boole değil SAYAÇ ile doğru
   çözülüyor.
2. **Exception ile yarıda kesme:** Canlı test edildi — `system_write()`
   içinde yapay bir `RuntimeError` fırlatıldı, `finally` çalıştı, sayaç
   `0`'a döndü, hemen ardından aynı thread'de yapılan normal bir yazı
   yine doğru reddedildi. **Sızıntı YOK.**
3. **Thread yeniden kullanımı:** `ThreadPoolExecutor(max_workers=1)` ile
   `QThreadPool`'un aynı OS thread'ini ardışık görevler için yeniden
   kullanması simüle edildi — Görev A `system_write()` ortasında yarıda
   kesildi, Görev B AYNI OS thread'inde hemen ardından normal bir yazı
   denedi. **Sızıntı YOK** — Görev B doğru şekilde reddedildi.
4. **Audit kontrolü:** Reddedilen bir yazının `audit_log`'a düşüp
   düşmediği kontrol edildi. **Gerçek bir boşluk bulundu**:
   `_yazma_yetkisini_dogrula()` `raise` etmeden önce hiçbir `db.log(...)`
   çağırmıyordu — `weak_hwid_binding_rejected`/`usb_auth_rejected`'in
   izlediği "reddet ve kaydet" deseninin dışında kalıyordu.

**Düzeltme (istek üzerine, aynı turda).** `_yazma_yetkisini_dogrula()`
artık `raise YazmaYetkisiYokError(...)`'dan HEMEN önce
`self.log("rbac_write_rejected", detail=...)` çağırıyor. `detail`:
`role=<rol> table=<tablo> op=<INSERT/UPDATE/DELETE/REPLACE>
caller=<modül>.<fonksiyon>:<satır>` — çağıran bağlamı `sys._getframe(2)`
ile `execute()`'u ÇAĞIRAN çerçeveden okunuyor.

**Rekürsiyon riski — kontrol edildi, varsayılmadı.** İki BAĞIMSIZ
garanti: (1) `self.log()` `CORE.audit_chain.append_entry()`'ye
yönleniyor, o da `self.conn` (ham `sqlite3.Connection`) üzerinden
yazıyor — `self.execute()`'u hiç GÖRMÜYOR; (2) `audit_log` zaten
`_RBAC_KORUMALI_TABLOLAR`'ın dışında. Canlı doğrulandı: reddedilen bir
yazı tam olarak 1 `audit_log` satırı ekliyor, sonsuz döngü/rekürsif red
YOK.

**Testler (`tests/test_db_manager_rbac.py`'e 5 yeni test, 21 toplam):**

- `test_reddedilen_yazi_audit_loga_tam_bir_rbac_write_rejected_satiri_dusuyor`
  — ANA TEST: tam 1 satır ekleniyor, `role`/`table`/`op`/`caller`
  alanları doğru.
- `test_reddedilen_yazi_kaydi_yeniden_uretilebilir_tum_gatelenmis_tablolarda`
  — birden fazla tablo/fiil kombinasyonunda tekrarlanabilirlik.
- `test_yazma_denemesi_reddedilmeden_once_kayit_dusuyor_yarim_kalmiyor` —
  reddedilen yazının kendisi kalıcı olmuyor, `detail` satır DEĞERLERİNİ
  (ör. denenen etiket adı) SIZDIRMIYOR, yalnızca yapısal bilgi taşıyor.
- `test_system_write_icindeki_mesru_yazi_rbac_write_rejected_uretmiyor` —
  NEGATİF test: `system_write()` içindeki meşru bir yazı yanlışlıkla
  "reddedildi" diye loglanmıyor.
- `test_otomatik_temizleyiciler_calisirken_de_yanlis_red_kaydi_uretmiyor`
  — aynı negatif kontrolün gerçek üretim koduyla (`purge_expired_file()`)
  tekrarı.

**Mutasyon kontrastı — `git stash` ile, İKİNCİ kez.** Yalnızca
`DB/db_manager.py`'deki audit-loglama eklentisi geri alındı (önceki
turun `git stash` testi zaten TÜM düzeltmeyi kapsıyordu — bu kez amaç
SPESİFİK olarak yeni loglama davranışını izole etmekti): audit'e özgü
iki test TEK BAŞINA başarısız oldu (`AssertionError: tam olarak 1 audit
satırı beklenir, 0 eklendi`), paketin geri kalanı (reddin kendisini
ölçen testler dahil) geçmeye devam etti — bu, testlerin GERÇEKTEN
loglama davranışını ölçtüğünü, yalnızca reddi değil, kanıtlıyor. Sonra
`git stash pop` ile düzeltme geri getirildi.

SECURITY.md §4.17 (EN+TR) güncellendi: bypass incelemesinin sonucu
(sızıntı yok), audit boşluğunun bulunuşu ve düzeltmesi, testlerin
mutasyon kontrastı. `test_belge_dil_paritesi.py` (27/27) ile doğrulandı.

Tam test suite: 2790 passed, 4 skipped (bu bölümde eklenen 5 yeni test
dahil), `ruff check .` temiz.

---

## B-075 — Kilit ekranı checkout'u durduruyordu, toplu indirmeyi değil: USB çekilince arka planda düz metin yazılmaya devam edebiliyordu, düzeltildi

**Durum:** Kapalı
**Öncelik:** Yüksek (düz metnin diske yazılmaya devam ettiği ölçülen, canlı
kanıtlanmış bir pencere)
**Bulundu ve kapatıldı:** 2026-08-29 — aynı turda

### İstek

"USB çekilince kilitlenir" iddiası kısmen yanlış: kilit ekranı görünse
bile arka planda süren bir işlem (şifre çözme/yazma) devam edip düz
metni diske yazmaya devam edebilir. USB çıkarma event'inde tüm aktif
worker'lara abort sinyali gönder, bellekteki hassas tamponları sıfırla
(zeroize). Test: dosya işlenirken USB'yi çek, worker'ın hemen durduğunu
ve yarım kalan düz metnin yazılmadığını doğrula.

### Sorgu — haritalama

`UI/main_window_lock.py::_lock()` (`_poll_usb()`'un çağırdığı) yalnızca
İKİ şey yapıyor: açık checkout'ları senkron kapatmak
(`_close_all_checkouts()`) ve UI durumunu değiştirmek (overlay,
bulanıklaştırma). `QThreadPool`'a, herhangi bir worker'a ya da
`should_continue`/durdurma-olayı mekanizmasına HİÇ dokunmuyor.

Düz metnin diske yazıldığı yerler tarandı: checkout açma
(`CORE/checkout.py::check_out()`), tekli indirme
(`UI/main_window_files.py`), toplu indirme
(`CORE/export.py::export_to_directory()`, `UI/main_window_bulk.py`
üzerinden). İlk ikisi SENKRON, ana iş parçacığında, aralarında
`QApplication.processEvents()` OLMADAN çalışıyor — Qt olay döngüsü
bunlarla iç içe geçemez, `_poll_usb()`'un zamanlayıcısı çağrı bitene
kadar hiç çalışamaz. **Toplu indirme farklı**: `UI/main_window_bulk.py`
ilerleme geri çağrımı her dosyada `QApplication.processEvents()`
çağırıyor — gerçek bir yeniden giriş noktası. `should_continue`
yalnızca ilerleme penceresinin İptal düğmesini dinliyordu, kilit
durumunu HİÇ görmüyordu.

`_FileRunnable` (dosya EKLEME, `QThreadPool` işçisi) yalnızca
`encrypt_file()` çağırıyor, hiç `decrypt_file` çağırmıyor — düz metin
YAZMIYOR, risk yüzeyi değil.

### Canlı doğrulama

Sekiz dosyalık bir toplu indirme kuyruğa alındı; `on_progress` geri
çağrımının kendisi, dosya index=3'ü işlerken bir `locked` bayrağını
`True` yaptı (`_poll_usb`'un etkisi, gerçek USB donanımı olmadan taklit
edildi). Düzeltmeden ÖNCEki kod, `should_continue` yalnızca döngü
BAŞINDA kontrol edildiği için, index=3'ü de çözüp yazdı: `saved=4`,
kilit noktasının bir dosya ötesi.

### Düzeltme

**Abort sinyali.** `CORE/export.py::export_to_directory()` artık
`should_continue`'u İKİNCİ KEZ kontrol ediyor — `on_progress` döndükten
hemen sonra, bir sonraki dosya çözülmeden ÖNCE (yalnızca `on_progress`
GERÇEKTEN verildiyse; yoksa yeniden giriş fırsatı da yok, ikinci kontrol
`should_continue`'un çağrı SAYISINI gereksiz yere değiştirirdi — bkz.
`test_directory_export_can_be_cancelled`). İki kontrol arasında olay
döngüsü hiç dönmediği için bir dosya her zaman ya TAMAMEN yazılıyor ya
HİÇ başlamıyor. `UI/main_window_bulk.py`'nin `should_continue`
lambda'sı artık `self._locked`'ı da okuyor — CORE düzeltmesini gerçek
kilit sinyaline bağlayan tek satır.

**Zeroize.** `decrypt_file()`'a isteğe bağlı `zeroizable=True` parametresi
eklendi: varsayılan `bytes(buf)` (değiştirilemez, asla sıfırlanamaz —
SECURITY.md §3'teki bilinen sınır) yerine, çözümlemenin YAZDIĞI aynı
`bytearray`'i döndürüyor; çağıran işini bitirince (artık genel)
`zero_bytearray()` (eski `_zero`, yeniden adlandırıldı) ile GERÇEKTEN
sıfırlayabiliyor. Hata yolunda `finally` hâlâ tamponu sıfırlıyor;
yalnızca `zeroizable=True` BAŞARI yolu bunu atlıyor (döndürülen değer
TAM O tamponun kendisi, `finally` çağırana ulaşmadan önce çalışıyor —
sıfırlarsa boş bir tampon dönerdi, canlı doğrulanıp bir bayrakla
(`buf_cagirana_devrediliyor`) korumaya alındı). `export_to_directory()`
artık `zeroizable=True` kullanıyor ve `write_bytes()`'ten hemen sonra
`zero_bytearray()` çağırıyor. Diğer tüm çağıranlar (`CORE/checkout.py`,
`CORE/backup.py`, `CORE/hclx.py`, `UI/main_window_files.py`,
`export_to_zip()`) ETKİLENMEDİ — varsayılan davranış aynı kaldı.
`export_to_zip()` bilerek eski yolda bırakıldı: `processEvents()` hiç
çağırmıyor, yeniden giriş yapılamıyor, ölçülen boşluğun parçası değildi.

### Testler

**`tests/test_export.py`** (3 yeni test): `test_lock_ortasinda_daha_
fazla_dosya_yazilmiyor` — ANA TEST, yukarıdaki canlı senaryonun kalıcı
hâli; `test_lock_on_progress_YOKSA_ikinci_kontrol_devreye_girmiyor` —
mutasyon kontrastı, ikinci kontrolün `on_progress` yokken devreye
girmediğini (eski çağrı-sayısı varsayımının bozulmadığını) doğruluyor;
`test_lock_sirasinda_zeroizable_tampon_gercekten_sifirlaniyor` —
`zero_bytearray()`'in her dosya için tam bir kez, doğru içerikle
çağrıldığını casus bir sarmalayıcıyla ölçüyor.

**`tests/test_crypto.py`** (4 yeni test, yeni bölüm "1b. Bellek
güvenliği — zeroizable"): varsayılanın hâlâ `bytes` döndürdüğü,
`zeroizable=True`'nun doğru içerikli bir `bytearray` döndürdüğü,
`zero_bytearray()` sonrası içeriğin GERÇEKTEN sıfır olduğu, hata
yolunda da (`AuthenticationError`) tamponun sıfırlandığı (finally'nin
istisnasız çalıştığı, ikinci bir çağrının çökmediği ile dolaylı kanıt).

**`tests/test_bulk_download_lock.py`** (yeni dosya, 2 test) — gerçek
`_on_ctx_bulk_download()` üzerinden UÇTAN UCA: gerçek `HycleusWindow`,
gerçek şifreleme, TOTP korumalı. `self._locked`,
`QProgressDialog.setValue()`'nun İÇİNDEN (gerçek `_ilerleme()`'nin her
dosyada yaptığı TAM çağrı) çevriliyor — yalnızca CORE mekanizmasını
değil, gerçek UI bağlamasını doğruluyor. İkinci test (mutasyon
kontrastı) kilitlenmeden tüm dosyaların normal indiğini doğruluyor.

**Mutasyon kontrastı — `git stash` ile, üç ayrı düzeyde:**
- `CORE/export.py` (+ `CORE/crypto.py`) geri alındığında
  `test_lock_ortasinda_daha_fazla_dosya_yazilmiyor` `saved=4` ile
  BAŞARISIZ oldu (manuel canlı tekrarla TAM eşleşen sonuç);
  `test_lock_sirasinda_zeroizable_tampon...` `AttributeError` ile
  (henüz `zero_bytearray` yok).
- `CORE/crypto.py` tek başına geri alındığında `tests/test_crypto.py`
  toplanamadı bile (`ImportError: cannot import name 'zero_bytearray'`)
  — "bu paket kazayla geçemez"in en güçlü biçimi.
- `UI/main_window_bulk.py` tek başına geri alındığında (CORE düzeltmesi
  YERİNDEYKEN) `test_kilit_ortasinda_bulk_indirme_gercekten_duruyor`
  BAŞARISIZ oldu — CORE mekanizması var olsa bile UI bağlaması eksikse
  test bunu YAKALIYOR, yalnızca alttaki mekanizmayı değil.

Üçünde de sonra `git stash pop` ile düzeltme geri getirildi.

SECURITY.md'ye yeni bölüm **§4.18** (EN+TR) eklendi: §4.10'un checkout
için doğru olan iddiasının toplu indirme için neden doğru OLMADIĞI,
canlı ölçüm, düzeltme, zeroize'ın dürüst kapsamı (`export_to_zip()`'in
neden dışarıda bırakıldığı dahil). `test_belge_dil_paritesi.py` (27/27)
ile doğrulandı.

Tam test suite: 2801 passed, 4 skipped (bu turda eklenen 9 yeni test
dahil), `ruff check .` ve `mypy` temiz.

---

## B-076 — Kayıt Ol ekranındaki üç mockup alanı ("Kurum Planı", "Referans Kodu", "Talep Edilen Rol") tek tek karara bağlandı

**Durum:** Kapalı
**Öncelik:** Orta (kod-mockup ayrışması; kırılan bir şey değil ama üç
alan aynı soruyu soruyor gibi görünüp aslında üç FARKLI durumda)
**Bulundu ve kapatıldı:** 2026-08-29 — aynı turda

### Görev

Kayıt Ol ekranı mockup'ının üç alanı için net bir karar istendi: (a)
gerçek backend kur, ya da (b) mockup'tan çıkar. Üçü TEK bir soru gibi
sorulsa da inceleme üçünün üç FARKLI durumda olduğunu gösterdi — tek bir
blok karar (hepsi (a) ya da hepsi (b)) en az birini yanlış temsil
ederdi.

### 1. "Kurum Planı" kutusu (plan/tier) — **(b), zaten karar verilmiş, DEĞİŞMEDİ**

`077159e` (2026-08-23) bunu zaten "plan/tier chip" olarak ele almıştı:
backend karşılığı yok (kullanıcı/kurum/tier sütunu yok, çoklu-kiracı ya
da faturalama kavramı hiç yok), hiçbir moda eklenmedi. HYCLEUS
çok-kiracılı, faturalamalı bir SaaS DEĞİL — böyle bir kutu, B-071'in
AIR-GAPPED/ÇEVRİMDIŞI'de öğrettiği AYNI dersin bir varyantı: kullanıcıyı
olmayan bir yeteneğe inandırmak. Karar DEĞİŞMEDİ.

Tek fark: bu turda "Kurum Planı" metninin kendisi `tests/test_kayit_
ekrani.py`'nin `_YASAKLI_METINLER` listesine AYRICA eklendi — önceki
liste yalnızca `plan_chip`/`tier_chip`/`plan_badge`/`tier_badge` gibi
kod-tarzı isimleri kapsıyordu, mockup'ın kullanabileceği Türkçe görünen
metni ("Kurum Planı") değil. Bu, taramanın kendi kapsamındaki bir
boşluktu, koddaki bir boşluk değil — kapatıldı.

**Mockup kaynağı güncellenmedi.** Bu turda ulaşılabilen tek mockup
kaynağı (bkz. K0-6, aynı gün önceki bulgu) `https://claude.ai/code/
artifact/f348a8a1-...` Artifact'ı — o dosyada "Kurum Planı" ya da "Talep
Edilen Rol" metni ARANDI, BULUNAMADI. `DesignSync` (gerçek claude.ai/
design "Design System" projesi erişimi) bu oturumda YETKİLENDİRİLMEMİŞ
(`/design-login` etkileşimli olmayan bir oturumda çalışamıyor) — yani
kullanıcının bahsettiği mockup, erişilen Artifact'tan FARKLI bir kaynak
olabilir. Bu dürüstçe kaydediliyor: kodun kararı yukarıdaki gerekçeyle
sağlam, ama mockup tarafının GÖRSEL olarak teyit edilmesi bu oturumun
kapsamı dışında kaldı.

### 2. "Referans Kodu" — **zaten (a), zaten kurulu, DEĞİŞMEDİ**

2026-08-26'da (arayüz güncellemesi turu) GERÇEK bir backend kuruldu:
`CORE/referans_id.py` (kurulum-geneli tek değer, `settings` tablosunda,
`secrets.choice` ile 32⁸ olasılıklı `KRM-XXXXXXXX` biçiminde), `UI/
login_dialog.py`'de KURUMSAL modda gerçekten karşılaştırılıyor (yanlış/
boş kod → kayıt reddedilir, DB'ye hiçbir satır yazılmaz). Bu turda YENİ
bir karar verilmedi — yalnızca teyit edildi: `tests/test_kayit_
kurumsal_referans.py` (6 test) + `tests/test_referans_id.py` (4 test) +
`tests/test_kayit_ekrani.py`'nin ilgili testleri yeniden koşuldu, hepsi
yeşil (aşağıdaki "Test" bölümü).

### 3. "Talep Edilen Rol" — **özünde zaten (a); yeni sütun EKLENMEDİ, yalnızca etiket hizalandı**

Kayıt formundaki mevcut "Rol" alanı (`self._reg_role`, Standart/Salt
Okunur) zaten TAM olarak bu semantiği taşıyor: seçilen değer `CORE/
registration.py::register_new_user()` ile `status='pending'` bir
`users` satırına yazılıyor, GERÇEK yetkiye (`status='approved'`)
yönetici `AdminPanel`'in "Bekleyen Kayıtlar" sekmesinden `✓ Onayla`
diyene kadar DÖNÜŞMÜYOR — yani kullanıcı bir rol SEÇMİYOR, TALEP ediyor,
tam da mockup'ın etiketinin söylediği gibi.

Buna rağmen ayrı bir `requested_role` sütunu EKLENMEDİ. Gerekçe: `role`
sütunu zaten bu değeri taşıyor; ikinci bir sütun aynı bilgiyi iki kopya
hâlinde tutardı ve "onaydan sonra ikisi ayrışırsa hangisi doğru" gibi bir
kaynak-otorite belirsizliği yaratırdı — çözülen bir sorun için yeni bir
tutarlılık riski açmak olurdu. Uygulanan tek değişiklik: `UI/
login_dialog.py`'deki alan etiketi "Rol"den "Talep Edilen Rol"e
değiştirildi — **yalnızca** self-servis Kayıt Ol ekranında.

`UI/RegisterDialog.py`'nin admin-başlatan akışında ("AdminPanel → Yeni
Kullanıcı Kaydet") etiket KASITLI olarak "Rol" kaldı: orada yönetici
BAŞKASI için değil, doğrudan KENDİ seçtiği bir değeri giriyor — "talep"
kelimesi orada yanlış bir aktör ima ederdi. İki ekranın etiketinin
BİLEREK farklı kalması `tests/test_kayit_ekrani.py::test_register_
dialog_rol_alani_KASITLI_olarak_ROL_kaliyor` ile kalıcı hale getirildi.

### Test

`tests/test_kayit_ekrani.py`'ye 2 yeni test (dosyanın toplamı 11'e
çıktı):

- `test_kayit_ol_rol_alani_TALEP_EDILEN_ROL_diye_etiketleniyor` — ANA
  TEST, `_reg_role`'ün widget ağacındaki kardeş `QLabel`'ini yapısal
  olarak bulup metnini doğruluyor (`_field()` etiketi `self`'e
  saklamıyor, doğrudan bir öznitelik yok).
- `test_register_dialog_rol_alani_KASITLI_olarak_ROL_kaliyor` — negatif/
  kontrast: admin akışının etiketi "Rol" kalıyor, "Talep Edilen Rol"
  oraya SIZMAMIŞ.

Ayrıca `_YASAKLI_METINLER`'e "Kurum Planı"/"kurum_plani"/"corporate_plan"
eklendi (madde 1).

**Mutasyon kanıtı:** `UI/login_dialog.py`'deki etiket geçici olarak
"Rol"e geri alınıp `test_kayit_ol_rol_alani_TALEP_EDILEN_ROL_diye_
etiketleniyor` çalıştırıldı — **BAŞARISIZ oldu** (`AssertionError: 'Rol'
== 'Talep Edilen Rol'`), doğru diff ile. Düzeltme geri konup test tekrar
yeşile döndü.

Referans Kodu'nun mevcut testleri (madde 2) de bu turda yeniden koşuldu:
`tests/test_kayit_kurumsal_referans.py` (6) + `tests/test_referans_id.py`
(4) + `tests/test_kayit_ekrani.py`'nin geri kalanı (9) — hepsi yeşil,
regresyon yok.

Tam test suite: 2803 passed, 4 skipped (bir önceki turdan +2 — bu
dosyaya eklenen 2 yeni test).

---

## B-077 — Tema seçici dropdown'dan görsel kart grid'e çevrildi; mockup'ın 11 teması teyit edildi

**Durum:** Kapalı
**Öncelik:** —
**Bulundu ve kapatıldı:** 2026-08-29 — aynı turda

### Görev

İki parça: (1) tema seçiciyi (`ThemeMixin._on_theme_menu`, düz metin bir
`QMenu`) mockup'taki gibi her kartın kendi renk paletini canlı önizlediği
bir kart grid'e çevir; (2) bu geçiş sırasında `register_theme()` ile koda
hiç geçmemiş kalan mockup temalarını (görev metninde "muhtemelen 6 tane"
deniyordu) gerçek kod tarafında kaydet.

**2. madde zaten kapalıydı — koddan doğrulandı.** `git log -- UI/
main_window_theme.py` incelendi: `4b07486` ("Arayuz guncellemesi BOLUM A:
mockup'in eksik 6 temasi eklendi") bu oturumdan ÖNCE, mockup'ın 11
temasının kalan 6'sını (Cam/Klasik/Akrilik/Aurora (Cam)/Gün Batımı/Grafit
(Cam)) zaten `register_theme()` ile kaydetmişti — `UI/main_window_
palette.py`'de tam token setleriyle (`_CAM`/`_KLASIK`/`_AKRILIK`/
`_AURORA_CAM`/`_GUN_BATIMI`/`_GRAFIT_CAM`, WCAG AA'ya göre ayarlanmış,
bkz. `tests/test_tema_kontrasti.py`). Bu turda yeni bir tema EKLENMEDİ —
`_THEMES`'in gerçekten 11 anahtar taşıdığı (`test_tam_11_tema_kayitli`)
ve her birinin `_DARK` referans şemasıyla AYNI anahtar kümesine sahip
olduğu (`test_her_temanin_dark_varyanti_tam_token_setine_sahip`,
parametrized) testlerle KALICI olarak doğrulandı — biri ileride bir
tema kaydını yanlışlıkla silerse ya da eksik bir token'la eklerse bu
testler kırılır.

### 1. madde — yeni dosya: `UI/ThemePickerDialog.py`

`ThemeMixin._on_theme_menu()`'un gövdesi değişti: artık bir `QMenu`
DEĞİL, `ThemePickerDialog`'u açıyor. Diyalog `available_themes()`'in
döndürdüğü SIRAYLA 11 kart kuruyor (3 sütunlu grid, kaydırma alanında).

**Token kaynağı — hiçbir yeni renk İCAT EDİLMEDİ.** Diyaloğun KENDİ
çerçevesi (başlık, arka plan, "Kapat" düğmesi) çağıranın GÜNCEL
`self._T`'siyle boyanıyor — `ProfileDialog`/`RecoveryShareDialog`'un
aynı `_stil(T)` deseni. Her kartın İÇİNDEKİ önizleme şeridi ise o kartın
TEMSİL ETTİĞİ preset'in KENDİ token'larından geliyor (`_THEMES[key]
["dark"/"light"]`) — kart kendi rengini gösterir, aktif temanın rengini
değil. Koyu-yalnızca preset'ler (`light is None`, ör. `aurora_borealis`)
önizlemede HER ZAMAN kendi koyu paletini gösterir, diyaloğun açık/koyu
modundan bağımsız — `_set_theme()`'in bu preset'i seçince `self._dark`'ı
zorla `True` yapmasıyla TUTARLI.

Kart tıklanabilirliği `UI/main_window_layout.py`'nin avatar/scrim
düğmeleriyle AYNI desen: ayrı bir sınıf açmak yerine `mousePressEvent`
örnek metoduna doğrudan atama (`kart.mousePressEvent = lambda _ev, k=key:
on_click(k)`) — bu depoda zaten kurulu, yeni bir soyutlama gerekmedi.

`_on_theme_menu()` `ThemePickerDialog`'u YEREL içe aktarıyor (`AdminPanel.
py`'nin `RecoveryShareDialog`'u içe aktarma deseniyle AYNI) — hem
`main_window_theme.py` <-> `ThemePickerDialog.py` arasındaki döngüsel
bağımlılığı modül-seviyesinde değil çağrı anında çözüyor, hem de testlerin
`UI.ThemePickerDialog.ThemePickerDialog`'u monkeypatch edip `.exec()`'i
GERÇEKTEN çağırmadan (başsız bir testte sonsuza kadar bloklamadan)
doğrulamasını sağlıyor.

### Test

`tests/test_theme_picker.py` (yeni dosya, 32 test), dört bölüm:

1. **Kayıt** — `_THEMES` gerçekten 11 anahtar taşıyor mu (tam küme,
   `available_themes()` aynı sırayla), her preset'in dark/light
   varyantı referans şemayla (`_DARK`) aynı anahtar kümesine sahip mi
   (parametrized, 11 tema).
2. **Diyalog yapısı** — tam 11 kart kuruluyor mu; iki farklı kartın
   önizlemesi AYNI stylesheet'i üretmiyor mu (mutasyon kanıtı, altta);
   koyu-yalnızca bir preset'in önizlemesi diyaloğun açık/koyu modundan
   bağımsız mı.
3. **Seçim** — şu an seçili tema tek kartta işaretli mi; bir karta
   "tıklamak" (`mousePressEvent(None)` — kodun kendi atadığı işleyiciyle)
   doğru anahtarı bildirip diyaloğu `Accepted` ile kapatıyor mu; "Kapat"
   düğmesi hiçbir şey bildirmeden `Rejected` ile kapatıyor mu.
4. **Uçtan uca** — gerçek `HycleusWindow` üzerinde 11 temanın HEPSİ
   (parametrized) `_set_theme(key)` ile seçilip `self._T`'nin preset'in
   dark/light varyantıyla BİREBİR eşit olduğu doğrulanıyor (görevin asıl
   istediği "her birinin doğru token setini uyguladığını doğrula");
   koyu-yalnızca bir tema seçilince `self._dark`'ın zorla `True` olduğu;
   `_on_theme_menu()`'un `ThemePickerDialog`'u pencerenin GÜNCEL
   `_T`/`_theme_key`/`_dark`'ıyla kurduğu (sahte sınıfla monkeypatch).

**Mutasyon kanıtı (üçü de bu turda, gerçek dosyada, sonra geri alındı):**

- `ThemePickerDialog.py`'de kart oluşturma çağrısı geçici olarak preset'in
  KENDİ rengi (`varyant`) yerine aktif temanın rengini (`T`) kullanacak
  şekilde değiştirildi — `test_farkli_kartlarin_onizlemesi_FARKLI_renkte`
  **BAŞARISIZ** oldu (iki farklı kartın önizlemesi AYNI çıktı).
- `main_window_theme.py`'de `register_theme("cam", ...)` çağrısı geçici
  olarak yorum satırına alındı — 5 test **BAŞARISIZ** oldu (kayıt sayısı,
  anahtar kümesi, kart sayısı, uçtan uca token uygulaması, açılış
  kwargs'ları) — tek bir eksik kaydın kaç farklı katmanda YAKALANDIĞININ
  kanıtı.

İkisi de geri alındıktan sonra `git diff --stat` temiz döndü, tüm paket
tekrar yeşile döndü.

Tam test suite: 2848 passed, 4 skipped (bir önceki turdan +35 — bu
dosyaya eklenen 32 yeni test + `test_layering.py`'nin YENİ dosyaları
otomatik kapsayan parametrizasyonlarından +3).

### 2026-08-29 (devam) — paralel yol / ölü kod / taşma sorgulandı, üçü de kapalı çıktı

Bir önceki turda `_on_theme_menu()`'un gövdesi `QMenu`'den `ThemePickerDialog`'a
değiştirilmişti ama şu üçü DOĞRULANMAMIŞTI: (a) eski `QMenu` yolu gerçekten
kod tabanından tamamen mi kalktı yoksa hâlâ çağrılabilir bir yerde mi duruyor,
(b) `_on_theme_menu()`'ye başka bir giriş noktası (ör. `AdminPanel.py`, bir
klavye kısayolu) var mı, (c) 11 kartlık grid küçük pencerede taşınca hâlâ
erişilebilir mi.

**(a) + (b) — tek giriş noktası, ölü kod yok.** `grep -rn "_on_theme_menu"`
tüm kod tabanında TEK bir çağrı yeri buldu: `UI/main_window_layout.py:204`
— `self._theme_btn.customContextMenuRequested.connect(lambda _pos:
self._on_theme_menu())`, yani tema düğmesine SAĞ TIK (tooltip: "Sol tık:
Gündüz / Gece · Sağ tık: Tema seç"). Sol tık ayrı bir metoda (`_toggle_theme`
— hızlı gündüz/gece geçişi) bağlı; bu KASITLI ayrı bir özellik, paralel bir
tema-seçim yolu DEĞİL. `UI/main_window_theme.py`'de `QMenu`/`QAction`
import'u YOK (bir önceki turda kaldırılmıştı) — dosyadaki tek `QMenu` sözü
docstring'de geçmiş zamanla ("eskiden... açıyordu"). Kod tabanının geri
kalanındaki `QMenu` kullanımları (`main_window.py`, `main_window_files.py`,
`main_window_bulk.py`, `main_window_tree.py`) dosya/ağaç sağ-tık menüleri —
temayla ilgisiz. `AdminPanel.py`'de tema anahtar kelimesi hiç geçmiyor,
klavye kısayolu (`QShortcut`) kod tabanında hiç kullanılmıyor. Sonuç: iki
yol paralel çalışmıyor, dolayısıyla canlı tutarsızlık testine (madde 3'ün
gerektirdiği) gerek kalmadı — test edilecek ikinci bir yol yok.

**(c) — küçük pencerede taşma GERÇEKTEN var, scroll bunu telafi ediyor.**
`tests/test_theme_picker.py`'ye yeni bölüm (5): `test_kucuk_pencerede_
TUM_kartlar_scroll_ile_erisilebilir` — diyaloğu kendi asgari boyutuna
(`560×420`) küçültüp GERÇEK widget geometrisini ölçüyor: içerik
`sizeHint()` yüksekliği (429px) viewport yüksekliğinden (285px) fazla
olduğunu, dikey kaydırma çubuğunun menzilinin sıfırdan büyük (204px)
olduğunu, 11 kartın hepsinin (görünür viewport'tan bağımsız) ağaçta ve
sıfır olmayan geometriye sahip olduğunu doğruluyor. Ölçülen sayılar
gerçek: `_KOLON`'u geçici olarak 3'ten 11'e çıkarıp (tek satır, taşma
YOK) testi çalıştırdım — `sizeHint 126 > viewport 271` iddiası beklenen
şekilde **BAŞARISIZ** oldu, yani test gerçekten taşmayı ölçüyor, sabit
`True` döndürmüyor. `_KOLON` geri alındı, `git diff --stat` temiz döndü.

Tam test suite: 2849 passed, 4 skipped (+1 — bu yeni taşma testi).
Ruff/mypy/bandit temiz.

---

## B-078 — Etiket Ata modalına satır başına görünürlük rozeti eklendi ("Herkes" / "Yalnızca Yönetici")

**Durum:** Kapalı
**Öncelik:** —
**Bulundu ve kapatıldı:** 2026-08-29 — aynı turda

### Görev

`UI/TagDialog.py`'deki mevcut "🔒 Mahrem (gizli)" checkbox mantığına
dokunmadan, mockup'taki gibi her etiket satırına görünürlük durumunu
gösteren bir rozet eklemek — sadece görsel gösterge, yetki mantığı
DEĞİŞMEDİ.

### Değişiklik

`UI/TagDialog.py`'ye yeni bir modül fonksiyonu: `_gorunurluk_rozeti(is_private,
T) -> QLabel` — gizli etiketler için "Yalnızca Yönetici" (kırmızı: `T['red']`/
`T['red_tint']`), normal etiketler için "Herkes" (yeşil: `T['green']`/
`T['green_tint']`) metinli, pilli-stil bir `QLabel`. Renk kaynağı `self._T` —
`main_window_theme.py::_apply_theme`'in `_role_badge` rozetiyle AYNI desen
(rounded pill, `T` token'larından `bg`/`fg`); yeni bir hex değeri hiçbir
yerde elle yazılmadı (B-055 kuralı). `_load_tags()`'teki satır kurulum
döngüsüne (`row_h.addWidget(...)`) tek satır eklendi — satırın kendisini
gizli/görünür yapan filtre (`if tag["is_private"] and not self._is_admin:
continue`) HİÇ değişmedi, rozet sadece o filtrenin ZATEN ürettiği satırlara
ekleniyor.

### Test

`tests/test_tag_dialog_gorunurluk_rozeti.py` (yeni dosya, 8 test):

1. **Saf birim** — `_gorunurluk_rozeti(True, ...)` "Yalnızca Yönetici" mi
   döndürüyor, `_gorunurluk_rozeti(False, ...)` "Herkes" mi; ikisinin
   stylesheet'i FARKLI mı; renk kaynağının gerçekten `T['red']`/
   `T['red_tint']`/`T['green']`/`T['green_tint']` olduğu (hardcode hex
   değil).
2. **Uçtan uca** — gerçek `TagDialog` üzerinde: gizli bir etiket
   "Yalnızca Yönetici" rozetiyle görünüyor mu, normal bir etiket "Herkes"
   rozetiyle görünüyor mu; karışık bir listede (biri gizli, biri normal)
   iki satırın rozeti KARIŞMADAN doğru eşleşiyor mu (indeks kaymasına
   karşı kanıt); normal (Yönetici olmayan) bir rol için gizli etiketin
   satırı — dolayısıyla rozeti — HİÇ görünmüyor mu (mevcut yetki
   mantığının bu turda BOZULMADIĞININ kanıtı).

**Mutasyon kanıtı:** `_gorunurluk_rozeti`'nin gizli dalı geçici olarak da
"Herkes" metnini döndürecek şekilde bozuldu — 3 test **BAŞARISIZ** oldu
(saf birim testi, uçtan uca gizli-etiket testi, karışık-liste testi).
Geri alındı, `git diff --stat` temiz döndü, tüm paket tekrar yeşile döndü.

Tam test suite: 2859 passed, 4 skipped (+10 — bu yeni dosyaya eklenen 8
test + `test_layering.py`'nin YENİ dosyaları otomatik kapsayan
parametrizasyonlarından +2). Ruff/mypy/bandit temiz.

---

## B-079 — Denetim Günlüğü modal'dan tam sayfaya taşındı; satır bazlı HALKA (zincir bütünlüğü) sütunu eklendi

**Durum:** Kapalı
**Öncelik:** —
**Bulundu ve kapatıldı:** 2026-08-29 — aynı turda

### Görev

İki parça: (1) Denetim Günlüğü'nü modal pencereden (`UI/AuditLogDialog.py`)
tam sayfa görünüme taşı, mockup'taki Tümü/Dosya/Kimlik/Yönetim/Uyarı
sekmeleriyle; (2) her satırın zincir bütünlüğü durumunu (sağlam/kopuk)
gösteren yeni bir HALKA sütunu ekle — önce `verify_audit_chain()`'in
mevcut satır bazlı çıktısına mı dayanacağına yoksa yeni bir hesaplama mı
gerektireceğine KARAR VER.

### 1. madde — `UI/AuditLogDialog.py` → `UI/AuditLogView.py`

`UI/GuvenlikView.py`'nin (§4.17/§4.18'in komşusu) AYNI deseni:
`_govde_yigini` (`QStackedWidget`) içinde 3. sayfa, durum (filtreler,
seçili sekme) gezinme boyunca korunuyor, sayfa kendi `setStyleSheet()`'ini
çağırmıyor — stil `UI/main_window_theme.py::_apply_theme()`'in merkezi
QSS'inden `#audit_view` nesne adıyla cascade ediyor. Beş sekme çıplak bir
`QTabBar` ile (`QTabWidget` DEĞİL — beşi de AYNI tabloyu filtreliyor,
beş kopya tablo kurmak gereksiz olurdu; `AdminPanel.py`'nin `QTabWidget`'ı
kendi durumunda — sekme başına GERÇEKTEN farklı içerik — doğru araç).

Kategori süzgeci (`_kategori()`) kod tabanındaki TÜM `.log(...)` çağrıları
taranarak çıkarılan action envanterine dayanıyor; bilinmeyen bir action
YANLIŞ kategoriye düşmüyor, yalnızca Tümü'nde görünüyor. Kendi `EYLEM_*`
sabiti olan action'lar (hclx/pin_rotation/tpm_sealing/trusted_roots/
secret_store/audit_chain) LİTERAL yazılmadı, İTHAL EDİLDİ —
`tests/test_hclx.py::test_denetim_eylemleri_yalnizca_hclx_modulunden`'in
tam olarak bunu aradığı ilk çalıştırmada ortaya çıktı (aynı dizeyi ikinci
bir dosyada literal yazmak o modülün "tek yazan/tanımlayan ben"
garantisini sessizce ikinci bir kopyaya açıyor), düzeltildi.

Sayfa **lazy** — `__init__`'te DB'ye dokunmuyor (`HycleusWindow.
__init__`'te GuvenlikView ile aynı yerde kuruluyor; her açılışta,
sayfa hiç ziyaret edilmese bile tüm zinciri yürütmek gereksiz bir
başlangıç maliyeti olurdu). İlk gerçek yük `yenile()` ile geliyor —
`main_window.py::_on_open_audit_log()` sayfaya HER dönüşte çağırıyor.

**Tesadüfi bulgu — rol kapısı boşluğu.** `_on_open_audit_log()`'un kendi
admin kontrolü YOKTU; erişilebilirlik yalnızca kenar çubuğu düğmesinin
gizlenmesine dayanıyordu. Hamburger menüsü (`_on_hamburger_menu`) AYNI
metodu rol kontrolü olmadan çağırıyordu — admin olmayan bir rol bu
turdan ÖNCE de ikinci yoldan denetim günlüğüne ulaşabiliyordu. Modal bir
diyalog için düşük önemdeydi; KALICI bir sayfaya taşırken aynı boşluğu
miras almamak için `_on_open_admin_panel()` ile AYNI kapı deseni eklendi
(ayrıntı ve gerekçe: SECURITY.md §4.20).

### 2. madde — HALKA sütunu

**Karar: `verify_audit_chain()`'e DAYANIYOR, yeni hesaplama YOK.**
`CORE/audit_chain.py::verify_audit_chain()` zaten zincirli her satırı bir
kez hash'liyor ve yalnızca başarısızlıkları `ChainVerification.breaks`'e
yazıyor. İkinci bir hash yürüyüşü, bu deponun en çok tekrarlanan
kusurunun (B-003/B-004/B-007/B-008/B-010/B-011) altıncı örneği olurdu.
Bunun yerine `CORE/audit_chain.py`'ye `link_status()`/`link_statuses()`
eklendi — mevcut sonucun saf bir OKUNMASI: satır `start_id`'den önceyse
(ya da zincir hiç başlamadıysa) **Kapsam Dışı**; `modified`/`unhashed`
kırılmasının `entry_id`'siyse **Kopuk**; aksi hâlde **Sağlam**. "Hiç
doğrulanmadı" ile "doğrulandı ve sağlam" ayrımı bilinçli — ikisini de
"sağlam" göstermek yanlış güven verirdi (aynı gerekçe `CORE/hwid_probe.py::
compare()`'in "bilinmiyor" sonucunda da var, B-016 turu).

`AuditLogView._load()` `zincir_raporu()`'yu HER yenilemede BİR KEZ
çağırıp aynı sonucu hem HALKA sütununa hem TXT dışa aktarım başlığına
besliyor — B-073'ün dışa aktarım için yaptığı düzeltmeyi sürdürüyor ve
sıkılaştırıyor: `_export_txt()` artık `zincir_raporu()`'yu kendisi ikinci
kez çağırmıyor, `_load()`'un ürettiği `self._son_rapor`'u yeniden
kullanıyor.

### Test

`tests/test_audit_chain.py`'ye 9 yeni test (§9: `link_status`/
`link_statuses`) — sağlam zincirde tüm satırların intact olduğu,
değiştirilen bir kaydın YALNIZCA kendisinin broken, öncekiler VE
sonrakiler intact kaldığı (kırılmadan sonra zincir saklanan hash'ten
devam ediyor), gap'ten sonraki ilk kaydın broken göründüğü, zincir
başlangıcından önceki kayıtların out_of_scope olduğu, zincir hiç
başlamamışsa her şeyin out_of_scope olduğu — ve yapısal bir kanıt:
`link_status()`'un `compute_entry_hash()`'i HİÇ çağırmadığı (casus ile
doğrulandı).

`tests/test_audit_log_view.py` (yeni dosya, 35 test): kategori/sekme
süzgeci (saf fonksiyonlar), sayfa yapısı (5 sütun, 5 sekme, lazy kurulum),
sekme filtresi (gerçek tablo), **HALKA sütunu — görevin ana kanıtı**
(bilerek kırılmış bir kayıt `UPDATE` ile üretilip HALKA hücresinin
"Kopuk" gösterdiği VE bu sonucun doğrudan `verify_audit_chain()`
çağrısıyla TUTARLI olduğu — bozulan kaydın `entry_id`'si hem
`first_broken_id` hem "Kopuk" hücresinin id'si; komşu kayıtlar hâlâ
"Sağlam"), dışa aktarım tutarlılığı (B-073 devamı, eski
`tests/test_audit_log_dialog_export.py`'den taşındı), kablolama (sayfa
geçişi, rol kapısı, tek-kaynak sayfa adı).

**Mutasyon kanıtları:**

- `CORE/audit_chain.py::link_status()` geçici olarak her zaman `LINK_
  INTACT` dönecek şekilde bozuldu — `tests/test_audit_chain.py`'den 2
  test **BAŞARISIZ** oldu (değiştirilen kayıt, gap sonrası kayıt).
- `UI/AuditLogView.py::_HALKA_METNI`'nin Sağlam/Kopuk metinleri geçici
  olarak TERS ÇEVRİLDİ — `tests/test_audit_log_view.py`'den 3 test
  **BAŞARISIZ** oldu (saf birim, uçtan uca kırılma testi, dışa aktarım).
- `UI/main_window_layout.py::_make_govde_yigini()`'ye eklenen 3. sayfa
  için `tests/test_guvenlik_view.py::test_yigin_UC_sayfali` güncellendi
  (2→3 sayfa) ve mutasyonla (sayfa eklenmeden nesne kurulursa) doğrulandı
  — GuvenlikView turundan miras kalan aynı denetim deseni.

İkisi de/hepsi geri alındı, `git diff --stat` temiz döndü.

### Yan bulgu — `test_hclx.py` regresyonu (bulundu ve düzeltildi bu turda)

İlk yazılışta `_KATEGORI_KIMLIK`/`_KATEGORI_YONETIM` frozenset'lerine
`"hclx_created"`/`"hclx_opened"`/`"hclx_rejected"`/`"tsa_root_added"`/…
LİTERAL yazılmıştı. Tam suite çalıştırılınca `tests/test_hclx.py::
test_denetim_eylemleri_yalnizca_hclx_modulunden` bunu yakaladı (CORE/
hclx.py DIŞINDA bu literal'lerin geçmesini yasaklıyor — ikinci bir yerin
`hclx_opened` YAZABİLMESİ, doğrulama yapmadan düşen bir denetim kaydı
riski). Düzeltme: `CORE.hclx`/`CORE.pin_rotation`/`CORE.tpm_sealing`/
`CORE.trusted_roots`/`CORE.secret_store`/`CORE.audit_chain`'in kendi
`EYLEM_*`/`GENESIS_ACTION` sabitleri İTHAL EDİLDİ, literal string'ler
kaldırıldı — okuma amaçlı bir kullanım olsa bile (yazma değil), aynı
dizeyi ikinci kez elle yazmak yanlış pratikti.

Tam test suite: 2910 passed, 4 skipped (bir önceki turdan +51 — bu iki
yeni dosyaya eklenen testler + `test_layering.py`'nin otomatik
kapsamasından gelen ek parametrizasyonlar). Ruff/mypy/bandit temiz.

### 2026-08-29 (devam) — hamburger menüsü de kapılı olmalıydı: USB Yönetimi'nde de AYNI boşluk vardı

Görev: `_on_open_audit_log()`'un rol kontrolünü K1-14 desenindeki gibi
(fonksiyonu UI'ı atlayıp doğrudan çağırarak) kanıtla; hamburger
menüsündeki "Denetim Günlüğü" öğesinin görünürlük durumunu netleştir,
`_on_open_admin_panel()`'in menü öğesiyle GERÇEKTEN aynı deseni takip
edip etmediğini doğrula, gerekirse düzelt.

**1. madde — fonksiyon-içi kontrol zaten test edilmişti, güçlendirildi.**
`tests/test_audit_log_view.py::test_yonetici_OLMAYAN_ENGELLENIYOR`
(önceki turdan) zaten `_on_open_audit_log()`'u gerçek bir `HycleusWindow`
üzerinde DOĞRUDAN çağırıyordu (K1-14'ün "UI'ı atla, fonksiyonu çağır"
deseni). Eklenen: `test_yonetici_OLMAYAN_DOGRUDAN_cagrida_da_
REDDEDILIYOR_ve_UYARI_gosterilir` — sayfanın açılmadığını değil, AYRICA
kullanıcının GERÇEKTEN bir "Erişim Reddedildi" kutusu gördüğünü de
doğruluyor (sessiz bir no-op'un bir önceki testi yanıltıcı biçimde
geçirebileceği ihtimaline karşı).

**2. madde — "aynı desen" varsayımı YANLIŞ çıktı: ikisi de kapısızdı.**
`_on_hamburger_menu()` baştan sona okundu: `act_audit` VE `act_usb`
ikisi de koşulsuz `menu.addAction(...)` ile ekleniyordu, hiçbir role
bağlı `.setVisible()`/`.setEnabled()` çağrısı YOKTU. Yani görevin
varsaydığı "admin_panel'in menü öğesi zaten gizleniyor, audit log'u ona
uydur" öncülü hatalıydı — `_on_open_admin_panel()`'in kendi menü öğesi
de kenar çubuğundaki eşdeğerinden (`_admin_panel_btn`, `_apply_role_
restrictions()`'ta zaten gizli) FARKLI davranıyordu. Hiçbir yorum ya da
BACKLOG maddesi bunu bilinçli bir tercih olarak işaretlemiyor — gözden
kaçmış bir nokta olarak değerlendirildi.

**3. madde — karar: ikisini de kapat, fonksiyon-içi kontrolü KALDIRMA.**
`act_audit` ve `act_usb` artık `is_admin_role(self._role)`'a göre
`.setVisible()`/`.setEnabled()` alıyor — kenar çubuğunun `_apply_role_
restrictions()` deseniyle BİREBİR aynı. "💬 Destek" bilerek DOKUNULMADI:
`ContactDialog`'un hiçbir rol kısıtlaması yok, onu gizlemek tutarlılık
değil YENİ bir kısıtlama olurdu. Fonksiyon-içi kontrol (`is_admin_role`
kontrolü) AYNEN duruyor — ikisi birlikte: görünürlük UX için (reddedilen
bir tıklama yerine seçenek hiç görünmesin), fonksiyon-içi kontrol gerçek
savunma için (menü tamamen atlanıp metot doğrudan çağrılsa bile kapı
kapalı kalır) — K1-14'ün `system_write()` için kurduğu AYNI katmanlı-
savunma şekli (SECURITY.md §4.17).

**4. madde — test.** `test_hamburger_menusunde_YONETICI_OLMAYANA_denetim_
ve_usb_gizli` gerçek menüyü kuruyor (`tests/test_backup_verify_ui.py`'nin
zaten kullandığı `QMenu` alt-sınıflama-ve-kaydetme deseniyle — doğrudan
`QMenu.exec` monkeypatch'i DEĞİL, `tests/test_timestamp_ui.py:549`'un
belgelenmiş gerekçesiyle) ve admin olmayan role hem "Denetim Günlüğü" hem
"USB Yönetimi"nin görünmez VE devre dışı, "Destek"in görünür kaldığını
doğruluyor; eşleştirilmiş bir admin-rolü testi de var.

**Yan etki — mevcut testler güncellendi.** `_on_hamburger_menu()` artık
`self._role`'e bakıyor; `tests/test_backup_verify_ui.py`'nin bu metodu
çıplak bir sahne nesnesiyle (`_Sahne2`/`_Sahne3`, `HycleusWindow._on_
hamburger_menu`'yu ödünç alan) çağıran iki testi `_role` özniteliği
olmadan `AttributeError` ile patlıyordu — ikisine de `self._role =
"Yönetici"` eklendi.

**Mutasyon kanıtları:**

- `_on_open_audit_log()`'daki `is_admin_role` kontrolü geçici olarak
  `if False and ...` ile devre dışı bırakıldı — 2 test **BAŞARISIZ**
  oldu (sayfa açıldı, uyarı hiç gösterilmedi).
- `act_audit`/`act_usb`'nin `.setVisible()`/`.setEnabled()` satırları
  geçici olarak kaldırıldı — admin-olmayan-role testi **BAŞARISIZ** oldu
  (öğeler yine görünür/etkin çıktı).

İkisi de geri alındı, `git diff --stat` temiz döndü, tüm paket tekrar
yeşile döndü.

SECURITY.md §4.20'ye (EN+TR) bu bulgu ve düzeltme belgelendi.

Tam test suite: 2913 passed, 4 skipped (bir önceki turdan +3 — bu iki
yeni test). Ruff/mypy/bandit temiz.

---

## B-080 — Kalıcı silme bir çökmede yarıda kesilebiliyordu: `disposal_queue` ile açılışta otomatik tamamlanıyor

Görev: uygulama bir dosyayı KALICI olarak silerken (İmha Odası'ndan
kalıcı silme ya da süresi dolmuş sayacın otomatik temizliği) tam ortasında
çökerse (güç kesintisi vb.), yarım kalan işlemin açılışta `disposal.py`
içindeki bir kuyruktan otomatik tamamlanmasını sağla.

**Önce boşluk doğrulandı.** `CORE/disposal.py::purge_file()`/
`purge_expired_file()` bir dosyayı silerken iki bağımsız adım atıyordu:
`Path.unlink()` (disk) ve `DELETE FROM files` (DB) — aralarında hiçbir
kalıcı kayıt yoktu. Süreç tam bu ikisinin arasında ölürse, veritabanı
artık diskte olmayan bir dosyayı hâlâ var sanmaya devam ediyordu; hiçbir
mekanizma bunu tespit etmiyordu. Görevin öncülü olan "disposal.py'deki
kuyruk" o an HİÇ YOKTU — kurulması gereken yeni bir altyapıydı, düzeltme
değil.

**Çözüm — yazarkasa deseni.** `DB/migrations.py` Migration 25:
`disposal_queue` tablosu. `db.execute()` her çağrıda kendi kendine commit
ettiği için (`DB/db_manager.py::execute()`), fiziksel silmeden ÖNCE bu
tabloya yazılan bir niyet satırı, sonrasında süreç ne zaman ölürse ölsün
diskte kalıcı kalıyor. Sıra: (1) `_enqueue()` niyeti yazar, (2)
`unlink()` denenir, (3) `files` satırı ve kuyruk satırı silinir
(`_dequeue()`). (2) ve (3) İKİSİ de idempotent (dosya zaten silinmişse
`exists()` False; satır zaten silinmişse DELETE etkisiz) — yani hangi
adımda kesildiği kurtarma açısından önemsiz.

**Kurtarma — `resume_pending_disposals()`.** Açılışta, `main.py`'de tam
`CORE/safezone.py::purge_orphans()`'ı çağıran bölümün hemen ardından
çağrılıyor — AYNI "kapanışta boş kalır, doluysa önceki oturum çökmüştür"
deseni. Kuyrukta kalan her satır için (2) ve (3)'ü tekrar oynatıyor,
dosya başına `disposal_resumed` audit kaydı düşüyor; tek satırın hatası
(kilitli dosya vb.) döngüyü durdurmuyor. `main.py`'de bir hata görürse
(`try/except`) açılışı ENGELLEMİYOR — SafeZone/denetim çıpası
bölümleriyle aynı "görünürlük açılışı durdurmaz" ilkesi; kalan hata
sayısı >0 ise kullanıcıya bir uyarı kutusu gösteriliyor.

**RBAC yan etkisi.** `disposal_queue`, `DB/db_manager.py::
_RBAC_KORUMALI_TABLOLAR`'a eklendi — eklenmeseydi Salt Okunur bir oturum
`files`'a yazamasa bile bu kuyruğa ham SQL ile satır ekleyip
`_require_approval()`'ı hiç görmeden bir dosyanın gelecekte silinmesini
tetikleyebilirdi. `resume_pending_disposals()` ve `purge_expired_file()`
içindeki enqueue/dequeue çağrıları bu yüzden `db.system_write()`
altında — `sweep_retention_expired()`'daki aynı gerekçe.
`tests/test_db_manager_rbac.py::test_salt_okunur_is_verisi_
tablolarina_dogrudan_yazamiyor`'un mevcut parametrizasyonuna
`disposal_queue` durumu eklendi.

**Testler — `tests/test_disposal.py::TestYarimKalanImhaKurtarmasi` (6
yeni test).** Gerçek bir process kill'i taklit etmek mümkün değil; bunun
yerine çökmenin DB'de bıraktığı DURUM elle kuruluyor (kuyrukta niyet
satırı var, temizlik adımları henüz çalışmamış) ve yalnızca kurtarma
tarafı test ediliyor:

- `test_unlink_SONRASI_files_DELETE_ONCESI_kesilen_silme_tamamlaniyor` —
  disk zaten silinmiş, `files` satırı hâlâ duruyor.
- `test_enqueue_SONRASI_unlink_ONCESI_kesilen_silme_tamamlaniyor` — disk
  dosyası HÂLÂ duruyor, resume'un kendisi silmeli.
- `test_birden_fazla_yarim_kalan_islem_tek_turda_tamamlaniyor` — aynı
  kuyrukta İKİ farklı çökme durumundaki dosya, tek turda ikisi de
  temizleniyor.
- `test_normal_akiste_kuyrukta_artik_kalmiyor` — mutlu yolda (çökme yok)
  kuyruk boş kalıyor.
- `test_ikinci_calistirma_etkisiz`, `test_bos_kuyruk_hicbir_sey_yapmiyor`
  — kurtarmanın kendisi idempotent.

**Mutasyon kanıtları (ikisi de geri alındı, `git diff --stat` temiz):**

- `resume_pending_disposals()` içindeki `files` DELETE'i geçici olarak
  devre dışı bırakıldı (`if False:`) — 3 test **BAŞARISIZ** oldu (`files`
  satırı silinmemiş kaldı).
- Aynı fonksiyondaki disk `unlink()` çağrısı geçici olarak devre dışı
  bırakıldı — 2 test **BAŞARISIZ** oldu (dosya diskte kalmaya devam etti).

SECURITY.md §4.21'e (EN+TR) belgelendi.

Tam test suite: 2920 passed, 4 skipped (bir önceki turdan +7 — bu altı
yeni test + `test_db_manager_rbac.py`'nin mevcut parametrizasyonuna
eklenen `disposal_queue` durumu). Ruff/mypy/bandit temiz.

---

### 2026-08-29 (devam 2) — disposal_queue'yu atlayan İKİNCİ bir yol var mı; resume_pending_disposals()'ın kendisi kesilirse ne olur

Görev: 4 ayrı denetim/test — (1) kod genelinde `files` tablosuyla ilişkili
başka bir disk+DB silme yolu var mı (yapısal denetim), (2) varsa
`disposal_queue`'ya bağla, (3) `resume_pending_disposals()` üç kayıt
işlerken ikincide yapay bir kesintiyle karşılaşırsa ne olur, (4) sonraki
açılışta kalan kayıtlar doğru tamamlanıyor mu.

**1. madde — yapısal denetim, sonuç: BAŞKA YOL YOK.** `CORE/`, `UI/`,
`DB/` genelinde `.unlink(`/`os.remove(`/`os.unlink(`/`shred_file(` çağrı
yerlerinin TAMAMI (`grep -rn` ile) listelendi ve her biri tek tek
incelendi:

- `CORE/backup.py` (2 yer) — yedek HEDEFİ ve geçici düz-metin dökümü
  temizliği, `files` tablosuyla ilgisi yok.
- `CORE/checkout.py`, `CORE/timestamp.py` — geçici kopya/dosya temizliği
  (SafeZone benzeri), `files` tablosuna hiç dokunmuyor.
- `CORE/safezone.py`, `CORE/secret_migration.py`, `CORE/secure_erase.py` —
  düz metin/sır silme, `files` tablosuyla ilgisi yok.
- `CORE/vault_manager.py`, `CORE/setup_usb.py::_do_reset` — `.hclv` kasa
  dosyaları + `usb_tokens` satırı siliyor. Görevin özellikle andığı
  "reprovisioning sırasında eski dosya temizliği" BU — ama `files`
  tablosuyla HİÇ ilgisi yok (farklı tablo, farklı dosya türü). Kapsam
  dışı: görev açıkça "`files` tablosuyla ilişkili bağlamda" diyor.
- F4-1'in toplu "İmhaya at" işlemi
  (`UI/main_window_bulk.py::_on_ctx_bulk_move_to_imha`) — yalnızca
  `move_to_imha()` çağırıyor, o da DİSKE HİÇ DOKUNMUYOR (yalnızca
  `label`/`expires_at` günceller). Bu bir silme yolu bile değil.
- AdminPanel'in "manuel silme akışı" olarak aranan şey — `AdminPanel.py`
  yalnızca USB kaydı siliyor (`CORE/vault_manager.py` üzerinden), `files`
  tablosuna dair bir silme UI'da hiç YOK: `purge_file()` şu anda hiçbir
  UI çağrı yerinden çağrılmıyor (ayrıca doğrulandı, `grep -rn
  "purge_file(" UI/` boş döndü) — CORE/disposal.py'nin kendi
  docstring'inin zaten söylediği gibi, bu ileriye dönük hazır altyapı.
  Yani "AdminPanel'in manuel silme akışı" diye bir şey bugün YOK.
- Karantina temizliği zaten önceki turda `purge_expired_file()`'a
  bağlanmıştı (B-004/B-008), yeni bir şey çıkmadı. `quarantine` tablosu
  `files(id)`e `ON DELETE CASCADE` ile bağlı
  (`DB/db_manager.py::_SCHEMA`) — SQLite'ın kendisi temizliyor, ayrı bir
  Python silme yolu yok.

`DELETE FROM files` metninin kod tabanındaki TEK GEÇTİĞİ üretim dosyası
`CORE/disposal.py` (`grep -rn "DELETE FROM files" --include=*.py`, test
dosyaları hariç) — üç yerde, üçü de benim eklediğim fonksiyonlar
(`purge_file`, `purge_expired_file`, `resume_pending_disposals`).

**Kalıcı test.** "Kontrol ettim, yoktu" değil, kalıcı bir CI kapısı:
`tests/test_disposal.py::TestKarantinaTemizligiKorumasi::
test_CORE_UI_DB_genelinde_disposal_queue_atlayan_baska_bir_silme_yolu_yok`
— K0-6'nın `rglob("*.py")` + AST deseniyle `CORE/`, `UI/`, `DB/`'nin
TAMAMINI tarıyor, disk-silme çağrısıyla `DELETE FROM files`'ı aynı
fonksiyon gövdesinde birleştirip `_enqueue(`/`_dequeue(` ÇAĞIRMAYAN her
fonksiyonu işaretliyor. Bilinen sınır (testin kendi docstring'inde
yazılı): bu bir METİN/AST denetimi, çağrı grafiği izlemesi değil — iki
ayrı fonksiyona bölünmüş bir bypass'ı (biri unlink çağırır, ayrı biri
`DELETE FROM files` yazar) yakalamaz. Mutasyon kanıtı: `CORE/` içine tam
bu deseni (kuyruğa hiç dokunmadan unlink + DELETE) yapan bir kullan-at
fonksiyon geçici olarak eklendi — test kırıldı (doğru dosya::fonksiyon
adıyla), dosya silinip test tekrar yeşile döndü.

**2. madde — N/A.** 1. maddede `purge_file()`/`purge_expired_file()`
DIŞINDA gerçek bir `files`+disk silme yolu BULUNMADI, yani bağlanacak
ikinci bir yol yok. Bu maddede yapılan İŞ: hiçbiri — bulunmayan bir şeyi
"düzeltmek" icat etmek yerine, 1. maddenin sonucu dürüstçe raporlandı.

**3-4. madde — resume_pending_disposals()'IN KENDİSİ ortasında kesinti.**
Fonksiyonun "hangi adımda kesildiği önemli değil" iddiası daha önce
yalnızca ORİJİNAL `purge_file()`/`purge_expired_file()` çağrısı için
kanıtlanmıştı; bu kez kurtarmanın KENDİ tekrar oynatması test edildi. İki
yeni test, disposal_queue'da 3 bekleyen kayıtla, ikincinin işlenmesini
`KeyboardInterrupt` ile öldürüyor (bilerek `Exception` DEĞİL — fonksiyonun
satır-başına `except Exception`'ı BİLİNÇLİ bir tasarım, sıradan bir
hatanın kalan satırları durdurmasını engelliyor; gerçek bir süreç ölümünü
taklit etmek onu AŞAN bir istisna gerektiriyor), iki farklı noktada:

- **DB adımında** (`with db.system_write(): db.execute(DELETE...);
  _dequeue(...)` bloğunun İÇİNDE, `db.execute()`'un kendi commit'inden
  SONRA ama `_dequeue()`'dan ÖNCE): ikinci kaydın diski VE `files` satırı
  ZATEN gitmiş — yalnızca kuyruk satırı (artık kozmetik) kalıyor. "Yarım
  kalmamış" (ara bir silme durumu yok), ama kuyruk dışarıdan "bekliyor"
  görünüyor.
- **Disk adımında** (`unlink()`'in kendisinde, HERHANGİ bir commit'ten
  önce): ikinci kayıt HİÇBİR şey commit olmadan üçüncü kayıtla BİREBİR
  aynı durumda kalıyor.

İki durumda da: birinci kayıt (sırası kesintiden ÖNCE geldi) TAM
tamamlanmış, üçüncü kayıt (sırası hiç gelmedi) TAMAMEN dokunulmamış.
Hemen ardından `resume_pending_disposals()` İKİNCİ KEZ çağrılınca (4.
madde — bir sonraki açılış): kalan iki kayıt (ikinci + üçüncü) doğru
tamamlanıyor, birinci kayıt kuyrukta hiç olmadığı için tekrar İŞLENMİYOR
ve ikinci bir `disposal_resumed` audit kaydı ÜRETİLMİYOR (doğrulandı:
birinci dosya için audit_log'da tam olarak 1 `disposal_resumed` satırı
var, ikinci çalıştırmadan sonra da hâlâ 1).

**Mutasyon kanıtları (üçü de geri alındı, `git diff --stat` temiz):**

- Satır-başına yakalayıcı `except Exception` → `except BaseException`
  genişletildi (simüle çökmeyi yutup döngünün YANLIŞLIKLA üçüncü kayda
  devam etmesine izin verirdi) — HER İKİ yeni test de **BAŞARISIZ** oldu.
- `resume_pending_disposals()` içinde `_dequeue()` çağrısı `files`
  DELETE'inden ÖNCEYE alındı (sıra değiştirildi) — DB-adımı testi
  **BAŞARISIZ** oldu (ikinci kaydın `files` satırı hâlâ duruyordu).

SECURITY.md §4.21'e (EN+TR) "Follow-up (same day)" paragrafı olarak
eklendi.

Tam test suite: 2923 passed, 4 skipped (bir önceki turdan +3 — bu üç yeni
test: yapısal denetim + iki resume-kesinti testi). Ruff/mypy/bandit
temiz. (Not: ilk tam koşuda `test_belge_dil_paritesi.py` yanlışlıkla
düştü — arka planda koşan tam suite SECURITY.md'yi tam ben EN/TR
düzenlemelerini yaparken okumuştu, aynı Tur 6'da tespit edilen dosya-
düzenleme yarışı; SECURITY.md'ye hiçbir eş zamanlı dokunuş olmadan yapılan
temiz bir tekrar koşusu 2923 passed/4 skipped verdi, gerçek bir regresyon
değildi.)

---

## B-081 — Büyük arşivlerde MpCmdRun.exe worker havuzunu kilitleyebiliyordu: `subprocess.run`'ın Windows'taki sınırsız ikinci `communicate()`'i bulundu ve düzeltildi

Görev: büyük arşiv dosyalarında MpCmdRun.exe'nin worker havuzunu
kilitlediği durumu incele, katı bir timeout ekle (CI'daki
`timeout-minutes` dersini uygulama içine taşı); timeout aşılırsa dosya
karantinaya alınsın, kullanıcıya net bir mesaj gösterilsin, worker havuzu
kilitlenmesin.

**Bulgu — `SCAN_TIMEOUT=120` zaten vardı ama garanti DEĞİLDİ.**
`CORE/scanner_backends.py::run_tool()` zaten `subprocess.run(...,
timeout=SCAN_TIMEOUT)` çağırıyordu. CPython'un bu timeout mekanizmasının
Windows dalı belgelenmiş bir kör nokta taşıyor: `TimeoutExpired`'da
`kill()`'den SONRA SINIRSIZ bir İKİNCİ `communicate()` daha yapıyor.
`MpCmdRun.exe` büyük bir arşivi taranırken bir yardımcı süreç doğurup
stdout/stderr pipe tanıtıcısını ona devredebilir — `kill()` yalnızca
MpCmdRun.exe'yi öldürür, torun süreç pipe'ı açık tutar, ikinci
`communicate()` SONSUZA KADAR bekler. `timeout=120` görünüşte katı bir
tavandı, büyük arşiv senaryosunda GERÇEKTEN öyle değildi.

**Düzeltme.** `run_tool()` `subprocess.Popen` ile elle kuruldu: zaman
aşımında `kill()` sonrası ikinci bir `communicate()` YOK, yalnızca
`wait(timeout=KILL_GRACE)` (5s) — `wait()` pipe'lara değil sürecin kendi
sonlanmasına baktığı için torun süreç onu etkilemiyor. Worker
`timeout + KILL_GRACE` içinde GARANTİLİ serbest kalıyor.

**Ayırt edici verdict + karantina + mesaj.** Yeni `timeout_result()`
(`verdict="timeout"`, `mock=False`) — eskiden `None` dönüp `mock_result()`
("unknown") ile karışıyordu, "hiç taranmadı" ile "taranmaya çalışıldı,
karar verilemedi" ayırt edilemiyordu. UI: yeni rozet (`⏱ Zaman Aşımı`,
`UI/main_window_palette.py`); manuel yeniden tarama akışında
(`_on_ctx_scan_done`) net bir uyarı kutusu — "tarama zaman aşımına uğradı,
manuel inceleme gerekli." Dosya TAŞINMIYOR: "🔍 Tara" zaten yalnızca
Karantina etiketli satırlarda sunuluyor (kontrol edildi — her yükleme
yolu `label="Karantina"` varsayılanıyla ekliyor), yani dosya zaten doğru
yerde. Toplu yükleme akışında dosya başına kutu YERİNE bir sayaç
tutuluyor, tur-sonu özetine ekleniyor (`_on_batch_complete`).

**Testler — üç katmanda:**

- `tests/test_scanner_backends.py` — `run_tool()`'un kendisi: sahte bir
  `Popen` ile `communicate()`'in TAM BİR kez çağrıldığını, `kill()`'den
  sonra ikinci bir `communicate()` DEĞİL sınırlı `wait()`'in geldiğini
  kanıtlıyor (`test_run_tool_zaman_asiminda_IKINCI_bir_communicate_
  YAPMIYOR`); gerçek bir alt süreçle (`time.sleep(30)`, `timeout=1`) tavanın
  uçtan uca tuttuğunu doğrulayan bir eşlik testi de var. Ayrıca her iki
  arka ucun (Defender/ClamAV) `TimeoutExpired`'da ayırt edici
  `timeout_result()` döndürdüğü ayrıca kanıtlandı.
- `tests/test_scan_timeout_worker_pool.py` — görevin asıl istediği iddia:
  gerçek bir `QThreadPool`'da (2 thread, 3 dosya, biri yapay yavaş) hızlı
  iki dosya yavaş olan BİTMEDEN tamamlanıyor.
- `tests/test_scan_timeout_ui.py` — `_on_ctx_scan_done()`'ın net mesaj
  gösterdiğini, rozetin ayırt edici olduğunu, dosyanın YANLIŞLIKLA
  taşınmadığını, `malicious`/`timeout`/`clean` üçünün birbirinden farklı
  davrandığını kanıtlıyor.
- `tests/test_scanner_flow.py` — `timeout` verdict'inin karantina audit
  kaydına `mock`/`unknown` ile karışmadan düştüğünü kanıtlıyor.

**Mutasyon kanıtları (üçü de geri alındı, `git diff --stat` temiz):**

- `run_tool()`'a tehlikeli ikinci `communicate()` geri eklendi — birim
  testi **BAŞARISIZ** oldu.
- Worker-havuzu testinde HER dosyanın taraması eşit derecede yavaş
  yapıldı (yalnızca biri değil) — zamanlama iddiaları **BAŞARISIZ** oldu.
- `_on_ctx_scan_done()`'daki `elif result.verdict == "timeout"` dalı
  geçici olarak devre dışı bırakıldı — iki UI testi **BAŞARISIZ** oldu.

**Ayrı bir bulgu — bilerek DÜZELTİLMEDİ, gelecek bir tur için not
düşüldü.** Worker-havuzu testinin ilk sürümü gerçek `_FileRunnable`'ı
(şifreleme + DB yazma + tarama) uçtan uca kullanıyordu ve ~10 çalıştırmada
1 aralıklı olarak SQLite hatalarıyla (`"another row available"`,
`"cannot commit - no transaction is active"`) düşüyordu. Kök neden:
`_FileRunnable.run()`, DB yazması (`record_encrypted_file`) için TEK bir
`sqlite3.Connection`'ı (`check_same_thread=False`, ama eşzamanlı erişim
için GÜVENLİ DEĞİL) birden fazla GERÇEK `QThreadPool` worker thread'i
arasında paylaşıyor. `CORE/scanner.py::_save_to_db()` tam bunu önlemek
için zaten kendi bağlantısını açıyor (docstring'i bunu açıkça söylüyor);
`_FileRunnable.run()` bu deseni takip etmiyor. Bu GERÇEK ve bu turun
kapsamı DIŞINDA bir eşzamanlılık kusuru (eşzamanlı dosya EKLEME
yazmalarıyla ilgili, tarama zaman aşımıyla değil) — düzeltilmedi, test
yalnızca `scan_file()` adımını yalıtacak biçimde yeniden yazıldı. Gelecek
bir turda: `_FileRunnable.run()`'ın DB yazması `_save_to_db()`'nin
deseniyle (thread başına ayrı bağlantı) hizalanmalı.

SECURITY.md §4.22'ye (EN+TR) belgelendi.

Tam test suite: 2938 passed, 4 skipped (bir önceki turdan +15 — dört yeni
test dosyası/eklemesi). Ruff/mypy/bandit temiz. (Not: bir ara koşuda
`test_belge_dil_paritesi.py`'nin üç testi yanlışlıkla düştü — arka planda
koşan tam suite SECURITY.md'yi ben hâlâ BACKLOG.md'yi düzenlerken okumuştu,
aynı dosya-düzenleme yarışı; SECURITY.md'ye hiçbir eş zamanlı dokunuş
olmadan yapılan temiz bir tekrar koşusu 2938 passed/4 skipped verdi,
gerçek bir regresyon değildi.)

**Takip (aynı gün): `kill()`+`wait()` düzeltmesi işçiyi zamanında serbest
bırakıyordu ama ARKASINDA bir sızıntı bırakıyordu — bulundu, ölçüldü,
düzeltildi.** Görev: run_tool()'un zaman aşımı dalındaki pipe/handle
sızıntısını incele, kanıtla, gerekirse düzelt; sızıntı varsa 50-100 tekrarla
Windows tanıtıcı/thread sayısını ölç, kalıcı bir regresyon testi ekle.

*Kod incelemesi.* `run_tool()` hâlâ `stdout=subprocess.PIPE,
stderr=subprocess.PIPE` kullanıyordu. CPython'un Windows dalında pipe'lar
arka plan thread'leriyle okunuyor (`Popen._readerthread`, `fh.read()`'de
EOF'a kadar bloklu) ve CPython'un KENDİ kaynak kodu (`Lib/subprocess.py`,
Python 3.14.4) zaman aşımında bunları KAPATMADIĞINI açıkça yazıyor —
yorumu birebir doğrulandı: "If we time out, the threads remain reading and
the fds left open in case the user calls communicate again." Ne
`Popen.communicate()` ne `run_tool()`'un kendi `kill()`+`wait()`'i bu
thread'lere ya da tuttukları pipe tanıtıcılarına DOKUNMUYORDU.

*Ölçüm — art arda 30 zaman aşımı, gerçek bir torun süreçle.*
Sahte/mock bir `Popen` bunu ÖLÇEMEZ (sızıntı yalnızca öldürülenin
KENDİSİ değil bir TORUNU pipe'ı tutarsa oluşuyor — `kill()` torunlara
dokunmuyor). Gerçek yeniden üretim: `cmd /c "ping -n 9999 127.0.0.1"` —
`run_tool()`'un öldürdüğü `cmd.exe` doğrudan çocuk, `ping.exe` onun
stdout/stderr'ini miras alıp `kill()`'den sağ çıkan yetim torun (tam
MpCmdRun.exe'nin bir yardımcı süreçle yapacağı şey). `psutil.
Process().num_handles()` / `threading.active_count()` ile ölçüldü: 30
tekrar → **+153 tanıtıcı, +60 thread — ikisi de tekrar sayısıyla BİREBİR
ORANTILI** (~5 tanıtıcı + 2 thread/zaman aşımı), zamanla geri düşmüyor.
Kalıcı, sınırsız, gerçek bir sızıntı — varsayım değil.

*Denendi ve REDDEDİLDİ — `kill()`+`wait()` sonrasına `proc.stdout.close()`.*
Görevin önerdiği iki seçenekten biri (elle `close()`, ya da eşdeğer olarak
`with subprocess.Popen(...) as proc:` — `Popen.__exit__` TAM AYNI
`.close()` çağrılarını yapıyor) İKİSİ DE aynı yeniden üretimle ölçüldü.
**İkisi de çağıran thread'i SONSUZA KADAR kilitledi** — `stdout closed`
satırı bir 15 saniyelik zaman aşımında bile hiç basılmadı. Windows'ta bir
pipe okuma ucunu, o TAM handle'da başka bir thread'de bloklu bir
`ReadFile` sürerken kapatmak okuyucuyu serbest bırakmıyor, kapatanı da
donduruyor. Bu, orijinal kusurdan DAHA KÖTÜ olurdu: sızan bir arka plan
thread'i yerine `QThreadPool` WORKER'IN KENDİSİ senkron olarak
donardı — bu B-081'in düzelttiği worker-havuzu kilitlenmesinin
KENDİSİ, artık olası değil KESİN.

*Gerçek düzeltme — pipe'ı hiç kullanma.* CPython yalnızca
`stdout=PIPE`/`stderr=PIPE` verildiğinde okuyucu thread başlatıyor.
`run_tool()` artık çocuğun çıktısını `tempfile.mkstemp()` ile açılan
gerçek geçici dosyalara yönlendiriyor; başarıda dosyalar geri okunuyor,
zaman aşımında hiç okunmuyor. Pipe yok → okuyucu thread yok → bloklanacak
`fh.read()` yok. Aynı 30 tekrarlık ölçüm düzeltmeyle: **+2 tanıtıcı TOPLAM
(tek seferlik, tekrar başına DEĞİL), +0 thread, kilitlenme YOK.**

*Kabul edilen, gizlenmeyen artık.* Torun süreç temizlik anında dosyayı
hâlâ açık tutuyorsa `unlink()` başarısız olabilir — doğrulandı, 60 geçici
dosyanın (30×stdout+stderr) HEPSİ sızıntı ölçümünden sonra diskte kaldı.
Artık yalnızca disk kalıntısı (canlı thread/tanıtıcı DEĞİL). Mitigasyon:
her `run_tool()` çağrısı `_eski_gecici_dosyalari_temizle()` ile 1 saatten
eski kendi kalıntılarını süpürüyor — `SCAN_TIMEOUT+KILL_GRACE`'in (~125s)
çok üstünde, devam eden bir taramaya asla dokunmuyor.

*Test — `tests/test_scan_timeout_handle_leak.py` (yeni, kalıcı).* Aynı
torun-pipe-tutuyor senaryosunu 60 kez tetikleyip (istenen 50-100 aralığı,
CI süresi için alt uca yakın) tanıtıcı/thread büyümesinin SABİT kaldığını
doğruluyor. Mutasyon kanıtı: `run_tool()`'a `stdout=PIPE`+`communicate()`
deseni geri kondu — test ANINDA **BAŞARISIZ** oldu (60 tekrarda 302
tanıtıcı, `302 < 120` yanlış), sonra geri alındı, `git diff --stat` temiz,
tekrar **BAŞARILI**. `tests/test_scanner_backends.py`'deki `_SahteSurec`
`communicate()`'i tamamen KALDIRILDI (artık çağrılırsa `AttributeError`
ile kendiliğinden patlıyor) ve `Popen`'a geçilen `stdout`/`stderr`'in
`subprocess.PIPE` OLMADIĞINI doğrudan denetleyen yeni bir test eklendi.

`psutil>=7.0` `requirements-dev.txt`'e eklendi (yalnızca bu testin
Windows tanıtıcı ölçümü için; Linux'ta test `sys.platform != "win32"`
ile atlanıyor).

SECURITY.md §4.22'nin sonuna (EN+TR) "Takip" bölümü olarak belgelendi.

Tam test suite: 2941 passed, 4 skipped (bir önceki turdan +3 — bir yeni
test dosyası). Ruff/mypy/bandit temiz. (Not: bir ara koşuda
`test_belge_dil_paritesi.py`'nin iki testi yanlışlıkla düştü — arka planda
koşan tam suite SECURITY.md'yi ben hâlâ TR "Takip" bölümünü eklerken
okumuştu, bu turda ÜÇÜNCÜ kez karşılaşılan aynı dosya-düzenleme yarışı;
SECURITY.md'ye hiçbir eş zamanlı dokunuş olmadan yapılan temiz bir tekrar
koşusu 2941 passed/4 skipped verdi, gerçek bir regresyon değildi.)

**İkinci takip (aynı gün): geçici dosya güvenliği dört başlıkta
denetlendi — üçü temiz, dördü (izinler) bulunup düzeltildi.** Önce YALNIZCA
denetim istendi ("henüz düzeltme yapma, yalnızca kanıt topla") — dört madde
ayrı ayrı ölçüldü, sonra bulguya göre düzeltme kararı ayrı bir mesajda
verildi.

*1. Oluşturma API'si — risk yok.* `tempfile.mkstemp()` `O_CREAT|O_EXCL`
(Windows'ta `CREATE_NEW`) kullanıyor — tahmin edilebilir PID/sayaç/zaman
damgası ADI YOK, rastgele 8 karakter + atomik "zaten varsa başarısız ol"
garantisi. Önceden dosya/symlink hazırlama saldırısı bu API'de çalışmıyor.

*2. Eşzamanlılık — risk yok, ölçüldü.* Gerçek `QThreadPool`'da
(maxThreadCount=20) 20 paralel `run_tool()` çağrısı, üretilen 40 dosya
adının (20×stdout+stderr) TAMAMI benzersiz, sıfır çakışma.

*3. Süpürme yarış durumu — risk yok, zorlanıp ölçüldü.* `_eski_gecici_
dosyalari_temizle()`'nin `unlink()`'i zaten `except OSError: pass`
içindeydi. 12 thread `threading.Barrier` ile aynı eski dosyayı GERÇEKTEN
aynı anda silmeye zorlandı — sıfır sızan exception, dosya bir kez silindi.

*4. Dosya izinleri — GERÇEK boşluk, düzeltildi.* `os.open(mode=0o600)`
Windows'ta gerçek bir ACL'e çevrilmiyor (CPython'un belgelediği davranış).
Ölçülen gerçek dosya, ebeveyn `%TEMP%`'in ACL'ini olduğu gibi devralıyordu
— yalnızca çalıştıran kullanıcıyla sınırlı DEĞİLDİ (bir grup ve çözülmemiş
bir SID de `Modify` hakkına sahipti). Düzeltme: `_gecici_dosyayi_
kullaniciya_kisitla()`, her iki geçici dosya için de oluşturulduktan hemen
sonra çağrılıyor, Windows'ta DACL'i `win32security.SetFileSecurity(...,
DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, ...)`
ile tam olarak {mevcut kullanıcı, SYSTEM}'e daraltıyor — kalıtım kesiliyor.
Gerçek bir dosya üzerinde doğrulandı: `GetFileSecurity()` sonrası tam
olarak beklenen iki SID, `icacls` ile bağımsız teyit edildi, önceki
grup/SID girişleri artık yok. `pywin32` yeni bağımlılık değil
(`requirements.txt`: `wmi` → `pywin32`, Windows'ta zaten zorunlu);
`CORE/secret_store.py`/`CORE/hwid_probe.py`'nin aynı tembel `import
win32...` deseni kullanıldı. Başarısız olursa (best effort) taramayı
düşürmüyor, yalnızca uyarı logluyor — dosya eski (bu değişiklikten önceki)
ACL'iyle kalıyor.

*Test — `tests/test_scan_timeout_dacl.py` (yeni).* Birim testi: gerçek
dosya oluşturup kısıtlayıp gerçek DACL'i sorguluyor, tam olarak {kullanıcı,
SYSTEM} bekliyor. Entegrasyon testi: `run_tool()`'un kısıtlama fonksiyonunu
HER İKİ dosya için de GERÇEKTEN çağırdığını (spy ile) doğruluyor — birim
testi bunu tek başına yakalayamaz. Üçüncü test: `SetFileSecurity`
patlarsa tarama akışının bozulmadığını doğruluyor. Mutasyon kanıtı:
`run_tool()`'daki iki kısıtlama çağrısı geçici olarak yorum satırına
alındı — entegrasyon testi ANINDA **BAŞARISIZ** oldu (0 çağrı, 2
bekleniyordu), sonra geri alındı, `git diff --stat` temiz, tekrar
**BAŞARILI**.

SECURITY.md §4.22'ye (EN+TR) "İkinci takip" bölümü olarak eklendi.

Tam test suite: 2945 passed, 4 skipped (bir önceki turdan +4 — bir yeni
test dosyası, `tests/test_scan_timeout_dacl.py`). Ruff/mypy/bandit temiz.

---

## B-082 — Çok-cihazlı hesap modeli: mockup çoklu USB listesi istiyor, şema (B-060) izin vermiyor

**Durum:** Açık — bilinçli olarak ertelendi
**Öncelik:** Düşük (talep edilmiş bir özellik değil, bir mockup uyuşmazlığı)

Görev: Profil dialogunu tam sayfaya taşı, "Cihazlar ve oturum" bölümü
ekle (kayıtlı USB token'ların LİSTESİ + hangisinin şu an takılı olduğu +
"Oturumu kapat"). Test senaryosu olarak "birden fazla kayıtlı cihazı olan
bir hesap" istendi.

**Bulgu.** `users.hwid` kısmi UNIQUE indeksli
(`DB/migrations.py::_m23_users_hwid_unique`, B-060): bir hesap en fazla
BİR HWID'e bağlanabiliyor. "Birden fazla kayıtlı cihaz" senaryosu bugünkü
şemada HİÇ VAR OLAMIYOR — bu bir UI eksikliği değil, B-060'ın kimlik
doğrulama modelinin (aksi hâlde aynı fiziksel USB token'ı paylaşan iki
hesap birbirinin yetkisini gasp edebilirdi) doğal ve KASITLI sonucu.

**Karar (kullanıcıya soruldu, tahmin edilmedi).** "Cihazlar ve oturum"
bölümü bugünkü GERÇEK modele göre inşa edildi: hesabın kendi TEK HWID'i
— token ID, kayıt tarihi, kara liste durumu, "şu an takılı" (canlı
`get_usb_hwid()` karşılaştırması). Veri kaynağı `UI/AdminPanel.py`'nin
USB Yönetim Paneli'yle AYNI fonksiyon (`CORE/usb_tokens.py::
token_kayitlarini_getir()`, `hwid=` filtresiyle daraltılmış) — iki
görünüm arasında ayrı SQL yazılıp veri tutarsızlığı riski açılmadı.
Şemayı GEVŞETİP çoklu cihaza izin vermek bu turda YAPILMADI: B-060'ın
kapattığı gaspı yeniden açar, kimlik doğrulama modelini değiştiren ayrı
ve bilinçli bir karar gerektirir.

**Gelecekte gerçekten çok-cihazlı bir model isteniyorsa gerekenler**
(bu turda değerlendirilmedi, yalnızca kapsamın büyüklüğünü göstermek
için not düşülüyor):

- `users.hwid` yerine ayrı bir `user_devices` tablosu (`user_id`,
  `hwid`, `share_2`, `token_id`, ekleme tarihi) — `users` artık tek bir
  HWID'e sabitlenmiyor.
- Her cihazın KENDİ Shamir payı: bugün `share_2` tek bir vault dosyasına
  bağlı; birden fazla cihaz aynı hesaba giriş yapabilecekse ya paylaşılan
  bir kasa ya da cihaz başına ayrı kasa + aynı role senkronize edilmiş
  bir mekanizma gerekir.
- `_reject_if_weak_binding`/kara liste/rol değişimi gibi HWID-özel
  akışların hepsinin "birden fazla geçerli HWID" varsayımına göre
  yeniden gözden geçirilmesi.
- Bir cihazın kara listeye alınmasının DİĞER cihazları etkileyip
  etkilemeyeceği kararı (hesap seviyesinde mi, cihaz seviyesinde mi).

SECURITY.md §4.23'e (EN+TR) belgelendi. `tests/test_profile_view.py`
bugünkü tek-cihaz modelini doğruluyor; bu madde açıldığında o testlerin
`AdminPanel`/`ProfileView` tutarlılık iddiası YENİDEN gözden geçirilmeli
(birden fazla satır artık MEŞRU olur).

---

## B-083 — Profil dialogu tam sayfaya taşındı: "Cihazlar ve oturum" ve "Kendi işlemlerim" bölümleri eklendi

Görev: Profil dialogunu modal'dan tam sayfaya taşı, mockup'taki "Cihazlar
ve oturum" bölümünü ekle (kayıtlı USB token'ların listesi + hangisinin şu
an takılı olduğu + "Oturumu kapat"). Bu verinin USB Yönetim Paneli'ndeki
token tablosuyla aynı kaynaktan mı geleceğini önce incele. "Kendi
işlemlerim" bölümünü ekle (kullanıcının kendi son denetim kayıtları).

**Modal → tam sayfa.** `UI/ProfileDialog.py` (kaldırıldı) → `UI/
ProfileView.py` — `UI/AuditLogView.py`/`UI/GuvenlikView.py` ile AYNI
`_govde_yigini` (`QStackedWidget`) deseni: kenar çubuğu düğmesi yok
(mevcut tetikleyici korundu — üst bardaki avatar tıklaması), sayfa
dördüncü giriş olarak eklendi. `main_window.py::_on_open_profile()`
`AuditLogView`'inkiyle aynı geçiş mantığını kullanıyor
(`setCurrentWidget` + `_page_title` + `.yenile()`).

**Veri kaynağı incelendi ÖNCE, düzeltme yazılmadan.** `UI/AdminPanel.py`
`_load()`'un SQL'i doğrudan gövdede embed ediyordu. Bu SQL `CORE/
usb_tokens.py::token_kayitlarini_getir()`'e taşındı (opsiyonel `hwid=`
filtresiyle); `AdminPanel` KENDİSİ de bu fonksiyonu çağıracak şekilde
refactor edildi — "aynı veriyi iki yerde farklı biçimde tutma" riski
İKİ AYRI SORGU yazmak yerine TEK fonksiyonla kapatıldı.

**Çoklu cihaz sorusu kullanıcıya soruldu, tahmin edilmedi.** `users.hwid`
kısmi UNIQUE (B-060) — bir hesap en fazla bir HWID'e bağlanabiliyor,
"birden fazla kayıtlı cihaz" senaryosu bugünkü şemada yok. Karar: bölüm
GERÇEK 1-hesap-1-cihaz modeline göre inşa edildi (tek satır — token ID,
kayıt tarihi, kara liste durumu, canlı "şu an takılı" göstergesi),
şemayı gevşetmek yerine. Ayrıntı: BACKLOG B-082, SECURITY.md §4.23.

**"Oturumu Kapat" gerçek kilit mekanizmasını kullanıyor, ikinci bir
uygulama YAZILMADI.** Yeni bir kilit nedeni ("manual") `LockMixin`'in
(`UI/main_window_lock.py`) mevcut `_lock()`/`_unlock()`/`_lock_reasons`
kümesine eklendi — `_unlock_idle()`'ın AYNI PIN-doğrulama deseni,
AYRI denetim eylemleriyle (`session_logged_out`, `manual_unlock_success/
failed` — "hareketsizlikten kilitlendi" ile "kullanıcı kendi isteğiyle
kilitledi" aynı sinyale düşerse denetim kaydı yanlış sebep gösterir).
KRİTİK doğrulama: `_poll_usb`'nin varsayılan `_unlock()` çağrısı yalnızca
"usb" nedenini kaldırıyor, "manual" bundan ETKİLENMİYOR — aksi hâlde
kullanıcının kendi USB'si takılı kaldığı için "Oturumu Kapat" tıklaması
gözle görülmeden bir anlığına kilitleyip hemen kendiliğinden açardı.
Bu, ayrı bir testle ZORLANARAK doğrulandı (`_poll_usb()` manuel kilitten
HEMEN sonra çağrıldı).

**"Kendi işlemlerim" — `AuditLogView`'in KOPYASI değil, küçük bir alt
kümesi.** `audit_log` tablosunun `user_id` ile daraltılmış son 20 kaydı;
HALKA zincir sütunu, filtreler, TXT dışa aktarım YOK — amaç "tüm günlüğü
yönet" değil "son işlemlerime hızlı bakış." Tam günlük gerekiyorsa
kullanıcı (yetkisi varsa) Denetim Günlüğü sayfasına gidebilir.

**Test — `tests/test_profile_view.py` (yeni, 6 test).** (1) Cihaz
satırının `AdminPanel`'in aynı HWID için gösterdiğiyle tutarlı olduğu —
İKİNCİ, ilgisiz bir token eklenerek `hwid=` filtresinin gerçekten
çalıştığı kanıtlandı (tek token varken filtreli/filtresiz sorgu HER ZAMAN
aynı sonucu verirdi, test tesadüfen geçerdi). (2) Kara liste durumunun
iki görünümde tutarlı olduğu. (3) "Şu an takılı"nın canlı `get_usb_hwid()`
karşılaştırmasına göre değiştiği (USB çekilince "Hayır"a döndüğü).
(4) "Kendi işlemlerim"in BAŞKA bir kullanıcının kaydını sızdırmadığı.
(5) "Oturumu Kapat"ın kilitlediği ve aynı USB takılıyken `_poll_usb`
tarafından kendi kendine açılmadığı. (6) Doğru PIN'le açıldığı.

**Mutasyon kanıtları (üçü de geri alındı, `git diff --stat` temiz):**

- `token_kayitlarini_getir()`'in `hwid=` filtresi devre dışı bırakıldı —
  satır sayısı denetimi **BAŞARISIZ** oldu (1 yerine 2 satır).
- `_load_islemlerim()`'in `WHERE user_id = ?` koşulu kaldırıldı —
  sızıntı denetimi **BAŞARISIZ** oldu (başka kullanıcının kaydı sızdı).
- `_poll_usb()`'a "manual"ı da temizleyen bir regresyon eklendi —
  kalıcılık denetimi **BAŞARISIZ** oldu (kilit yanlışlıkla açıldı).

**Ayrıca düzeltildi (yol boyunca bulundu):** `tests/conftest.py::
SahteUSB._HEDEF_MODULLERI`'ne `UI.ProfileView` eklendi — eklenmeseydi
`sahte_usb` fixture'ı kullanan testler ProfileView'ın `get_usb_hwid()`'ini
yamalamadan GERÇEK donanımı görmeye devam ederdi (yorumun kendi uyarısı).
`main.py::_SELFTEST_MODULLERI`'ne yeni `CORE.usb_tokens` modülü eklendi
(paketleme öz-testi kapsıyor).

`UI/ProfileDialog.py`'ye çapraz referans veren dosyalar güncellendi:
`tests/test_pin_rotation.py`, `tests/test_contact_dialog.py`,
`tests/test_authz_invariants.py` (B-065 testi artık `ProfileView`
kullanıyor), `CORE/pin_rotation.py`, `UI/PinRotationDialog.py`,
`UI/ThemePickerDialog.py` (şimdiki-zaman anlatımlı yorumlar). Geçmiş
zaman anlatımlı tarihsel referanslar (`tests/test_login_dialog_kurtarma_
ekrani_yok.py`, `tests/test_ui_yasakli_iddia_terimleri.py`) BİLEREK
değiştirilmedi — o zamanki gerçek durumu doğru anlatmaya devam ediyorlar.

SECURITY.md §4.23'e (EN+TR) belgelendi.

Tam test suite: 2955 passed, 4 skipped (bir önceki turdan +10 — bir yeni
test dosyası, `tests/test_profile_view.py`). Ruff/mypy/bandit temiz.

---

## B-084 — USB Yönetim Paneli modal'dan tam sayfaya taşındı; "Bekleyen Kayıtlar" ve "Ayarlar" ayrı kenar çubuğu girişlerine bölündü

Görev: USB Yönetim Panelini modal'dan tam sayfaya taşı, "Bekleyen
Kayıtlar" ve "Ayarlar" sekmelerini mockup'taki gibi ayrı sidebar menü
öğelerine böl (Tokenlar sayfası kendi başına kalsın). Veri modeline
dokunma, yalnızca navigasyon/layout değişikliği. Test: mevcut USB
token/onay/reddet akışlarının hepsinin yeni yerleşimde çalıştığını
doğrula (regresyon testi).

**Modal → üç tam sayfa.** `UI/AdminPanel.py` (tek bir application-modal
`QDialog`, üç `QTabWidget` sekmesi) kaldırıldı; yerine `_govde_yigini`nde
(`GuvenlikView`/`AuditLogView`/`ProfileView` ile AYNI `QStackedWidget`
deseni) üç ayrı sayfa geldi: `UI/UsbTokensView.py` (kendi başına kaldı,
davranış/veri değişmedi), `UI/PendingRegistrationsView.py`,
`UI/AdminSettingsView.py`. Kenar çubuğunda tek "🔌 USB Yönetimi"
düğmesinin yerini üç düğme aldı; hamburger menüsündeki "USB Yönetimi"
öğesi USB Tokenlar sayfasına açılıyor (üçünü tekrar etmiyor). Paylaşılan
stil yardımcıları ve canlı yetki denetimi yeni `UI/admin_common.py`'de.

**Mimari sadeleştirme: kendi zamanlayıcısı silindi, ama esas garanti
GÜÇLENDİRİLEREK korundu.** Eski `AdminPanel` application-modal olduğu
için ana pencerenin `_lock()`/`_poll_usb()`'sinden (B-064/B-066) habersizdi
ve kendi 3 sn'lik `_yetki_timer` + uyarı şeridini taşıyordu. Sayfalar artık
`centralWidget()`'ın içinde olduğundan bu zamanlayıcı GEREKSİZLEŞTİ ve
silindi (`_lock()` zaten tüm sayfaları kapsıyor). Ama `centralWidget().
setEnabled(False)` yalnızca fare/klavye olaylarını engelliyor, doğrudan
bir Python metot çağrısını (`sayfa._on_approve()`) ENGELLEMİYOR — eski
panelin asıl garantisi buydu ve modal/gömülü ayrımından bağımsızdı, bu
yüzden `UI.admin_common.yonetici_hala_yetkili()` her yetkili eylemden
önce aynı canlı DB doğrulamasını (`oturum_yetkisi_gecerli_mi`) yapmaya
devam ediyor. ÜSTELİK sıkılaştırıldı: üç sayfa artık (Güvenlik/Denetim
Günlüğü/Profil gibi) KOŞULSUZ kuruluyor, yani yönetici olmayan bir
oturumun penceresi de `window._pending_view` gibi canlı bir referans
tutuyor — eskiden panel yalnızca bir yönetici onu AÇTIĞINDA var oluyordu.
`oturum_yetkisi_gecerli_mi()` tek başına bunu kapatmıyor (yalnızca rol
DRIFT'ini yakalıyor, başından beri yönetici olmayan bir oturumu değil) —
`yonetici_hala_yetkili()` bu yüzden ÖNCE `is_admin_role(pencere._role)`'u
kontrol edip kapalı başarısız oluyor. Ayrıntı: SECURITY.md §4.24.

**Bireysel/Kurumsal görünürlük — panelin kendi sekme-gizlemesinden
pencerenin `_apply_role_restrictions()`'ına taşındı.** Eskiden Bireysel
modda "Bekleyen Kayıtlar" panelin İÇİNDE bir sekme olarak gizlenirdi
(`_apply_mode_visibility`, panelin kendi `_load_settings()`'i her
açılışta çağırırdı). Artık bu ayrı bir sayfa/düğme olduğu için karar
`main_window.py::_apply_role_restrictions()`'a taşındı — "gizlemek silmek
değil" ilkesi AYNEN korunuyor: `_pending_view` ve verisi hiçbir zaman
silinmiyor, yalnızca kenar çubuğu düğmesi ve tablo sütunu gizleniyor.

**Tema tazeleme — modal olmanın örtük bir avantajı kayboluyordu, elle
kapatıldı.** Eski panel her açılışta O ANKİ temayla taze kuruluyordu
(kendi `T=` parametresi); kalıcı bir sayfa için bu geçerli değil ve tema
seçici artık her sayfadan (hamburger menüsü) erişilebilir. `UI/
main_window_theme.py::_refresh_after_theme_change()` `AuditLogView`'ın
kendi elle boyanan sütunları için zaten kullandığı mekanizmayla üç admin
sayfasının `_restyle()`'ını da çağıracak şekilde genişletildi.

**Test — mevcut akışların regresyonu.** Yeni davranışlı hiçbir test
yazılmadı; MEVCUT testler yeni yerleşime taşındı ve hepsi geçiyor:
`tests/test_app_mode_ui.py` (Bireysel/Kurumsal görünürlük, artık
`window._pending_btn`/`window._admin_settings_view` üzerinden),
`tests/test_authz_invariants.py` (B-064 — USB çekilince onayın
reddedilmesi, artık panel kapatma yerine `pencere._lock("revoked")`
doğrulanıyor), `tests/test_trusted_roots.py` (TSA kök ekleme/kaldırma,
`AdminSettingsView` üzerinden), `tests/test_tema_kontrasti.py`,
`tests/test_recovery_share_ui.py`, `tests/test_guvenlik_view.py`,
`tests/test_role_decision_point.py`, `tests/test_slide_over.py`,
`tests/test_kurtarma_usb_kapisi.py`, `tests/test_main_window_smoke.py`
(baseline metot envanteri — `_on_open_admin_panel` üç yeni adla
değiştirildi), `tests/test_audit_report.py`, `tests/test_first_run_
isolation.py`, `tests/test_profile_view.py` (iki test hâlâ `AdminPanel`
kuruyordu — ithal edilemediği için SESSİZCE atlanıyordu, `UsbTokensView`
kullanacak şekilde düzeltildi; B-024 dersinin bir tekrarı: bir denetimin
KENDİSİNİN çalıştığından emin olunmadan yeşil sayılmamalı).

**Ayrıca düzeltildi (yol boyunca bulundu):** `tests/conftest.py::
SahteUSB._HEDEF_MODULLER`'den `UI.AdminPanel` çıkarıldı, yerine
`UI.UsbTokensView`/`UI.PendingRegistrationsView`/`UI.AdminSettingsView`/
`UI.admin_common` eklendi.

SECURITY.md §4.24'e (EN+TR) belgelendi.

Tam test suite: 2960 passed, 4 skipped. Ruff/mypy/bandit temiz.

---

## B-085 — B-084'ün guard sırası ve rol-değişikliği koruması yeniden doğrulandı: `AdminSettingsView.__init__`'in kapıdan ÖNCE atan bir sorgusu bulundu ve düzeltildi

Görev: Üç yönetici sayfasının guard sırasını ve rol-değişikliği
korumasını kanıtla, gerekirse düzelt — `is_admin_role()` tam olarak
nerede çalışıyor (nesne kurulmadan önce mi, `__init__`/veri çekme
adımından sonra mı), doğrudan örnekleme testiyle (K1-14 deseni) her üç
sayfa için ayrı ayrı göster; kaldırılan 3sn'lik zamanlayıcının
karşıladığı rol-değişikliği tehdidini yeniden değerlendir.

**Guard sırası — VARSAYILMADI, kod okunarak ölçüldü.** `UsbTokensView`/
`PendingRegistrationsView`: `__init__` yalnızca boş widget kuruyor,
HİÇBİR sorgu atmıyor — veri yükü tamamen `.yenile()`'ye ertelenmiş,
`.yenile()`'nin üretimdeki TEK çağrı yeri rol-kapılı `_on_open_*()`.
`AdminSettingsView`: **BULUNDU** — `__init__` `_load_settings()`'i VE
(`_tsa_kok_bloku()` üzerinden) `_tsa_yukle()`'yi KOŞULSUZ çağırıyordu,
yönetici olmayan bir oturum için de, rol kapısından ÖNCE. Düzeltildi:
ikisi de `__init__`/`_build_ui()`'dan kaldırıldı, yalnızca `.yenile()`'de
kaldı (zaten oradaydı) — üç sayfa artık TUTARLI.

**Doğrudan örnekleme testi — yeni dosya `tests/
test_admin_pages_construction_guard.py` (9 test).** UI menüsü/hamburger
HİÇ kullanılmıyor: gerçek bir `"Standart"` (yönetici olmayan, ama
`can_write=True`) rollü `HycleusWindow` kuruluyor ve `_make_govde_yigini()`
tarafından ZATEN inşa edilmiş `window._usb_tokens_view`/`_pending_view`/
`_admin_settings_view`'a doğrudan erişiliyor.

  1. Üç sayfa için de: DB'de "sorgu çalışsaydı görünürdü" bir satır
     seedlenip pencere kuruluyor, `__init__`'ten HEMEN sonra ilgili
     tablo/combo'nun BOŞ/varsayılan kaldığı doğrulanıyor — sonra
     `.yenile()` çağrılıp GERÇEKTEN dolduğu gösteriliyor (mekanizma
     bozuk değil, yalnızca ertelenmiş). `AdminSettingsView` testi
     düzeltmeden ÖNCE KIRMIZIYDI — mutasyonla kanıtlandı: düzeltme
     `git stash`'le geçici olarak geri alınıp test yeniden koşturuldu,
     AYNI hata (combo DB'nin Bireysel değerini erkenden gösteriyordu)
     tekrar üretildi, geri getirilip yeşile dönüldüğü teyit edildi.
  2. `"Standart"` rolüyle (can_write=True, is_admin_role=False) üç
     sayfanın birer yetkili eylemi (kara listeye al / onayla / ayar
     kaydet) doğrudan çağrılıyor — DB'nin KENDİ yazma kapısı (B-074,
     `can_write`) bu rolü DURDURMAZDI; reddeden `UI.admin_common.
     yonetici_hala_yetkili()`'nin KENDİ `is_admin_role()` kontrolü.
     Mutasyon kontrastı: `yonetici_hala_yetkili` atlatılınca AYNI
     "Standart" çağrı GERÇEKTEN geçiyor.
  3. **Rol-değişikliği penceresi, `_poll_usb()`'DEN BAĞIMSIZ ölçüldü.**
     Canlı bir yönetici oturumunun DB rolü `'user'`e düşürülüyor — USB
     HİÇ çekilmiyor, `_poll_usb()` (main_window'un kendi 3sn'lik
     zamanlayıcısı, B-066, bu turda DEĞİŞMEDİ) test boyunca HİÇ
     çağrılmıyor — ve ZATEN AÇIK olan sayfada doğrudan `_on_approve()`
     çağrılıyor: reddediliyor, pencere kilitleniyor. Sonuç: kaldırılan
     modal-özgü zamanlayıcının karşıladığı tehdit GERÇEKTEN kapalı
     kalıyor, ama `_poll_usb()` YÜZÜNDEN değil — her yetkili handler'ın
     TIKLAMA ANINDA yeniden sorguladığı `yonetici_hala_yetkili()`
     yüzünden. Yazma-anı maruziyet penceresi "`_poll_usb()`'nin en
     fazla 3 saniyesi" DEĞİL, tıklama ile guard'ın kendi sorgusu
     arasındaki fark — fiilen sıfır.

**O zaman "kasıtlı olarak değiştirilmedi" denen asimetri, HİÇ DENENMEDEN
verilmiş bir iddiaydı — takip turunda GERÇEKTEN denendi ve düzeltildi.**
Bu maddenin ilk yazımı `.yenile()`'nin kendi `is_admin_role()` kontrolü
taşımadığını (yalnızca yetkili/yazan handler'ların taşıdığını) doğru
tespit etmiş, ama "üretimde erişilemez, o yüzden kasıtlı" diyerek
kapatmıştı — KANITSIZ bir ifade. Takip görevi ("`.yenile()`'ye yapılan
tüm çağrı yerlerini kanıtla, gerekirse savunma-derinliği guard'ı ekle")
bunu gerçekten sınadı:

  1. **Çağrı yeri denetimi, tam kapsam.** `.yenile()`'nin `UI/`, `CORE/`,
     `DB/`, `main.py` genelindeki TÜM çağrıları grep'lendi: TAM OLARAK
     üç yer var, hepsi `main_window.py`'de (`_on_open_usb_tokens:430`,
     `_on_open_pending:442`, `_on_open_admin_settings:454`), her biri
     kendi fonksiyonunun kendi `is_admin_role()` kontrolünden HEMEN
     sonraki SON ifade. Zamanlayıcı, sinyal/slot bağlantısı ya da
     "Yenile" düğmesi ÜZERİNDEN çağrılan bir yol YOK ("Yenile" düğmeleri
     `_load()`/`_load_pending()`'e bağlı, `.yenile()`'ye değil).
     `_refresh_after_theme_change()`'in çağrısı `_restyle()`'a (DB'siz
     olduğu doğrulandı), `.yenile()`'ye DEĞİL.
  2. **Doğrudan atlatma testi.** Gerçek bir `"Standart"` rollü
     `HycleusWindow` kurulup `_on_open_*()` HİÇ çağrılmadan
     `.yenile()` doğrudan çağrıldı: ÜÇÜ DE sorguyu GERÇEKTEN çalıştırıp
     tabloyu/combo'yu/listeyi doldurdu — "erişilemez" öncülü giriş
     noktalarının VARLIĞINA dayanıyordu, `.yenile()`'nin KENDİSİNİN
     güvenliğine değil.
  3. **Düzeltildi.** `UI.admin_common.sayfa_erisimi_var_mi()` — erken-
     dönüşlü bir `is_admin_role(pencere._role)` kontrolü,
     `yonetici_hala_yetkili()`'den KASITLI daha hafif (bu bir YAZMA
     değil, salt-okuma; canlı DB gidiş-dönüşü GEREKSİZ ağırlık olurdu) —
     artık üç `.yenile()` metodunun da BAŞINDA. İKİ YÖNDE mutasyonla
     kanıtlandı: düzeltme `git stash`'le geri alınıp aynı doğrudan-çağrı
     testi kırmızı yakalandı, geri getirilip yeşile döndü; AYRICA
     `sayfa_erisimi_var_mi`'yi her zaman `True` dönecek şekilde
     monkeypatch'lemek AYNI "Standart" çağrının tabloyu YENİDEN
     doldurduğunu gösterdi.
  4. Bu düzeltme, section 2/3'teki (bir önceki turdan kalma) YAZMA-reddi
     testlerinin `.yenile()` ÇAĞIRAN hazırlık adımlarını da etkiledi —
     `.yenile()` artık "Standart" rol için veri YÜKLEMEDİĞİNDEN, o dört
     test ham `_load()`/`_load_pending()`/`_load_settings()`'e
     güncellendi (seçilecek satırı doldurmak için) — asıl ölçtükleri
     şey (YAZMA reddi) değişmedi.

SECURITY.md §4.24'teki KANITSIZ "kasıtlı, gözden kaçırma değil" cümlesi
kaldırıldı; yerine yukarıdaki denetim + düzeltim + mutasyon kanıtını
anlatan yeni paragraflar geldi (EN+TR).

Tam test suite: 2972 passed, 4 skipped. `tests/
test_admin_pages_construction_guard.py` 9'dan 10 teste çıktı (yeni
mutasyon-kontrastlı test). Ruff/mypy/bandit temiz.

---

## B-086 — Denetim günlüğü dışa aktarımı bir formattan (TXT) üçe çıktı: Tablo (CSV) ve İmzalı Rapor (PDF)

Görev: Denetim günlüğü indirme seçeneklerini mockup'taki gibi üçe çıkar:
Düz metin (mevcut TXT), Tablo (Excel/SIEM için ayrık sütunlu CSV/XLSX),
İmzalı rapor (PDF + özet, zincir doğrulama sonucu ve dış çıpa dahil).
Karar: İmzalı rapor RFC 3161 mührüyle (K4-20) birlikte mi, yoksa PDF
şimdilik mühürsüz mü? Test: her üç formatın da doğru veriyi içerdiğini,
indirme işleminin kendisinin de denetim kaydına yazıldığını doğrula.

**Karar — PDF şimdilik MÜHÜRSÜZ, K4-20 AYRI bir maddeye (B-087)
ertelendi.** Sessizce "sonraya" bırakılmadı: PDF kendini mühürlenmiş gibi
GÖSTERMİYOR, belge içinde "RFC 3161 zaman damgasıyla MÜHÜRLENMEMİŞTİR"
diye AÇIKÇA söylüyor — `txt_basligi()`'nin "bu dosya imzalı DEĞİLDİR"
notuyla AYNI dürüstlük ilkesi. "İmzalı" burada rapor'un zincirin KENDİ
kanıtını (hash zinciri + dış çıpa karşılaştırması) GÖMÜLÜ taşıması
anlamına geliyor — dosyanın kendisinin dış bir otorite tarafından
damgalanması DEĞİL. Ayrıntı: BACKLOG B-087, SECURITY.md §4.25.

**Tek getirme, üç render'layıcı.** `UI/AuditLogView.py::_load()` ARTIK
render edilmiş tabloyla BİRLİKTE, aynı sorgudan, kırpılmamış bir
`CORE/audit_report.py::DenetimSatiri` listesini de (`self._son_export_
satirlari`) topluyor — ikinci, bağımsız filtrelenmiş bir sorgu YOLU
AÇILMADI. TXT eski hâliyle tabloyu okumaya devam ediyor (davranış
DEĞİŞMEDİ); CSV/PDF bu yeni HAM listeyi okuyor.

**Tablo (CSV), UI'nin okunabilirlik kırpmalarını MİRAS ALMIYOR —
kasıtlı.** UI tablosu HWID'i 16 karaktere kırpıyor, zamanı biçimlendirilmiş
gösteriyor — SIEM/Excel için YANLIŞ. `DenetimSatiri` TAM HWID, ham ISO
zaman damgası, ham `action`, TAM `detail` taşıyor. Doğrudan doğrulandı:
30 karakterlik sentetik bir HWID UI tablosunda "…" ile kırpılıyor, CSV'de
TAM hâliyle görünüyor.

**CSV, XLSX DEĞİL — bilinçli.** `CORE/inventory.py::
export_inventory_csv()` zaten `utf-8-sig` (BOM'lu UTF-8) kararını vermişti
— Excel'de doğru açılıyor VE SIEM'lerin evrensel girdi formatı. Gerçek
`.xlsx` yeni bir bağımlılık (`openpyxl`) gerektirirdi, iki isimlendirilen
tüketicinin de (Excel, SIEM) CSV'ye göre özel olarak ihtiyaç duymadığı
bir format için.

**PDF, `CORE/inventory.py::export_inventory_pdf()`'in AYNI reportlab
deseniyle.** `CORE/audit_report.py::export_pdf()` — A4 yatay, sayfa
başına tekrarlayan başlık satırı, reportlab kurulu değilse anlaşılır
`RuntimeError` (içe aktarım fonksiyon İÇİNDE, TXT/CSV çalışmaya devam
etsin). Rapor gövdesi: başlık + oluşturulma zamanı + filtre notu +
`zincir_raporu().baslik()`/`.ayrinti()` (zincir bütünlüğü + dış çıpa) +
RFC 3161 uyarısı + satır tablosu.

**Kaçış yardımcısı paylaşıldı, ikinci kopya YAZILMADI.** `CORE/
inventory.py::_escape()` (reportlab Paragraph için mini-HTML kaçışı) yeni
`CORE/pdf_utils.py::escape_for_reportlab()`'a taşındı; `CORE/inventory.py`
onu import ediyor. Denetim `detail` alanı da kullanıcı girdisi taşıyabilir
(dosya adı vb.) — AYNI kaçış ihtiyacı iki modülde.

**İndirme eylemi artık kendini kaydediyor — üçü için de, TXT dahil.**
Görev "indirme işleminin kendisi de denetim kaydına yazılsın" diyordu;
mevcut TXT dışa aktarımı bunu HİÇBİR ZAMAN yapmıyordu (bulundu, ölçüldü).
Üçü de artık `_log_disa_aktarim()`'i (tek action: `audit_log_exported`,
`format=` alanıyla ayrışan — `usb_role_changed`'in deseni) başarılı
yazımdan SONRA, onay diyaloğundan ÖNCE çağırıyor (`UI/main_window_files.
py::file_downloaded`'ın AYNI sırası). Parametrize testle üç format için
de doğrulandı (önce/sonra sayım + `user_id`/`format=` kontrolü); iptal
edilen bir dışa aktarımın HİÇBİR ŞEY yazmadığı ayrı bir testle kanıtlandı
(boş bir iddia olmadığını göstermek için). AST tabanlı bir test üç
`_export_*` metodunun da GERÇEKTEN `_load()`/kendi `export_*` fonksiyonu/
`_log_disa_aktarim()` çağırdığını doğruluyor.

**Yol boyunca bulunan bir mevcut test kırılması, DOĞRU yönde düzeltildi.**
`tests/test_audit_log_view.py::test_export_arkaplanda_eklenen_kaydi_...`
dışa aktarımdan SONRA `audit_log` satır sayısını okuyordu — yeni
kendi-kendini-loglama eklendiğinde bu sayım artık dışa aktarımın KENDİ
denetim kaydını da içeriyordu (5 yerine 6). Test dosyanın gösterdiği
sayıyla DEĞİL, dışa aktarımdan SONRA değişmiş bir sayımla karşılaştırıyordu
— sayım artık dışa aktarımdan ÖNCE alınıyor (asıl sınanan şey: dışa
aktarım ANINDAKİ veritabanı durumu, dışa aktarımın KENDİ yan etkisi
DAHİL bir durum değil).

**Test-doğrulanabilirlik bulgusu — `pageCompression=0`.**
`export_inventory_pdf()`'in testleri ham PDF baytlarında metin arıyordu
(`b"KVKK" in ...`) ama bu SADECE `title=` metadata'sı için tesadüfen
çalışıyordu (PDF Info sözlüğü sıkıştırılmaz); gövde metni (tablo
hücreleri) varsayılan ayarlarla ARANAMAZ çıktı — ölçüldü. `SimpleDocTemplate`'e
`pageCompression=0` geçmek bunu düzeltti — yeni bir PDF-ayrıştırma
bağımlılığı (pypdf vb.) EKLEMEDEN. Bedel: daha büyük, sıkıştırılmamış
dosya — nadiren indirilen bir dışa aktarım için kabul edilebilir.

SECURITY.md §4.25'e (EN+TR) belgelendi.

Tam test suite: 3000 passed, 4 skipped (bir önceki turdan +28 — `CORE/
audit_report.py`'ye CSV/PDF için 22 yeni test, `UI/AuditLogView.py`
kablolamasına 11 yeni test, `tests/test_rehber_kopyalari.py`'ye 1 yeni
denetim). Ruff/mypy/bandit temiz.

---

## B-087 — RFC 3161 mührü (K4-20): İmzalı Rapor (PDF) kasıtlı olarak MÜHÜRSÜZ kaldı, ayrı bir mimari karar olarak izleniyor

B-086'nın "İmzalı Rapor" (PDF) seçeneği zincirin KENDİ kanıtını (hash
zinciri + dış çıpa) gömüyor, ama PDF DOSYASININ KENDİSİNİ bir RFC 3161
zaman damgası otoritesine imzalatmıyor — dosya sonradan değiştirilirse
bunu tespit etmenin hiçbir yolu yok, ve PDF bunu KENDİSİ açıkça söylüyor
("RFC 3161 zaman damgasıyla MÜHÜRLENMEMİŞTİR").

Bu B-082'nin (çok-cihazlı hesap modeli) izlediği AYNI ilke: kapsamı
sessizce genişletmek yerine, gerçekten isteniyorsa ayrı, bilinçli bir
karar olarak buraya işlendi.

**Yapılması gerekenler (gerçekten isteniyorsa):**
- `CORE/timestamp*.py`/`UI/TimestampDialog.py`'nin ZATEN dosya
  içerikleri için kullandığı RFC 3161 akışının (freetsa.org ya da
  yapılandırılabilir bir TSA) PDF dosyasının SHA-256'sına uygulanması.
- Ağ bağımlılığı ve TSA kullanılamazlığı için bir hata yolu — PDF dışa
  aktarımı bugün TAMAMEN çevrimdışı, bu onu bozar; kullanıcıya "TSA'ya
  ulaşılamadı, mühürsüz devam et mi?" gibi bir seçenek gerekebilir.
- Mühürlü PDF'in doğrulanması: `CORE/trusted_roots.py`'nin güven
  listesine karşı, `UI/TimestampDialog.py`'nin dosya doğrulamasıyla AYNI
  yol — ikinci bir doğrulama uygulaması YAZILMAMALI.
- `export_pdf()`'in RFC 3161 uyarı satırının kaldırılması/güncellenmesi
  (mühürlendiğinde artık doğru değil).

Ayrıntı: SECURITY.md §4.25, §4.16 (K4-20/F2-2'nin daha önceki
referansları).

---

## B-088 — CSV dışa aktarımı formül enjeksiyonuna (CWE-1236) açıktı: bulundu, gerçek veriyle kanıtlandı, düzeltildi

Görev: CSV export'unda formül enjeksiyonu riskini incele, kanıtla,
gerekirse düzelt — tüm mutasyon testleri dahil.

**Kod incelemesi — kanıt.** `export_csv()`'nin özgün gövdesi
`writer.writerow([s.id, s.zaman, s.islem, s.kullanici, ..., s.detay,
...])` — hiçbir kaçışlama YOKTU. `csv` modülünün kendi kaçışlaması
(RFC 4180 virgül/tırnak/satır-içi-yenisatır) CSV SÖZDİZİMİNİ koruyor,
Excel/LibreOffice Calc'in bir hücreyi FORMÜL sanmasını KAPSAMIYOR —
tamamen ayrı bir kusur sınıfı.

**Gerçek veriyle enjeksiyon testi.** `kullanici="=1+1"` olan bir
`DenetimSatiri` dışa aktarıldı; `csv.reader` ile geri okunan hücre TAM
OLARAK `=1+1` — kaçışlanmamış. `+cmd|'/c calc'!A1`, `-2+3+cmd|'/c
calc'!A1`, `@SUM(1+1)`, sekme/CR önekli varyantlar da AYNI şekilde ham
yazılıyordu.

**"Gerçek elektronik tablo doğrulaması" — bu ortamda kurulu değil,
kaynak gösterildi.** Ne LibreOffice ne `openpyxl`/`pandas` bu makinede
kurulu; kurulu olsalar bile ikisi de PARSER, hesaplama motoru DEĞİL —
bir formülü GERÇEKTEN çalıştırmazlardı. "`=`/`+`/`-`/`@` ile başlayan
kaçışlanmamış bir hücrenin Excel/LibreOffice Calc'te formül olarak
değerlendirilmesi" OWASP'ın CSV Injection (CWE-1236) rehberinde
belgelenmiş, DIŞ bir uygulama davranışı — bu sandbox içinde yeniden
üretilecek bir şey değil, kaynak gösterildi.

**Düzeltme — yeni `CORE/csv_utils.py::csv_hucre_guvenli()`.** Tehlikeli
bir önekle (`=`/`+`/`-`/`@`/sekme/CR — OWASP'ın standart kümesi)
başlayan hücrenin BAŞINA tek bir tek-tırnak (`'`) ekliyor: Excel/
LibreOffice bunu "bu hücre KESİNLİKLE metin" işareti olarak okuyor,
DEĞERLENDİRMİYOR. TÜM metin sütunlarına (kullanıcı, işlem, HWID, detay)
İSTİSNASIZ uygulandı — `detay`'ın BUGÜN her zaman bir `key=value`
önekiyle geldiği (dolayısıyla asla çıplak tehlikeli karakterle
BAŞLAMADIĞI) doğru, ama bu MEVCUT çağıranların bir tesadüfü, hiçbir
yerde ZORUNLU KILINAN bir garanti değil — buna güvenmek düzeltmeyi
gelecekteki bir `detail=` çağrı yerinden bir adım uzakta bırakırdı.

**AYNI kusur, kardeş fonksiyonda: `CORE/inventory.py::
export_inventory_csv()`.** İlkini düzeltirken bulundu, sonraya
BIRAKILMADI — dosya adı/kullanıcı adı AYNI şekilde kaçışlanmıyordu. İki
fonksiyon da artık AYNI paylaşılan yardımcıyı kullanıyor, iki ayrı kopya
YAZILMADI (`escape_for_reportlab()`'ın zaten kurduğu paylaşım deseniyle
AYNI).

**Mutasyon testleri — üç eksen.**
  a. Düzeltme `git stash`'le (yeni `csv_utils.py` DAHİL, `-u` bayrağıyla)
     geçici olarak geri alındı — enjeksiyon testleri HER payload
     varyantında VE İKİ fonksiyonda da (16 test) KIRMIZI yakalandı; geri
     getirilip hepsi yeşile döndü.
  b. Tehlikeli-önek demeti teste ÖZGÜ bir monkeypatch'le yalnızca `("=",)`
     ile sınırlandı — `+`/`-`/`@` payload'larının o zaman
     ETKİSİZLEŞTİRİLMEDEN geçtiği doğrulandı: gerçek test takımının,
     yalnızca `=`'i kapsayıp diğer üç öneki KAÇIRAN eksik bir düzeltmeyi
     gerçekten YAKALADIĞININ kanıtı.
  c. Negatif test: "Ahmet Yılmaz", "2026-08-30", ORTASINDA `=` geçen (ama
     BAŞINDA geçmeyen) bir `detay` alanı — hiçbiri değişmiyor. Sayılar/
     `None` `csv_hucre_guvenli()`'den hiç dokunulmadan (dizeye bile
     çevrilmeden) geçiyor.
  d. Tüm mutasyonlar geri alındı, `git status --short` yalnızca kalıcı
     değişiklikleri gösterdiği doğrulandı.

**Kapsam dışı, bilinçli: PDF.** PDF formül DEĞERLENDİRMEZ (sabit bir
görsel belge, yeniden açılan bir hesaplama motoru değil) — CSV
formül-enjeksiyonu PDF'e uygulanmıyor, PDF'e ayrı bir kaçışlama
eklenmedi.

SECURITY.md §4.25'e (EN+TR) eklendi.

Tam test suite: 3019 passed, 4 skipped (bir önceki turdan +19 — `CORE/
csv_utils.py` için birim testleri, `export_csv()`/`export_inventory_csv()`
için enjeksiyon/negatif/mutasyon testleri). Ruff/mypy/bandit temiz.

---

## B-089 — Bekleyen Kayıtlar tablodan kart listesine döndü: mockup'a uygun, veri/mantık dokunulmadan; onayla/reddet bağlanması API-şekli değişikliği gerektirdi

Görev: Bekleyen Kayıtlar tablosunu mockup'taki gibi kart listesine çevir
(isim + rol + HWID + kayıt tarihi, Onayla/Reddet butonları). Kozmetik bir
değişiklik, veri/mantığa dokunma. Test: onaylama/reddetme akışının yeni
kart görünümünde de doğru çalıştığını doğrula.

**Değişiklik.** `UI/PendingRegistrationsView.py` bir `QTableWidget`'tan
kart listesine (her kart `QFrame`, `UI/GuvenlikView.py::_kart()`'ın
ZATEN kurduğu görsel desen — `search_bg`/`border`/8px radius — yeni
`admin_common.kart_stil(T)` üzerinden ÖDÜNÇ ALINDI, yeniden İCAT
EDİLMEDİ) tamamen yeniden yazıldı. SQL sorgusu (`SELECT username, hwid,
role, created_at FROM users WHERE status='pending' ORDER BY created_at
DESC`), onay/red diyalog metinleri ve denetim kaydı `detail=` biçimi
BAYT BAYT AYNI kaldı.

**Kozmetik kalamayan tek şey: `_on_approve`/`_on_reject` imzası.** Tabloda
"seçili satır" vardı; kart listesinde yok — her kartın kendi düğmesi
kendi `hwid`/`username`'ini taşımak zorunda. İkisi de sıfır-argümandan
`(hwid, username)`-zorunlu imzaya döndü, `functools.partial` ile kart
kurulurken bağlanıyor (döngü-içi lambda'nın geç-bağlama hatasından
KAÇINILDI). "Kullanıcı Adı" Bireysel-modda gizleme (`setColumnHidden`)
yeni `set_kullanici_adi_gizli(bool)` metoduna taşındı — AYNI anında-etki
garantisiyle.

**Kendi kendine bulunan bir layout hatası.** İlk taslak, boş-durum
etiketini ("Bekleyen kayıt yok.") kart temizleme döngüsünün YANLIŞLIKLA
sildiği bir hataya sahipti — biçimsel testler çalışmadan ÖNCE elle
smoke-testle bulunup `self._kart_widgetleri` ile açıkça izlenerek
düzeltildi.

**Test — üç dosyanın güncellenmesi + bir yeni özel dosya.**
`tests/test_authz_invariants.py` (20 passed), `tests/
test_admin_pages_construction_guard.py` (10 passed), `tests/
test_app_mode_ui.py` (9 passed) — hepsi `_on_approve()`'un yeni imzasına
ve `_pending_table` → `_kart_widgetleri`'e göre güncellendi, hepsi yeşil.
Yeni `tests/test_pending_registrations_view.py` (9 passed) — kart
içeriği/kırpma, boş-durum görünürlüğü, ve en önemlisi: **GERÇEK düğme
tıklamasıyla**, iki bekleyen kayıt varken, birinci kartın düğmesine
basmanın SADECE o kullanıcıyı etkilediğini (`functools.partial`
bağlamasının GERÇEKTEN doğru hwid'i taşıdığının kanıtı — tek-kartlı bir
test bunu YAKALAMAZDI), artı denetim kaydı doğrulaması ve iptal-durumu-
değiştirmiyor testi.

SECURITY.md §4.26'ya (EN+TR) eklendi; §4.24/§4.25'in artık AYNI dosyaya
(`_make_pending_table`, `_on_approve()`) yaptığı BAYAT referanslar da
güncellendi.

Tam test suite: 3019 passed, 4 skipped (bir önceki turdan +9 — yeni
`tests/test_pending_registrations_view.py`). Ruff/bandit temiz; mypy
yalnızca değişiklik-öncesiyle AYNI sayıda pre-existing PySide6-stub
`attr-defined` hatası gösteriyor (39 hata, `git stash` ile karşılaştırılıp
doğrulandı).

---

## B-090 — Denetim çıpasının izolasyonunu GERÇEK yaptı: env var'lı yönlendirme yerine USB token'a otomatik ikinci kopya + iki kopyayı karşılaştıran doğrulama

Görev: Denetim zinciri dış çıpasını gerçek bir izolasyona taşı — env var
ile başka dizine yazmak yarım çözüm (aynı dosya sistemi, aynı saldırgan).
Çıpayı, zaten takılı olan USB token'a da yaz (ek altyapı gerektirmiyor,
mevcut USB zaten var). Test: çıpanın hem yerel diskte hem USB'de tutarlı
olduğunu, biri bozulursa diğeriyle karşılaştırmanın bunu yakaladığını
doğrula.

**Sorun — kanıtlandı.** `HYCLEUS_AUDIT_ANCHOR` ortam değişkeni çıpa
dosyasını BAŞKA bir dizine taşıyabiliyordu ama o dizin genellikle AYNI
diskte duruyor — veritabanına yazabilen saldırganın (bu modülün TANIMLADIĞI
tehdit modeli) zaten yazma erişimi olduğu AYNI güven sınırı. Gerçek
izolasyon fiziksel olarak AYRI bir cihaz gerektiriyordu.

**Çözüm — iki yeni yetenek.**
  1. `CORE/usb_manager.py::get_usb_mount_root(hwid)` — bu modül bugüne
     kadar USB'nin dosya sistemine HİÇ YAZMAMIŞTI (yalnızca WMI'dan
     donanım KİMLİĞİ okuyordu). WMI'ın disk→bölüm→mantıksal-disk ilişki
     zincirini kullanarak `hwid`'e sahip diskin SÜRÜCÜ HARFİNİ buluyor —
     "ilk USB" değil, `get_usb_hwid()`'in belirlediği AYNI fiziksel diski
     (birden fazla USB takılıyken yanlış sürücüye yazmamak için).
  2. `CORE/audit_chain.py::write_anchor()` artık `write_usb=True`
     varsayılanıyla YEREL kopyayı YAZDIĞI GİBİ, o an takılı USB'ye de
     (`usb_anchor_path()`, `<bağlama_kökü>/HYCLEUS/audit_anchor.log`)
     AYNI DB-türetilmiş içerikle bir ikinci kopya yazıyor. USB o an
     takılı değilse ya da yazım başarısız olursa BEST-EFFORT sessizce
     atlanıyor — yerel kopyanın yazımı bundan HİÇ etkilenmiyor. HYCLEUS
     zaten kimlik doğrulanmış bir oturum için USB'yi ZORUNLU kıldığından
     (çıkarılınca kilitliyor), ek altyapı GEREKMEDİ.

**Yeni doğrulama — `verify_anchor_replicas()`.** Tek bir çıpa dosyasının
kendi iç zinciri (`verify_anchor_file()`) yalnızca o dosyanın TUTARLI
biçimde yeniden numaralanmadan değiştirilmediğini kanıtlıyor — o dosyaya
yazabilen bir saldırgan bir satırı değiştirip SONRAKİ tüm
`prev_anchor_hash`'i yeniden hesaplayarak dosyanın KENDİ zincirini yine
temiz doğrulatabilir (zincirin TAM YENİDEN YAZIMA karşı sahip olduğu AYNI
zayıflık, bir seviye aşağıda). `verify_anchor_replicas()` yerel ve USB
kopyalarının içerik alanlarını (`last_id`/`last_hash`/`entry_count`/
`chain_start_id`/`reason`/`anchored_at`) ORTAK ÖNEKLERİ üzerinde
karşılaştırıyor — uzunluk farkı TEK BAŞINA sorun değil (USB best-effort,
bazı yazımları KAÇIRABİLİR), ama ORTAK bir konumdaki İÇERİK farkı
kurcalamanın kanıtı. `main.py` açılışına, mevcut `verify_against_anchor()`
kontrolüyle AYNI engellemeyen desenle bağlandı; `CORE/audit_report.py`'nin
imzalı-rapor makinesine ya da "Zincir Doğrula" düğmesine BİLEREK
bağlanmadı — bu turun kapsamı dışındaydı.

**Testler gerçek donanıma DOKUNMUYOR.** Yeni autouse `isolate_usb_anchor`
(`tests/conftest.py`) `get_usb_mount_root()`'u TÜM suite için None'a
sabitliyor — bu olmasaydı `write_anchor()`'ın yeni varsayılanı HER testte
(bu turdan önceki ~15 test DAHİL) gerçek bir WMI sorgusu tetikleyebilirdi.
Yeni `tests/test_usb_mount_root.py` (9 test) `get_usb_mount_root()`'un
WMI ilişki-zinciri mantığını `tests/test_hwid_probe.py`'nin ZATEN kurduğu
sahte-WMI desenini genişleterek ölçüyor. `tests/test_audit_chain.py`'ye
eklenen "USB ikinci kopya" bölümü (17 test) çift yazımı, dosya-başına
BAĞIMSIZ seq zincirlerini, USB yokken/yazım başarısız olduğunda yerel
kopyanın ETKİLENMEDİĞİNİ, ve — görevin asıl istediği — **iki kopyanın
tutarlı olduğunu VE birini kurcalamanın diğeriyle karşılaştırılınca
YAKALANDIĞINI** (hem USB tarafı hem yerel taraf kurcalanarak, simetrik
olarak) kanıtlıyor.

**Mutasyonla kanıtlandı.** Çift yazımı geri almak (USB hedefini HER ZAMAN
`None`'a zorlamak) 7 testi kırdı; `verify_anchor_replicas()`'ın
karşılaştırılan-alan listesini boşaltmak kurcalama-yakalama testlerinin
3'ünü kırdı. İkisi de geri alındı.

SECURITY.md §4.27'ye (EN+TR) eklendi.

Tam test suite: 3055 passed, 4 skipped (bir önceki turdan +25 — yeni
`tests/test_usb_mount_root.py` ve `tests/test_audit_chain.py`'ye eklenen
"USB ikinci kopya" bölümündeki testler). Ruff/mypy temiz; bandit'in
`CORE/usb_manager.py` üzerindeki bulgu sayısı 6'dan 7'ye çıktı — hepsi
best-effort donanım probu için ZATEN kabul edilmiş AYNI `try/except/pass`
deseni (`git stash` ile karşılaştırılıp doğrulandı).

### B-090 takibi (aynı gün) — çoklu-USB eşleştirmesi kanıtlandı; `write_anchor()`'a hwid çapraz-doğrulaması eklendi

Görev: `get_usb_mount_root(hwid)`'in çoklu-USB senaryosunda doğru cihaza
eşlendiğini kanıtla, gerekirse `write_anchor()`'a çapraz-doğrulama ekle.

**1. Çoklu-USB eşleştirmesi — zaten vardı, mutasyonla sınandı.**
`tests/test_usb_mount_root.py::test_birden_fazla_usb_dogru_olani_seciyor`
(bir önceki turda yazılmıştı) iki farklı seri/sürücü harfine sahip sahte
USB diskiyle her hwid'in KENDİ harfine eşleştiğini ZATEN doğruluyordu.
Boş bir iddia olmadığı `_sanitize_hwid(serial) != hwid: continue`
korumasını kaldıran bir mutasyonla kanıtlandı — 2 test (bu ve eşleşmeyen-
hwid testi) hemen kırıldı, yanlış sürücü harfi döndü; geri alındı.

**2. Yanlış eşleşme riski — DEĞERLENDİRİLDİ, GERÇEK boşluk (b) bulundu.**
`get_usb_mount_root()`'un KENDİ eşleştirmesi yapısı gereği doğru (ilişki
zinciri BELİRLİ disk nesnesi üzerinde yürüyor, genel sorgu değil). Ama
`write_anchor()`'ın otomatik yolu hwid'i `get_usb_hwid()`'den alıyordu —
o an takılı USB'lerin WMI sırasındaki İLKİ, OTURUMUN kendi hwid'i olduğu
GARANTİSİ olmadan. Birden fazla kayıtlı token aynı anda takılıysa (iki
yönetici token'ı) `get_usb_hwid()` BAŞKA bir kullanıcının hwid'ini
döndürebilir — sonuç (a) sessiz başarısızlık DEĞİL, (b) BAŞKA BİR
KULLANICININ USB'sine YAZMA: gerçek, kuramsal olmayan bir boşluk.

**3. Çapraz-doğrulama eklendi — `_usb_hwid_dogrulanmis_mi()`.**
`write_anchor()` artık otomatik-bulunan hwid'i USB'ye yazmadan ÖNCE İKİ
katmanda doğruluyor: (1) `source` bir `DBManager`'sa VE `_hwid`'i
biliniyorsa (üretimdeki HER çağrı yeri — `main.py` — bunu geçiriyor) —
DOĞRUDAN eşitlik, `usb_tokens`da kayıtlı BAŞKA bir hwid bile bunu
KURTARMAZ; (2) `source` ham bir bağlantıysa — `usb_tokens`da kayıtlı VE
kara listeye alınmamış mı diye bakılır. Uyuşmazlıkta USB kopyası
ATLANIYOR (yerel kopya ETKİLENMİYOR), tıpkı USB takılı değilken olduğu
gibi.

**4. Test.** (a) çoklu-USB — madde 1. (b) `write_anchor(db, ...)` —
`db`'nin KENDİSİ, oturumun kendi hwid'i biliniyor — o an takılı USB
BAŞKA, GEÇERLİ biçimde kayıtlı bir kullanıcınınsa, USB'ye yazılmıyor,
yerel yazım etkilenmiyor (`test_write_anchor_usb_skipped_cross_user_
even_if_registered`) — görevin ASIL istediği senaryo. Artı: kayıtsız
hwid, kara listeli hwid, güçlü katmanın zayıf katmandan ÖNCELİKLİ olduğu
doğrudan birim testleri. (c) Mutasyon: `_usb_hwid_dogrulanmis_mi()`'yi
HER ZAMAN `True` dönecek şekilde zorlamak 6 testi kırdı (cross-user
senaryosu DAHİL); geri alındı.

SECURITY.md §4.27'ye (EN+TR) eklendi.

Tam test suite: 3064 passed, 4 skipped (bu takipten +9). Ruff/mypy/bandit
temiz (bandit sayısı ÖNCEKİ turdan değişmedi — yeni kod yalnızca CORE/
audit_chain.py'de, o dosyada bandit bulgusu yok).

---

## B-091 — Kurtarma parçası ekranından "Panoya Kopyala" tamamen kaldırıldı; ekranda gösterme + QR + yazdırma güçlendirildi

Görev: Kurtarma parçası için panoya kopyalama seçeneğini tamamen kaldır
(ekran koruması/pano geçmişi uygulama kontrolünde değil, tek doğru hamle
bu). Yerine ekranda gösterme + QR kod + yazdırma seçeneklerini bırak/
güçlendir. Test: "panoya kopyala" butonunun artık bulunmadığını, QR ve
yazdır seçeneklerinin çalıştığını doğrula.

**Kaldırma.** `UI/RecoveryShareDialog.py`'nin "Panoya Kopyala" düğmesi
(kopyalamadan ÖNCE uyarı, kopyalanan içeriği 30 saniye sonra — YALNIZCA
pano hâlâ tam olarak yazdığı şeyi tutuyorsa — otomatik temizleme) ve ona
bağlı TÜM kod (`_on_panoya_kopyala`, geri sayım zamanlayıcısı, `closeEvent`/
`done()`'daki temizlik çağrıları, `PANO_UYARISI`/`PANO_TEMIZLEME_SN`
sabitleri, `pano_saniye` kurucu parametresi) SİLİNDİ — devre dışı
BIRAKILMADI. Gerekçe kullanıcının verdiği: ekran yakalama Windows'ta
GERÇEKTEN uygulamanın denetiminde (`WDA_EXCLUDEFROMCAPTURE`), ama pano
geçmişi (Win+V, üçüncü taraf araçlar) HİÇBİR platformda değil — "önce
uyar" düğmesi yine de "bu güvenli bir yol" izlenimi veriyordu.

**Güçlendirme — yazdırma GERÇEK bir yol oldu.** Onay kutusu HER ZAMAN "Bu
parçayı yazdırdım..." diyordu ama pencerede yazdıracak bir düğme HİÇ
YOKTU — bu tutarsızlık, görev vesilesiyle bulundu ve kapatıldı. Yeni
`_on_yazdir()` gerçek bir `QPrinter`/`QPrintDialog` akışı açıyor;
`_yazdirilabilir_belge()` ekranın ZATEN gösterdiği AYNI `qr_svg`'i (İKİNCİ
bir QR üretim yolu AÇMADAN — mevcut "TEK YOL" AST denetimi bunu yazdırma
için de zorluyor) rasterize edip base32 metniyle birlikte bir
`QTextDocument`'a koyuyor. Paylaşılan/ağ yazıcılarının kuyruk/bellek
riskini adlandıran bir uyarı düğmenin yanında HER ZAMAN görünür (panonun
"sessiz" riskinin aksine).

**Test riski, bulundu ve düzeltildi: GERÇEK `QPrinter` inşa etmek bile
tehlikeli.** İlk yazılan testler gerçek `QPrinter(...)`/`QPrintDialog(...)`
kuruyor, yalnızca `.exec()`'i monkeypatch'liyordu. pytest altında (düz bir
Python betiğinde DEĞİL) bu, Windows'un yazıcı COM arabirimlerini
sorgularken `0x80040155` COM istisnasına düşüyordu — testi KIRMADI ama
`faulthandler`'ın "Windows fatal exception" uyarısını bastı; farklı bir
makinede/CI'da GERÇEKTEN çökebilirdi. Düzeltme: `PySide6.QtPrintSupport.
QPrinter`/`QPrintDialog`'un KENDİSİ sahtelerle değiştiriliyor (`_on_yazdir()`
ikisini de YEREL olarak içe aktardığı için bu, gerçek donanıma/COM'a hiç
dokunmadan çalışıyor); `QTextDocument.print_()` de ayrıca sahteleniyor
(sahte `QPrinter` gerçek `print_()`'e verilirse tip hatası verirdi).

**Test.** Yeni "3. Pano KALDIRILDI + Yazdırma" bölümü (11 test):
"Panoya Kopyala" düğmesinin YOKLUĞU (`objectName` üzerinden) + kaynakta
pano'yla ilgili HİÇBİR izin kalmadığını doğrulayan bir tarama, yazdır
düğmesinin VARLIĞI, uyarının HER ZAMAN göründüğü, düğme→diyalog→kabul→
`print_()` uçtan-uca akışı, İPTAL edilince HİÇ yazdırılmadığı, yazdırılan
belgenin hem QR'ı hem base32'yi (hem de uyarı metnini) taşıdığı, QR
yokken (`qrcode` paketi kurulu değilken) belgenin YİNE DE çökmeden
kurulduğu. Section 4'teki (ekran yakalama) bir test `_btn_pano`'ya
kalıntı bir referans taşıyordu — `_btn_yazdir`'e güncellendi.

SECURITY.md §4.4'e (EN+TR) eklendi — panoyu KALDIRMA gerekçesi ve yazdırma
eklemesinin neyi kapattığı. README.md'nin "Anahtar Bölme" satırı güncellendi.

Tam test suite: 3066 passed, 4 skipped (bir önceki turdan +2 — 11 yeni test,
9 pano testi silindi). Ruff/mypy/bandit temiz (mypy'de aynı sayıda —11—
pre-existing PySide6-stub `attr-defined` yanlış pozitifi, `git stash` ile
karşılaştırılıp doğrulandı; bandit temiz, önceki turdan fark yok).

---

## B-092 — AAD'deki `original_sha256` anahtarsız bir DOĞRULAMA-ORACLE'I: kaldırmak/HMAC'lemek, ayrı bir mimari karar olarak izleniyor

**K3-2a — "AAD'den düz metin dosya adı hash'ini (SHA-256) kaldır veya
HMAC'le" — bu haliyle KAPATILMADI, WONTFIX (bu turda).** Talimat görevi
"bu turda yalnızca hash'i kaldırmak veya anahtarlı HMAC'e çevirmek yeterli"
diye küçük bir düzeltme varsayıyordu. Analiz (önceki tur, kod
değiştirmeden) gerçek düzeltmenin RFC 3161'in "anahtarsız doğrulama"
özelliğini KALICI olarak feda eden, dört CORE modülü + bir CLI aracı +
~900 satır test kapsayan, kendi başına AYRI bir mimari karar olduğunu
ortaya çıkardı. Kapsamı buraya, B-092'ye taşındı — sessizce ertelenmiş
değil, NEDEN ertelendiği aşağıda.

**1. Sorunun tam tanımı.** `CORE/crypto.py::encrypt_file()` her dosyanın
DÜZ METİN içeriğinin SHA-256'sını (`original_sha256`) AAD'ye (Additional
Authenticated Data) yazıyor — AAD'nin bütünlüğünü GCM tag'i koruyor ama
AAD ŞİFRELENMİYOR, dosya başlığında AÇIK duruyor. Sonuç: M2 erişimine
sahip biri — yalnızca bir `.hcl` dosyasının KOPYASI, DB'ye/kimlik
bilgisine/çalışan uygulamaya erişim GEREKMEDEN (SECURITY.md §1.1'in M2
tanımı: "holds a copy of the data, not the machine") — elinde tuttuğu bir
ADAY belgeyi kendisi hash'leyip başlıktaki değerle karşılaştırarak, kasa
içeriğini HİÇ çözmeden, o belgenin TAM OLARAK orada olduğunu %100
kesinlikle doğrulayabiliyor. Bu, `filename`/`user_id`/`hwid` gibi diğer
AAD alanlarının sağladığı SIRADAN metadata sızıntısından NİTELİKSEL olarak
farklı: SHA-256 herkesin çalıştırabileceği, anahtarsız bir fonksiyon
olduğu için pasif sızıntıyı bir DOĞRULAMA ORACLE'INA çeviriyor.

**2. Tuz işe yaramıyor.** Tuz rainbow-table (önceden hesaplanmış, ÇOK
hedefe karşı paylaşılan tablo) saldırılarına karşı işe yarar; burada
saldırgan TEK bir adayı TEK bir hedefe karşı DOĞRUDAN karşılaştırıyor.
Anahtarsız kalması için tuzun da AAD'de AÇIK durması ZORUNLU — saldırgan
onu aday belgesine ekleyip AYNI sıfır maliyetle kendi hash'ini yeniden
üretir. Yalnızca gerçek bir SIR (anahtar) bunu kapatır — ki bu da
"anahtarsız damgalama" tanımıyla DOĞRUDAN ÇELİŞİR: hesaplamak/doğrulamak
için sır gerekiyorsa, artık anahtarsız değildir.

**3. Gerçek çözümün kapsamı.** `original_sha256`'yı AAD'den kaldırmak/
HMAC'lemek, RFC 3161'in "anahtar İSTEMEZ, düz metne HİÇ dokunmaz" tasarım
hedefini (`CORE/timestamp.py` modül docstring'i, satır 53) KALICI olarak
feda ediyor:
  - `CORE/timestamp.py::timestamp_file()` — `key` ZORUNLU hâle gelmeli;
    `verify_file()` akış sırasında düz metnin hash'ini de hesaplayacak
    şekilde değiştirilmeli (mümkün, ama gerçek bir kod değişikliği).
  - `CORE/timestamp_verify.py::verify_timestamp()` — bugün `key`
    parametresi YOK (satır 512-517, TASARIM GEREĞİ); eklenmesi ve 10.
    doğrulama adımının (AAD'deki `original_sha256` ile TSTInfo özetini
    karşılaştırma, satır 77) YENİDEN YAZILMASI gerekir.
  - `CORE/timestamp_report.py`, `CORE/merkle.py` — aynı alanı okuyan
    raporlama ve toplu-damgalama (Merkle ağacı) yolları.
  - `CORE/verify_timestamp_cli.py` — `--verify-timestamp`'in "air-gapped,
    anahtarsız doğrulama" iddiası ANLAMINI KAYBEDER.
  - Testler: `tests/test_timestamp.py`'deki 20 `timestamp_file()`
    çağrısının 17'si (%85) anahtarsız; `tests/test_timestamp_batch.py`
    (25 nokta), `tests/test_timestamp_verify.py` (589 satır),
    `tests/test_verify_timestamp_cli.py` (277 satır) — büyük kısmı
    yeniden yazılmalı, toplam ~900 satır.
  - **Geriye dönük ONARILMIYOR:** GCM AAD'si ciphertext'e bağlı; anahtar
    olmadan mevcut bir dosyanın AAD'sinden bir alan sessizce
    çıkarılamaz/değiştirilemez. Yalnızca BUNDAN SONRA şifrelenen dosyalar
    korunur — mevcut HER `.hcl` dosyası, yeniden şifrelenmedikçe (ayrı bir
    migrasyon işi) bu saldırıya KALICI olarak açık kalır.

**4. Belgeleme — kod DEĞİL, yalnızca doğru/güncel risk tanımı.**
SECURITY.md §1.2'nin (EN+TR) AAD gizliliği satırı ve ardından gelen
paragraf güncellendi: "M2: readable in header" artık yalnızca bir sızıntı
değil, bir DOĞRULAMA ORACLE'I olarak netleştirildi, tuzun neden işe
yaramadığı kısaca gerekçelendirildi, ve bu madde (B-092) işaret edildi.
§3'ün "Metadata confidentiality"/"Metadata gizliliği" paragrafı zaten
"confirming a suspected file without decrypting it" diyordu — B-092 bunu
DEĞİŞTİRMEDİ, yalnızca §1.2'ye aynı netliği taşıdı.

**5. Kapsam kararı.** Bu, K3-2a'nın "devamı" DEĞİL — kendi başına AYRI bir
mimari karar. B-087'nin (RFC 3161 mührü/İmzalı Rapor) izlediği AYNI ilke:
kapsamı sessizce genişletmek yerine, gerçekten isteniyorsa bilinçli,
ayrı bir karar olarak buraya işlendi. Ne zaman ele alınacağı — ve
"anahtarsız RFC 3161 doğrulaması" özelliğinin kalıcı olarak feda edilip
edilmeyeceği — kullanıcı kararına bağlı.

Ayrıntı: SECURITY.md §1.2 (EN+TR), §1.1 (M2 tanımı), §3 "Metadata
confidentiality"/"Metadata gizliliği", §4.9 (RFC 3161 sınırları).

Bu turda kod/test değişikliği YOK — yalnızca dokümantasyon.

---

## B-093 — Doğrulama Merkezi: üç doğrulama + Kurtarma Parçası tek sayfada; mimari karar GuvenlikView'ın YERİNE geçmesiydi

Görev: Damga Doğrula, Yedek Doğrula ve Denetim Zincirini Doğrula
kartlarını mockup'taki gibi tek bir "Doğrulama Merkezi" ekranında
birleştir, Kurtarma parçası kartını da aynı sayfaya ekle. Önce mimari
kararı ver: mevcut GüvenlikView'ın yerini mi alacak yoksa ayrı bir
sidebar öğesi mi olacak.

**Mimari karar — GuvenlikView'ın YERİNE geçti, ayrı bir sidebar öğesi
AÇILMADI.** `UI/GuvenlikView.py` ZATEN üç doğrulamayı tek sayfada
topluyordu ("Güvenlik" adıyla) — dördüncü bir kartla GENİŞLETMEK aynı
fikrin doğal devamıydı. Ayrı bir sayfa açmak, üç kartı (damga/yedek/
zincir) İKİ yerde göstermek anlamına gelirdi — modülün kendi "iki
çağıran, tek gövde" kuralının SAYFA seviyesinde ihlali olurdu. Sınıf/
dosya adı (`GuvenlikView`/`GuvenlikView.py`) ve dahili özellik adları
(`_guvenlik_view`, `nav_guvenlik`) BİLEREK DEĞİŞTİRİLMEDİ — B-089'un
"dahili adları değiştirmek kullanıcı görmeyen bir yerde risk almak"
kararıyla AYNI; yalnızca `SAYFA_ADI` ("Güvenlik" → "Doğrulama Merkezi")
ve görünen metinler değişti.

**Kurtarma Parçası kartı — gövde AdminSettingsView'den ÇIKARILDI.**
`AdminSettingsView._on_kurtarma_parcasi()`'nin TÜM gövdesi (PIN sorgusu,
`export_recovery_share`, `build_export`, `RecoveryShareDialog`, B-064/
B-066 canlı-yetki kontrolü) `UI/security_actions.py::
kurtarma_parcasini_goster()`'e taşındı — zincir doğrulamasının B-085/086
turlarında `UsbTokensView`'den `security_actions.py`'ye taşınmasıyla AYNI
desen ("iki çağıran, tek gövde"). AdminSettingsView'in düğmesi ve
Doğrulama Merkezi'nin yeni kartı artık AYNI fonksiyonu çağırıyor;
`AdminSettingsView.py`'deki `export_recovery_share`/`has_recovery_share`
importları artık kullanılmadığı için kaldırıldı.

**Kurtarma Parçası kartı KENDİ, ayrı rol kapısını taşıyor.** Diğer üç
kart salt okuma; sayfa Salt Okunur DIŞINDA her role açık
(`GUVENLIK_SALT_OKUNURA_ACIK`, B-034 hâlâ açık). Kurtarma parçası
SECURITY.md §4.4'ün "en hassas ekranı" açıyor — bu yüzden YALNIZCA
yönetici görüyor. İki katman: (1) `GuvenlikView.kurtarma_karti_goster()`
kartı yalnızca `is_admin_role` iken gösteriyor, `main_window.py::
_apply_role_restrictions()`'tan HER rol kontrolünde çağrılarak (rol
oturum sırasında düşerse kart da geri gizlenir, B-066) — kart varsayılan
olarak GİZLİ kuruluyor, "açan gelene kadar kapalı" ilkesiyle; (2)
`kurtarma_parcasini_goster()`'in KENDİSİ `admin_common.
yonetici_hala_yetkili()` ile AYNI canlı-yetki kontrolünü TAŞIYOR — kart
gizliyken bile doğrudan çağrılsa reddedilir. UsbTokensView/
PendingRegistrationsView'in "koşulsuz kurulma" turlarında (B-084/B-085)
kurulan İKİ KATMANLI desenin AYNISI.

**Test.**
  1. Dört kart/düğme sayfada (`test_dort_kart_da_sayfada`,
     `test_dort_dugme_de_var`).
  2. İKİ ÇAĞIRAN, TEK GÖVDE — yapısal (AST): GuvenlikView/AdminSettingsView
     hiçbiri kurtarma parçasını kendisi UYGULAMIYOR
     (`test_kurtarma_govdesi_AdminSettingsView_den_CIKARILDI`,
     `test_gorunum_dogrulamayi_KENDISI_uygulamiyor`'un genişletilmiş
     yasak kümesi); paylaşılan gövdenin İÇİNDE zincirin TAMAMI
     (`test_kurtarma_govdesi_PAYLASILAN_yerde_ZINCIRIN_TAMAMI`,
     `test_PIN_gercekten_KULLANICIDAN_geliyor`,
     `test_adminpanel_payi_DISKE_yazmiyor` — üçü de artık
     `security_actions.py`'yi ölçüyor).
  3. Rol kapısı: kart varsayılan gizli, `kurtarma_karti_goster()` açıp
     kapatıyor, diğer üç kartı ETKİLEMİYOR,
     `_apply_role_restrictions()`'ın onu GERÇEKTEN `is_admin` değeriyle
     çağırdığı AST ile kanıtlandı.
  4. **Görevin asıl istediği — bağımsızlık:**
     `test_bir_kartin_hatasi_DIGER_UCUNU_bozmuyor` yedek kartının
     çağırdığı işleyicisini BİLEREK patlatıyor (yakalanmamış bir
     `RuntimeError`), sonra AYNI `gorunum` nesnesinde damga, zincir VE
     kurtarma kartlarının hâlâ normal çalıştığını doğruluyor — GuvenlikView
     paylaşılan hiçbir durumu bu hatadan ötürü bozmadı.
     `test_gorunum_tercihi_hatadan_SONRA_da_ayni_kalir` aynı senaryoda
     tek paylaşılan durumun (`Gelişmiş`/`Basit` tercihi) da bozulmadığını
     ayrıca ölçüyor.
  5. `tests/test_slide_over.py::test_RecoveryShareDialog_HALA_modal`
     (başka bir turdan) `RecoveryShareDialog`'un çağrı yerini
     `AdminSettingsView.py`'den `security_actions.py`'ye güncellendi —
     modal kalma iddiası DEĞİŞMEDİ, yalnızca çağrı yeri.

**Mutasyon kanıtı.** `_apply_role_restrictions()`'taki
`kurtarma_karti_goster(is_admin)` çağrısını `kurtarma_karti_goster(True)`
olarak sabitlemek `test_rol_kisitlamasi_kurtarma_kartini_GERCEKTEN_
cagiriyor`'u kırdı; `_kartlar()`'daki varsayılan-gizli satırını kaldırmak
`test_kurtarma_karti_VARSAYILAN_gizli`'yi kırdı. İkisi de geri alındı.

SECURITY.md §4.4'e (EN+TR) eklendi — ikinci UI giriş noktasının AYNI
kod/kapı olduğu, ve neden salt okunura AÇILMADIĞI.

Tam test suite: 3076 passed, 4 skipped (bir önceki turdan +10 — 12 yeni
test `test_guvenlik_view.py`'de, 4 test yeniden yapılandırıldı
`test_recovery_share_ui.py`'de, 1 test güncellendi `test_slide_over.py`'de).
Ruff/bandit temiz; mypy'de değişiklik yok (aynı 768 pre-existing PySide6-
stub hatası, `git stash` ile karşılaştırılıp doğrulandı).

---

## B-094 — Genel dosya görünümüne çoklu seçim (kutucuk) + toplu işlem çubuğu: mevcut sağ-tık gövdesine ikinci giriş noktası, K1-14 rol denetimi kanıtlandı

Görev: Genel dosya görünümüne çoklu seçim (checkbox) ve toplu işlem
çubuğu ekle (Etiket ata / Kritik'e taşı / İndir / İmhaya at). Her toplu
işlemin tekli fonksiyonları mı sırayla çağıracağı yoksa toplu bir
fonksiyon mu gerekeceğine karar ver — ama en kritik nokta: K1-14'ün DB
seviyesi rol denetiminin toplu işlemlerde de aynı şekilde çalıştığından
emin ol.

**Keşif — arka uç ZATEN vardı.** `UI/main_window_bulk.py::
BulkActionsMixin` çoklu satır seçimini (sağ tık menüsü, `QTableWidget.
ExtendedSelection`) ZATEN destekliyordu — Toplu Etiket Ata, Seçilenleri
İndir, Karantinadan Çıkar, Kritik'e Taşı, İmha Odasına At, hepsi çalışan,
denetim kaydı düşen kod. Görev genuine olarak YENİ bir arka uç DEĞİL,
YENİ bir GİRİŞ NOKTASI (kutucuk + kalıcı araç çubuğu) istiyordu —
mockup'ın istediği "Karantinadan Çıkar" hariç dört eylem.

**Tekli mi toplu mu — karar: SIRALI, mevcut `_on_ctx_bulk_*` gövdeleri
DEĞİŞTİRİLMEDİ.** Zaten dosya başına bir `db.execute()` döngüsü
kullanıyorlardı, TEK bir toplu `UPDATE ... WHERE id IN (...)` değil.
Gerekçe (kod değiştirmeden, yalnızca karar): (1) dosya başına AYRI
denetim kaydı (`target_id=fid`) düşüyor, toplu SQL bunu ya kaybederdi ya
KENDİ döngüsünü gerektirirdi; (2) K1-14'ün rol denetimi HER `execute()`
çağrısında çalışıyor, döngü zaten salt okunur bir rolü İLK yinelemede
kapalı hatayla durduruyor — tek ifadeye sıkıştırmak reddi SADECE atomik
GÖSTERİRDİ, korumayı değiştirmezdi (rol tek tıklama İÇİNDE değişmiyor).

**Uygulama.**
  - `UI/main_window_table.py::_insert_row()` — sütun 0'daki dosya adı
    öğesine `Qt.ItemIsUserCheckable` + `setCheckState(Unchecked)`. YENİ
    bir sütun AÇILMADI: ayrı sütun `_set_scan_badge()` dahil sütun
    indeksine bağlı HER yeri değiştirmeyi gerektirirdi, kozmetik bir
    eklenti için orantısız risk.
  - `UI/main_window_layout.py::_make_bulk_toolbar()` — 1+ kutucuk
    işaretliyken görünen araç çubuğu (`_make_content()`'in tablo
    ÖNCESİNE eklendi, sayfa geçişleriyle otomatik gizlenip gösteriliyor
    — ayrı bir `setVisible` kablolaması GEREKMEDİ).
  - `UI/main_window_bulk.py` — `_checked_selection()` (kutucuklardan
    `(rows, file_ids, labels, filepaths)` üretir, sağ-tık menüsünün
    seçili SATIRLARDAN aynı şekli üreten döngüsünün kutucuk karşılığı),
    `_on_table_item_changed()` (araç çubuğunu gösterip/gizler,
    Kritik'e Taşı/İmhaya At'ın `removeRow()`'undan SONRA elle de
    çağrılıyor — o çağrı `itemChanged` TETİKLEMİYOR), dört
    `_on_bulk_toolbar_*` — hiçbiri YENİ bir toplu işlem UYGULAMIYOR,
    hepsi mevcut `_on_ctx_bulk_*` gövdelerini çağırıyor.

**Test — `tests/test_bulk_toolbar_rbac.py` (7 test).**
  1. Salt Okunur rol, kutucuklarla iki dosya işaretleyip Kritik'e Taşı/
     İmhaya At'a tıklayınca İKİSİ de REDDEDİLİYOR — DB etiketleri
     DEĞİŞMİYOR, satırlar tablodan KALDIRILMIYOR, `rbac_write_rejected`
     denetim kaydı düşüyor, pencere KİLİTLENMİYOR (RBAC reddi B-064/
     B-066'nın canlı-yetki kilitlemesiyle KARIŞTIRILMIYOR).
  2. Yetkili rol (Yönetici VE Standart), üç dosyadan İKİSİNİ işaretleyip
     toplu işlem çağırınca YALNIZCA işaretli ikisi etkileniyor, İŞARETSİZ
     üçüncüsü DEĞİŞMEDEN kalıyor — araç çubuğu işlem sonrası otomatik
     GİZLENİYOR.
  3. Kutucuk durumu, `QTableWidget`'ın native satır seçiminden (Ctrl/
     Shift-tık, mavi vurgu) BAĞIMSIZ okunuyor — yalnızca bir satırı
     TIKLAMAK (kutucuğu işaretlemeden) toplu araç çubuğunu TETİKLEMİYOR.

**Mutasyon kanıtı.** `_checked_selection()`'daki kutucuk filtresini
kaldırmak "yalnızca işaretliler etkileniyor" ve "native seçim ≠ kutucuk"
testlerini kırdı; `DB/db_manager.py::_yazma_yetkisini_dogrula()`'daki
`can_write()` kontrolünü (K1-14) devre dışı bırakmak İKİ RBAC ret testini
kırdı. Üçü de geri alındı.

**Keşif — test kurulumu sırası.** İlk taslak, dosyaları DB'ye eklemeden
ÖNCE pencereyi kurup SONRA `_insert_row()`'u elle TEKRAR çağırıyordu —
`HycleusWindow.__init__()` ZATEN "Genel" etiketli dosyaları otomatik
yüklediği için bu satırları İKİLİYORDU (rowCount 2 yerine 4). Ayrıca
`_apply_role_restrictions()`'ın `__init__` İÇİNDE ÇAĞRILMADIĞI (üretimde
`main.py`'nin `.show()` SONRASI tetiklediği ayrı bir adım, `tests/
test_app_mode_ui.py`'nin zaten bildiği bir gerçek) gözden kaçmıştı — bu
olmadan `DBManager()._role` `None` kalıyor ve K1-14 rolü HİÇ KONTROL
ETMEDEN geçiyordu. İkisi de testler YAZILIRKEN, kod değil test
düzeltilerek bulundu ve giderildi.

SECURITY.md §4.17'ye (EN+TR) eklendi — üçüncü giriş noktasının AYNI kapıya
ulaştığı, ve toplu-yazma kısayoluna neden büyümediği.

Tam test suite: 3085 passed, 4 skipped (bir önceki turdan +9 — yeni
`tests/test_bulk_toolbar_rbac.py`). Ruff/bandit temiz (bandit'in
`UI/main_window_table.py` üzerindeki 2 bulgusu ÖNCEKİ turdan değişmedi,
`git stash` ile karşılaştırılıp doğrulandı). mypy: `UI/main_window_
layout.py`'de +19 hata — hepsi bu depoda ZATEN yaygın olan "mixin
kendi kardeşinin metodunu göremiyor" kalıbı (`_on_context_menu` gibi
PRE-EXISTING örnekleri aynı dosyada zaten var); GERÇEK bir tip hatası
değil, `HycleusWindow`'un çoklu-miras MRO'sunu mypy'nin dosya-başına
denetiminin GÖRMEMESİ — kod tabanının ZATEN 376 örnekle yaşadığı AYNI
sınır, yeni bir sınıf değil.

---

## B-095 — Giriş ekranındaki PIN alanı tek kutudan 6 kutucuğa çevrildi: yapıştırma otomatik dağıtıyor, PIN politikasıyla geriye uyumluluk korundu

Görev: Giriş ekranındaki PIN alanını tek bir metin kutusundan mockup'taki
gibi 6 ayrı rakam kutusuna çevir. Yapıştırma davranışını da düşün —
kullanıcı 6 haneli PIN'i tek seferde yapıştırırsa otomatik dağıtılsın.

**Uyumluluk riski — önce netleştirildi.** `CORE/pin_policy.py` PIN'in tam
6 hane ya da yalnızca rakam olacağını HİÇBİR ZAMAN garanti etmez:
`LOGIN_MIN_LEN=4` (6 hane politikasından önce kaydolmuş kullanıcıları
kasıtlı kabul eder), `PIN_MAX_LEN=32` GUI akışlarında hiç zorlanmaz, ve
karakter sınıfı için (rakam-dışı harf/sembol PIN'ler dahil) hiçbir kısıt
yok — yalnızca Authenticator kodu `isdigit()` ile denetleniyor, PIN
değil (`CORE/pin_policy.py`, `CORE/pin_rotation.py`, `CORE/setup_usb.py`,
`UI/RegisterDialog.py`, `UI/ProfileView.py`, `UI/login_dialog.py`
üzerinde grep ile doğrulandı). Naif bir "6 rakam, digit-only" kutucuk
tasarımı eski/uzun/rakam-dışı PIN sahiplerini KİLİTLERDİ. Karar: kutular
KARAKTER SINIFINI KISITLAMIYOR ve SONUNCU kutucuk taşıyor (6. karakterden
sonrası da oraya yazılıyor) — mockup'ın "6 kutu" görünümü karşılanıyor.

DÜZELTME (aşağıdaki "devam" bölümüne bkz.): "mevcut HİÇBİR PIN'in giriş
yapma yeteneği bozulmuyor" ifadesi TAM doğru değildi — sonuncu kutu
`CORE.pin_policy.PIN_MAX_LEN`e (32) sınırlı olarak uygulandı, yani toplam
`5 + PIN_MAX_LEN` (37) karakterden UZUN bir PIN varsa (aşırı olası
değil, ama teorik olarak mümkün — üst sınır hiçbir yerde ayrıca
doğrulanmıyor) bu widget'a TAM giremez. Kabul edilen dar bir ödünleşim,
"asla bozulmaz" değil.

**Uygulama — `UI/login_dialog.py`.**
  - `_PinDigitBox(QLineEdit)` — tek kutucuk. `paste()`'i override ediyor
    (Ctrl+V VE sağ-tık "Yapıştır" ikisi de bu ortak Qt kancasından geçiyor
    — `QLineEdit`'te `insertFromMimeData` YOK, o yalnızca `QTextEdit`
    ailesinde var; ilk taslak bunu yanlış varsaymıştı, mypy'nin "undefined
    in superclass" uyarısıyla YAKALANDI ve düzeltildi). `keyPressEvent`'i
    override ederek BOŞ kutuda Backspace'i önceki kutuya odak olarak ele
    alıyor.
  - `_PinBoxInput(QWidget)` — 6 `_PinDigitBox`; ilk 5'i `maxLength(1)`,
    sonuncusu `maxLength(PIN_MAX_LEN)` (taşma burada). `text()`/`setText()`/
    `setFocus()`/`clear()` — `LoginDialog._on_login()`'in ve MEVCUT
    testlerin (`dlg._pin_input.setText(pin)`) beklediği `QLineEdit`
    arayüzünü taklit ediyor. `setEnabled()` ayrıca override GEREKMEDİ —
    Qt'de bir üst widget'ı disable etmek çocuklarına otomatik yayılıyor
    (`_apply_lockout`/`_tick_lockout` bunu zaten kullanıyordu).
  - Yapıştırma: hangi kutu odaktaysa fark etmeksizin metni BAŞTAN (1.
    kutudan) dağıtıyor — kullanıcı "PIN'i tek seferde yapıştırınca"
    tamamının ilk kutudan yerleşmesini bekliyor, odak konumuna göre farklı
    davranmak kafa karıştırırdı.
  - `_build_register_page()`/`_build_setup_ui()`'nin KENDİ `_pin_input`
    alanları (ayrı, karşılıklı dışlayıcı sayfalar) DOKUNULMADAN kaldı —
    görev yalnızca giriş ekranını kapsıyordu. `LoginDialog._pin_input`ın
    sayfaya göre `QLineEdit | _PinBoxInput` olabilmesi için sınıf
    seviyesinde açık bir Union tip belirtimi eklendi (mypy'nin tek
    öznitelik için iki sayfadaki farklı atamaları reddetmesini önlemek
    için).

**Keşif — mevcut testler `.setText()` bekliyordu.** `tests/
test_pin_rotation_ui.py` ve `tests/test_usb_weak_binding_ui.py`
`dlg._pin_input.setText(pin)` çağırıyordu; `_PinBoxInput` ilk taslakta
`setText()` UYGULAMIYORDU — TAM test suite çalıştırılınca 9 test
`AttributeError` ile KIRILDI (yalnızca kendi yeni test dosyamı
çalıştırırken GÖRÜNMEDİ). `setText()` eklenip (`_yapistir()`yle aynı
dağıtım mantığını, ama odak DEĞİŞTİRMEDEN paylaşan bir `_dagit()`
yardımcısına çıkarılarak) düzeltildi; TAM suite tekrar çalıştırılıp 9'u da
yeşile döndüğü doğrulandı. Ders: bu depoda `_pin_input` gibi paylaşılan
bir özniteliğe dokunan bir değişikliğin GÜVENLİ olduğunu yalnızca YENİ
test dosyasını çalıştırarak DEĞİL, TAM suite'i çalıştırarak doğrulamak
gerekiyor.

**Keşif — `.show()` sonrası `qWaitForWindowExposed()` TAM suite'te
çöktü.** İlk fixture taslağı `QTest.qWaitForWindowExposed(w)` çağırıyordu;
tek başına ya da birkaç dosyayla çalıştırılınca sorunsuzdu, ama TÜM
paket (~3000+ test) art arda çalıştırıldığında offscreen platform'da bir
access-violation ile ÇÖKTÜ. Bu depoda `qWaitForWindowExposed` kullanan
BAŞKA hiçbir test dosyası YOK — diğerleri (`test_theme_picker.py` gibi)
yalnızca `.show()` kullanıyor. O çağrı `qapp.processEvents()` ile
DEĞİŞTİRİLDİ; TAM suite tekrar çalıştırılıp çökme YENİDEN ÜRETİLEMEDİ.

**Test — `tests/test_pin_giris_kutulari.py` (9 test).** Tek tek yazmanın
kutuları doldurup odağı ilerlettiğini, boş kutuda Backspace'in önceki
kutuya döndüğünü, tam-6-haneli yapıştırmanın doğru dağıldığını, odaktaki
kutudan BAĞIMSIZ baştan dağıtıldığını, 4 haneli (eski) PIN yapıştırmanın
kalan kutuları boş bıraktığını, 10 haneli (uzun) PIN yapıştırmanın
sonuncu kutuda taştığını, rakam-dışı karakterlerin reddedilmediğini,
`clear()`'ın tüm kutuları boşalttığını, ve gerçek `LoginDialog`'un giriş
sayfasının `_PinBoxInput` kullandığını (tek kutuya GERİ DÖNÜLMEDİĞİni)
doğruluyor.

**Mutasyon kanıtı (geçici, geri alındı).** `_PinDigitBox.paste()`'in
yakalamasını devre dışı bırakmak 4 yapıştırma testini kırdı (tümü ilk
karaktere kısaltılmış PIN'ler görüyordu); `_kutu_degisti()`'nin
odak-ilerletmesini kaldırmak tek-tek-yazma VE rakam-dışı-karakter
testlerini kırdı. İkisi de geri alındı, `grep -n "MUTATION"` ve `git
diff --stat` ile temiz dönüş doğrulandı.

Güvenlik-ilgisi değerlendirmesi: yapıştırma zaten ESKİ tek kutulu alanda
da native Qt davranışıyla ÇALIŞIYORDU (maxLength yoktu) — bu değişiklik
YENİ bir yetenek EKLEMİYOR, yalnızca aynı davranışı 6 widget'a
dağıtıyor. `_on_login()`'in doğrulama mantığı DOKUNULMADI. SECURITY.md
güncellemesi gerekli GÖRÜLMEDİ.

Tam test suite: 3096 passed, 4 skipped (bir önceki turdan +11 — yeni
`tests/test_pin_giris_kutulari.py`, `qWaitForWindowExposed` çökmesi
düzeltildikten sonra tam paket tek çöküşsüz geçti). Ruff temiz. mypy:
`UI/login_dialog.py`'de +2 hata (`Key_Backspace`, `QSizePolicy.Fixed`) —
dosyada ZATEN 39+ örnekle yaygın olan "PySide6 enum'ları mypy'nin
göremediği" kalıbı, gerçek bir tip hatası değil. bandit: tek bulgu (B110,
satır ~1274) DEĞİŞMEDİ — bu turdan ÖNCE de oradaydı (vault açma hata
yolu), benim eklediğim kod DEĞİL.

**B-095 (devam, aynı gün) — `setText()`/`text()` round-trip'i ve son
kutunun sınırı ayrıca doğrulandı.** Talep: `_PinBoxInput.setText()` ile
ayarlanan bir PIN'in `.text()` ile karakter kaybı OLMADAN geri okunduğunu,
ve son kutunun (`PIN_MAX_LEN`'e sınırlı) gerçek bir taşma sınırının olup
olmadığını göster.

**Round-trip — `tests/test_setText_text_round_trip_karakter_kaybi_olmadan`
(5 parametrize senaryo).** Tam 6 hane, kısa 4 hane (legacy), 5 hane, uzun
14 karakter, rakam-dışı karakterli bir dize — hepsi `setText(pin)` →
`.text() == pin` birebir eşleşiyor.

**Son kutunun sınırı — GERÇEK, `PIN_MAX_LEN`'e (32) eşit.** Kod:
`UI/login_dialog.py::_PinBoxInput.__init__`, `kutu.setMaxLength(1 if i <
5 else PIN_MAX_LEN)` — ilk 5 kutu 1 karakterle, sonuncusu 32 karakterle
sınırlı (SINIRSIZ değil, ama pratikteki hiçbir gerçekçi PIN uzunluğu bunu
zorlamıyor). Üç test bunu doğruluyor:
  - `test_son_kutunun_gercek_bir_maxLength_siniri_var` — sınırı doğrudan
    `.maxLength()` ile okuyor.
  - `test_uzun_pin_setText_ile_/_yapistirma_ile_tasan_karakterleri_
    kesmiyor` — 14 karakterlik (taşan kısım yalnızca 9 karakter, 32'nin
    çok altında) bir PIN'in HEM `setText()` HEM `paste()` yolunda hiçbir
    karakter kaybetmediğini kanıtlıyor.
  - `test_pin_max_len_asilinca_son_kutu_gercekten_kesiyor` — sınırı
    BİLEREK aşan (toplam 45 karakter, `5+PIN_MAX_LEN`=37'yi 8 aşıyor) bir
    PIN ile GERÇEK kesme davranışını gösteriyor: `.text()` ilk 37 karaktere
    kısalıyor, ORİJİNALLE eşleşmiyor. Bu, Qt'nin `QLineEdit.setText()`nin
    kendi `maxLength`'i aştığında verilen metni SESSİZCE ilk N karaktere
    kısalttığı (boş bir `QLineEdit` ile ayrıca doğrulandı) gerçeğinin
    doğrudan sonucu.

**DÜZELTME (B-095, aynı gün, ikinci geçiş) — bu sınırın kaynağı, bir
ÖNCEKİ paragrafta VE test yorumlarında YANLIŞ belgelenmişti.** İlk
yazımda "`PIN_MAX_LEN` GUI'de asla POLİTİKA olarak zorlanmadığı için bu
widget-seviyesi sınır, üst katmanda karşılığı OLMAYAN, yalnızca Qt'nin
kendi kısıtı" deniyordu — bu YANLIŞ ve kendi içinde ÇELİŞKİLİYDİ: aynı
turda "son kutu `PIN_MAX_LEN`'e sınırlı" da yazılmıştı, ikisi birlikte
doğru olamazdı. Kod incelemesiyle netleştirildi:
  - `UI/login_dialog.py:61` — `from CORE.pin_policy import LOGIN_MIN_LEN,
    PIN_MAX_LEN, PIN_MIN_LEN, validate_new_pin` — `PIN_MAX_LEN` GERÇEKTEN
    `CORE/pin_policy.py`'den ithal ediliyor.
  - `UI/login_dialog.py:419` — `kutu.setMaxLength(1 if i < self.
    _KUTU_SAYISI - 1 else PIN_MAX_LEN)` — bu İTHAL EDİLEN isim, AYRI/elle
    yazılmış bir `32` sabiti YOK.
  Doğru ifade: `CORE/pin_policy.py`'nin GENEL "PIN_MAX_LEN hiçbir GUI
  akışında zorlanmaz" gerçeği hâlâ kayıt/ilk-kurulum sihirbazı ve kayıt
  ekranı için GEÇERLİ (o sayfaların `_pin_input`'ları hâlâ sınırsız
  `QLineEdit`) — ama GİRİŞ EKRANININ bu YENİ kutucuklu widget'ı için
  ARTIK GEÇERSİZ: bu widget `PIN_MAX_LEN`i GERÇEKTEN okuyor ve son
  kutuyu onunla sınırlıyor, toplam `5 + PIN_MAX_LEN` (bugün 37) karakter
  üst sınırı GETİRİYOR. Teorik (aşırı olası olmayan) bir ödünleşim: bu
  sınırdan uzun bir PIN'i olan bir kullanıcı (varsa) artık giriş
  ekranından PIN'ini TAM giremez — eski/kısa PIN'leri koruyan
  `LOGIN_MIN_LEN` mantığının TERSİNE, üst sınırda hiçbir koruma
  eklenmedi. `UI/login_dialog.py::_PinBoxInput` docstring'i ve
  `tests/test_pin_giris_kutulari.py::
  test_pin_max_len_asilinca_son_kutu_gercekten_kesiyor`'un yorumu buna
  göre düzeltildi.

**Yeni kalıcı test — `test_son_kutunun_pin_max_len_ile_CANLI_baglantisi`.**
Statik `== PIN_MAX_LEN` eşitliği (yukarıdaki ilk test) yalnızca BUGÜNKÜ
değerlerin TESADÜFEN aynı olduğunu kanıtlar — AYRI bir `32` sabitiyle de
geçerdi. Bu yeni test `UI.login_dialog.PIN_MAX_LEN`i (dikkat: `CORE.
pin_policy.PIN_MAX_LEN` DEĞİL) çalışan süreç İÇİNDE 20'ye monkeypatch'liyor
ve YENİ construct edilen bir `_PinBoxInput`'un son kutusunun bunu
GERÇEKTEN yansıttığını (`maxLength() == 20`) doğruluyor — canlı, aktif
tekil-kaynaklılık kanıtı. `UI.login_dialog.PIN_MAX_LEN` özellikle
yamalanıyor çünkü `from CORE.pin_policy import PIN_MAX_LEN` ithal ANINDA
bir DEĞER KOPYASI bağlıyor (Python'un `from X import Y` semantiği) —
ampirik olarak doğrulandı: `CORE.pin_policy.PIN_MAX_LEN`i ÇALIŞAN bir
süreçte SONRADAN değiştirmek `UI.login_dialog.PIN_MAX_LEN`i GÜNCELLEMEZ
(`pp.PIN_MAX_LEN = 999` sonrası `ld.PIN_MAX_LEN` 32 kaldı, ayrıca
doğrulandı).

**Ek doğrulama — GERÇEK kaynak dosyası değiştirilerek (taze süreç).**
`CORE/pin_policy.py`'deki `PIN_MAX_LEN = 32` GEÇİCİ olarak `20`'ye
değiştirildi, TAZE bir Python süreci başlatılıp hem `CORE.pin_policy.
PIN_MAX_LEN` hem `UI.login_dialog.PIN_MAX_LEN` hem YENİ construct edilen
bir `_PinBoxInput`'un son kutusunun `maxLength()`'i okundu — üçü de 20
verdi (taze süreçte İKİ modül de AYNI değeri sıfırdan ithal ettiği için
tutarlı — çalışan-süreçte-sonradan-yama senaryosundan FARKLI). Tam test
dosyası bu değişiklikle de 19/19 yeşil kaldı (testler `PIN_MAX_LEN`i
kendileri de dinamik ithal ettiği için). Sonra `CORE/pin_policy.py`
orijinaline geri alındı, `grep -n "MUTATION"` ve `git diff --stat` ile
temiz dönüş doğrulandı.

**Mutasyon kanıtı — yeni test gerçekten yakalıyor mu.** Son kutunun
`setMaxLength(... PIN_MAX_LEN)` çağrısı geçici olarak `setMaxLength(...
32)` (AYRI, elle yazılmış bir kopya) ile DEĞİŞTİRİLDİ —
`test_son_kutunun_pin_max_len_ile_CANLI_baglantisi` beklendiği gibi
`assert 32 == 20` ile KIRILDI (doğru teşhis mesajıyla: "ayrı, senkron-dışı
bir sabitten okunuyor olabilir"). Geri alındı, temiz dönüş doğrulandı.

**Mutasyon kanıtı (ikisi de geçici, geri alındı).**
  (a) `_dagit()`'in taşma yazımını `son.setText(metin[5:])`'ten
      `son.setText(metin[5:6])`'ya (yalnızca 1 taşan karakter) bozmak 6
      testi kırdı (round-trip'in 14-karakter ve rakam-dışı senaryoları
      dahil, hem taşma hem sınır-aşımı testleri). Geri alındı.
  (b) Son kutunun `setMaxLength(PIN_MAX_LEN)` çağrısını yapay olarak
      `setMaxLength(8)`'e düşürmek 5 testi kırdı (doğrudan `.maxLength()`
      testi dahil — 32 yerine 8 okundu). Geri alındı.
  İkisinde de `grep -n "MUTATION"` (temiz) ve `git diff --stat` (yalnızca
  beklenen dosya) ile dönüş doğrulandı.

Tam test suite: 3105 passed, 4 skipped (+9 — yeni round-trip/sınır
testleri). Ruff temiz.

---

## B-096 — USB kilit ekranı başlığı mockup'a uygun "Kasa Kilitlendi"ye çevrildi (yalnızca metin, mantık değişmedi)

Görev: "Kayıtlı USB Token Çıkarıldı" kilit ekranı metnini mockup'taki
"Kasa kilitlendi" metnine ve tonuna güncelle — yalnızca metin/kopya
değişikliği, mantığa dokunma.

**Değişiklik.** `UI/main_window.py::HycleusWindow._LOCK_MESSAGES["usb"]`
başlığı "Kayıtlı USB Token Çıkarıldı"dan "Kasa Kilitlendi"ye çevrildi
(dict'in Title Case kuralına uygun — bkz. "Oturum Kilitlendi", "Erişim
İptal Edildi"). Alt metin DOKUNULMADI ("Oturuma devam etmek için USB'yi
yeniden takın — algılanınca otomatik devam eder") — talep yalnızca
başlığı adlandırıyordu, alt metnin içeriği hâlâ doğru/gerekli.

**Kapsam DIŞI bırakılan, kasıtlı.** `UI/main_window_lock.py:134`'teki
`_LockOverlay.__init__`'in inşa-anındaki varsayılan `QLabel("USB Token
Çıkarıldı")` metnine DOKUNULMADI — `set_message()` HER ZAMAN `.show()`
öncesi çağrıldığı için (bkz. satır 317/321) bu metin kullanıcıya HİÇBİR
ZAMAN görünmüyor; değiştirmek "mantığa dokunma" sınırının dışına
taşırdı ve gereksizdi. `tests/test_lock_overlay.py::
test_overlay_defaults_to_the_usb_message` bu inşa-anı varsayılanını
zaten test ediyordu, DOKUNULMADI, hâlâ geçiyor.

**Test güncellemesi — beklenen yan etki, mantık DEĞİL.**
`tests/test_lock_overlay.py`'deki 5 test, GERÇEK kilit akışının
(`_lock("usb")` → `_LOCK_MESSAGES["usb"]` → `set_message()`) ürettiği
başlığı `"USB" in ...` alt dizesiyle doğruluyordu — yeni başlık "USB"
içermediği için bu beş assert YANLIŞ (ama anlamsız) bir kırılmayla
başarısız olurdu. Alt dize `"Kasa"`ya güncellendi (aynı hafif-dokunuşlu
stil, dosyanın geri kalanıyla tutarlı):
`test_usb_lock_shows_the_usb_message`,
`test_idle_lock_shows_the_idle_message` (negatif kontrol),
`test_remaining_reason_message_is_shown_after_partial_unlock`,
`test_idle_unlock_does_not_clear_a_usb_lock`,
`test_ucdan_uca_usb_cikarilinca_uyari_gosteriliyor_geri_takilinca_devam_ediyor`.

**Mutasyon kanıtı (geçici, geri alındı).** Başlığı `"MUTATION-DEGISTI"`ye
bozmak yukarıdaki 5 testin TAMAMINI beklenen nedenle kırdı; geri alındı,
`grep -n "MUTATION"` (temiz) ve `git diff --stat` (yalnızca beklenen 2
dosya) ile doğrulandı.

Etkilenen dosyalar: `tests/test_lock_overlay.py`,
`tests/test_authz_invariants.py`, `tests/test_checkout_ui.py`,
`tests/test_idle_lock.py`, `tests/test_main_window_smoke.py` — hepsi
çalıştırıldı (234 test), yeşil. Tam suite: 3106 passed, 4 skipped
(değişmedi — yeni test eklenmedi, yalnızca 5 assert güncellendi). Ruff
temiz.

---

## B-097 — Yedek manifestosuna tam şema yerine basit boyut/tip kapısı: ayrıştırıcı artık bozuk/kötü niyetli dosyaya güvenle çöküyor değil reddediyor

Görev: Yedek manifest dosyası için tam şema doğrulaması yerine önce basit
bir boyut/tip sınırı kontrolü ekle (riskin çoğunu bu bile kapatıyor).
Manifest ayrıştırıcının kötü niyetli/bozuk bir dosyaya karşı güvenli
başarısız olduğunu (crash etmediğini, güvenli bir hata döndürdüğünü)
doğrula.

**Keşif — çökme GERÇEKTİ, dört farklı şekilde.** Düzeltmeden ÖNCE, ampirik
olarak dört farklı istisna tipi doğrudan üretildi:
  1. Üst seviye JSON bir dict değil (liste) → `AttributeError` (`manifest.
     get(...)` çağrısında).
  2. `entries` alanı bir liste değil (string) → `TypeError`
     (`girdi["name"]`'de — string üzerinde integer-olmayan indeksleme).
  3. `entries` içindeki bir öğe dict değil (sayı) → `TypeError` (`girdi[
     "name"]`'de — sayı subscriptable değil).
  4. Bir girdide `size`/`sha256` eksik, AMA referans verdiği dosya
     GERÇEKTEN var → `KeyError`. (Dosya YOKSA `missing` listesine düşüp
     döngü erken `continue` ediyor, `girdi["size"]`'a hiç erişmiyor — bu
     çökme yalnızca dosyanın GERÇEKTEN var olduğu senaryoda tetikleniyor,
     ilk denemede bu ayrıntı kaçırılıp "eksik-anahtar" senaryosu yanlışlıkla
     çökmesiz göründü.)
  Hiçbiri `try/except BackupError` ile yakalanmıyordu — ikisi (`verify_
  backup()`, `backup_cli.py`) `read_manifest()`'i `except BackupError`
  içine alıyordu ama `BackupError` hiç fırlamıyordu, ham istisna
  doğrudan çağırana sızıyordu.

**Karar — tam şema DEĞİL, basit boyut+tip kapısı.** Görevin kendisi bunu
istiyordu ("riskin çoğunu bu bile kapatıyor") ve doğru: `sha256`'nin 64
hex karakter olması, `size`'ın negatif olamayacağı gibi ince kurallar
YOK — yalnızca (a) dosya `read_text()`'e verilmeden ÖNCE bir boyut
tavanı, (b) `json.loads()`'tan SONRA üst seviyenin dict, `entries`'in
liste, her girdinin dict olduğu ve `name`/`size`/`sha256`'ın doğru tipte
VAR olduğu kontrolü. Bu, DÖRT çökmenin DÖRDÜNÜ de kapatıyor — ayrıntılı
doğrulama zaten `verify_backup()`'ın kendisinde (boyut/özet karşılaştırması,
GCM tag doğrulaması) var, onunla ÇAKIŞMIYOR.

**Uygulama — `CORE/backup.py`, TEK çağrı noktası.** `read_manifest()`
hem `verify_backup()` hem `restore_backup()` hem `backup_cli.py`'nin
TEK ortak giriş noktası — düzeltme SADECE orada, üç çağıranın hiçbiri
DOKUNULMADI:
  - `_MANIFEST_MAX_BYTES = 10 * 1024 * 1024` (10 MB) — gerçekçi bir
    manifesto çok küçük (girdi başına ~100 bayt JSON, 50.000 dosyalı dev
    bir yedek bile ~5 MB), 10 MB gerçek kullanımın ÇOK üzerinde bir tavan.
    `read_manifest()` bu boyutu `read_text()`'ten ÖNCE kontrol ediyor —
    aşırı büyük bir dosya HİÇ belleğe okunmuyor.
  - `_manifest_sekli_gecersiz_mi(manifest)` — üst seviye/`entries`/her
    girdinin tipini kontrol eden, sorun varsa açıklayan bir metin,
    temizse `None` döndüren yardımcı fonksiyon. `json.loads()` SONRASI,
    `format` alanı kontrolünden ÖNCE çağrılıyor (format kontrolü zaten
    `manifest.get(...)` kullanıyor, dict OLMASI şart).
  - İkisi de `BackupError` fırlatıyor — `verify_backup()`'ın MEVCUT
    `except BackupError: rapor.ok=False` bloğu ek koda gerek KALMADAN
    yakalıyor.

**Test — `tests/test_backup.py` (7 yeni test).** Dört çökme senaryosunun
DÖRDÜ de (üst-seviye-liste, entries-string, entry-not-dict,
entry-eksik-anahtar) artık `rapor.ok=False` ile güvenle reddediliyor;
beşincisi beklenmeyen TİP (size bir sayı değil, string) için ayrı bir
test; altıncısı boyut tavanını (`_MANIFEST_MAX_BYTES`'ı testte 100 bayta
`monkeypatch` ile indirip birkaç yüz baytlık zararsız bir dosyayla aşan
— GERÇEK 10 MB'lık bir dosya YAZMIYOR, hem hızlı hem güvenli); yedincisi
sağlıklı bir yedeğin hâlâ geçtiğini doğrulayan regresyon kontrolü.

**Keşif — ilk "boyut" testi taslağı TEHLİKELİYDİ.** İlk taslak, testin
İÇİNDE `_MANIFEST_MAX_BYTES`'ı doğrudan ithal edip dosya boyutunu ONA
GÖRE (`_MANIFEST_MAX_BYTES // 2`) hesaplıyordu — bu, sabiti ARTIRAN bir
mutasyon testinde testin YAZDIĞI dosyanın da ORANTILI BÜYÜDÜĞÜ anlamına
geliyordu: sabiti 10 GB'a çıkaran bir mutasyon denemesinde test GERÇEKTEN
~10 GB'lık bir dosya diske yazmaya ÇALIŞTI (14 saniye sürdü, disk dolması
riskliydi). Düzeltildi: test artık sabiti KÜÇÜK bir değere (100 bayt)
`monkeypatch` ediyor ve sabit boyutlu (birkaç yüz bayt), tamamen zararsız
bir dosyayla aşıyor — hem hızlı (0,16sn) hem sabitin GERÇEK DEĞERİNDEN
bağımsız olarak karşılaştırma mantığını sınıyor.

**Mutasyon kanıtı (üçü de geçici, geri alındı).**
  (a) Şekil kontrolünü (`_manifest_sekli_gecersiz_mi` çağrısını) devre
      dışı bırakmak 5 testi kırdı — biri gerçek bir `KeyError` ile test
      İÇİNDE çöktü (yakalanmamış istisna, tam olarak düzeltmeden önceki
      canlı davranış), dördü `AssertionError` ile.
  (b) Boyut karşılaştırmasını (`if boyut > _MANIFEST_MAX_BYTES`) `if
      False`'a bozmak boyut testini KIRDI — dosya artık boyut kapısından
      GEÇTİ ama JSON olarak geçersiz olduğu için YİNE reddedildi, farklı
      (yanlış) bir hata metniyle; test bunu doğru şekilde yakaladı.
  Üçü de geri alındı, `grep -n "MUTATION"` (temiz) ve `git diff --stat`
  (yalnızca beklenen 2 dosya) ile doğrulandı.

SECURITY.md §4.11'e (EN+TR) eklendi — §4.12'nin "sertleştirme, açık
kapatma değil" çerçevesiyle aynı: manifesto zaten güvenilmeyen/
DEĞİŞTİRİLEBİLİR olarak belgeliydi (bütünlüğü şifreli kopyayla
karşılaştırma sağlıyor), bu düzeltme bir GİZLİLİK/BÜTÜNLÜK açığını
KAPATMIYOR — doğrulama ARACININ KENDİSİNİN güvenilmeyen bir dizine karşı
çökmemesini sağlıyor (kullanılabilirlik). Doc-parity testi (`tests/
test_belge_dil_paritesi.py`) ilk yazımda EN tarafında `` `tests/
test_backup.py` `` satır-kaydırmasıyla bölünüp sayılmadığı için
kırıldı — bu oturumda daha önce de görülen AYNI kalıp; tek satıra alınıp
düzeltildi.

Etkilenen: `CORE/backup.py`, `tests/test_backup.py`. İlgili suite: 109
passed (+7). Ruff/mypy temiz. bandit: tek pre-existing bulgu (B608,
satır ~294, `# noqa: S608` ile zaten işaretli sabit tablo listesi)
DEĞİŞMEDİ, benim eklediğim kod DEĞİL.

---

## B-098 — Windows CI'da "Test (pytest)" adımı 30 dakika sessizce takılıp "cancelled" ile bitiyordu: pytest-timeout eklendi, kök neden HÂLÂ TEŞHİS EDİLEMEDİ

Görev: "windows cı testi çökmüş düzeltirmisin."

**Teşhis — GitHub Actions API'siyle (gh CLI yok, ortamda kurulu değil).**
`curl https://api.github.com/repos/.../actions/runs` (kimliksiz, herkese
açık depo) son ~10 çalıştırmayı listeledi: hepsi `conclusion=cancelled`.
İlk bakışta ürkütücü ama çoğu ZARARSIZ: `ci.yml`'nin `concurrency:
cancel-in-progress: true` ayarı, bu oturumda art arda hızlı push
yapıldığı için önceki çalıştırmayı YENİ push gelince iptal ediyor —
beklenen davranış.

**Ama en son çalıştırma (19732b8, B-097 — bu oturumdaki SON push, ondan
SONRA başka push YOK) da "cancelled" idi ve iş bazında incelemede ("
/actions/runs/{id}/jobs"): `windows-latest · Python 3.11` işinin `Test
(pytest)` ADIMI 20:51:11 → 21:20:21, TAM 29 dakika 10 saniye sürüp
`cancelled` ile bitti — `ci.yml`'nin `timeout-minutes: 30` iş sınırına
tam oturdu. Sonrasında gelen hiçbir push YOKTU, yani bu bir concurrency
iptali DEĞİL, GERÇEK bir zaman aşımı. `test-results-windows-latest-*`
artifact'i bu çalıştırmada HİÇ ÜRETİLMEMİŞ (yalnızca ubuntu'nunki var) —
`--junitxml` dosyası ya hiç yazılmadı ya da iptal ANINDA flush
edilmeden kaldı, yani hangi testte takıldığına dair DOSYA BAZLI hiçbir iz
yok. Aynı desen bir turda daha (d878561, B-095 devam) doğrulandı:
`windows-latest` işi 19:51:36 → 20:21:49, yine TAM 30 dk 13 sn — bu ikisi
ARASINDAKİ push'lar (217dd3a, affb91d) ÇOK ÇABUK iptal edildi (sonraki
push onlardan önce geldi), yani hâlâ takılıp takılmadıkları
GÖZLEMLENEMEDİ.

**Ham günlüğe erişim ENGELLENDİ.** `/actions/jobs/{id}/logs` uç noktası
kimliksiz istekte `403 Must have admin rights to Repository` döndürüyor
— herkese açık bir depo bile olsa iş günlüklerinin ham metnini kimliksiz
indirmek MÜMKÜN DEĞİL (yalnızca metadata/artifact listesi açık). Bu
oturumda `gh` CLI kurulu değil (`command not found`, hem Bash hem
PowerShell'de) ve depo sahibinin kimlik bilgileri paylaşılmadı — yani
HANGİ testin tam olarak takıldığını gösteren stack trace/son satırlar
şu an OKUNAMIYOR. Bu, "kök neden bulunup düzeltildi" değil, "kök neden
teşhis edilemedi, ama BİR SONRAKİ çalıştırma artık kendini teşhis
edecek" durumu — kullanıcıya böyle iletildi.

**Öne çıkan (ama DOĞRULANAMAMIŞ) şüpheli — panoya (clipboard) erişim.**
Bu turdan hemen önceki turlarda (`tests/test_pin_giris_kutulari.py`,
B-095) `QApplication.clipboard().setText(...)` kullanan 9+ yeni test
eklendi; panoya erişim, etkileşimli masaüstü OLMAYAN başsız CI
koşucularında bilinen bir Windows-özgü asılma kategorisi. Ama bu SADECE
bir hipotez — GitHub'ın `windows-latest` koşucuları genelde etkileşimli
oturumla çalışıyor (gerçek Session-0 izolasyonu YOK), yani bu iddia
günlük OKUNMADAN doğrulanamaz ve kesin olarak İLERİ SÜRÜLMEDİ.

**Uygulanan düzeltme — teşhis edilebilirlik, kök neden değil.**
`pytest-timeout` eklendi (`requirements-dev.txt`) ve `pytest.ini`'ye
`timeout = 120` yazıldı. Gerekçe doğrudan `ci.yml`'nin kendi başındaki
ilkeyle aynı: "Sessiz bir bekleme, açık bir başarısızlıktan her zaman
kötüdür." 120 sn, yerel en yavaş testin (`--durations=25` ile ölçülen
18,76 sn, `test_run_tool_torun_surec_pipe_tutsa_bile_tanitici_ve_
thread_SIZDIRMIYOR`) 6 katından fazla bir pay bırakıyor — Windows
koşucusunun bilinen yavaşlığı (`ci.yml`: "dosya sistemi ve Defender
taraması") hesaba katılarak. Windows'ta `SIGALRM` olmadığı için paket
otomatik `thread` yöntemine düşüyor: takılan testi zorla İPTAL EDEMEZ
(altında GERÇEKTEN bloke eden bir sistem çağrısı varsa süreç yine de
kilitli kalabilir) ama zaman aşımı ANINDA TÜM thread'lerin TAM yığın
izini test çıktısına yazdırıyor — mekanizma, 2 saniyelik yapay bir
zaman aşımıyla (`@pytest.mark.timeout(2)`, `time.sleep(10)` yapan
geçici bir test) doğrudan doğrulandı: beklenen `+++ Timeout +++`
bandı ve TAKILAN satırı gösteren tam stack trace üretildi, geçici test
silindi.

**Bu YETERLİ mi?** Emin değil. `thread` yöntemi süreç GERÇEKTEN kilitli
kalırsa (ör. bir Win32 API çağrısı sonsuza dek bloke oluyorsa) 120 sn'de
bir stack trace BASAR ama süreç yine de iş-seviyesi 30 dk sınırına kadar
oturabilir — yine de bu sefer günlükte TAKILAN satır YAZILI olacak, yani
bir SONRAKİ Windows CI koşusu artık ya (a) 120 sn'de temiz bir
`Timeout` hatasıyla düşecek ve stack trace'i gösterecek, ya da (b) genel
görünür bir "cancelled" olacak ama BU SEFER `test-results.xml` en
azından o ana kadarki testleri kaydetmiş olacak. İkisi de bugünkü
"hiçbir iz yok" durumundan STRICTLY iyi.

**Yerel doğrulama.** Tam paket (3113 test) `timeout=120` altında yerel
olarak YENİDEN çalıştırıldı — hiçbir yanlış-pozitif zaman aşımı yok,
süre değişmedi (~5 dk). `pytest --collect-only` ile ini seçeneğinin
hatasız yüklendiği doğrulandı ("timeout method: thread" satırı çıktıda
görünüyor).

**Takip gerekiyor.** Bu push'tan sonraki İLK Windows CI çalıştırması
izlenmeli — `Test (pytest)` adımı 120 sn'lik bir `Timeout` bandıyla
düşerse hangi testin takıldığı ORADA görünecek ve GERÇEK düzeltme o
zaman yapılabilecek. Kullanıcıdan, erişilemeyen ham günlüğün son
satırlarını (GitHub Actions arayüzünden) paylaşması istendi — paylaşılırsa
teşhis bu turu beklemeden hemen tamamlanabilir.

---

## B-099 — B-092'nin kararı UYGULANDI: `original_sha256` AAD'den kaldırıldı, anahtarsız RFC 3161 doğrulaması KALICI olarak feda edildi

Görev: B-092'nin analizini temel alıp uygulamaya geç. Karar (önerilen,
kullanıcı onayıyla): `original_sha256`'yı AAD'den kaldır, anahtarsız RFC
3161 doğrulamasını feda et. Gerekçe: M2 tehdit modelinde (yalnızca bir
`.hcl` kopyasına erişim) kesin bir içerik-doğrulama oracle'ı, "anahtarsız
air-gapped doğrulama" kolaylığından daha ağır basıyor.

**Karara katıldım — gerekçe.** B-092'nin analizindeki "tuz işe yaramaz"
argümanı zaten HMAC seçeneğini de fiilen eledi: anahtarsız kalmak için
tuzun da AAD'de açık durması gerekirdi, ki bu "anahtarsız" tanımıyla
çelişirdi — yani gerçek seçenek hiçbir zaman "kaldır mı HMAC'le mi"
değildi, "kaldır" idi (HMAC bir anahtar gerektirdiği andan itibaren zaten
"anahtarsız" olma özelliğini kaybediyordu). Bu proje K1-14/K0'da HWID/HMAC
gibi anahtar-kaynaklı kontrolleri zaten normalleştirmiş durumda; aynı
disiplini burada uygulamak tutarlı.

**Kapsam — B-092'nin öngördüğünden GENİŞ çıktı.** B-092 dört CORE modülü +
CLI + ~900 satır test öngörmüştü. Gerçekte dokunulan:
  - `CORE/crypto.py` — `encrypt_file()` artık `original_sha256`'yı AAD'ye
    YAZMIYOR (hâlâ hesaplayıp DB için DÖNDÜRÜYOR). `verify_file()`'a yeni
    `return_sha256: bool = False` parametresi (mevcut `decrypt_file()`nin
    `zeroizable` desenini taklit eden `@overload` çifti) — `True` ise düz
    metnin SHA-256'sını AYNI akan-blok döngüsünde (`decryptor.
    update_into()`'nin artık KULLANILAN dönen uzunluğuyla), biriktirmeden
    hesaplayıp `(meta, sha256_hex)` döndürüyor. VARSAYILAN `False`: mevcut
    çağıranların (backup.py, integrity.py, fuzz) çoğu yalnızca GCM tag'ini
    önemsiyor, ek özet geçişinin maliyetini ödememeli — BİLEREK opt-in,
    global bir imza değişikliği DEĞİL.
  - `CORE/timestamp.py` — `timestamp_file()`/`timestamp_batch()`'in `key`
    parametresi artık ZORUNLU (varsayılan yok). `_file_digest()` → genel
    `file_digest()` oldu (artık `timestamp_verify.py` da kullanıyor, TEK
    kaynak). `read_aad()` KALDIRILMADI — hâlâ dışa açık, genel amaçlı
    (filename/created_at gibi diğer alanlar için); yalnızca bu modülün
    KENDİSİ artık kullanmıyor.
  - `CORE/timestamp_verify.py` — `verify_timestamp()`'e ZORUNLU `key`
    eklendi. 10. adım YENİDEN YAZILDI: `read_aad()` + AAD'nin
    `original_sha256`'sı yerine `file_digest(path, key=key)` — yani artık
    "AAD'nin iddia ettiği özet damgalanmış mı" değil "dosyanın GERÇEK
    içeriği damgalanan özete sahip mi" soruluyor. Yeni hata yolları
    (AuthenticationError/ValueError/OSError/TimestampError) MEVCUT `"aad"`
    failed_check'ine düşüyor — YENİ bir kod GEREKMEDİ, açıklaması ("bu
    içeriğe bağlanamadı") zaten uyuyordu.
  - `CORE/timestamp_report.py` — kod DEĞİŞMEDİ, yalnızca ARTIK YANLIŞ olan
    iki metin düzeltildi: modül docstring'inin "DOĞRULUK, SADELİKTEN ÖNCE
    GELİR" bölümü ve `notlar()`'ın "Bu kontrol neyi kapsıyor" bilgi notu —
    ikisi de eskiden "içerik burada kontrol EDİLMİYOR" diyordu, artık
    ediliyor.
  - `CORE/verify_timestamp_cli.py` — `--key-file` (ZORUNLU, ham 32 bayt,
    hex/base64 DEĞİL) eklendi. Modül docstring'i ve `argparse`
    `description`'ı "ne anahtar ne USB istemiyor" iddiasını KALDIRDI.
  - `UI/main_window_files.py::_on_ctx_verify_timestamp()` — B-092'nin
    listesinde YOKTU ama `verify_timestamp()`'in imza değişikliği
    DOLAYLI olarak bunu da kırıyordu: canlı "Damgayı Doğrula" sağ-tık
    eylemi. `self._key` (zaten `decrypt_file()` için kullanılan canlı
    oturum anahtarı) geçiriliyor artık. Docstring'in "ne anahtar ne ağ
    gerekiyor... kasa oturumu düşmüşken de çalışıyor" iddiası düzeltildi:
    `self._key` kilitliyken de canlı kalıyor (USB geri takılınca PIN'siz
    devam ediyor), ama kasa HİÇ açılmamışsa artık çalışamıyor.

**`CORE/merkle.py` — İNCELENDİ, DEĞİŞİKLİK GEREKMEDİ.** B-092 bunu da
listelemişti; gerçekte yalnızca docstring'de "dosya `original_sha256`'sı"
diye BETİMSEL bir geçiş var, hiçbir fonksiyonel kod AAD okumuyor —
kavram (dosyanın düz metin özeti) hâlâ doğru, yalnızca kaynağı değişti.

**Mimari karar — anahtarsız yolun KENDİSİ, "sessizce eksik" DEĞİL.**
`timestamp_file(path)` (key'siz) artık `TypeError` — Python'un kendisi
reddediyor, çünkü `key` artık varsayılansız bir pozisyonel parametre.
Aynısı `verify_timestamp(path)` için. Bu BİLİNÇLİ: "eksik anahtar →
sessizce eski davranışa düş" gibi bir geriye-uyumluluk köprüsü KURULMADI,
çünkü o köprünün kendisi oracle'ı YENİDEN AÇARDI.

**GERİYE DÖNÜK ONARILAMAMA SINIRI — SECURITY.md'ye (EN+TR) NET yazıldı.**
GCM AAD'si ciphertext'e bağlı; anahtar olmadan mevcut bir dosyanın
AAD'sinden bir alan sessizce çıkarılamaz. Yalnızca BUNDAN SONRA
şifrelenen dosyalar korunuyor — mevcut HER `.hcl` dosyası, yeniden
şifrelenmedikçe bu oracle'a KALICI olarak açık kalıyor. Migrasyon bu
turun KAPSAMINDA DEĞİL — ayrı madde: **B-100**.

**Test — mevcut ~900 satırlık yükün TAMAMI anahtarlı API'ye göre yeniden
yazıldı, artı YENİ testler.** Etkilenen dosyalar ve YAKLAŞIK test sayıları
(hepsi çalıştırıldı, hepsi yeşil):
  `tests/test_crypto.py` (42), `tests/test_timestamp.py` (71 — 2 yeni
  `_eski_format_hcl` testi dahil), `tests/test_timestamp_batch.py` (34),
  `tests/test_timestamp_verify.py` (27), `tests/test_timestamp_report.py`
  (88), `tests/test_verify_timestamp_cli.py` (19 — 2 yeni `--key-file`
  testi dahil), `tests/test_timestamp_ui.py` (29), `tests/
  test_trusted_roots.py` (33), `tests/test_guvenlik_view.py` (35),
  `tests/test_merkle.py`/`tests/test_deneysel_bagli_degil.py`
  (DEĞİŞİKLİK GEREKMEDİ, doğrulandı) — B-092'nin listesinde OLMAYAN ama
  imza değişikliği yüzünden GERÇEKTEN kıran 4 dosya da bulunup
  düzeltildi: `tests/test_backup.py`, `tests/test_checkout.py`, `tests/
  test_recovery_e2e.py` (üçü de `meta["original_sha256"]` okuyordu,
  zaten ayrı bir içerik-eşitliği assert'iyle KAPSANAN bir kontroldü,
  kaldırıldı) ve `tests/test_ui_yasakli_iddia_terimleri.py` (satır
  numarasına SABİT KODLANMIŞ bir `raise` mesajı araması — `CORE/
  timestamp.py`ye satır eklenince kaydı; arama metne göre yapılacak
  şekilde SAĞLAMLAŞTIRILDI).

**Yeni test — "sessiz yanlış-pozitif olmamalı" talebi.**
`tests/test_timestamp.py::test_an_old_format_file_still_verifies_and_
stamps` ve `test_an_old_format_files_stale_hash_is_silently_ignored_
not_trusted` — B-099 ÖNCESİ `encrypt_file()`'ın ürettiği formatı BİREBİR
simüle eden bir yardımcı (`_eski_format_hcl`, ham `cryptography` GCM
ilkelleriyle) kuruyor ve: (1) eski formattaki bir dosyanın hâlâ sorunsuz
doğrulandığını/damgalandığını, (2) AAD'deki eski alan BİLEREK YANLIŞ
bir değer taşısa bile (`"0"*64`) hem `verify_file()` hem `file_digest()`
hem `timestamp_file()` hem `verify_timestamp()`'in GERÇEK özeti
kullandığını, eski alana ASLA güvenmediğini kanıtlıyor.

**Mutasyon kanıtı (test tasarımının kendisini de sınadı).** İlk taslakta
`file_digest()`'i eski AAD alanına GERİ DÖNDÜREN bir mutasyon
uygulandığında testler YEŞİL KALDI — sebebi bulundu: `timestamp_file()`
`verify_file()`'ı DOĞRUDAN çağırıyor, `file_digest()`'i HİÇ kullanmıyor,
yani mutasyon o test yolunu ETKİLEMİYORDU. Test, `timestamp_batch()`/
`verify_timestamp()`'in ortak yolu olan `file_digest()`'i AYRICA
çağıracak şekilde GÜÇLENDİRİLDİ; aynı mutasyon tekrarlanınca bu sefer
doğru şekilde `AssertionError` ile YAKALANDI. Geri alındı, `grep -n
"MUTATION"` (temiz) ve `git diff --stat` ile doğrulandı.

**SECURITY.md (EN+TR) — §1.2, §3, §4.9 güncellendi.** AAD gizliliği
tablosu satırı, "AAD gizliliği satırı kendi alanlarından birini hafife
alıyor" paragrafı, "Metadata confidentiality" paragrafı ve §4.9'un TAMAMI
(açılış, "Anahtarsız damgalamada özet doğrulanmamıştır" bölümü, Merkle
paragrafı, CLI kod örneği) — hepsi geçmiş zamana (B-099 ÖNCESİ nasıldı) ve
şimdiki zamana (B-099 SONRASI nasıl) ayrıştırılarak yeniden yazıldı,
geriye dönük onarılamama sınırı her ikisinde de açıkça belirtildi.
README.md (EN+TR) özellik tablosu satırı `--key-file` gerekliliğini
belirtecek şekilde güncellendi. Doc-parity testi (`tests/
test_belge_dil_paritesi.py`) EN/TR'nin hâlâ eşleştiğini doğruluyor.

Tam test suite: 3116 passed, 4 skipped (B-098'den +10 — yukarıdaki yeni
testler). Ruff temiz. mypy: `UI/main_window_files.py`'de +1 hata
(`self._key` — bu dosyada ZATEN 106 örnekle yaygın olan "mixin kendi
kardeşinin özniteliğini göremiyor" kalıbı, B-094'te belgelenen AYNI
kategori, gerçek bir tip hatası değil). bandit: yeni bulgu YOK.

Ayrıntı: BACKLOG.md **B-092** (analiz), SECURITY.md §1.2/§3/§4.9 (EN+TR).

---

## B-100 — Mevcut `.hcl` dosyalarının `original_sha256`'sını AAD'den temizleyen migrasyon (B-099'un tamamlayıcısı, henüz UYGULANMADI)

**Durum: AÇIK, kapsam dışı bırakıldı (B-099'un kendi kararı).**

B-099, `original_sha256`'yı AAD'den kaldırdı ama bu GERİYE DÖNÜK DEĞİL:
GCM AAD'si ciphertext'e bağlı olduğu için anahtar olmadan mevcut bir
dosyanın AAD'sinden bir alan sessizce çıkarılamaz. Bu değişiklikten ÖNCE
şifrelenmiş HER `.hcl` dosyası, bu madde ele alınana kadar
`original_sha256`'yı AAD'sinde okunabilir taşımaya devam ediyor — yani
M2 doğrulama-oracle'ı riski, MEVCUT kasalar için hâlâ TAM olarak açık.

**Gerekli olan (taslak, henüz tasarlanmadı):** kasadaki her `.hcl`
dosyasını anahtarla ÇÖZÜP `original_sha256` alanı OLMADAN yeniden
şifreleyen bir toplu işlem. Düşünülmesi gerekenler:
  - Yeniden şifreleme yeni bir nonce üretir — eski dosyayla byte-byte
    farklı bir ciphertext demektir. Zaten damgalanmış (RFC 3161) dosyalar
    için bu bir SORUN: `CORE/crypto.py`'nin "Neden düz metnin özeti
    damgalanıyor, ciphertext'in değil" gerekçesi burada da geçerli mi
    kontrol edilmeli — muhtemelen EVET (damga düz metne bağlı, ciphertext
    değişse de damga geçerli kalmalı) ama AYRICA doğrulanmalı.
  - `CORE/checkout.py`'nin AÇIK belgeleri (transparent access) migrasyon
    sırasında nasıl ele alınacak — kilitli bir dosyayı yeniden şifrelemek
    checkout kaydını bozabilir.
  - Ölçek: büyük bir kasada binlerce dosya olabilir; ilerleme raporlama,
    kesinti toleransı (yarıda kalan bir migrasyonun güvenli şekilde
    devam edilebilir/geri alınabilir olması) gerekiyor.
  - Denetim kaydı: migrasyon kendi başına kayda değer bir olay
    (`file_re_encrypted` gibi), B-094/B-097'nin "her yazma kendi
    denetim izini bırakır" ilkesiyle tutarlı olmalı.

Ele alınana kadar SECURITY.md bu sınırı açıkça belirtiyor (§1.2, §3,
§4.9, EN+TR) — sessizce "çözüldü" gibi davranılmıyor.

---

## B-101 — sqlcipher3'e geçiş analizi (SQLite DB'yi disk hırsızlığına karşı şifreleme) — ANALİZ, henüz UYGULANMADI

**Durum: ANALİZ TAMAMLANDI, kod değişikliğine GEÇİLMEDİ — maliyet/fayda net olumlu değil.**

Tetikleyici: `DB/db_manager.py`'nin kendi modül docstring'i zaten "Şu an düz
sqlite3 kullanıyor. sqlcipher3 geçişi: connect() içindeki iki satırı
değiştir" diyor ve `connect()` bir `key: bytes | None` parametresi taşıyor
— görünüşte hazır bir iskelet. Bu madde o iskeletin GERÇEKTEN iki satırlık
bir iş olup olmadığını inceliyor.

### 1. Bugün ne durumda — iskelet var, hiç kullanılmıyor

`key` parametresi kod tabanının HİÇBİR gerçek çağrı yerinde dolu
verilmiyor — üçü de `key=None`:

  - `main.py:349` — `DBManager().connect(hwid=hwid, key=None)`,
    yorumu: "DB bağlantısını geçici boş anahtar ile aç (şifreleme anahtarı
    login'den sonra gelir)" — ama login SONRASI yeniden `connect()`
    çağrılmıyor (bkz. §2, bu "sonra gelir" hiç gelmiyor).
  - `CORE/backup_cli.py:97`, `CORE/recover_vault.py:250` — aynı desen.

Yani bugün `data/hycleus.db` HER ZAMAN düz sqlite3, hiçbir kurulumda
istisna yok. İçeriği: `users` (username, role — password_hash zaten
hash'li, düşük değerli), `files` (filename, filepath, notes),
`audit_log` (detail — serbest metin), `usb_tokens` (hwid, token_id),
`quarantine` (reason). Gerçek, bugün var olan düz metin maruziyeti.

`CORE/backup.py` (KARAR 2, modül docstring'i) bu boşluğu KISMEN zaten
ele alıyor ama yalnızca YEDEK kopyası için: DB tabloları kanonik JSON'a
çıkarılıp `encrypt_file()`/master_key ile şifrelenip yedeğe
`metadata.hcl` olarak giriyor. Canlı `data/hycleus.db`'ye
DOKUNULMUYOR — operatörün makinesindeki çalışan kopya her zaman düz
metin kalıyor. sqlcipher3 sorusu tam olarak bu kalan boşlukla ilgili.

### 2. Kritik mimari engel — anahtar SIRASI, "iki satır" değil

`CORE/vault_manager.py::open_vault()` — `master_key`'i ÜRETEN fonksiyonun
KENDİSİ — `master_key` henüz yokken DB'den okuyor:

```
share_1, role = _decrypt_vault(hwid, pin)
row = DBManager().fetchone("SELECT hwid FROM usb_tokens WHERE hwid = ?", (hwid,))
master_key = _sss_recover(share_1, _load_share_2(hwid))   # ← master_key BURADA doğuyor
```

Ayrıca `main.py` DB'yi login/İlk Kurulum akışından TAMAMEN ÖNCE açıyor
(`users` tablosu okuma, `login_attempts` hız sınırlaması — hepsi
kimlik doğrulanmadan ÖNCE çalışması gereken sorgular, tıpkı
`secret_store.py`'nin HWID-önce-kayıt sorununa benzer bir tavuk-yumurta).

Sonuç: `master_key` (ya da ondan HKDF ile türetilmiş herhangi bir şey)
`PRAGMA key` OLAMAZ — DB, master_key var olmadan ÖNCE okunabilir olmak
zorunda. `connect()` içindeki iki satırı değiştirmek yetmez; bu,
pre-auth DB erişim yolunun (rate limiting, users tablosu, usb_tokens
kontrolü) YENİDEN TASARLANMASINI gerektirir — modülün kendi yorumunun
iddia ettiğinden çok daha büyük bir değişiklik.

### 3. Anahtar nerede tutulur — üç tasarım

  **(a) master_key'den türetilmiş (HKDF, ayrı context).** §2 nedeniyle
  MİMARİ OLARAK İMKÂNSIZ — reddedildi.

  **(b) share_2/TOTP ile AYNI OS anahtar kasası, ama BAĞIMSIZ yeni bir
  sır** (`db_key:<hwid>` gibi bir kullanıcı adı, `secret_store.py`'nin
  zaten kurduğu şemayla simetrik). `create_vault()` sırasında bir kez
  üretilir; `main()` içinde `ensure_available()` başarılı olur olmaz —
  PIN/USB kombinasyonundan ÖNCE — okunup `connect()`'e verilir. Bu,
  §2'deki sıra sorununu ÇÖZER (kasa DB'den önce açılabiliyor) ve
  kullanıcının orijinal gerekçesiyle (K0'da HWID/HMAC gibi anahtar-
  kaynaklı kontroller zaten normalleştirildi) TUTARLI. Gerçek kazanım:
  `data/` dizininin OS OTURUMU DIŞINDA kopyalanması (disk görüntüleme,
  el konan/atılan makine, çalınan yedek medya) senaryosunda DPAPI/
  Keychain/Secret Service kullanıcı oturumuna bağlı olduğu için anahtar
  da erişilemez kalır — dosya İÇERİĞİNİN bugün zaten sahip olduğu
  koruma katmanının DB metadata'sına GENİŞLEMESİ.

  Bedeli: YENİ bir kayıp kategorisi. Bu kasa girdisi silinir/bozulursa
  (makine değişimi, kasa temizliği) DB TAMAMEN okunamaz hâle gelir —
  Shamir bunu KAPSAMIYOR (yalnızca `master_key`'i kurtarıyor,
  `CORE/backup.py` KARAR 3: "yedek → medya kaybı, Shamir → anahtar
  kaybı" ayrımı burada üçüncü bir kategori olarak "db_key kaybı" açar).
  Kısmen hafifletici: `CORE/backup.py::restore_backup()` zaten
  `metadata.hcl`'i (aynı master_key ile) ayrı şifreliyor ve
  `apply_metadata` üzerinden bir DB'ye uygulayabiliyor — GÜNCEL bir
  yedek varsa "db_key kayıp" pratikte "yeni anahtarlı boş DB + son
  yedekten geri yükle" ile kurtarılabilir GİBİ görünüyor, ama bu
  DOĞRULANMADI (`apply_metadata` bugün canlı DB'yi değil ayrı bir
  hedefi dolduruyor — bkz. `restore_backup()` docstring'i "canlı
  veritabanına DOKUNULMUYOR") ve yedekten SONRA eklenen veri her hâlde
  gider. Kendi başına, Shamir'e EKLENMEYEN (KARAR 3'ün "kasayı
  yedekleme, offline kaba kuvvet hedefi yaratır" gerekçesi burada da
  geçerli) bir kurtarma tasarımı gerektirir — bugün TASARLANMADI.

  **(c) Shamir eşiğine dahil (4. bir pay).** Reddedildi: (b) zaten
  aynı OS-kasası koruma gücünü veriyor, eşiği genişletmenin ek bir
  faydası yok, yalnızca karmaşıklık ekliyor.

  **Sonuç: (b) tek mimari olarak tutarlı seçenek, ama kendi kurtarma
  hikâyesi tasarlanmadan eksik.**

### 4. Paketleme etkisi — CI, EXE (Windows), AppImage (Linux)

  - Her iki paketleme işi de (`HYCLEUS.spec`, `HYCLEUS-linux.spec`)
    PyInstaller `Analysis`'e `collect_all()`-tarzı `hiddenimports`/
    `binaries` ekleme desenini ZATEN kullanıyor (wmi, reportlab) —
    yeni bir C-uzantısı için aynı desen (`collect_dynamic_libs` ya da
    eşdeğeri) uygulanabilir; YENİ bir mekanizma icat etmek GEREKMİYOR.
  - `sqlcipher3-binary` (PyPI, son sürüm 0.6.0, 2025-12-31) Linux
    (manylinux) ve Windows için KENDİ KENDİNE YETEN, statik bağlı,
    harici bağımlılık istemeyen wheel'ler sağlıyor. Doğruysa,
    AppImage işindeki apt-sertleştirme dramının (f61a470, ~30dk asılma,
    ci.yml'nin bugün ÜÇ AYRI mekanizma kapattığı bölüm) bir benzerinin
    YAŞANMAMASI anlamına gelir — `libsqlcipher`'ı apt'tan kurmak
    gerekmiyor GİBİ görünüyor.
  - Ama bu iddia CI'da HENÜZ DOĞRULANMADI. pip metadata'sına/PyPI
    açıklamasına güvenip kabul etmek, B-024'ün tam olarak REDDETTİĞİ
    şey — B-024 iki sessiz paketleme bozukluğundan doğdu ve o
    zamandan beri bu depoda kural: "gerçekten temiz bir ağaçta üretiliyor
    mu" ÖLÇÜLÜR, varsayılmaz.
  - `requirements.txt`'e yeni bir satır gerekir (platform işaretçisiz —
    DB her iki platformda da açılıyor, `wmi`'nin aksine).
  - **Lisans:** SQLCipher Community Edition BSD tarzı ama Zetetic'in
    kendi lisans sayfası uygulamanın "About" ekranında/belgelerinde
    GÖRÜNÜR bir lisans+telif bildirimi istiyor. Projede bugün böyle bir
    üçüncü-taraf-lisans bildirim yüzeyi YOK (doğrulanmalı) — yeni bir
    UI/doküman yükümlülüğü, "requirements.txt'e bir satır" kadar basit
    değil.
  - `requirements-security.txt`/pip-audit yeni pakete otomatik bakar,
    ek iş yok. `.semgrep/hycleus.yml` yerel kuralları DB bağlantı
    katmanına bugün dokunmuyor gibi görünüyor, gözden geçirilmeli ama
    şu an bir engel değil.

### 5. Test/migrasyon maliyeti (uygulanırsa — bu maddenin kapsamı DEĞİL)

  - Mevcut kurulumlardaki `data/hycleus.db` düz sqlite3 formatında;
    sqlcipher3 bağlantısı bunu AÇAMAZ. B-100'e simetrik bir "geriye
    dönük onarılamama" sınırı gerekir: yalnızca YENİ kurulan kasalar
    şifreli DB alır, mevcutlar migrasyon olmadan (`sqlcipher_export()`
    ya da ATTACH+dışa aktarma) plaintext kalır. Migrasyonun kendisi
    ayrı bir BACKLOG maddesi olurdu (B-100'ün DB karşılığı).
  - `tests/conftest.py` dahil DB'ye dokunan onlarca test dosyası
    (`connect(hwid=...)` çağıran ~15+ dosya) `key` zorunlu hâle
    gelirse etkilenir — B-099'daki "beklenenden geniş kapsam"
    deneyiminin AYNISI, muhtemelen daha büyük ölçekte (DB neredeyse
    her testin altyapısında).

### 6. Maliyet/fayda — neden bu turda KOD YAZILMADI

Kapattığı gerçek boşluk: `data/hycleus.db`'nin OS oturumu DIŞINDA
(disk görüntüleme, el konan/atılan makine, çalınan yedek medya) düz
metin okunabilir olması. SECURITY.md §3 bu boşluğu zaten yazılı
biçimde kabul ediyor.

Ama proje AYNI kategorideki bir boşluk için (`.hcl` AAD metadata'sı)
zaten açık bir pozisyon almış durumda: *"Çevrimdışı saldırgan
senaryolarını kapatan kontrol tam disk şifrelemesidir. HYCLEUS onun
yerine geçmez."* (SECURITY.md §3). DB'nin durumu ÖLÇEK olarak daha
büyük (tek dosyanın AAD'si değil, tüm envanter + denetim izi) ama
KATEGORİ olarak aynı: M2/M3, disk erişimi olan bir saldırgan. Bu analiz
o pozisyonu SORGULAMIYOR — yalnızca not düşüyor: sqlcipher3'e
geçilecekse SECURITY.md'de bu çizginin DB için neden farklı çizildiği
açıklanmalı; sessizce iki farklı standart bırakılamaz.

Maliyet üç kalemde toplanıyor: (1) mimari — bağımsız bir kasa girdisi
gerekiyor ve onun kendi kurtarma/kayıp hikâyesi bugün TASARLANMADI
(§3b); (2) paketleme — "harici bağımlılık istemez" iddiası CI'da
DOĞRULANMADI, doğrulanırsa maliyet düşük, doğrulanmazsa (özellikle
Windows'ta önceden derlenmiş bir ikili bulunamazsa) önemli ölçüde
yükselir; (3) lisans — bugün karşılığı olmayan yeni bir görünür-bildirim
yükümlülüğü.

**Sonuç: bu turda kod değişikliğine GEÇİLMEDİ.** Maliyet/fayda net
olumlu değil.

**Önerilen sıradaki adım (ayrı bir tur, bu maddenin kapsamı):** ucuz bir
spike — `sqlcipher3-binary`'i hem Windows hem Linux CI koşucusunda
(geçici bir dal/iş) kurup PyInstaller `Analysis`'in onu SORUNSUZ
topladığını ve üretilen EXE/AppImage'ın `--selftest`inde gerçekten bir
`PRAGMA key` round-trip'i yaptığını ölçmek — tam entegrasyon değil,
yalnızca "bu bağımlılık iki platformda GERÇEKTEN sorunsuz mu" sorusuna
kanıt. Sonuç olumluysa (3b)'deki anahtar tasarımı ve DB migrasyonu
(B-100'ün karşılığı) ayrı maddeler olarak açılır; olumsuzsa bu madde
kapatılır.

---

## B-102 — Aynı dosyanın birden fazla uygulama örneğinde açılmasını engelleyen kilit (`file_locks`)

**Durum: UYGULANDI.**

`CORE/checkout.py::CheckoutRegistry` bellekte, süreç başına — iki AYRI
HYCLEUS süreci (aynı makinede çift açılış, ya da aynı `data/` dizinini
paylaşan iki kurulum) aynı `file_id`'yi aynı anda çıkışa alırsa hiçbiri
diğerinin kaydını GÖRMÜYORDU: iki düz metin kopyası, iki bağımsız
düzenleme, son geri yazan diğerininkini sessizce siliyordu.

`DB/migrations.py::_m26_file_locks` (Migration 26) `disposal_queue`
(B-079) ile AYNI desen: niyet FİİLİ çözmeden ÖNCE kalıcı yazılır.
`file_id` PRIMARY KEY olduğu için ikinci bir yazma `IntegrityError` ile
atomik biçimde reddedilir — SELECT-sonra-INSERT'ün açacağı yarış
penceresi yok. `CORE/checkout.py::acquire_lock()`/`release_lock()`
`check_out()`/`check_in()`/`discard()`/`check_in_all()`'a `db`
(zorunlu) ve `session_id` (süreç başına bir kez üretilen `SESSION_ID`)
parametreleriyle bağlandı; kilit yalnızca `shred=True`/`discard`'ta
(belge GERÇEKTEN kapanırken) serbest bırakılıyor, ara geri yazmalarda
(`shred=False`, autosave) korunuyor.

Çakışma `FileLockedError` (yeni, `CheckoutError`'ın alt sınıfı) ile
bildiriliyor — mevcut `except CheckoutError` çağrı yerleri
(`UI/main_window_open.py::_on_ctx_open`) hiçbir değişiklik gerekmeden
onu da yakalıyor.

Çökme kurtarması `release_stale_locks()` — `main.py`'de
`resume_pending_disposals()`/`purge_orphans()` ile aynı açılış
bölümünde çağrılıyor. Yalnızca BU makineye ait (`hostname` eşleşen) VE
`pid`'i artık yaşamayan satırlar temizleniyor; `_pid_alive()` Windows'ta
`os.kill(pid, 0)` KULLANMIYOR (Windows'ta sinyal 0 `TerminateProcess`'e
düşüyor ve GERÇEKTEN öldürüyor) — bunun yerine `ctypes`/`OpenProcess`.
Başka bir makineye ait bir kilidin canlılığı doğrulanamıyor, o yüzden
DOKUNULMUYOR — yanıtlanamayan bir soruya "ölü" demek yanlış tarafta
hata yapmak olurdu. Bilinen sınır: `pid` yeniden kullanılmışsa (süreç
çıkmış, OS aynı numarayı başka bir programa vermiş) canlılık kontrolü
yanlış pozitif verir ve kilit gereğinden uzun tutulur — KASITLI: bu,
canlı bir kilidi erken serbest bırakıp iki sürecin aynı dosyayı aynı
anda düzenlemesine izin vermekten kesinlikle daha güvenli.

`file_locks` BİLEREK `_RBAC_KORUMALI_TABLOLAR`'a EKLENMEDİ —
`login_attempts`'le aynı gerekçe: dosya açmak (yalnızca görüntülemek)
rol bağımsız çalışıyor, kilidin amacı gizlilik/yetki değil eşzamanlılık.

Test: `tests/test_checkout.py` bölüm 10 — iki AYRI `CheckoutRegistry` +
farklı `session_id` ile gerçek süreç başlatmadan "iki uygulama örneği"
simülasyonu. İki eşzamanlı açılıştan yalnızca birinin kazandığı,
kapatma/atmanın kilidi sonraki örneğe devrettiği, ara geri yazmanın
kilidi koruduğu, ölü bir `pid`'in kilidinin açılışta temizlenip dosyanın
devralınabildiği, CANLI bir `pid`'in (test sürecinin kendi PID'i) ve
BAŞKA bir `hostname`'in süpürmede DOKUNULMADAN hayatta kaldığı ayrı ayrı
doğrulandı. `_pid_alive()`'ı her zaman `True` döndürecek şekilde
mutasyonla bozup çökme-kurtarma testinin gerçekten düştüğü, sonra
düzeltilip geçtiği ölçüldü.

---

## B-103 — Toplu dosya-ekleme işçi havuzu, düşük RAM'de küçülen bir tavan alıyor

**Durum: UYGULANDI.**

`UI/main_window.py`'nin `QThreadPool`'u (dosya ekleme: şifrele → DB
kaydı → tara) uzun süre sabit `setMaxThreadCount(6)` taşıdı.

**Ölçülen gerçek** (bu maddeye başlamadan önce, `CORE/worker_sizing.py`
modül docstring'inde de yazılı): `CORE/crypto.py::encrypt_file()` zaten
64 KB'lık bloklar hâlinde akıyor — 6 işçi eş zamanlı 100 MB'lık birer
dosyayı (600 MB toplam) şifrelerken süreç RSS'i yalnızca ~1 MB büyüdü.
Yani kripto tamponunun KENDİSİ "6 worker × tampon" şişmesinin kaynağı
değil. Buna rağmen bir işçinin GERÇEK ayak izi yalnızca o tampondan
ibaret değil — OS iş parçacığı yığını, `scan_file()`'ın ayrı alt
süreci, Qt/GC yükü — ve sabit "6" bunu hiç ölçmüyordu; eski/kısıtlı bir
adli bilişim istasyonunda (1-2 GB RAM) ya da ileride `_CHUNK` büyürse
önemli hâle gelebilir.

`CORE/worker_sizing.py::recommended_thread_count()` bu payı işçi
SAYISINI (tampon boyutunu DEĞİL — `_CHUNK` GCM akışının paylaşılan,
gerekçeli sabiti, dokunulmadı) O AN `psutil.virtual_memory().available`
RAM'in bir kesrine göre öneriyor. RAM bol olduğunda (ve `psutil`
erişilemediğinde — bu bir güvenlik kontrolü DEĞİL, sessizce dünkü sabit
6'ya düşülüyor) davranış AYNI kalıyor, yalnızca gerçekten düşük RAM'de
küçülüyor. `UI/main_window.py`'deki tek çağrı yeri güncellendi.

**Paketleme**: `psutil` `requirements-dev.txt`'ten (yalnızca B-081
tutamaç-sızıntısı regresyon testi için) `requirements.txt`'e taşındı —
artık üretim kodu da kullanıyor. `worker_sizing.py` onu FONKSİYON
GÖVDESİNDE import ediyor (`_kullanilabilir_ram_bytes()`), yani
PyInstaller'ın statik analizi göremiyor — reportlab/qrcode ile AYNI
sınıf sorun (B-024). Her iki spec'e de (`HYCLEUS.spec`,
`HYCLEUS-linux.spec`) `collect_all('psutil')` eklendi (paket saf Python
değil, platforma özgü derlenmiş bir C uzantısı taşıyor) ve `main.py::
_SELFTEST_MODULLERI`/`_SELFTEST_UCUNCU_TARAF`'a `CORE.worker_sizing`/
`psutil` eklendi — `tests/test_packaging.py`'nin elle tutulan liste
denetimi bunu YAKALADI (ilk `pytest -q` tam koşusunda tek başarısızlık
buydu, düzeltilip yeniden koşuldu).

Test (`tests/test_worker_sizing.py`, 8 test): saf hesap (`available_bytes`
enjekte edilerek — bol RAM'de sabit 6, düşük RAM'de orantılı küçülme,
`min_count`/`max_count` kelepçeleri, `psutil` erişilemezse sessiz
düşüş) VE gerçek ölçüm — `psutil.Process().memory_info()` ile 6×20 MB'lık
GERÇEK bir toplu şifrelemenin RSS büyümesinin toplam verinin dörtte
birinin ÇOK altında kaldığı, ayrıca düşük-RAM simülasyonuyla küçülen
işçi sayısının GERÇEKTEN o kadar işçiyle bir toplu işlemi sorunsuz
tamamladığı doğrulandı. `_CHUNK`'ı geçici olarak devasa bir değere
büyütüp (akmayı iptal ederek) bellek testinin gerçekten düştüğü
(`MemoryError`), sonra düzeltilip geçtiği ölçüldü.

Tam suite: 3136 passed, 4 skipped. ruff/mypy/bandit temiz.

---

## B-104 — Kurtarma parçası görüntülemesi denetim çıpasına anında kazınıyor

**Durum: UYGULANDI.**

`UI/security_actions.py::kurtarma_parcasini_goster()` (B-093'te
ortaklaştırılan gövde — damga/yedek/zincir/kurtarma dört doğrulamanın
sonuncusu) kurtarma parçasını (`master_key`'in Shamir 3. payı)
ÜRETTİĞİNDE bugüne kadar HİÇBİR denetim kaydı BIRAKMIYORDU — dosyada
zaten `db.log(...)` çağıran `zinciri_dogrula()`'nın YANINDA, kendisi
sessizdi. Kasadaki en hassas sırrın dışarı çıktığı an izsizdi.

`_kaydet_ve_cipaya_kazi(hwid)` (yeni, özel bir yardımcı) eklendi:
`export_recovery_share()` başarıyla döndükten HEMEN sonra çağrılıyor —
`RecoveryExport`/modal gösteriminden ÖNCE, çünkü asıl kayda değer olay
payın PIN'le başarıyla ÜRETİLMİŞ olması. İki şey yapıyor:

  1. `db.log(EYLEM_KURTARMA_GORUNTULENDI, ...)` — normal audit_log satırı,
     hash zincirine katılıyor.
  2. `write_anchor(db, EYLEM_KURTARMA_GORUNTULENDI)` — B-090'ın çift-yazım
     (yerel + takılı USB) altyapısı, GÜNLÜK döngüyü (`maybe_write_daily_
     anchor`) BEKLEMEDEN. `main.py`'nin kapanışta `write_anchor(DBManager(),
     "shutdown")` çağırdığı AYNI "olay-tetiklemeli anında çıpa" deseni
     (B-090) — yeni bir mekanizma İCAT EDİLMEDİ. Gerekçe: günlük döngü
     saatler sonra çalışabilir; o pencerede kayıt zincirde dursa bile
     ÇIPALANMAMIŞ kalır ve sessizce silinebilir/değiştirilebilir.

**Payın kendisi hâlâ hiçbir yere gitmiyor** — `_kaydet_ve_cipaya_kazi()`
imzası yalnızca `hwid` alıyor, `share_3`/`disa_aktarim`'a ERİŞİMİ YOK;
bu, "pay hiçbir kalıcı çağrıya ulaşmaz" kuralının derleme zamanı
garantisi. Mevcut `tests/test_recovery_share_ui.py::
test_adminpanel_payi_DISKE_yazmiyor` testi bu yüzden YENİDEN
YORUMLANDI (eskiden "log içeren HİÇBİR çağrı olamaz" derdi, artık
yanlış olurdu) ve YENİ, DAHA GÜÇLÜ bir test eklendi
(`test_the_recovery_share_value_never_reaches_a_persisting_call`) —
çağrı ADINA değil ARGÜMANLARINA bakıyor, payı BAŞKA bir yardımcıya
parametre olarak geçirip "temiz" görünmeyi de yakalıyor (mutasyonla
ölçüldü, `test_the_persisting_call_argument_scanner_is_not_blind`).

Ayrıca dosyanın sonundaki YİNELENEN `__all__` ataması (ikincisi
`kurtarma_parcasini_goster`'ı SESSİZCE dışarıda bırakıyordu) düzeltildi
— bu maddenin kapsamı değildi ama dokunulan dosyada fark edilen gerçek
bir kusurdu.

Test (`tests/test_recovery_share_anchor.py`, 6 test): GERÇEK bir vault +
GERÇEK bir "takılı USB" simülasyonuyla `kurtarma_parcasini_goster()`
uçtan uca çalıştırılıyor (yalnızca Qt diyalogları/canlı-yetki kapısı
sahte). Görüntülemenin hem `audit_log`'a hem YEREL hem USB çıpa
kopyasına düştüğü, iki ayrı görüntülemenin iki ayrı çıpa satırı
ürettiği doğrulandı. Asıl test — `tests/test_audit_chain.py`'nin
`verify_anchor_replicas()` testleriyle AYNI desen: yalnızca YEREL
kopyayı kurcalayıp (`entry_count` sahtelenerek) USB'yle karşılaştırınca
farkın YAKALANDIĞI gösterildi. Mutasyonla ölçüldü:
`_kaydet_ve_cipaya_kazi(hwid)` çağrısı geçici olarak kaldırılıp 5/6
testin GERÇEKTEN düştüğü, geri konunca hepsinin geçtiği doğrulandı.

Ayrıca `tests/test_layering.py`'nin depo-geneli denetimi (her test
dosyasının Qt/UI import'larını `try/except ImportError` ile sarması —
çıplak bir Linux koşucusunda TOPLAMA HATASI vermesin diye) yeni dosyayı
YAKALADI; diğer yedi UI test dosyasındaki desene sarıldı.

Tam suite: 3146 passed, 4 skipped. ruff/mypy/bandit temiz.

---

## B-105 — İkili dosyaya gömülü güven kökü (K4-20 ön koşulu): B-044'ün "dış depo" fikri yerine TLS yığınlarının deseni

**Durum:** Kapalı — dar kapsamlı bir öncül olarak teslim edildi
**Öncelik:** Yüksek (K4-20'yi bu hafta önden açıyor)
**Bulundu:** 2026-09-02 — K4-20 (RFC 3161 mührü, B-087) sıraya alınırken

B-044, `CORE/trusted_roots.py`'nin güven kökü listesinin `settings`
tablosunda (M3'e açık, şifresiz) durduğunu belgelemiş ve çözüm olarak
`HYCLEUS_AUDIT_ANCHOR`'ın (§4.6) deseni — bir ortam değişkeniyle listeyi
USB'ye/ağ paylaşımına yönlendiren "dış güvenli depo" — önermişti. Bu tur
o yön DEĞERLENDİRİLDİ ve reddedildi: ikinci bir ortam değişkeni, ikinci
bir "hangi kaynak kazanır" kararı, ikinci bir sızıntı yüzeyi — B-044'ün
kendi metninin de yazdığı gibi, iki kaynağı aynı anda kurmak zaten "tek
karar noktası" sınırını bulanıklaştırırdı.

### Yapılan: her TLS yığınının yaptığı

`CORE/trusted_roots_builtin.py` (yeni) güven kökünün KENDİSİNİ ikili
dosyaya, değişmez bir Python sabiti olarak gömüyor — OpenSSL'in
`ca-certificates` paketinin ya da bir tarayıcının kök mağazasının
yaptığı gibi. `tests/data/freetsa_response.der` fixture zincirinden
çıkarılan, freetsa.org'un GERÇEK kendinden imzalı Root CA'sı (parmak izi
sabit bir değere kilitli: `a6379e7c...d18aabc`). `gomulu_kokler()`
kasıtlı olarak `db` parametresi ALMIYOR — settings'e ne okuma ne yazma
var, yani M3'ün erişebileceği bir yüzey değil. Veri dosyası değil sıradan
bir `.py`: `HYCLEUS.spec`/`HYCLEUS-linux.spec`'e yeni bir `datas` girişi
gerekmiyor (B-081'in wmi/reportlab'da defalarca yakaladığı "paketlemede
unutulan bağımlılık" kusur sınıfının kendisi burada yapısal olarak yok).

### Kapsam BİLEREK dar tutuldu: genel doğrulama akışına karıştırılmadı

İlk deneme `gomulu_kokler()`'i sağ tık menüsündeki genel damga
doğrulamasına (`UI/main_window_files.py::_on_ctx_verify_timestamp`)
karıştırıyordu — ve bu GERÇEK bir regresyon üretti, testle yakalandı:
`tsa_url` kurum başına ayarlanabilir bir ayar ve `verify_timestamp
(trusted_roots=...)` VERİLDİĞİNDE eşleşmeyen kök `anchor_trusted=False`
değil doğrudan GEÇERSİZ (`failed_check=trust_anchor`) üretiyor.
`tests/test_timestamp_ui.py`'nin `FakeTSA()` kullanan iki testi
(`test_diyalog_gercekten_KURULUYOR`, `test_dogrulama_DENETIM_kaydina_
geçiyor`) gömülü kök karıştırılınca "uyarılı geçerli" beklerken
"GEÇERSİZ" ürettiğini gösterdi — yani kendi (freetsa OLMAYAN) TSA'sını
kullanan bir kurumun damgaları, o kurum kendi kökünü Ayarlar'a eklemeden,
YANLIŞLIKLA geçersiz görünürdü. Bu, TLS istemcilerinin gerçek davranışına
(eşleşmeyen zincir reddedilir) uysa da HYCLEUS'un § 4.9'da belgelediği
üç durumlu tasarımı ("kök tanımlı değilse uyarılı") kırardı — geri
alındı. `UI/main_window_files.py` değişmeden kaldı, yalnızca AÇIKLAYICI
bir yorum eklendi.

Gömülü kökün bugünkü tek KULLANICISI yok — henüz yazılmamış K4-20'nin
(B-087) önkoşulu olarak hazır bekliyor. K4-20'nin denetim raporu mührü
HER ZAMAN uygulamanın kendi varsayılan TSA'sıyla üretileceği için, orada
sert eşleşme (genel akıştan farklı olarak) yanlış pozitif üretmez — ve
mühür dışa aktarıldığında, onu doğrulayacak makinede HYCLEUS hiç kurulu
olmasa bile (`gomulu_kokler()` DB istemiyor) doğrulanabilmesi gerekiyor;
tam olarak bu maddenin sağladığı şey.

### Test (`tests/test_trusted_roots_builtin.py`, 12 test)

- Gömülü olduğunun yapısal kanıtı: `gomulu_kokler()`'in imzasında `db`
  yok; hiçbir test dosyası `db`/`DBManager` fixture'ı KURMADAN
  çağrılabiliyor; modülün AST'i disk/ağ/DB ilkeli (`open`, `sqlite3`,
  `requests`, ...) çağırmıyor.
- Gömülü olanın GERÇEKTEN freetsa.org'un kökü olduğunun kanıtı: fixture
  zincirindeki kökle bayt bayt eşleşiyor, ayrıca sabit bir SHA-256
  değerine kilitli.
- Uçtan uca: GERÇEK bir freetsa damgası, `db`/`DBManager` HİÇ
  kurulmadan, yalnızca `gomulu_kokler()` ile `anchor_trusted=True`
  çıkıyor.
- Negatif kontrol: genel doğrulama akışının gömülü kökü KULLANMADIĞI
  AST ile denetleniyor — yukarıdaki regresyonun geri gelmesini engeller.
- `main.py --selftest` listesine `CORE.trusted_roots_builtin` eklendi
  (B-103'ün yakaladığı paketleme kusur sınıfı).

Mutasyonla ölçüldü: `gomulu_kokler()` geçici olarak `[]` döndürecek
şekilde bozulup 7/12 testin GERÇEKTEN düştüğü, geri alınca hepsinin
geçtiği doğrulandı (`git diff --stat` ile temiz geri alım teyit edildi).

SECURITY.md §4.9 (EN+TR) güncellendi: iki yoldan üçe çıkan tablo + yeni
bir paragraf, gömülü kökün neden genel akışın dışında tutulduğunu
anlatıyor. `test_SECURITY_md_kok_deposunu_anlatiyor`'un saydığı sabit
değerler (`tsa_trusted_roots` × 2, "B-044" × 2) korundu.

Tam suite: 3146 passed → **3161 passed**, 4 skipped. ruff/mypy/bandit
temiz.

---

## B-106 — Denetim raporu (PDF) artık GERÇEK bir RFC 3161 mührü taşıyabiliyor (K4-20, B-087 kapandı)

**Durum:** Kapalı
**Öncelik:** Yüksek (B-087'nin bilinçli olarak ertelediği madde)
**Bulundu:** 2026-09-02 — B-105'in gömülü kökü kullanılabilir hâle gelince

B-087, `export_pdf()`'in "İmzalı Rapor"unun zincirin KENDİ kanıtını
(hash zinciri + dış çıpa) gömdüğünü ama PDF DOSYASININ KENDİSİNİ bir
RFC 3161 otoritesine imzalatmadığını, bunu kasıtlı olarak ayrı bir
maddeye bıraktığını belgelemişti. Bu madde onu kapatıyor.

### `CORE/timestamp.py::request_token()` — tek istemci gövdesi ayrıştırıldı

`timestamp_file()`/`timestamp_batch()`'in `build_request → gönder →
parse_response` gövdesi ORTAK bir fonksiyona çıkarıldı: `request_token
(digest, *, url, timeout, transport)`. `.hcl` formatından tamamen
bağımsız — yalnızca 32 baytlık bir özet alıp imzalı token döndürüyor.
Saf çıkarma (davranış değişmedi); `timestamp_file()`/`timestamp_batch()`
şimdi bunu çağırıyor, ikisi de aynı testlerle (`test_timestamp.py`,
`test_timestamp_batch.py`) hiç değişmeden geçti.

### `CORE/audit_report.py::export_sealed_pdf()` — döngüsel bağımlılık çözümü

PDF'in KENDİ SHA-256'sı mühre gidecek değer; ama PDF'in gövde metni
"mühürlü mü değil mi" diyorsa ve o metin token'a özgü bilgi (seri no,
damga zamanı) taşısaydı, metni yazmadan mühür alınamaz, mühür almadan
metin yazılamazdı — döngü. Çözüm: `sealed=True` metni token'a özgü HİÇBİR
ŞEY içermiyor, yalnızca dosyanın KENDİ adını (`<pdf>.tsr`, `verify_
report_seal_cli.py`) — ikisi de mühür alınmadan ÖNCE bilinir. Akış:

1. PDF'i `sealed=True` metniyle üret (`export_pdf(..., sealed=True)`).
2. O NİHAİ dosyanın SHA-256'sını hesapla.
3. `request_token()` ile TSA'ya damgalat.
4. Başarılıysa token'ı `<pdf>.tsr` (openssl'in `.tsr` adlandırmasıyla
   aynı) yardımcı dosyasına yaz.
5. BAŞARISIZSA (ağ, TSA reddi): PDF'i `sealed=False` metniyle YENİDEN
   üret — disk asla yanlış bir "mühürlü" iddiası TAŞIMAZ.

Mühür HER ZAMAN `DEFAULT_TSA_URL` (freetsa.org) kullanıyor, kurumun
yapılandırılabilir `tsa_url(db)` ayarını DEĞİL — bilinçli: B-105'in
gömülü kökü yalnızca freetsa.org'u taşıyor, doğrulama o kökle YAPILACAK.

### `CORE/verify_report_seal_cli.py` — bağımsız doğrulama, `verify_timestamp_cli.py`'nin eşdeğeri

`verify_timestamp_cli.py` bir `.hcl` KASA DOSYASI için yazıldı ve
`--key-file` zorunlu (B-092/B-099). PDF hiç şifreli değil — bu yeni araç
vault anahtarı/DB istemiyor, yalnızca PDF'in kendi SHA-256'sı ve `.tsr`
token'ı. Doğrulama gövdesi ORTAK: `CORE.timestamp_verify.verify_token()`
— ikinci bir kripto implementasyonu YOK. Varsayılan güven kökü BİLEREK
`verify_timestamp_cli.py`'den FARKLI: o araç kök verilmezse "doğrulanmadı"
der (denetlediği dosya HERHANGİ bir TSA'yla damgalanmış olabilir); bu
araç doğruladığı mührün HER ZAMAN freetsa.org'la üretildiğini bildiği
için varsayılanı B-105'in gömülü kökü (`CORE.trusted_roots_builtin.
gomulu_kokler()`) — DB'siz, dosyasız, yalnızca ikili dosyanın kendisi.
`--trusted-root` yine de veriliyorsa (testler için) onun YERİNE geçiyor.

`main.py --selftest` listesine `CORE.verify_report_seal_cli` eklendi.

### Test (`tests/test_report_seal.py`, 22 test)

- Metin flip: `sealed=False` → "MÜHÜRLENMEMİŞTİR" (ASCII-güvenli
  "KANITLAMAZ" araması, Türkçe özel karakterlerin reportlab'ta ham
  bayt aramasıyla eşleşmediği B-086'nın bilinen kısıtı); `sealed=True`
  → "MÜHÜRLÜDÜR" + `verify_report_seal_cli.py`/`.tsr` referansı, İKİSİ
  BİRDEN asla aynı belgede.
- `export_sealed_pdf()`: yazılan `.tsr`'nin döndürülen `TimestampInfo.
  token_der`'le AYNI baytlar olduğu; damgalanan özetin ARA (mühürsüz)
  sürümün değil NİHAİ (mühürlü metinli) dosyanın SHA-256'sı olduğu
  (döngüsellik kontrolü); TSA başarısızlığında dürüst geri dönüş VE
  `.tsr` dosyasının hiç yazılmadığı.
- CLI: gerçek bir mühür `FakeTSA` (gerçekten imzalayan test TSA'sı,
  `tests/tsa_fixtures.py`) ile üretilip `--trusted-root` ile doğrulandı;
  varsayılan (gömülü, gerçek freetsa) kökle yanlış TSA'nın GEÇERSİZ
  (yalnızca "doğrulanmadı" değil — B-105'in "trusted_roots verilince
  sert eşleşme" kuralı burada da geçerli) çıktığı; `gomulu_kokler()`
  monkeypatch'lenip varsayılan kökün GERÇEKTEN çağrıldığı; PDF kurcalama
  tespiti; eksik `.tsr`/PDF hataları; `--token` verilmeden `<pdf>.tsr`
  varsayılanının çalıştığı; gerçek alt süreçle (`subprocess.run`)
  `__main__` yolunun çalıştığı (`verify_timestamp_cli.py`'nin kendi
  testiyle AYNI desen).
- Yapısal: `CORE/audit_report.py`/`CORE/verify_report_seal_cli.py`
  `requests`'i DOĞRUDAN import ETMİYOR (tek HTTP çağrısı `CORE/
  timestamp.py::_http_post()`'ta); `export_sealed_pdf()` `request_token`
  çağırıyor, `build_request`/`_http_post`'u DOĞRUDAN çağırmıyor.

Mutasyonla ölçüldü: (a) `sealed=True` dalını geçici olarak devre dışı
bırakınca 2 test düştü (mühürlü metin hiç üretilmedi); (b) CLI'ın
`--trusted-root` geçersiz kılmasını kaldırıp HER ZAMAN `gomulu_kokler()`
kullandırınca 3 test düştü (açık kök verilen testler artık yanlış kökü
kullanıyordu). İkisi de geri alındı, `git diff --stat` ile temiz.

SECURITY.md §4.25 (EN+TR) güncellendi: B-087'nin ertelediği kararın
kapandığını, döngüsellik çözümünü ve varsayılan kök seçimini anlatan bir
"Güncelleme" paragrafı.

Tam suite: **3187 passed**, 4 skipped (22 yeni test dahil). ruff/mypy/
bandit temiz.

---

## B-107 — Kurumsal Referans Kodu girişine hız sınırı: CORE/rate_limit.py'nin AYNI mekanizması, AYRI anahtar uzayı

**Durum:** Kapalı
**Öncelik:** Orta (kaba kuvvet sertleştirmesi — backend F0-2 (a)'da zaten kurulu)
**Bulundu:** 2026-09-02

F0-2 kararı (a) (2026-08-26) Referans Kodu doğrulamasını ZATEN üretime
soktu (`CORE/referans_id.py`, `UI/login_dialog.py::_on_register()`) —
girilen kod `get_referans_id(db)`'nin döndürdüğüyle GERÇEKTEN
karşılaştırılıyor. Eksik olan tek şey: karşılaştırma sınırsız denenebiliyordu
— 32⁸ ≈ 1.1×10¹² olasılık uzayı bile, hız sınırı olmadan, otomatikleştirilmiş
bir istemcinin dakikada binlerce deneme yapmasını engellemiyordu.

### Ne YAPILMADI

Yeni bir sayaç tablosu, yeni bir kilit mekanizması, yeni bir `LockState`
sınıfı — HİÇBİRİ. `CORE/rate_limit.py` giriş ekranı için ZATEN vardı
(`login_attempts` tablosu, DB'de tutulan sayaç — yeniden başlatmak
sıfırlamaz, üstel geri çekilme 30→60→120→300 sn) ve `check()`/
`record_failure()`/`record_success()`/`record_blocked_attempt()` dört
fonksiyonu aynen çağrılıyor.

### Tek yeni karar: ayrı anahtar uzayı

`_on_register()`'daki referans kodu bloğu `_rl_key()` (çıplak HWID)
yerine yeni `_referans_rl_key()`'i kullanıyor — `f"referans:{hwid}"`.
Aynı `login_attempts` tablosunda, `hwid` sütunu düz metin PRIMARY KEY
olduğu için önekli bir string de geçerli bir satır. Gerekçe: referans
kodu denemeleri ile PIN/TOTP giriş denemeleri AYRI olaylar — aynı kovaya
düşselerdi, bir kullanıcının kayıt sırasında kod yazım hataları o USB'nin
GİRİŞ ekranını da kilitlerdi. Mutasyonla ölçüldü (bkz. aşağı).

Akış `_on_login()` ile AYNI sıra: önce `rate_limit.check()` — kilitliyse
karşılaştırma hiç YAPILMADAN reddediliyor (doğru kod bilse bile kilitliyken
geçemiyor, "hız sınırı" gerçek bir sınır, yalnızca yanlış tahminleri
yavaşlatan bir sayaç değil). Boş gönderim (`girilen_kod == ""`) sayaca HİÇ
işlenmiyor — bir tahmin değil, "Kayıt Ol"a boş alanla art arda basmak bile
kilitlenmeye yol açardı. Doğru kod `record_success()` ile sayacı sıfırlıyor
— giriş ekranıyla AYNI davranış.

Audit log action adları (`login_failed`/`login_rate_limited`/
`login_blocked`) BİLEREK değiştirilmedi — bu fonksiyonların içinde sabit;
yeniden isimlendirmek "ikinci bir implementasyon" tarafına kayardı.
Ayırt edici bilgi zaten `detail=`'de: `hwid=referans:<hwid>` öneki gerçek
bir HWID'de asla görünmeyeceği için denetim kaydını okuyan biri karıştırmaz.

### Test (`tests/test_kayit_kurumsal_referans.py`, +4 yeni test)

- Art arda `MAX_ATTEMPTS` (5) yanlış kod → eşik aşılınca DOĞRU kod bile
  reddediliyor (kilitliyken karşılaştırma hiç çalışmıyor).
- Yanlış pozitif yok: taze bir HWID'de doğru kod İLK denemede, hiçbir
  gecikme olmadan geçiyor.
- Ayrı anahtar uzayı: referans sayacı kilitlenince GİRİŞ ekranının PIN/
  TOTP sayacı (`_rl_key()`) ETKİLENMİYOR.
- Boş kod denemeleri (10 kez) sayacı hiç artırmıyor; ardından doğru kod
  yine gecikmesiz geçiyor.

Mutasyonla ölçüldü: (a) `if lock.locked:` bloğunu `if False:`e çevirince
"art arda" testi GERÇEKTEN düştü (hız sınırı aşıldıktan sonra doğru kod
geçti); (b) `_referans_rl_key()`'i `_rl_key()` ile AYNI değeri
döndürecek şekilde bozunca "karışmıyor" testi GERÇEKTEN düştü (referans
denemeleri giriş ekranını da kilitledi). İkisi de geri alındı, `git diff
--stat` ile temiz.

Tam suite: 3187 passed → **3191 passed**, 4 skipped. ruff/mypy/bandit
temiz (yeni dosyalarda; `UI/login_dialog.py`'nin mypy'de değişmeyen 50
ön-var-olan Qt stub hatası, `git stash` ile teyit edildi).

---
