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

**Durum:** Açık — DÜZELTİLMEDİ, karar kullanıcıya bırakıldı
**Öncelik:** Orta (hiçbiri kod hatası değil; hepsi belge doğruluğu)
**Bulundu:** 2026-08-21 — üç saldırgan modeli eklendikten sonraki okuma turu

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

**Durum:** Açık — bilinçli kapsam sınırları, hata değil
**Öncelik:** Orta (1. madde), Düşük (kalanlar)
**Bulundu:** 2026-08-21 — TPM 2.0 mühürlemesi eklenirken

`CORE/tpm_sealing.py` eklendi ve SECURITY.md §4.13'te belgelendi. Bilerek
YAPILMAYAN dört şey burada; hiçbiri gizlenmiyor.

### 1. Mevcut kayıtlar geriye dönük mühürlenmiyor — ASIL EKSİK

Mühürleme yalnızca YAZMA anında oluyor. `share_2` ise yalnızca kasa
kurulurken ya da yeniden sağlanırken yazılıyor. Sonuç:

> **TPM'li bir makinedeki YERLEŞİK bir kurulum, kasa yeniden sağlanana
> kadar bu özellikten hiçbir kazanım görmüyor.**

Ve bunu hiçbir arayüz söylemiyor. Kullanıcı Hakkında kutusunda "TPM
mühürlemesi ETKİN" görüyor — ki doğru, mühürleme etkin — ama KENDİ
`share_2` kaydı hâlâ mühürsüz olabilir. Bu, B-025'in şeklinin bir tık
yumuşamış hâli: katman açık, ama o kayda uygulanmamış.

Neden bu turda yapılmadı: göç iki yoldan biriyle olurdu ve ikisi de
istenen "saf ekleme" sınırını aşıyor.

  (a) **Okurken yeniden mühürle.** `load()` mühürsüz bir kayıt görünce
      mühürleyip geri yazar. Ucuz ama `open_vault()` bir OKUMA işlemine
      yazma ekler — kasa açma akışının davranışı değişir.
  (b) **Açılışta göç adımı.** `DB/migrations.py` iskeleti hazır ama o
      defter SQLite şeması için; anahtar kasası kayıtları şema değil.
      Ayrı bir göç noktası gerekir.

Yapılacak: önce ÖLÇÜM. `share_2` kaydının mühürlü olup olmadığı
`muhurlu_mu()` ile bakılabiliyor; AdminPanel'e "bu kasa TPM'e mühürlü:
evet/hayır" satırı eklemek göçten önce gelmeli — göç edilmemiş kurulumun
görünmemesi, göçün kendisinden daha büyük sorun.

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
