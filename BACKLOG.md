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

**Durum:** Açık — CI yeşil, kurallar bilinçli olarak gevşek
**Öncelik:** Düşük (teknik borç, çalışma zamanı etkisi yok)
**İlgili:** 1.3 (CI kurulumu) ile birlikte açıldı
**Bulundu:** 2026-08-13, CI kurulumu sırasında

### Bulgu

CI'ı ayağa kaldırırken ruff ve mypy mevcut kodu FAIL ettirmeyecek şekilde
yapılandırıldı ([`pyproject.toml`](pyproject.toml)). Susturulan gerçek ihlaller:

| Kural | Adet | Açıklama |
|---|---:|---|
| `E402` | 33 | Modül-seviyesi import en üstte değil — `sys.path` bootstrap'ı bilinçli |
| `F401` | 8 | Kullanılmayan import (çoğu `UI/` altında) |
| `F541` | 3 | Yer tutucusuz f-string |
| `F841` | 1 | Kullanılmayan yerel değişken |
| `E741` | 1 | Belirsiz değişken adı (`l` / `I` / `O`) |

mypy tarafında gevşetilenler: `ignore_missing_imports = true`,
`check_untyped_defs = false`, `strict` kapalı, `UI/` tamamen hariç.

### Yapılacaklar (sırayla, ayrı ayrı ele alınabilir)

1. `F401` / `F541` / `F841` / `E741` temizliği — `ruff check --fix` çoğunu
   otomatik hallediyor; `ignore` listesinden çıkar.
2. `E402` kalıcı istisna mı karar ver. `sys.path` bootstrap'ı bir paket
   girişine (`__main__` / konsol scripti) taşınırsa kural açılabilir.
3. mypy: önce `check_untyped_defs = true`, sonra `CORE/` için
   `disallow_untyped_defs = true`. `CORE/` zaten büyük ölçüde tipli —
   en düşük maliyetli adım burası.
4. `UI/` için PySide6 stub durumuna bakıp `exclude` listesinden çıkarmayı
   değerlendir.

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

## B-004 — İmha Odası sayacı yalnızca UI açıkken işliyor

**Bulundu:** 2026-08-13, saklama profili silme/imha akışı çalışması sırasında.
**Durum:** düzeltilmedi — bulgu kaydı.

### Bulgu

İmha Odası'na atılan dosya `expires_at = now + imha_ttl_hours` alıyor, ama bu
sayacı işleten iki mekanizmadan hiçbiri arka planda `Imha` etiketini
temizlemiyor:

| Mekanizma | Nerede | Hangi etiket |
|---|---|---|
| `_purge_expired` (APScheduler, 10 dk) | `CORE/scheduler.py` | **yalnızca `Karantina`** |
| `_tick_expiry` (QTimer, 1 sn) | `UI/main_window.py` | `Imha` — **ama yalnızca İmha Odası sekmesi açıkken** |

`_tick_expiry` ilk satırında `if self._current_label != "Imha": return` var.
Yani süresi dolmuş bir İmha Odası dosyası, kullanıcı o sekmeye girmediği
sürece süresiz olarak diskte kalıyor. "24 saat içinde silinecek" diyen
kullanıcı mesajı (`main_window.py`, `_on_ctx_move_to_imha`) bu durumda
doğru değil.

### Etkisi

Veri kaybı değil, veri KALIŞI: silinmesi beklenen dosya diskte duruyor.
Kullanıcı sekmeyi açtığı anda toplu olarak siliniyor — yani silme zamanı
kullanıcının gezinme davranışına bağlı, öngörülemez.

### Saklama profilleriyle ilişkisi

Saklama süresi süpürmesi (`CORE/disposal.py::sweep_retention_expired`) bu
sayaca BİLEREK bağlanmadı: süresi dolan dosyaya `expires_at = NULL` yazıyor,
çünkü sayaç kurmak dosyayı 24 saat sonra onaysız imha ederdi. Dolayısıyla bu
bulgu saklama akışını etkilemiyor — süpürülen dosyalar zaten sayaçsız.

### Olası çözüm (uygulanmadı)

`_purge_expired` sorgusundaki `label = 'Karantina'` koşulunu
`label IN ('Karantina', 'Imha')` yapmak sayacı arka plana taşır. DİKKAT: bu
değişiklik yapılırsa `sweep_retention_expired`'in `expires_at = NULL`
davranışı KRİTİK hale gelir — NULL olmayan her satır artık arka planda ve
onaysız silinir. `CORE/disposal.py` modül docstring'i bu bağımlılığı
açıklıyor, oradaki gerekçe okunmadan dokunulmamalı.

---

## B-006 — Denetim zinciri doğrulamasının arayüzde karşılığı yok

**Durum:** Açık — mekanizma çalışıyor, kullanıcıya görünmüyor
**Öncelik:** Orta (özellik erişilemez durumda; güvenlik zafiyeti **değil**)
**İlgili:** Denetim kaydı hash zinciri (`CORE/audit_chain.py`, SECURITY.md §4.6)
**Bulundu:** 2026-08-13, zincir uygulaması sırasında

### Bulgu

Zincir doğrulaması üç yerden çağrılabiliyor: `db.verify_audit_chain()`,
`verify_against_anchor()`, `verify_anchor_file()`. Hiçbirinin arayüzde
düğmesi yok. Kullanıcının zinciri kontrol edebildiği tek an açılış: uyuşmazlık
varsa `main.py` bir uyarı gösteriyor. "Şimdi kontrol et" diyebileceği bir yer
yok, halbuki [`UI/AuditLogDialog.py`](UI/AuditLogDialog.py) bunun doğal yeri.

Kurcalama kanıtı, ancak birileri kanıta BAKABİLİYORSA işe yarar.

### İkinci bulgu — TXT dışa aktarımı zincirden habersiz

`AuditLogDialog._export_txt()` yalnızca dört sütun yazıyor (zaman, işlem,
kullanıcı, HWID). Hash yok, zincirin son ucu yok, doğrulama durumu yok.
Halbuki bu dışa aktarım, kullanıcının denetim kaydını makine dışına
taşıdığı tek yol — yani §4.6'nın "çıpayı başka bir güven alanına taşıyın"
tavsiyesinin pratikte karşılığı olabilecek şey. Şu hâliyle dışa aktarılan
dosyayla veritabanının tutarlı olup olmadığı sonradan gösterilemez.

### Yapılacaklar (uygulanmadı)

1. `AuditLogDialog`'a "Zinciri Doğrula" düğmesi; sonucu
   `ChainVerification.summary()` ile göster (metin zaten kullanıcıya
   gösterilecek biçimde yazıldı, Türkçe ve kırılma noktasını içeriyor).
2. Kırık zincirde satırları görsel olarak işaretle — `_is_failure()`'ın
   kırmızı satır deseni hazır.
3. Dışa aktarıma zincir başlığı ekle: `chain_start_id`, son hash, doğrulama
   sonucu ve varsa çıpa karşılaştırması.
4. Çıpa dosyasının yolunu (ve `HYCLEUS_AUDIT_ANCHOR` ile
   değiştirilebildiğini) ayarlar ekranında göster — USB'ye yönlendirme şu an
   yalnızca ortam değişkeniyle mümkün ve hiçbir yerde yazmıyor.

---

## B-007 — Klasör görünümü mahrem etiket filtresini uygulamıyor

**Durum:** Açık — mevcut davranış korundu, testle sabitlendi
**Öncelik:** **Orta-yüksek.** Gizlilik boşluğu: mahrem olarak işaretlenmiş
bir dosya, yönetici olmayan bir kullanıcıya bir görünümde gizlenirken
başka bir görünümde gösteriliyor. Veri kaybı ya da kripto zafiyeti değil,
ama "mahrem etiket" özelliğinin vaadi tam olarak bu.
**İlgili:** 2.7 Faz 1 adım 3 (`CORE/file_queries.py`)
**Bulundu:** 2026-08-13, dört liste sorgusu CORE'a taşınırken

### Bulgu

Mahrem etiket (`tags.is_private = 1`) taşıyan dosyalar yönetici olmayan
kullanıcılardan gizleniyor — ama bu filtre dört liste görünümünün yalnızca
ikisinde var:

| Görünüm | SQL filtresi | Arayüz engeli | Sonuç |
|---|---|---|---|
| `files_by_label()` | ✅ var | — | gizli |
| `search_files()` | ✅ var | — | gizli |
| `files_by_tag()` | ❌ yok | ✅ mahrem etiket kenar çubuğunda gösterilmiyor, tıklanamıyor | pratikte kapalı |
| `files_by_folder()` | ❌ yok | ❌ **yok** | **görünür** |

Yani yönetici olmayan bir kullanıcı bir klasöre girdiğinde, o klasördeki
mahrem etiketli dosyaları görüyor. Aynı dosyalar "Genel" etiket
görünümünde ve aramada gizleniyor.

Etiket görünümündeki eksik filtre şu an sömürülebilir değil: mahrem
etiketler yönetici olmayana kenar çubuğunda hiç çizilmiyor
([`UI/main_window.py`](UI/main_window.py) `_refresh_tag_sidebar`) ve
tıklanması `_on_tag_click` içinde ayrıca engelleniyor. Ama savunma tek
katman — kenar çubuğu mantığı değişirse sorgu bir engel sunmaz.

### Neden 2.7'de düzeltilmedi

2.7 saf bir yeniden düzenleme; sözü verilen şey davranışın DEĞİŞMEMESİ.
Filtreyi dört görünüme birden uygulamak refactor'ü davranış değişikliğine
çevirirdi ve gerçek bir düzeltme olsa bile 2900 satırlık bir taşıma
commit'inin içinde gizlenmiş olurdu. Bulgu, düzeltilmesi gereken yerde
görünür kalsın diye buraya yazıldı.

Mevcut (hatalı) davranış [`tests/test_file_queries.py`](tests/test_file_queries.py)
içinde `test_folder_view_does_NOT_filter_private_files` ve
`test_tag_view_does_NOT_filter_private_files` ile **sabitlendi**. Bu testler
bir onay değil, bir işaret: düzeltme yapıldığında ikisi de kırılacak ve
güncellenmeleri gerekecek — yani düzeltme bilinçli bir karar olarak
görünecek.

### Yapılacaklar (uygulanmadı)

1. `files_by_folder()` ve `files_by_tag()` fonksiyonlarına da
   `include_private` parametresi ekle; `CORE/file_queries.py` içinde
   `_EXCLUDE_PRIVATE` zaten hazır, tek satırlık ekleme.
2. Çağrı yerlerini (`_load_folder_files`, `_load_tag_files`) diğer ikisiyle
   aynı biçimde `include_private=self._role == "Yönetici"` ile bağla.
3. `test_file_queries.py`'deki iki sabitleme testini yeni davranışa göre
   güncelle (adlarındaki `does_NOT` ifadeleri de değişmeli).
4. Kenar çubuğu engelini KALDIRMA — iki katman birlikte dursun.

### Not — rol adı katman sınırında kalıyor

`include_private` bilerek bir bool: `"Yönetici"` rol adı bir arayüz sabiti
ve `CORE/file_queries.py` onu bilmiyor. Rol → yetki eşlemesini CORE'a
taşımak ayrı bir iş (vault rolü ile `users.role` sütunu farklı şeyler ve
şu an ikisi birbirine karışmış durumda).

---

## B-009 — Toplu indirme dosya başına ayrı sorgu atıyor (N+1)

**Durum:** Açık — mevcut davranış korundu (saf refactor kuralı)
**Öncelik:** Düşük (performans; doğruluk etkisi yok)
**İlgili:** 2.7 Faz 1 adım 5 (`CORE/export.py`)
**Bulundu:** 2026-08-13, iki indirme akışı yan yana getirilirken

### Bulgu

İki dışa aktarma akışı `aad_metadata`'yı farklı biçimde okuyor:

| Akış | Sorgu |
|---|---|
| Klasör → ZIP | **tek sorgu**, tüm alanlar önden (`WHERE folder_id = ?`) |
| Toplu → dizin | **dosya başına bir sorgu**, döngü içinde (`WHERE id = ?`) |

500 dosyalık bir toplu indirme 500 ek sorgu atıyor. Sorgular indeksli
(birincil anahtar) ve yerel SQLite'a gidiyor, dolayısıyla etkisi ölçülebilir
ama küçük — asıl maliyet zaten çözme ve diske yazma.

### Neden düzeltilmedi

Değişiklik tek satırlık: `WHERE id IN (...)` ile bir kez okuyup sözlüğe
almak. Ama 2.7 saf bir yeniden düzenleme ve sorgu sayısını değiştirmek
teknik olarak davranış değişikliğidir (eşzamanlı bir yazma varsa okunan
değer farklı olabilir). Bu turda taşınan kod birebir korundu.

Kod `CORE/export.py::export_to_directory` içinde ve döngüdeki sorgu
`# B-009` yorumuyla işaretli.

### Yapılacak (uygulanmadı)

1. `export_to_directory` çağrılmadan önce `aad_metadata`'yı tek sorguyla
   toplayıp `{file_id: aad}` sözlüğü olarak geçir.
2. `export_to_zip` zaten satırları hazır alıyor — iki akış aynı desende
   buluşur ve `db` parametresi `export_to_directory`'de yalnızca denetim
   kaydı için kalır.

---

## B-010 — İki indirme akışı AAD'sız dosyalarda farklı davranıyor

**Durum:** Açık — mevcut davranış korundu, testle sabitlendi
**Öncelik:** Orta (tutarsız güvenlik kontrolü; hangi tarafın doğru olduğu
belirlenmeli)
**İlgili:** B-009 ile aynı kod, 2.7 Faz 1 adım 5
**Bulundu:** 2026-08-13

### Bulgu

`aad_metadata` boş ya da içinde `hwid` yoksa iki akış farklı karar veriyor:

```
ZIP     : hwid = aad_hwid or (DEV-HWID-1234 / oturum hwid'i)  → doğrulama YAPILIR
Dizine  : hwid = aad_hwid                                      → doğrulama YAPILMAZ
```

Sonuç: AAD'sı olmayan eski bir kayıt, **klasör indirmede "bütünlük hatası"
verip atlanırken toplu indirmede sorunsuz çözülüyor.** Aynı dosya, aynı
anahtar, aynı kullanıcı — farklı sonuç.

Bu bir açık değil (GCM doğrulaması her iki yolda da yapılıyor; farklı olan
yalnızca AAD'daki hwid'in oturum hwid'iyle karşılaştırılıp
karşılaştırılmadığı), ama tutarsız ve hangisinin kasıtlı olduğu belli değil.

Mevcut davranış [`tests/test_export.py`](tests/test_export.py) içinde
`test_zip_falls_back_to_the_session_hwid` ve
`test_directory_export_does_NOT_fall_back_by_default` ile sabitlendi.

### Yapılacak (uygulanmadı)

Önce karar: AAD'da hwid yoksa oturum hwid'iyle doğrulanmalı mı?

- **Evet ise** — toplu indirme de `hwid_fallback` almalı. Yan etki: başka
  cihazda şifrelenmiş eski dosyalar toplu indirmede de erişilemez olur.
- **Hayır ise** — ZIP akışındaki geri dönüş kaldırılmalı. Yan etki:
  hwid doğrulaması AAD'sı olmayan dosyalarda tümüyle devre dışı kalır.

`CORE/export.py` her iki davranışı da destekliyor (`hwid_fallback`
parametresi), yani düzeltme yalnızca çağrı yerlerinde tek satır.

---

## B-011 — Klasör oluşturma eksik `users` satırını uyduruyor

**Durum:** Açık — mevcut davranış korundu, testle sabitlendi
**Öncelik:** Orta (veri bütünlüğü; denetim kaydının güvenilirliğini etkiler)
**İlgili:** 2.7 Faz 1 adım 6 (`CORE/folders.py`)
**Bulundu:** 2026-08-13

### Bulgu

`create_folder()`, `owner_id` olarak verilen kullanıcı `users` tablosunda
yoksa **onu uyduruyor**:

```sql
INSERT INTO users (id, username, password_hash, role, status, hwid)
VALUES (?, 'yonetici', '', 'admin', 'approved', ?)
```

Yani: boş parola hash'i, `admin` rolü, `approved` durumu. Sebep
`folders.owner_id` yabancı anahtarı — DEV_MODE'da ya da `users` satırı hiç
yazılmamış bir oturumda klasör oluşturma FK hatasıyla düşerdi ve bu kaçamak
onu susturuyor.

### Etkisi

- **Denetim kaydı güvenilirliğini zedeliyor.** Sonradan bakan biri
  `users` tablosunda gerçek bir "yonetici" hesabı görüyor; o hesap hiç
  kaydolmamış, sadece bir FK'yı susturmak için var.
- **Boş parola hash'i.** Bugün zararsız: giriş yolu vault üzerinden
  işliyor ve `users.password_hash` doğrulamada kullanılmıyor. Ama boş
  hash'li `admin` rollü bir satır, ileride parola tabanlı bir yol
  eklenirse hazır bir açık olur.
- Aynı `user_id` ile ikinci kez çağrılırsa satır zaten var, dokunulmuyor —
  yani tek seferlik bir kirlilik.

### Kök neden

Oturum açılırken `users` satırının yazılacağı garanti değil: kimlik vault
dosyasından geliyor, `users` tablosu ise ayrı yaşıyor. İkisi arasında
bir "oturum açan kullanıcıyı kaydet" adımı yok.

### Yapılacaklar (uygulanmadı)

1. Oturum açılışında (`main.py`, giriş başarılı olduktan hemen sonra)
   kullanıcıyı gerçek bilgilerle `users` tablosuna yaz/güncelle.
2. `ensure_owner_exists()` kaçamağını kaldır; `create_folder()` FK
   hatasını olduğu gibi yükseltsin.
3. Uydurulmuş satırları tespit etmek için tek seferlik bir kontrol:
   `SELECT id FROM users WHERE password_hash = '' AND username = 'yonetici'`.

Mevcut davranış [`tests/test_folders.py`](tests/test_folders.py) içinde
`test_create_writes_a_placeholder_user_when_missing` ile sabitlendi.

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

## B-015 — `main.py`'nin son yedekten haberi yok

**Durum:** Açık — 3.3 (yedekleme) turunda fark edildi

Yedekleme özelliği var ama HATIRLATMASI yok. Haftalık bütünlük taraması
(`CORE/integrity.py`) "son çalışma zamanı" ayarını tutup kapı deseniyle
kendini tetikliyor; yedeklemede böyle bir şey yok.

Sonuç: yedek yalnızca kullanıcı aklına geldiğinde alınıyor. Kullanılmayan
bir yedekleme özelliği, olmayan bir yedekleme özelliğidir — ve bu, 3.3'ün
kapatmayı amaçladığı boşluğu (medya kaybı) fiilen açık bırakıyor.

### Yapılacaklar (uygulanmadı)

1. `create_backup()` başarıyla bittiğinde `settings`'e son yedek zamanını
   yaz (`backup_last_run`, `integrity_last_sweep` ile aynı desen).
2. Açılışta ya da zamanlayıcıda kontrol: son yedek N günden eskiyse
   (ya da hiç alınmamışsa) arayüzde kalıcı olmayan bir uyarı göster.
   Eşik ayarlanabilir olsun; `0` uyarıyı kapatsın (hareketsizlik kilidi
   ayarıyla aynı kalıp).
3. Uyarı ENGELLEYİCİ olmamalı — tekrar tespitindeki gibi bilgilendirici.
4. `CORE.backup.latest_backup()` zaten var; hedef dizin ayarlarda
   tutulursa uyarı o dizine bakarak "yedek gerçekten duruyor mu" da
   diyebilir.

### Not

Yedek hedefi ayarlarda tutulacaksa, harici diskin takılı olmadığı
durumun sessizce "yedek yok" gibi görünmemesi gerekir — "hedef
erişilemiyor" ile "yedek eski" farklı mesajlar.

**Öncelik:** düşük-orta. Düzeltme değil, eksik özellik tamamlaması.

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

### Kalan tek ölçüm

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

**Durum:** Açık — CI yeşil, kurallar bilinçli olarak gevşek
**Öncelik:** Düşük (teknik borç), **B-607 kısmı orta**
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

## B-019 — CI özet betiği `defusedxml` kullanmıyor

**Durum:** Açık — bilinçli karar, gerekçesi kodda yazılı
**Öncelik:** Düşük
**Bulundu:** 2026-08-16, semgrep'in ilk taramasında

[`.github/scripts/test_summary.py`](.github/scripts/test_summary.py) JUnit
XML'ini `xml.etree.ElementTree` ile okuyor. semgrep iki yerde
`use-defused-xml` veriyor.

Bulgu teknik olarak geçerli: ElementTree "billion laughs" iç varlık
genişlemesine açık (dış varlık çözümlemesi zaten desteklenmiyor).

**Neden düzeltilmedi:** girdi, aynı CI işinde bir önceki adımda pytest'in
ürettiği `test-results.xml`. Düşmanca XML yazabilen biri zaten CI çalışma
alanında kod çalıştırabiliyor demektir — SECURITY.md §1'in sınırının
içinde. Yalnızca bunun için yeni bir CI bağımlılığı eklemek, güvenlik
odaklı bir projede bağımlılık yüzeyini kazanç olmadan büyütürdü.

### Yapılacak (uygulanmadı)

Yine de yapılacaksa iki satır: `requirements-dev.txt`'e `defusedxml`,
betikte `from defusedxml.ElementTree import parse`. Karar, bağımlılık
sayısını mı yoksa bulgu sayısını mı sıfırda tutmak istediğimize bağlı.
Bugünkü tercih birincisi ve satırda `# nosemgrep` ile gerekçeli.

---

## B-020 — semgrep kural dosyasını yerel kod sayfasıyla okuyor

**Durum:** Açık — yukarı akış (upstream) sorunu, geçici çözüm devrede
**Öncelik:** Düşük (geliştirici deneyimi), ama TUZAK
**Bulundu:** 2026-08-16

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

## B-022 — `hwid_probe` serili aygıtı "serisiz" diye raporluyor

**Durum:** Açık — prototipte, üretim kodunu etkilemiyor
**Öncelik:** Düşük (yalnızca 3.4 prototipi; `usb_manager` doğru okuyor)
**İlgili:** [`CORE/hwid_probe.py`](CORE/hwid_probe.py), B-016
**Bulundu:** 2026-08-16, B-016 ölçümü sırasında — prototipin çıktısı ham
WMI verisiyle çelişince

### Bulgu

Gerçek USB token takılıyken `python -m CORE.hwid_probe` şunu dedi:

```
windows  ????:????  tanımlayıcı_seri=(yok)  üretilmiş=EVET
UYARI: 1 aygıtta taşınabilir kimlik YOK.
```

Aygıtın serisi **var** (bkz. B-016). Prototip yanlış rapor verdi. İki
bağımsız kusur üst üste bindi:

**1. Yanlış düğümü okuyor.** `read_windows()` `Win32_DiskDrive`'ın
`PNPDeviceID`'sini alıyor, o da **depolama** yığını düğümü:

```
USBSTOR\DISK&VEN_SANDISK&PROD_CRUZER_BLADE&REV_1.00\<seri>&0
```

`parse_windows_pnp_id()` ise `USB\VID_xxxx&PID_yyyy\<instance>` biçimine
göre yazılmış. USBSTOR düğümünde VID/PID **yok** — çıktıdaki `????:????`
bunun belirtisi ve zaten görülüyordu, ama okumaya değil biçime yorulmuştu.

**2. "Üretilmiş kimlik" sezgisi yanlış pozitif veriyor.**

```python
_GENERATED_INSTANCE_RE = re.compile(r"^[0-9a-fA-F]+&")
```

Kural şuydu: üretilmiş kimlikler `8&F2CB6FA&0&9` gibi görünür, gerçek
seriler `&` içermez. USBSTOR düğümü ise seriye `&0` örnek soneki
**ekliyor** — ve SanDisk serileri baştan sona onaltılık karakterlerden
oluşuyor. Sonuç: `<seri>&0` desene tam uyuyor.

Bu nadir bir kenar durum değil, SanDisk için **sistematik**. Ölçüm:

| Girdi | `parse_windows_pnp_id` | Doğru mu |
|---|---|---|
| `USBSTOR\DISK&VEN_SANDISK&…\<seri>&0` | `(None, None, '<seri>&0', True)` | **hayır** |
| `USB\VID_0781&PID_5567\<seri>` | `('0781', '5567', '<seri>', False)` | evet |

Yani ayrıştırıcı doğru, **beslendiği veri** yanlış.

### Neden önemli

Prototipin tek işi bir mimari soruya kanıt üretmekti ve **ters yönde
kanıt üretti**: taşınabilir kimliği olan bir aygıta "yok" dedi. B-016
kararı bu çıktıya bakarak verilseydi, gereksiz bir mimari geçiş
başlatılırdı. Sessizce yanlış cevap veren bir ölçüm aracı, hiç
olmayandan kötü.

### Üretim kodu etkilenmiyor

`usb_manager.get_usb_hwid()` `PNPDeviceID`'ye hiç bakmıyor; doğrudan
`Win32_DiskDrive.SerialNumber` okuyor ve o alan doğru değeri veriyor.
Prototip uygulamaya bağlı değil (modül docstring'inin ilk satırı).

### Yapılacak

1. `read_windows()` USB yığını düğümünü de okusun (`Win32_PnPEntity`,
   `PNPDeviceID LIKE 'USB\VID_%'`) ve seriye göre USBSTOR düğümüyle
   eşleştirsin. VID/PID ancak oradan gelir.
2. USBSTOR örnek sonekini (`&<rakam>`) sezgiye sokmadan önce ayıkla.
3. Regresyon testi: yukarıdaki iki gerçek `PNPDeviceID` dizesi tabloya
   girsin — ikisinin de doğru sınıflandırıldığı sabitlensin.

### Yanında duran ikinci kusur

`normalize_serial()` sonunda `.lstrip("0")` var. Amaç Windows'un
biçimlendirmesini temizlemekti ama bu, **sıfırla başlayan seriyi
bozuyor**: `0123ABC` → `123ABC`. Farklı iki aygıt aynı kimliğe
çakışabilir. Bugün zararsız (fonksiyonu yalnızca prototipin `stable_id`'si
çağırıyor, üretimde kullanılmıyor), ama 1. maddeyi yaparken düzeltilmeli
— yoksa düzeltilmiş okuyucu bu sefer doğru seriyi kırpar.
