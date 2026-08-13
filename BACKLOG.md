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
