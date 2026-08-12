# HYCLEUS — Backlog

Planın doğrudan kapsamadığı, sonraya bırakılan bulgular.

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
