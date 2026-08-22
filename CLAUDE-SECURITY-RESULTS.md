# HYCLEUS — Güvenlik Taraması Sonuçları

**Tarih:** 2026-08-22
**Kapsam:** Tüm depo (CORE, DB, UI, main.py, tests, packaging, .github/workflows)
**Yöntem:** `claude-security` skill'i bu ortamda tanımlı değil (`Unknown skill`).
Onun yerine deponun kendi CI'ında zaten kullandığı araçlarla — bandit,
semgrep (yerel + kayıt defteri kuralları), pip-audit — tam depo taraması
yapıldı, bulgular tek tek elle doğrulandı. **Bu tur yalnızca rapor; hiçbir
kod değiştirilmedi.**

---

## Özet

| Araç | Kapsam | Ham sonuç | Doğrulama sonrası gerçek bulgu |
|---|---|---:|---:|
| bandit (yapılandırılmış, CI ile aynı) | CORE, DB, UI, main.py | 0 | 0 |
| bandit (ham, susturmasız) | CORE, DB, UI, main.py | 40 | 0 kritik, 3 süreç/tutarlılık notu |
| semgrep — yerel kurallar (`.semgrep/hycleus.yml`) | CORE, DB, UI, main.py | 0 | 0 |
| semgrep — kayıt defteri (`p/python`, `p/secrets`, `p/security-audit`, 236 kural) | CORE, DB, UI, main.py | 0 | 0 |
| pip-audit | requirements*.txt (3 dosya) | 0 | 0 |
| Sabit kod içi sır/anahtar taraması (regex) | tüm depo | 0 | 0 |
| GitHub Actions script-injection taraması (elle) | `.github/workflows/*.yml` | 1 | 1 düşük öncelikli sertleştirme notu |

**Severity dağılımı (bandit'in kendi etiketiyle, ham tarama):**

| Severity | Adet | Sonuç |
|---|---:|---|
| HIGH | 0 | — |
| MEDIUM | 17 (hepsi B608) | 17/17 incelendi, **istismar edilebilir değil** |
| LOW | 23 (B110×14, B603×5, B404×4) | 22/23 bilinen "en iyi çaba" deseni; 1'i tutarsızlık notu |

**En çok işaretlenen dosyalar (üretim kodu, ham tarama):**

| Dosya | Bulgu adedi | Tür |
|---|---:|---|
| `CORE/file_queries.py` | 4 | B608 (güvenli — sabit sütun listeleri) |
| `CORE/secure_erase.py` | 3 | B608 (güvenli — tek çağıran, sabit literal) |
| `CORE/usb_manager.py` | 4 | B110×3, B404+B603×1 (bilinen desen) |
| `CORE/audit_chain.py` | 2 | B608 (güvenli — modül sabiti) |
| `DB/migrations.py` | 2 | B608 (güvenli — modül sabiti) |
| `UI/main_window_table.py` | 2 | B110 (bilinen desen) |
| `UI/main_window_open.py` | 3 | B603×2 (güvenli, liste biçimi) + B110×1 |

(Test dosyalarındaki 3196 B101 — `assert` kullanımı — bandit'in pytest'i
"güvenlik açığı" sayması; gerçek bulgu değil, rapora dahil edilmedi.)

---

## Ayrıntılı bulgular

### 1. B608 (f-string ile SQL) — taban sayı kaymış: 13 → 17

`pyproject.toml`'daki `[tool.bandit]` yorumu 2026-08-16 taramasında **13**
örneği belgeliyor ve hepsini "incelendi, güvenli" diye işaretliyor. Bu
turun ham taraması **17** buldu. Fark, 2026-08-16'dan sonra eklenen dört
dosya/satır:

| Yer | Enterpolasyona giren | Kullanıcı girdisi mi |
|---|---|---|
| `CORE/audit_chain.py:312,519` | `_SELECT_FIELDS` (modül sabiti, `", ".join(FIELD_ORDER)`) | Hayır |
| `DB/migrations.py:452,550` | `LEDGER_TABLE = "schema_migrations"` (modül sabiti) | Hayır |
| `CORE/export.py:150`, `CORE/scheduler.py:103` | yalnızca `?` yer tutucuları | Hayır — zaten `# nosemgrep` ile gerekçeli |
| `UI/TagDialog.py:240` | `len(self._file_ids)` (tamsayı) | Hayır |

Elle doğrulandı: **17'sinin de değerleri `?` ile bağlı**; enterpolasyona
giren yalnızca sabit tablo/sütun adları, `?` yer tutucu sayısı ya da bir
`len()` tamsayısı. Hiçbiri saldırgan kontrolündeki bir dizeyi SQL metnine
sokmuyor. **İstismar edilebilir değil.**

`CORE/secure_erase.py:62,74,81` ayrıca incelendi: `table`/`column`
parametreleri gerçekten dinamik ama tek çağıran (`CORE/secret_migration.py:144`)
üçünü de sabit literal (`"usb_tokens"`, `"share_2"`, `"hwid"`) geçiyor;
docstring bunu sözleşme olarak zaten yazıyor.

**Sorun bulgu değil, süreç boşluğu:** dokümante taban güncel değil —
dördü aynı titizlikle incelenmemiş görünüyordu (aslında güvenliydi, ama
bunu doğrulamak bu turu gerektirdi). → **B-051**.

### 2. `CORE/scanner.py` — aynı hata iki yerde farklı görünürlükte

`scan_file()` (satır ~117) ve `scan_by_hash()` (satır 136) **aynı**
`_save_to_db()` çağrısını aynı şekilde sarmalıyor, ama:

```python
# scan_file()  — GÖRÜNÜR
except Exception:
    _log.exception("scan_db_error  file_id=%d", file_id)

# scan_by_hash() — SESSİZ
except Exception:
    pass
```

İstismar edilebilir değil — ikisi de yalnızca tarama sonucunun quarantine
tablosuna YAZILMASINI etkiliyor, tarama sonucunun kendisini değil (zaten
üretilip çağırana dönüyor). Ama bu depo tam olarak bu sınıftan bir hatayı
daha önce yaşadı (audit_log FK ihlali `_kaydet()` içinde sessizce
yutuluyordu, bu oturumun önceki turlarında not edildi). Aynı fonksiyonun
iki çağrı yerinin farklı davranması, "hangisi doğru" sorusunu açık
bırakıyor. → **B-052**.

### 3. `.github/workflows/fuzz.yml` — tırnaksız `workflow_dispatch` girdisi

```yaml
python tests/fuzz/fuzz_${{ matrix.hedef }}.py \
  -max_total_time=${{ inputs.sure }} \
```

`inputs.sure` bir `type: string`, serbest metin, ve doğrudan `run:`
bloğuna enjekte ediliyor. Klasik GitHub Actions script-injection sınıfı
**ama tetikleyici `workflow_dispatch`** — yalnızca depoya YAZMA yetkisi
olan biri tetikleyebilir ve o kişi zaten dosya değiştirip push edebilir.
Yani bir güven sınırını AŞMIYOR; yine de savunma derinliği eksik.
Depoda `pull_request_target`/`issue_comment` tetikleyicisi YOK — yani
gerçek (yetkisiz PR'dan) script-injection yüzeyi hiç yok. → **B-053**
(düşük öncelik, sertleştirme).

### 4. Temiz çıkanlar

- **Sabit kod içi sır/anahtar:** AWS anahtarı, private key bloğu, GitHub
  token, Slack token, Google API anahtarı deseni — 0 eşleşme. Ayrıca
  `password/secret/token = "..."` biçiminde 8+ karakterlik sabit atama — 0
  eşleşme (ortam değişkeni okuyanlar ve test/örnek dizeleri hariç).
- **Bağımlılık zafiyeti:** `pip-audit` üç requirements dosyasında (`requirements.txt`,
  `requirements-dev.txt`, `requirements-build.txt`) **0 bilinen zafiyet**
  buldu.
- **semgrep kayıt defteri:** `p/python` + `p/secrets` + `p/security-audit`
  (236 kural, 77 dosya) — **0 bulgu**.
- **Kabuk/PowerShell enjeksiyonu:** `packaging/` altındaki `.sh`/`.ps1`
  betiklerinde ve `.github/workflows/*.yml`'de `eval`, `Invoke-Expression`,
  `curl | sh` deseni — 0 eşleşme.
- **subprocess çağrıları** (`hwid_probe.py`, `scanner_backends.py`,
  `usb_manager.py`, `main_window_open.py`): hepsi liste biçimi
  (`shell=False` zımni), sabit komut adı ya da `shutil.which()` ile
  sabit bir allowlist'ten (`clamdscan`, `clamscan`) çözülüyor. Enjeksiyon
  yüzeyi yok.
- **B110 (try/except/pass), 14/15 örnek:** hepsi bilinen "en iyi çaba"
  deseni (konsol kodlaması, WMI sondası, keyring temizliği, opsiyonel
  alan ayrıştırma) — güvenlik kararı DEĞİL, dayanıklılık deseni.

---

## Bu turda YAPILMAYAN

- Kod değişikliği (`git apply` yok) — istendiği gibi.
- `B-018`'in zaten açık kalan kısımlarına (B608/B110'un kendisi) dokunulmadı.
- `pyproject.toml`'daki dokümante taban sayısı güncellenmedi — B-051 bunu
  bir karar olarak kullanıcıya bırakıyor (13 → 17 güncellensin mi, yoksa
  dört yeni satır ayrı mı belgelensin).
