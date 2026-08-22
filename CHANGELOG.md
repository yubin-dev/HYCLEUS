# HYCLEUS — Değişiklik Günlüğü

Bu belge **konsolide bir özet**tir, geçmişin yerine geçmez. Her satırın
karşılığı `git log`'da duruyor; commit'ler bu belge için yeniden
yazılmadı, sıkıştırılmadı ya da birleştirilmedi (squash YOK).

---

## v2.3.0 — 2026-08-22

**Önceki etiket:** v2.1.2 (2026-08-13) · **87 commit** · **10 gün**

### Sürüm numarası hakkında bir not

Bu geliştirme döngüsü boyunca `CORE/version.py::__version__` **"2.2.0.dev"**
idi ve iç planlamada "v2.2" olarak anılıyordu. Etiketleme anında **v2.3**'e
doğrudan geçildi — **v2.2 hiçbir zaman etiketlenmedi ya da yayınlanmadı.**
Bu bilinçli bir kullanıcı kararı, atlanan bir adım değil; gerekçe
`CORE/version.py`'nin "v2.2 NEDEN YOK" bölümünde de yazılı.

---

## Büyük özellikler

Bu sürümde İLK KEZ gelen, kullanıcının doğrudan göreceği ya da
SECURITY.md'nin doğrudan bahsettiği yetenekler:

| Özellik | Commit | Özet |
|---|---|---|
| **TPM 2.0 mühürleme** (Windows/CNG) | `fb97223` | Sır saklama artık TPM varsa TPM'de; yoksa keyring'e düşüş **her zaman görünür/loglu** (sessiz düşüş yok — B-025 dersi). |
| **RFC 3161 toplu damga + Merkle ağacı** | `ff7516d` | Çok sayıda dosya için TEK bir TSA çağrısı; her dosyanın damgası Merkle yoluyla doğrulanıyor. |
| **`.hclx` imzalı teslim paketi** | `9d08450` | Kasa dışına süreli, doğrulanabilir dosya paylaşımı. Süre dolunca **açılmaz, silinmez** (bilinçli tasarım, `CORE/hclx.py` başlığında gerekçeli). |
| **Kurumsal güvenilir kök deposu** | `85c6dcc` | Zaman damgası doğrulaması artık "geçerli" ile "geçerli VE güvenilir kök" ayrımını arayüzde gösteriyor. |
| **Güvenlik sekmesi** | `45ccb7f` | Damga/yedek/zincir doğrulama üç ayrı menüden tek sekmeye toplandı — eski giriş noktaları kaldırılmadı, aynı fonksiyona ikinci çağıran eklendi. |
| **Kullanıcı rehberi — üç erişim yolu** | `dae688d` | `docs/kullanici-rehberi.md` artık PDF (asıl kopya), hamburger menüsü ve `.hclx` paketine gömülü kopya olarak üç yerden erişilebilir; üçü tek kaynaktan senkron. |
| **Kurtarma parçası modalı** | `3718827` | QR + base32 yan yana, zorunlu onay kutusu (kapatma engeli DEĞİL — B-003 dersi), panolu kopyalama uyarısı + 30 sn otomatik temizleme, Windows'ta ekran yakalama koruması. |
| **Linux paketleme (AppImage)** | `749a790` | CI'da üretilip duman testinden geçiyor. |
| **Windows EXE CI yapı işi** | `503d7b0` | Derleme + `--selftest` + artifact — ayrı platform, ayrı doğrulama. |
| **KVKK saklama envanteri + imha akışı** | `118da7c`, `da35bf1`, `5463cc9` | Saklama profilleri, erken silme koruması, PDF/CSV envanter raporu. |
| **Denetim kaydı hash zinciri + dış çapa** | `f1f2c88` | Denetim kaydı geriye dönük değiştirilemez biçimde zincirleniyor. |
| **Haftalık bütünlük taraması** | `ed12ec5` | GCM tag + vault HMAC arka planda düzenli doğrulanıyor. |
| **Hareketsizlik kilidi + SafeZone** | `297327f` | Oturum otomatik kilitleniyor; geçici dosyalar güvenli temizleniyor. |
| **Şeffaf erişim** | `81f6555` | Çöz → düzenle → geri şifrele akışı tek adımda. |
| **Şifreli yedekleme + doğrulanabilir geri yükleme** | `60d6255` | Yedek bütünlüğü ayrıca doğrulanabiliyor. |
| **Çapraz platform HWID** | `44487c1` ve devamı | macOS/Linux için donanım kimliği prototipten gerçek USB ölçümüne (B-016/B-022). |
| **Sorumlu ifşa politikası + CI statik güvenlik** | `1381058`, `bc6fafd` | SECURITY.md §6, CI'da bandit + semgrep. |
| **Atheris fuzzing** (kripto/Shamir) | `4eca804` | Kapsam güdümlü fuzzing, gerçek bir ihlal buldu ve düzeltildi. |
| **Linux ClamAV entegrasyonu** | `8859c4e` | Tarama motoru arka ucu Windows Defender'dan ayrıldı. |
| **Tekrar tespiti** | `0ef97e4` | SHA-256 indeksiyle aynı dosyanın tekrar eklenmesi yakalanıyor. |
| **pip-audit CI entegrasyonu** | `666483b` | Bağımlılık zafiyet taraması — ilk sonuç temiz. |
| **SECURITY.md: üç saldırgan modeli + EN/TR paritesi** | `734729a`, `a09ba85` | Belge artık hangi iddianın hangi saldırgana karşı geçerli olduğunu işaretliyor; iki dil artık sessizce ayrışamıyor (test var). |

## Alt yapı ve iç mimari

Kullanıcıya doğrudan görünmeyen ama tekrar eden bir hata sınıfını kapatan
değişiklikler:

- **`CORE/roles.py`** — rol karşılaştırması 19 karar noktasından **tek**
  karar noktasına indirildi (B-028/B-030, `db0a68f`…`5b6bb07`).
- **`DB/migrations.py`** — şema göçlerinin tek kayıt defteri (`f16dd70`).
- **`CORE/version.py`** — sürüm dizesinin tek kaynağı (B-017, `b9d4461`).
- **`main_window.py`** mixin'lere bölündü: 2782 → 376 satır (`e4bd08c`).
- **CI:** test sayısı görünürlüğü (junitxml + artifact + iş özeti,
  `184066d`), Qt offscreen koruması + AST denetimi (B-047), asılan
  işlerin dakikalara indirilmesi (`8f1089a`).

---

## Kapanan backlog maddeleri

### Tamamen kapanan — 6

| Madde | Konu | Tarih |
|---|---|---|
| **B-003** | Kısa PIN'li kullanıcılar girişte 6 haneye zorlanıyor | 2026-08-21 |
| **B-024** | Windows `.spec` dosyasındaki iki paketleme bozukluğu | 2026-08-19 |
| **B-028** | Rol karşılaştırması → `CORE/roles.py` tek karar noktası | 2026-08-19 |
| **B-030** | Arayüz rolü → `users.role` eşlemesi (B-028 ile birlikte) | 2026-08-19 |
| **B-047** | `test_guvenlik_view.py` Qt toplama hatası + kalıcı AST denetimi | 2026-08-22 |
| **B-051** | bandit B608 dokümante tabanının koda eşitlenmesi | 2026-08-22 |

### Kısmen kapanan — 3

| Madde | Konu | Kapanan | Açık kalan |
|---|---|---|---|
| **B-002** | Lint/tip denetimi sıkılaştırması | ruff tarafı (2026-08-17) | mypy tarafı |
| **B-018** | bandit'in susturulan denetimleri | B607 (2026-08-17) | B608, B110 |
| **B-041** | SECURITY.md'de saldırgan modeliyle çelişen 5 iddia | 4/5 (2026-08-21) | 5. madde (§5 "device binding") — **kullanıcı kararıyla kapsam dışı**, düzeltilmedi değil |

**Toplam: 9 madde bu sürümde ilerledi (6 tam, 3 kısmi).**

---

## Bu sürümde AÇILAN, henüz kapanmayan öncelikli maddeler

Tam liste `BACKLOG.md`'de. Yüksek öncelikli olanlar: B-025 (HWID donanımdan
değil dosyadan türüyor), B-035 (hiçbir akış zaman damgası atmıyor), B-036
(USB fiziksel kaybında kurtarma yolu yok), B-046 (ubuntu CI'ın asıl kırmızı
sebebi B-047 ile maskesi kalktı ama henüz doğrulanmadı — bir sonraki
push'ta netleşecek).

---

## Bir düzeltme — "3-OS CI" iddiası

Bu turun talebinde CI'ın üç işletim sistemini kapsadığı belirtilmişti;
ölçüldü: `.github/workflows/ci.yml` matrisi yalnızca **iki** işletim
sistemi çalıştırıyor (`ubuntu-latest`, `windows-latest`); `macos` hiçbir
job'da geçmiyor. Toplam **5 CI işi** var (test×2, AppImage, EXE, semgrep)
ama bunlar 2 platforma dağılıyor, 3'e değil. Bu belge gerçek durumu
yazıyor, istekteki sayıyı değil.
