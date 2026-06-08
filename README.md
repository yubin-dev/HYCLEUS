# HYCLEUS — Beta 1.2

Şifrelenmiş dosya yönetimi ve USB donanım kimlik doğrulaması için Windows masaüstü güvenlik uygulaması.

---

## Gereksinimler

- Python 3.11 veya üzeri
- Windows 10 / 11
- (Opsiyonel) VirusTotal Public API anahtarı

---

## Kurulum

### 1. Depoyu klonlayın

```bash
git clone <repo-url>
cd HYCLEUS
```

### 2. Sanal ortam oluşturun ve bağımlılıkları yükleyin

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Ortam değişkenlerini ayarlayın (opsiyonel)

Proje kök dizininde `.env` dosyası oluşturun:

```
VT_API_KEY=buraya_virustotal_api_anahtarinizi_yazin
```

API anahtarı yoksa uygulama çalışmaya devam eder; tarama sonuçları `mock` (bilinmiyor) olarak gösterilir.

### 4. Geliştirme modunu etkinleştirin (gerçek USB yoksa)

Aynı `.env` dosyasına ekleyin:

```
DEV_MODE=true
```

Bu seçenek gerçek bir USB token yerine sanal HWID kullanır.

---

## İlk Çalıştırma — Kurulum Ekranı

Uygulama ilk açıldığında kurulum sihirbazı görünür. Sırasıyla:

1. **Rol seçin**
   | Rol | Yetkiler |
   |-----|----------|
   | Yönetici | Tam erişim — tüm özellikler aktif |
   | Standart | Dosya yönetimi aktif, Kritik sekme görünür |
   | Salt Okunur | Sadece görüntüleme; drag-drop ve Kritik sekme devre dışı |

2. **PIN belirleyin** — En az 4 karakter, iki kez girilmesi gerekir

3. **Authenticator ayarlayın** — Google Authenticator (veya uyumlu uygulama) ile QR kodu tarayın, ardından üretilen 6 haneli kodu doğrulama alanına girin

4. **"Doğrula ve Kaydet"** butonuna tıklayın — Ayarlar `data/` klasörüne güvenli biçimde kaydedilir

---

## Normal Giriş

Sonraki başlatmalarda giriş ekranı gelir:

1. PIN girin
2. Authenticator uygulamasındaki 6 haneli kodu girin
3. **"Giriş Yap"** butonuna tıklayın

> 5 başarısız denemeden sonra uygulama kilitlenir ve yeniden başlatılması gerekir.

---

## Demo Akışı

### Dosya Karantinaya Alma

1. Uygulamayı başlatın ve giriş yapın
2. Dosya Gezgini'nden herhangi bir dosyayı uygulama penceresine sürükleyip bırakın
3. Dosya otomatik olarak **AES-256-GCM** ile şifrelenir, `data/quarantine/` altına `.hcl` uzantısıyla kaydedilir
4. Tablo satırında **"⟳ Taranıyor..."** rozeti görünür; arka planda VirusTotal sorgusu başlar
5. Tarama tamamlanınca rozet güncellenir:

   | Rozet | Renk | Anlam |
   |-------|------|-------|
   | `✓ Temiz` | Yeşil | Hiçbir motorda algılanmadı |
   | `⚠ Şüpheli` | Sarı | En az bir motor şüpheli işaretledi |
   | `✗ Zararlı` | Kırmızı | En az bir motor zararlı işaretledi |
   | `? Bilinmiyor` | Gri | VT'de kayıt yok veya API anahtarı eksik |
   | `(m)` eki | Gri | Sonuç gerçek değil, mock veridir |

### Sidebar Navigasyonu

| Sekme | İçerik |
|-------|--------|
| Genel | Standart dosyalar |
| Kritik | Yüksek öncelikli dosyalar *(Salt Okunur rolünde gizlenir)* |
| Karantina | Şüpheli ve taranmış dosyalar |
| İmha Odası | Kalıcı silme için işaretlenmiş dosyalar |

### USB Token Kilidi

- USB token çekildiğinde ekran **bulanıklaşır** ve kilit katmanı görünür
- Token yeniden takıldığında uygulama otomatik olarak kilidi açar
- Kilit açıkken dosya yüklenemez

### Otomatik Süresi Dolmuş Dosya Temizliği

Karantina etiketli ve `expires_at` süresi geçmiş dosyalar, uygulama açık olduğu sürece **10 dakikada bir** arka plan zamanlayıcısı tarafından diskten ve veritabanından otomatik silinir.

---

## Güvenlik Notları

- PIN `data/pin_hash.json` dosyasında **Argon2id** ile hashlenerek saklanır — düz metin hiçbir zaman yazılmaz
- TOTP secret `data/totp_secret.json` dosyasında saklanır
- `data/` klasörü `.gitignore` kapsamındadır; `pin_hash.json` ve `totp_secret.json` depoya gitmez
- `.env` dosyası `.gitignore` kapsamındadır; `VT_API_KEY` depoya gitmez
- Şifrelenmiş dosyalar (`*.hcl`) ve `data/` içeriği depoya dahil edilmez

---

## Proje Yapısı

```
HYCLEUS/
├── main.py                  # Giriş noktası
├── requirements.txt
├── .env                     # Git'e gitmez — VT_API_KEY, DEV_MODE
├── CORE/
│   ├── crypto.py            # AES-256-GCM şifreleme (.hcl formatı)
│   ├── scanner.py           # VirusTotal Public API entegrasyonu
│   ├── scheduler.py         # APScheduler — süresi dolmuş dosya temizliği
│   └── usb_manager.py       # USB HWID doğrulama (WMI)
├── DB/
│   └── db_manager.py        # SQLite3 singleton yöneticisi
├── UI/
│   ├── login_dialog.py      # Giriş / ilk kurulum diyaloğu (Argon2id + TOTP)
│   └── main_window.py       # Ana pencere, sidebar, tablo, USB kilit overlay
└── data/                    # Git'e gitmez — çalışma zamanı verileri
    ├── hycleus.db           # SQLite veritabanı
    ├── pin_hash.json        # Argon2id PIN hash + rol
    ├── totp_secret.json     # TOTP base32 secret
    └── quarantine/          # AES-256-GCM şifreli .hcl dosyaları
```
