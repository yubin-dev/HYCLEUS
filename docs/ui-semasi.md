# HYCLEUS — Uygulama Şeması (UI Ağacı)

Bu belge kod yazılmadan, yalnızca `UI/` altındaki her dosya tek tek açılıp
gerçek içeriği okunarak çıkarılmıştır — tahmin edilmemiştir. Her dalın
yanında onu üreten dosya/fonksiyon kısaca not düşülmüştür. Amaç: tasarım
fazına referans olacak bir harita, davranış belgesi değil.

Tarih: 2026-08-22 · Taranan dosya sayısı: `UI/` altındaki 20 `.py` dosyasının
tamamı (`__pycache__` hariç).

---

## Giriş öncesi

```
main.py
└─ LoginDialog                                    UI/login_dialog.py
   │
   ├─ [İlk kurulum — first_run=True]
   │   Rol seç (radio) → PIN → PIN Tekrar → QR/TOTP kur → "Doğrula ve Başla"
   │                                                LoginDialog._on_setup_confirm
   │
   ├─ Sekme: "Giriş Yap"
   │   PIN + Authenticator kodu → "Giriş Yap"        LoginDialog._on_login
   │   └─ [kısa PIN'le girildiyse — B-003, ZORUNLU]
   │       PinRotationDialog — kapatılamaz            UI/PinRotationDialog.py
   │       (Esc, pencere X ve closeEvent'in üçü de görmezden gelinir;
   │        yalnızca "PIN'i Güncelle ve Devam Et" ile kapanır)
   │
   └─ Sekme: "Kayıt Ol"
       Kullanıcı Adı + PIN + PIN Tekrar + Rol → "Kayıt Ol"
       (users tablosuna status='pending' yazar, admin onayı bekler)
                                                       LoginDialog._on_register
```

---

## Ana pencere

```
HycleusWindow (QMainWindow)                        UI/main_window.py
│  (mixin'lere bölünmüş: main_window_{layout,theme,tree,table,
│   files,bulk,open,lock}.py — hepsi aynı `self`)
│
├─ ÜST BAR                                          main_window_layout.py::_make_top_bar
│  ├─ Sayfa başlığı (aktif sekmeye göre değişir)
│  ├─ ☀ / 🌙  Tema düğmesi → _toggle_theme           main_window_theme.py
│  └─ Avatar (kullanıcı baş harfi) → _on_open_profile
│      └─ ProfileDialog                              UI/ProfileDialog.py
│          ├─ Sekme "Profil": bilgiler + PIN hatırlatma (180 gün) +
│          │   PIN Değiştir formu → CORE/pin_rotation.py::rotate_pin()
│          └─ Sekme "İletişim": "Destek ve İletişim Penceresini Aç"
│              └─ ContactDialog  (bkz. aşağıda — İKİNCİ giriş noktası)
│
├─ EYLEM BARI                                        main_window_layout.py::_make_action_bar
│  ├─ "Dosya Ekle" → _on_add_file (QFileDialog)       main_window.py
│  ├─ "📁 Klasör Ekle" → _on_add_folder                main_window.py
│  ├─ "Tümünü Tara" → _on_scan_all                    main_window.py
│  ├─ "Yeni Etiket" → _on_new_tag (QInputDialog)      main_window_tree.py
│  └─ "☰" hamburger menü → _on_hamburger_menu         main_window.py
│      ├─ 📋 Denetim Günlüğü → AuditLogDialog          UI/AuditLogDialog.py
│      │   (filtre: tarih aralığı + işlem türü, "TXT Dışa Aktar")
│      ├─ 🔌 USB Yönetimi → AdminPanel [yalnızca admin]  UI/AdminPanel.py
│      ├─ 💬 Destek → ContactDialog                    UI/ContactDialog.py
│      ├─ 📘 Kullanım Rehberi → _on_open_rehber
│      │   (yol kararı CORE/rehber.py::erisim_yolu() — PDF varsa PDF,
│      │    yoksa web; PDF'yi QDesktopServices ile açar)
│      ├─ 💾 "Yedek Al…" → _on_create_backup            main_window_open.py::BackupMixin
│      ├─ 🔍 "Yedek Doğrula…" → _on_verify_backup
│      │   └─ BackupVerifyDialog                        UI/BackupVerifyDialog.py
│      └─ ℹ "Hakkında" → QMessageBox (sürüm + TPM durumu)
│
├─ SOL KENAR ÇUBUĞU                                   main_window_layout.py::_make_sidebar
│  ├─ "DOSYALAR" nav — Genel / Kritik / Karantina / İmha Odası
│  │   (liste: main_window_palette.py::_SIDEBAR_NAV) → _on_sidebar_click
│  │
│  ├─ "GÜVENLİK" — 🛡 Güvenlik → _on_guvenlik_click
│  │   └─ GuvenlikView (içerik alanının 2. sayfası)     UI/GuvenlikView.py
│  │       │  "Gelişmiş ayrıntı" onay kutusu — sade/gelişmiş görünüm,
│  │       │  yalnızca OTURUM İÇİNDE tutulur, hiçbir doğrulamayı
│  │       │  KENDİSİ uygulamaz — üç mevcut metodu çağırır:
│  │       │
│  │       ├─ 🕓 "Damgayı Doğrula" (Dosya Seç…)
│  │       │   → HycleusWindow._on_ctx_verify_timestamp  main_window_files.py
│  │       │   → TimestampDialog (sade=…)                UI/TimestampDialog.py
│  │       │   [aynı gövdenin 2. giriş noktası — 1.'i aşağıda, sağ tık menüsünde]
│  │       │
│  │       ├─ 🔍 "Yedek Doğrula" (Dizin Seç…)
│  │       │   → HycleusWindow._on_verify_backup (sade=…) main_window_open.py
│  │       │   → BackupVerifyDialog                       UI/BackupVerifyDialog.py
│  │       │   [aynı gövdenin 2. giriş noktası — 1.'i hamburger menüsünde]
│  │       │
│  │       └─ 🔗 "Denetim Zincirini Doğrula" (Doğrula)
│  │           → UI/security_actions.py::zinciri_dogrula()
│  │           → QMessageBox sonuç kutusu
│  │           [aynı gövdenin 2. giriş noktası — 1.'i AdminPanel'de]
│  │
│  ├─ Klasörler bölümü
│  │   ├─ "＋ Klasör Ekle" → _on_create_folder (QInputDialog)  main_window_tree.py
│  │   └─ klasör satırı sağ tık → _on_folder_context_menu
│  │       ├─ ⬇ "Klasörü İndir (ZIP)" — TOTP + QFileDialog
│  │       ├─ 🔥 "İmha Odasına At" (confirm)
│  │       └─ 🗑 "Klasörü Sil" (confirm)
│  │
│  ├─ Etiketler bölümü (dinamik, DB'den) → _on_tag_click
│  │   └─ etiket satırı sağ tık → 🗑 "Etiketi Sil" (confirm)
│  │
│  └─ "YÖNETİCİ" bölümü — yalnızca admin rolüne görünür/etkin
│      ├─ 🚫 "Kara Listeye Al" → _on_blacklist_usb (QInputDialog + confirm)  main_window.py
│      ├─ 📋 "Denetim Günlüğü" → AuditLogDialog        [2. giriş noktası — 1.'i hamburger menüsü]
│      ├─ 🔌 "USB Yönetimi" → AdminPanel               [2. giriş noktası — 1.'i hamburger menüsü]
│      └─ 💬 "Destek" → ContactDialog                  [2. giriş noktası — 1.'i profil/hamburger]
│
└─ İÇERİK ALANI (QStackedWidget, 2 sayfa)              main_window_layout.py::_make_govde_yigini
   │
   ├─ Sayfa 0 — Dosya görünümü
   │  ├─ Arama çubuğu → _search_files                   main_window.py
   │  ├─ İlerleme / imha geri sayım banner'ları
   │  ├─ Dosya tablosu (sürükle-bırak destekli)          main_window_table.py
   │  │  │
   │  │  ├─ Tekli seçim sağ tık menüsü                    main_window_files.py::_on_context_menu
   │  │  │  ├─ 📄 "Aç" / ✔ "Bitir (geri şifrele)" — şeffaf erişim  main_window_open.py::OpenMixin
   │  │  │  ├─ 🏷 "Etiket Ata" → TagDialog                UI/TagDialog.py
   │  │  │  ├─ 🔍 "Tara" (yalnızca Karantina etiketinde)
   │  │  │  ├─ ⬇ "İndir" (TOTP kodu + QFileDialog)
   │  │  │  ├─ 🛡 "Kritik'e Taşı" / 📂 "Klasöre Taşı" (alt menü) /
   │  │  │  │   "Onayla → Genel'e taşı" / "Reddet → İmha Odası'na taşı" /
   │  │  │  │   🔥 "İmha Odasına At"  (etikete göre değişen alt küme)
   │  │  │  └─ 🕓 "Damgayı Doğrula"
   │  │  │      → TimestampDialog                          UI/TimestampDialog.py
   │  │  │      [1. giriş noktası — 2.'si Güvenlik sekmesinde]
   │  │  │
   │  │  └─ Çoklu seçim sağ tık menüsü                    main_window_bulk.py::_on_bulk_context_menu
   │  │     ├─ 🏷 "Toplu Etiket Ata" → TagDialog (file_ids=…)
   │  │     ├─ ⬇ "Seçilenleri İndir" (TOTP + QProgressDialog)
   │  │     ├─ ✅ "Karantinadan Çıkar → Genel" (yalnızca hepsi Karantina'daysa)
   │  │     ├─ 🛡 "Seçilenleri Kritik'e Taşı"
   │  │     └─ 🔥 "Seçilenleri İmha Odasına At"
   │  │
   │  └─ Sürükle-bırak alanı (drop_hint) → _handle_dropped_file/_folder
   │
   └─ Sayfa 1 — Güvenlik (GuvenlikView — yukarıda tam ayrıntı var)
```

### Kilit örtüsü (ayrı pencere değil, aynı pencerenin üstüne bindirilen katman)

```
_LockOverlay                                          UI/main_window_lock.py
  · USB çekilince otomatik görünür; USB geri takılınca otomatik kalkar
  · Hareketsizlik eşiği aşılınca görünür; tıklanınca → _unlock_idle
      → QInputDialog (PIN) → CORE.vault_manager.read_vault_role()
  · USB değişimi tespit edilirse → _trigger_usb_reauth
      → QInputDialog (PIN) → yeni rol/HWID ile oturum devam eder
```

---

## Yönetim Paneli (yalnızca admin rolü açabilir)

```
AdminPanel (QDialog, 3 sekme)                          UI/AdminPanel.py
│
├─ Sekme 1 — "USB Tokenlar"
│  Tablo: HWID / Token ID / Rol / Son Giriş / Durum
│  ├─ "Kara Listeye Al" / "Kara Listeden Çıkar" (seçime göre metin değişir)
│  ├─ "Rolü Değiştir" → QInputDialog (rol seç) + QInputDialog (PIN)
│  │   → CORE.vault_manager.change_vault_role()  (admin rolü değiştirilemez)
│  ├─ "Sil" (confirm, geri alınamaz) → delete_usb_token()
│  ├─ "Zinciri Doğrula" → UI/security_actions.py::zinciri_dogrula()
│  │   [2. giriş noktası — 1.'i Güvenlik sekmesinde; GÖVDE security_actions.py'de]
│  └─ "Yenile"
│
├─ Sekme 2 — "Bekleyen Kayıtlar"
│  Tablo: Kullanıcı Adı / HWID / Rol / Kayıt Tarihi
│  ├─ "✓ Onayla" (confirm) → users.status = 'approved'
│  ├─ "✕ Reddet" (confirm) → kullanıcı + USB token silinir
│  ├─ "＋ Yeni Kullanıcı Kaydet" → RegisterDialog          UI/RegisterDialog.py
│  │   (1. Admin USB doğrula → 2. "USB Tespit Et" → 3. kullanıcı bilgileri
│  │    → 4. "Kaydet (Onay Bekleyecek)")
│  └─ "Yenile"
│
└─ Sekme 3 — "Ayarlar"
   ├─ İmha Odası TTL combo (1/6/12/24/48 saat) + "Kaydet"
   ├─ Hareketsizlik kilidi combo (dakika / Kapalı) + "Kaydet"
   │   → kaydettiğinde açık ana pencereye anında uygulanır (reload_idle_timeout)
   ├─ "Güvenilir zaman damgası kökleri" bloğu
   │   ├─ Liste (konu · parmak izi)
   │   ├─ "Kök Ekle…" → QFileDialog (.pem/.crt/.cer/.der) → CORE/trusted_roots.py::ekle()
   │   └─ "Kaldır" (confirm) → CORE/trusted_roots.py::sil()
   │   (kaydet düğmesine BAĞLI DEĞİL — anında yazılır)
   └─ "Kurtarma parçası" bloğu
      └─ "Kurtarma Parçasını Göster…" → QInputDialog (PIN)
          → CORE.vault_manager.export_recovery_share()
          → RecoveryShareDialog                            UI/RecoveryShareDialog.py
             ├─ Ekran yakalama koruması durumu (Windows: SetWindowDisplayAffinity;
             │   diğer platformlarda "korunamıyor" — açıkça yazılır, B-049)
             ├─ Uyarı bloğu (CORE/recovery_share.py::WARNING_TEXT, CLI ile aynı metin)
             ├─ QR bloğu (solda) + Base32 metin bloğu (sağda) — TEK üretim yolu,
             │   ikisi de CORE/recovery_share.py::build_export() çıktısından
             ├─ "📋 Panoya Kopyala" → önce uyarı QMessageBox, sonra kopyalama,
             │   30 sn sonra (veya pencere kapanınca) otomatik pano temizliği
             ├─ Onay kutusu ("Bu parçayı yazdırdım ve güvenli bir yere koydum")
             │   — GÜVENLİK kontrolü DEĞİL, yalnızca "Tamam"ı aktifleştiren bir
             │   dikkat kontrolü; Esc/pencere X her zaman açık kalır (B-003 dersi)
             └─ "Tamam" (onay işaretlenmeden pasif)

── PLANLANAN, HENÜZ KOD DEĞİL ──────────────────────────────────────────────
Sekme 4 — "Saklama Envanteri" (KVKK)
  AdminPanel.py içinde yorum satırı olarak duruyor (satır ~172-201):
  CORE/inventory.py tarafı hazır (generate_retention_inventory,
  export_inventory_csv, export_inventory_pdf) ama bu sekme HİÇ
  eklenmemiş — ne düğme ne tablo var. Yorumdaki not, panelin doğal yer
  olduğunu ve main_window araç çubuğunun alternatif ama daha zayıf bir
  seçenek olduğunu söylüyor.
```

---

## Ortak/paylaşılan altyapı (bağımsız pencere değil)

```
UI/dialog_kit.py
  RAPOR_STILI, ayrac(), kutu(), sarmali() — TimestampDialog, BackupVerifyDialog
  ve PinRotationDialog'un ortak stil/yerleşim tesisatı. Kendi başına açılan
  bir ekran değil.

UI/security_actions.py
  zinciri_dogrula() — AdminPanel VE GuvenlikView'ın "Denetim Zincirini
  Doğrula" düğmelerinin ORTAK gövdesi. Kendi penceresi yok, QMessageBox
  açar.
```

---

## Aynı işin iki giriş noktasına sahip olduğu yerler (özet)

Bu depoda bilinçli bir kural var: **iki çağıran, tek gövde** — aynı iş iki
menüden erişilebilir olsa da uygulaması tek yerde durur.

| İş | Giriş noktası 1 | Giriş noktası 2 | Gövde |
|---|---|---|---|
| Damga doğrulama | Dosya sağ tık menüsü | Güvenlik sekmesi | `main_window_files.py::_on_ctx_verify_timestamp` |
| Yedek doğrulama | Hamburger menüsü | Güvenlik sekmesi | `main_window_open.py::BackupMixin._on_verify_backup` |
| Zincir doğrulama | AdminPanel | Güvenlik sekmesi | `UI/security_actions.py::zinciri_dogrula` |
| Denetim Günlüğü | Hamburger menüsü | Sidebar → Yönetici | aynı `AuditLogDialog` |
| USB Yönetimi | Hamburger menüsü | Sidebar → Yönetici | aynı `AdminPanel` |
| Destek | Hamburger menüsü | Sidebar → Yönetici / Profil | aynı `ContactDialog` |
