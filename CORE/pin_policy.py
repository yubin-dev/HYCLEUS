"""
HYCLEUS — PIN uzunluk politikası (tek kaynak)

Bu sabit daha önce dört ayrı dosyada tekrarlanıyordu (login_dialog,
RegisterDialog, setup_usb) ve ProfileDialog'da sabit kodlanmıştı; biri
güncellenip diğerleri unutulabiliyordu. Artık tüm PIN belirleme akışları
buradan geçer.

İki ayrı eşik var — karıştırmayın
--------------------------------
PIN_MIN_LEN (6)   — YENİ PIN belirlerken zorunlu minimum.
                    İlk kurulum, kullanıcı kaydı, PIN değiştirme, CLI kurulum.

LOGIN_MIN_LEN (4) — GİRİŞ ekranındaki alt sınır.
                    Politika 4'ten 6'ya çıkarıldığında zaten kayıtlı olan
                    4-5 haneli PIN'ler geçersiz hâle gelmemeli: Argon2id hash
                    doğrulaması uzunluktan bağımsız çalışır, ama giriş
                    ekranındaki uzunluk kontrolü 6'ya çekilirse bu kullanıcılar
                    kendi doğru PIN'leriyle giriş yapamaz — sessiz bir kilitlenme.
                    Bu yüzden giriş tarafı eski tabanda bırakıldı.

                    Mevcut kullanıcıları 6 haneye zorlamak ayrı bir karar:
                    zorunlu PIN yenileme akışı gerektirir (bkz. BACKLOG.md).
"""
from __future__ import annotations

# Yeni PIN belirlerken zorunlu minimum uzunluk
PIN_MIN_LEN = 6

# Giriş ekranı alt sınırı — eski PIN'ler kilitlenmesin diye 4'te bırakıldı
LOGIN_MIN_LEN = 4

# CLI kurulumunda uygulanan üst sınır (setup_usb.py'den taşındı)
PIN_MAX_LEN = 32


def validate_new_pin(pin: str) -> str | None:
    """
    Yeni belirlenen bir PIN'i doğrular.

    Returns:
        None       — PIN geçerli
        str        — kullanıcıya gösterilecek hata mesajı

    Not: yalnızca alt sınır uygulanır. Üst sınır (PIN_MAX_LEN) şu an sadece
    CLI kurulumunda kontrol ediliyor; GUI akışlarına eklemek mevcut uzun
    PIN'leri reddetmek olurdu, o yüzden burada zorlanmıyor.
    """
    if len(pin) < PIN_MIN_LEN:
        return f"PIN en az {PIN_MIN_LEN} karakter olmalı."
    return None
