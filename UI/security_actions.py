"""
HYCLEUS — doğrulama eylemlerinin İKİ giriş noktadan da çağrılan gövdesi

Neden bu dosya var
------------------
Doğrulama Merkezi (`UI/GuvenlikView.py`) dört işi tek yerde topluyor ama
eski giriş noktaları KALDIRILMADI: damga doğrulama hâlâ dosya sağ tık
menüsünde, yedek doğrulama hamburger menüsünde, zincir doğrulama USB
Tokenlar sayfasında, kurtarma parçası Yönetim Paneli → Ayarlar'da duruyor.

Yani her iş artık İKİ yerden çağrılıyor. Bu deponun beş kez ürettiği kusur
tam olarak burada başlar: aynı işi iki yerde AYRI AYRI uygulamak
(B-004/B-008, B-007, B-010, B-011, pay ayrıştırıcı). Kural bu turda da
aynı — **iki çağıran, tek gövde**.

Dört işin gövdesi bugün dört farklı yerde ve hepsi olması gereken yerde:

    damga    → `UI/main_window_files.py::_on_ctx_verify_timestamp`
    yedek    → `UI/main_window_open.py::BackupMixin._on_verify_backup`
    zincir   → BURASI
    kurtarma → BURASI

İlk ikisi ana pencerenin metodu ve Doğrulama Merkezi onları DOĞRUDAN
çağırıyor — taşımaya gerek yok, zaten tek gövde. Son ikisi (zincir,
kurtarma) `AdminPanel`'in/`AdminSettingsView`'in birer metoduydu ve o
sayfalar yalnızca yöneticiye açılıyor; Doğrulama Merkezi'nden
çağrılabilmeleri için gövdelerinin oradan ÇIKMASI gerekti. Eski sayfalar
artık BURADAKİ fonksiyonları çağırıyor.

`tests/test_guvenlik_view.py` dördünün de tek gövdeden geçtiğini AST ile
denetliyor.
"""
from __future__ import annotations

import logging
from typing import Any

from PySide6.QtWidgets import QInputDialog, QLineEdit, QMessageBox

_log = logging.getLogger("hycleus.security_actions")

#: Zincir doğrulamasının denetim kaydı eylemi.
EYLEM_ZINCIR = "audit_chain_verified"

#: Kurtarma parçası GÖRÜNTÜLENMESİNİN denetim kaydı eylemi (B-104).
EYLEM_KURTARMA_GORUNTULENDI = "recovery_share_viewed"


def zinciri_dogrula(parent: Any, hwid: str, *, sade: bool = False) -> None:
    """
    Denetim zincirini ve çıpayı doğrular, sonucu gösterir, kayda geçirir.

    Args:
        parent: Diyaloğun sahibi.
        hwid:   Doğrulamayı yapan cihazın HWID'i — kullanıcıyı bulmak için.
        sade:   `True` ise yalnızca sonuç başlığı gösteriliyor; ayrıntı
                (`rapor.ayrinti()`) ve doğrulayan satırı gizleniyor.

                Diğer iki diyalogla AYNI kural: gizlenen şey ikinci bir
                metin değil, aynı raporun ayrıntı yarısı. Sonuç kaydı ise
                sade modda da AYNEN düşüyor — görünüm tercihi denetim
                kaydını etkilememeli.
    """
    from CORE.audit_report import zincir_raporu
    from CORE.session_user import kullanici_bilgisi
    from DB.db_manager import DBManager

    try:
        db = DBManager()
        rapor = zincir_raporu(db)
        kim = kullanici_bilgisi(db, hwid)
    except Exception as exc:
        QMessageBox.critical(parent, "Zincir Doğrulama", str(exc))
        return

    kutu = QMessageBox(parent)
    kutu.setWindowTitle("Denetim Zinciri")
    kutu.setIcon(QMessageBox.Information if rapor.saglam else QMessageBox.Critical)
    kutu.setText(rapor.baslik())
    if not sade:
        kim_metni = f"{kim[1]} (id={kim[0]})" if kim else f"hwid={hwid}"
        kutu.setInformativeText(f"{rapor.ayrinti()}\n\nDoğrulayan: {kim_metni}")
    kutu.exec()

    try:
        db.log(
            EYLEM_ZINCIR,
            user_id=kim[0] if kim else None,
            detail=(
                f"ok={rapor.saglam} checked={rapor.zincir.checked}"
                f" anchors={rapor.cipa.anchors_checked}"
                f" first_break={rapor.ilk_kirilma_id}"
            ),
        )
    except Exception as exc:  # kayıt düşmezse sonuç yine gösterildi
        _log.warning("audit_chain_verified log failed: %s", exc)


def kurtarma_parcasini_goster(parent: Any, pencere: Any) -> None:
    """
    Kurtarma parçasını üretir ve modalda gösterir — eski `AdminSettingsView.
    _on_kurtarma_parcasi()`'nin gövdesi, DEĞİŞMEDEN buraya taşındı.

    Args:
        parent:  Diyalogların sahibi (`QInputDialog`, `QMessageBox`,
                 `RecoveryShareDialog`).
        pencere: `HycleusWindow` — `_hwid` ve `_T` için.

    Diğer üç doğrulamanın AKSİNE bu bir "doğrulama" değil, bir DIŞA
    AKTARIM: kasadaki anahtar payını GÖSTERİYOR. Bu yüzden `zinciri_
    dogrula()`'nın aksine kendi rol kapısını TAŞIYOR
    (`admin_common.yonetici_hala_yetkili`) — çağıranın (Doğrulama Merkezi)
    sayfası yönetici olmayan roller için de açık, ama bu eylem DEĞİL. B-064/
    B-066'nın canlı-yetki deseniyle AYNI: `is_admin_role` + USB hwid + DB'deki
    rol/durum hâlâ oturumun GİRİŞTEKİ rolüyle uyuşuyor mu, üçü sırayla.

    Pay DİSKE YAZILMIYOR: `build_export` yalnızca bellekte yaşayan bir nesne
    döndürüyor, blok biterken hem o hem `share_3` bırakılıyor
    (`CORE/recovery_share.py`'nin kuralı).
    """
    from UI import admin_common

    if not admin_common.yonetici_hala_yetkili(parent, pencere):  # B-064/B-066
        return

    from CORE.recovery_share import build_export
    from CORE.vault_manager import export_recovery_share, has_recovery_share
    from UI.RecoveryShareDialog import RecoveryShareDialog

    hwid = pencere._hwid
    if has_recovery_share(hwid):
        # Aynı pay yeniden üretiliyor — kasa DEĞİŞMİYOR. Kullanıcı
        # "yeni bir parça mı alıyorum, eskisi geçersiz mi oluyor"
        # sorusunu sorar; yanıtı sormadan veriyoruz.
        if QMessageBox.question(
            parent, "Kurtarma Parçası",
            "Bu cihaz için daha önce kurtarma parçası alınmış.\n\n"
            "Yeniden göstermek kasayı DEĞİŞTİRMEZ; aynı parça üretilir "
            "ve eski çıktınız geçerli kalır.\n\nDevam edilsin mi?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        ) != QMessageBox.Yes:
            return

    pin, ok = QInputDialog.getText(
        parent, "PIN Doğrulama",
        "Kurtarma parçasını görmek için vault PIN'inizi girin:",
        QLineEdit.Password,
    )
    if not ok or not pin.strip():
        return

    try:
        share_3 = export_recovery_share(hwid, pin.strip())
    except Exception as exc:  # noqa: BLE001 — vault katmanı çeşitli tip atıyor
        QMessageBox.critical(
            parent, "Kurtarma Parçası",
            f"Kurtarma parçası üretilemedi:\n\n{exc}")
        return

    # Payın KENDİSİ (share_3/disa_aktarim) bu çağrının argümanlarına HİÇ
    # girmiyor — yalnızca OLAYIN KENDİSİ (kim, ne zaman, hangi cihaz)
    # kaydediliyor. B-104: her görüntüleme silinemez bir uyarı olarak
    # çıpaya kazınmalı — bkz. `_kaydet_ve_cipaya_kazi()` docstring'i.
    _kaydet_ve_cipaya_kazi(hwid)

    try:
        disa_aktarim = build_export(share_3)
        try:
            RecoveryShareDialog(disa_aktarim, parent, T=pencere._T).exec()
        finally:
            del disa_aktarim
    finally:
        del share_3


def _kaydet_ve_cipaya_kazi(hwid: str) -> None:
    """
    Kurtarma parçası GÖRÜNTÜLENDİ olayını denetim kaydına yazar ve HEMEN
    (günlük döngüyü beklemeden) bir çıpa hazırlar — B-104.

    Neden HEMEN, günlük anchor'ı (`maybe_write_daily_anchor`) beklemeden:
    bu, kasadaki en hassas sırrın (master_key'in Shamir payı) DIŞARI
    ÇIKTIĞI an. Günlük döngü saatler sonra çalışabilir; o arada denetim
    kaydı zincirde dursa bile ÇIPALANMAMIŞ kalır — kaydı okuyabilen biri
    o pencerede satırı SESSİZCE silebilir/değiştirebilir, bir sonraki
    günlük çıpaya kadar hiçbir karşılaştırma bunu yakalayamaz. `main.py`
    kapanışta `write_anchor(DBManager(), "shutdown")` çağırıyor — burası
    AYNI "olay-tetiklemeli anında çıpa" deseni (B-090); yeni bir
    mekanizma İCAT EDİLMEDİ. `write_anchor()` kendi içinde YEREL diske
    HER ZAMAN, takılı USB token'a da (varsa) İKİNCİ bir kopya yazıyor —
    çift-yazım burada TEKRARLANMIYOR, olduğu gibi kullanılıyor.

    Payın KENDİSİ bu fonksiyona hiç GİRMİYOR — imza yalnızca `hwid`
    alıyor, `share_3`/`disa_aktarim`'a erişimi YOK. Bu, "pay hiçbir
    kalıcı çağrıya ulaşmaz" kuralının (bkz. `tests/test_recovery_share_ui.py::
    test_the_recovery_share_value_never_reaches_a_persisting_call`)
    derleme zamanı garantisi: bu fonksiyon share_3'ü PARAMETRE OLARAK
    bile alamıyor.

    Kayıt/çıpa BAŞARISIZ olsa bile gösterim ENGELLENMEZ —
    `zinciri_dogrula()`'daki AYNI karar: kullanıcı zaten PIN'i doğru
    girdi ve yönetici yetkisi canlı doğrulandı, bir denetim yazma
    arızası payın kendisinin gösterilmesini durdurmamalı. Ama sessiz de
    değil: uygulama logına düşüyor.
    """
    from CORE.audit_chain import write_anchor
    from CORE.session_user import kullanici_bilgisi
    from DB.db_manager import DBManager

    db = DBManager()
    try:
        kim = kullanici_bilgisi(db, hwid)
    except Exception:
        kim = None
    try:
        db.log(
            EYLEM_KURTARMA_GORUNTULENDI,
            user_id=kim[0] if kim else None,
            detail=f"hwid={hwid}",
        )
        write_anchor(db, EYLEM_KURTARMA_GORUNTULENDI)
    except Exception as exc:
        _log.warning("recovery_share_viewed log/anchor başarısız: %s", exc)


__all__ = [
    "EYLEM_KURTARMA_GORUNTULENDI",
    "EYLEM_ZINCIR",
    "kurtarma_parcasini_goster",
    "zinciri_dogrula",
]
