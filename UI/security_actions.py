"""
HYCLEUS — doğrulama eylemlerinin İKİ giriş noktadan da çağrılan gövdesi

Neden bu dosya var
------------------
Güvenlik sekmesi (`UI/GuvenlikView.py`) üç doğrulamayı tek yerde topluyor
ama eski giriş noktaları KALDIRILMADI: damga doğrulama hâlâ dosya sağ tık
menüsünde, yedek doğrulama hamburger menüsünde, zincir doğrulama Yönetim
Paneli'nde duruyor.

Yani her iş artık İKİ yerden çağrılıyor. Bu deponun beş kez ürettiği kusur
tam olarak burada başlar: aynı işi iki yerde AYRI AYRI uygulamak
(B-004/B-008, B-007, B-010, B-011, pay ayrıştırıcı). Kural bu turda da
aynı — **iki çağıran, tek gövde**.

Üç işin gövdesi bugün üç farklı yerde ve hepsi olması gereken yerde:

    damga  → `UI/main_window_files.py::_on_ctx_verify_timestamp`
    yedek  → `UI/main_window_open.py::BackupMixin._on_verify_backup`
    zincir → BURASI

İlk ikisi ana pencerenin metodu ve Güvenlik sekmesi onları DOĞRUDAN
çağırıyor — taşımaya gerek yok, zaten tek gövde. Üçüncüsü `AdminPanel`'in
bir metoduydu ve panel yalnızca yöneticiye açılıyor; Güvenlik sekmesinden
çağrılabilmesi için gövdesinin panelden ÇIKMASI gerekti. `AdminPanel` artık
buradaki fonksiyonu çağırıyor.

`tests/test_guvenlik_view.py` her üçünün de tek gövdeden geçtiğini AST ile
denetliyor.
"""
from __future__ import annotations

import logging
from typing import Any

from PySide6.QtWidgets import QMessageBox

_log = logging.getLogger("hycleus.security_actions")

#: Zincir doğrulamasının denetim kaydı eylemi.
EYLEM_ZINCIR = "audit_chain_verified"


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


__all__ = ["EYLEM_ZINCIR", "zinciri_dogrula"]
