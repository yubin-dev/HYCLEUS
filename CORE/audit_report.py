"""
HYCLEUS — denetim zinciri raporu (B-006)

Sorun
-----
Zincir doğrulaması üç yerden çağrılabiliyordu (`verify_audit_chain`,
`verify_against_anchor`, `verify_anchor_file`) ama hiçbirinin arayüzde
düğmesi yoktu. Kullanıcının zinciri kontrol edebildiği tek an açılıştı ve
o da yalnızca uyuşmazlık varsa konuşuyordu.

**Kurcalama kanıtı, ancak birileri kanıta BAKABİLİYORSA işe yarar.**

İkinci boşluk: `AuditLogDialog._export_txt()` yalnızca dört sütun
yazıyordu (zaman, işlem, kullanıcı, HWID). Hash yok, zincirin son ucu yok,
doğrulama durumu yok. Halbuki bu dışa aktarım, kullanıcının denetim
kaydını makine dışına taşıdığı tek yol — yani SECURITY.md §4.6'nın
"çıpayı başka bir güven alanına taşıyın" tavsiyesinin pratikteki karşılığı
olabilecek şey. O hâliyle dışa aktarılan dosyayla veritabanının tutarlı
olup olmadığı sonradan gösterilemiyordu.

Bu modül neden CORE'da
----------------------
Rapor METNİNİ üretiyor, diyalog açmıyor. Böylece Qt olmadan test
edilebiliyor (bkz. tests/test_layering.py) ve aynı metin hem "Zincir
Doğrula" düğmesinde hem TXT başlığında kullanılıyor — iki ayrı biçim
yazılsaydı biri güncellenip diğeri geride kalırdı.

İki doğrulama BİRLİKTE anlamlı
------------------------------
`verify_audit_chain()` zincirin İÇ tutarlılığını ölçüyor: her kaydın
hash'i bir öncekini doğru zincirliyor mu. Yakalayamadığı iki durum var —
kuyruğun kesilmesi ve zincirin baştan yeniden yazılması. İkisi de
kendi içinde tutarlı bir zincir üretir.

`verify_against_anchor()` tam olarak onları yakalıyor, çünkü çıpa
veritabanının DIŞINDA duruyor. Rapor ikisini birden veriyor; yalnızca
birine bakmak yanlış bir güven duygusu üretirdi.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from CORE.audit_chain import (
    AnchorCheck,
    ChainVerification,
    anchor_path,
    verify_against_anchor,
    verify_audit_chain,
)

#: TXT başlığındaki ayraç genişliği — `AuditLogDialog` sütun genişlikleriyle
#: aynı toplamı veriyor.
_AYRAC = "-" * 95


@dataclass(frozen=True)
class ZincirRaporu:
    """Zincirin ve çıpanın birlikte değerlendirilmiş durumu."""

    zincir: ChainVerification
    cipa: AnchorCheck
    #: Çıpa dosyasının yolu — kullanıcıya nereye bakacağı söylenebilsin.
    cipa_yolu: Path | None = None

    @property
    def saglam(self) -> bool:
        """
        İKİSİ de geçtiyse sağlam.

        Çıpa hiç yoksa (`anchors_checked == 0`) `AnchorCheck.ok` True
        döner ama tek başına anlam taşımaz — o durum `cipa_var` ile ayrıca
        görünüyor, çünkü "doğrulandı" ile "karşılaştıracak bir şey yoktu"
        aynı cümle değil.
        """
        return self.zincir.ok and self.cipa.ok

    @property
    def cipa_var(self) -> bool:
        return self.cipa.anchors_checked > 0

    @property
    def ilk_kirilma_id(self) -> int | None:
        return self.zincir.first_broken_id

    def baslik(self) -> str:
        """Tek satırlık durum — düğme sonucunun ilk satırı."""
        if self.saglam:
            return "Denetim zinciri SAĞLAM"
        if not self.zincir.ok:
            nerede = (
                f" (ilk kırılma: id={self.ilk_kirilma_id})"
                if self.ilk_kirilma_id is not None
                else ""
            )
            return f"Denetim zinciri KIRIK{nerede}"
        return "Denetim zinciri kendi içinde tutarlı ama ÇIPA UYUŞMUYOR"

    def ayrinti(self) -> str:
        """Düğmeye basınca gösterilen tam metin."""
        parcalar = [self.zincir.summary(), "", self.cipa.summary()]
        if not self.cipa_var:
            parcalar.append(
                "\nÇıpa, veritabanının DIŞINDAKİ tek referans. Yoksa "
                "zincirin baştan yeniden yazılması tespit edilemez."
            )
        if self.cipa_yolu is not None:
            parcalar.append(f"\nÇıpa dosyası: {self.cipa_yolu}")
            parcalar.append(
                "Bu yol HYCLEUS_AUDIT_ANCHOR ortam değişkeniyle "
                "değiştirilebilir (ör. USB'ye)."
            )
        return "\n".join(parcalar)


def zincir_raporu(db: Any, *, cipa_yolu: Path | None = None) -> ZincirRaporu:
    """
    Zinciri ve çıpayı birlikte doğrular.

    Args:
        cipa_yolu: Test ve özel kurulumlar için; verilmezse `anchor_path()`.
    """
    # İkisi de `_connection()` üzerinden hem DBManager hem ham
    # sqlite3.Connection kabul ediyor — burada ayrıca çözmeye gerek yok.
    yol = cipa_yolu or anchor_path()
    return ZincirRaporu(
        zincir=verify_audit_chain(db),
        cipa=verify_against_anchor(db, path=yol),
        cipa_yolu=yol,
    )


def txt_basligi(
    rapor: ZincirRaporu,
    *,
    kayit_sayisi: int,
    simdi: datetime | None = None,
) -> list[str]:
    """
    TXT dışa aktarımının başlık satırları — zincir durumu DAHİL.

    Neden dışa aktarıma giriyor
    ---------------------------
    Dışa aktarılan dosya, denetim kaydının makine dışına çıkan tek
    biçimi. İçinde zincirin son ucu ve doğrulama durumu yoksa, dosyayla
    veritabanının tutarlı olup olmadığı sonradan gösterilemez — yani dosya
    bir kanıt değil, yalnızca bir liste olur.

    DIŞA AKTARIMIN KENDİSİ İMZALI DEĞİL. Buradaki satırlar dosyanın
    yazıldığı ANDAKİ durumu bildiriyor; dosyanın sonradan
    değiştirilmediğini kanıtlamıyorlar. Kanıt zincirin kendisinde ve
    çıpada; bu başlık ikisine bakmayı mümkün kılan referansı taşıyor.
    """
    an = simdi or datetime.now(timezone.utc)
    satirlar = [
        "HYCLEUS — Denetim Günlüğü",
        f"Dışa aktarım: {an.strftime('%Y-%m-%d %H:%M:%S')} UTC",
        _AYRAC,
        f"Zincir durumu : {rapor.baslik()}",
        f"Doğrulanan    : {rapor.zincir.checked} kayıt"
        f" (başlangıç id={rapor.zincir.start_id};"
        f" {rapor.zincir.unchained_before} eski kayıt kapsam dışı)",
        f"Son kayıt     : id={rapor.zincir.last_id}",
        f"Son hash      : {rapor.zincir.last_hash or '—'}",
    ]
    if rapor.ilk_kirilma_id is not None:
        satirlar.append(f"İlk kırılma   : id={rapor.ilk_kirilma_id}")
    for kirik in rapor.zincir.breaks:
        satirlar.append(f"                · {kirik}")

    satirlar.append(
        f"Çıpa          : {rapor.cipa.summary().splitlines()[0]}"
        if rapor.cipa_var
        else "Çıpa          : yok — dış referans bulunamadı"
    )
    if not rapor.cipa.ok:
        satirlar.extend(f"                · {p}" for p in rapor.cipa.problems)

    satirlar.append(
        "NOT           : bu dosya imzalı DEĞİLDİR; yukarıdaki durum "
        "yazıldığı andaki durumdur."
    )
    satirlar.append(_AYRAC)
    satirlar.append(f"Bu dışa aktarımdaki kayıt sayısı: {kayit_sayisi}")
    satirlar.append(_AYRAC)
    return satirlar
