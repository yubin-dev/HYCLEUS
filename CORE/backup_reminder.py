"""
HYCLEUS — yedekleme hatırlatması (B-015)

Sorun
-----
Yedekleme özelliği (3.3) vardı ama HATIRLATMASI yoktu. Yedek yalnızca
kullanıcının aklına geldiğinde alınıyordu. Kullanılmayan bir yedekleme
özelliği, olmayan bir yedekleme özelliğidir — yani 3.3'ün kapatmayı
amaçladığı boşluk (medya kaybı) fiilen açık kalıyordu.

Haftalık bütünlük taramasında bu sorun zaten çözülmüştü: zamanlayıcı sık
ama ucuz aralıklarla soruyor, kapıyı `settings`'teki bir zaman damgası
tutuyor. Aynı desen burada da kullanılıyor —
`CORE.scheduled_checks.ZamanKapisi`.

Bu modül UYARI GÖSTERMİYOR
--------------------------
Yalnızca "durum ne" sorusunu yanıtlıyor; diyalog açmak arayüzün işi ve
CORE Qt'ye dokunmuyor (bkz. tests/test_layering.py). Arayüz
`yedek_durumu()` çağırıp dönen `YedekDurumu`'na bakıyor.

Uyarı ENGELLEYİCİ DEĞİL
-----------------------
Tekrar tespitindeki gibi bilgilendirici. Yedek almamak bir hata değil,
bir risk; kullanıcıyı uygulamasının önünde tutmak orantısız olurdu.
`ERTELEME_AYARI` kullanıcının "bir daha sorma"yı seçebilmesi için;
`ESIK_AYARI` sıfıra çekilirse hatırlatma tümüyle kapanıyor — hareketsizlik
kilidi ayarıyla aynı kalıp.

"Hedef erişilemiyor" ile "yedek eski" AYNI ŞEY DEĞİL
----------------------------------------------------
Yedek hedefi harici bir diskse ve disk takılı değilse, dizini okuyup
"yedek yok" demek yanlış olur: yedek var, biz göremiyoruz. İkisi ayrı
durum (`HEDEF_ERISILEMIYOR` / `HIC_YEDEK_YOK`) ve arayüz farklı cümle
kuruyor. Bu ayrım olmasaydı kullanıcı, duran bir yedeği kaybolmuş sanıp
gereksiz bir tur daha alırdı — ya da tersi, uyarıyı "yine o disk mesajı"
diye görmezden gelmeye alışırdı.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any

from CORE.scheduled_checks import ZamanKapisi, simdi_damgasi

_log = logging.getLogger("hycleus.backup_reminder")

#: Son BAŞARILI yedeğin zamanı.
LAST_BACKUP_SETTING = "backup_last_run"

#: Kaç gün sonra hatırlatılsın. `0` hatırlatmayı kapatır.
ESIK_AYARI = "backup_reminder_days"

#: Kullanıcının "sonra" dediği an. Eşik kadar süre buradan da sayılıyor.
ERTELEME_AYARI = "backup_reminder_snoozed_at"

#: Yedek hedef dizini (varsa). Boşsa dosya sistemi kontrolü yapılmıyor.
HEDEF_AYARI = "backup_dest_dir"

#: Varsayılan eşik (B-108: 7 → 15 gün — bkz. `main.py`'deki gösterim
#: bloğunun yorumu).
VARSAYILAN_ESIK_GUN = 15


class YedekDurum(str, Enum):
    """Hatırlatma açısından yedeğin durumu."""

    #: Yakın zamanda yedek alınmış — uyarı yok.
    GUNCEL = "guncel"
    #: Eşik aşıldı.
    ESKI = "eski"
    #: Hiç yedek alınmamış.
    HIC_YEDEK_YOK = "hic_yedek_yok"
    #: Ayarlı hedef dizin okunamıyor (harici disk takılı değil vb.).
    HEDEF_ERISILEMIYOR = "hedef_erisilemiyor"
    #: Hatırlatma kapatılmış (eşik 0).
    KAPALI = "kapali"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class YedekDurumu:
    """`yedek_durumu()` sonucu — arayüzün göstereceği her şey burada."""

    durum: YedekDurum
    #: Son yedekten bu yana geçen tam gün; hiç yedek yoksa None.
    gecen_gun: int | None = None
    #: Yürürlükteki eşik.
    esik_gun: int = VARSAYILAN_ESIK_GUN
    #: Ayarlı hedef dizin, varsa.
    hedef: Path | None = None

    @property
    def uyarilmali(self) -> bool:
        """Arayüz bildirim göstermeli mi."""
        return self.durum in (
            YedekDurum.ESKI,
            YedekDurum.HIC_YEDEK_YOK,
            YedekDurum.HEDEF_ERISILEMIYOR,
        )

    def mesaj(self) -> str:
        """Kullanıcıya gösterilecek metin."""
        if self.durum is YedekDurum.HEDEF_ERISILEMIYOR:
            return (
                f"Yedek hedefi okunamıyor: {self.hedef}\n\n"
                "Harici disk takılı değilse takın. Yedeğinizin kaybolduğu "
                "anlamına GELMEZ — yalnızca şu an kontrol edilemiyor."
            )
        if self.durum is YedekDurum.HIC_YEDEK_YOK:
            return (
                "Henüz hiç yedek almadınız.\n\n"
                "Vault dosyanız ya da diskiniz kaybolursa dosyalarınıza "
                "erişemezsiniz."
            )
        if self.durum is YedekDurum.ESKI:
            return (
                f"{self.gecen_gun} gündür yedek alınmadı "
                f"(eşik: {self.esik_gun} gün).\n\n"
                "Son yedekten sonra eklenen dosyalar korunmuyor."
            )
        return ""


def _kapi(esik_gun: int) -> ZamanKapisi:
    return ZamanKapisi(
        LAST_BACKUP_SETTING, timedelta(days=esik_gun), "yedekleme"
    )


def esik_gun(db: Any) -> int:
    """
    Yürürlükteki eşik. Bozuk/negatif değer varsayılana düşüyor.

    Negatifi "kapalı" saymıyoruz: `0` kapatmanın açık yolu ve belgeli;
    `-3` ise büyük ihtimalle bir hata ve onu sessizce "hatırlatma yok"a
    çevirmek, kullanıcıyı yedeksiz bırakırdı.
    """
    ham = db.get_setting(ESIK_AYARI, "")
    if not ham:
        return VARSAYILAN_ESIK_GUN
    try:
        deger = int(ham)
    except ValueError:
        _log.warning("%s sayı değil: %r", ESIK_AYARI, ham)
        return VARSAYILAN_ESIK_GUN
    return deger if deger >= 0 else VARSAYILAN_ESIK_GUN


def yedek_alindi(db: Any, *, zaman: str | None = None) -> str:
    """
    Başarılı bir yedekten sonra çağrılır; damgayı yazar ve ertelemeyi siler.

    Erteleme SİLİNİYOR: kullanıcı "sonra" dedikten sonra gerçekten yedek
    aldıysa, o erteleme artık bir sonraki döngüyü bastırmamalı.
    """
    damga = _kapi(VARSAYILAN_ESIK_GUN).isaretle(db, zaman=zaman)
    db.set_setting(ERTELEME_AYARI, "")
    return damga


def ertele(db: Any, *, zaman: str | None = None) -> None:
    """Kullanıcı "sonra" dedi — bir eşik süresi daha sorulmayacak."""
    db.set_setting(ERTELEME_AYARI, zaman or simdi_damgasi())


def son_yedek(db: Any) -> datetime | None:
    """Son başarılı yedeğin zamanı; hiç alınmadıysa None."""
    return _kapi(VARSAYILAN_ESIK_GUN).son_calisma(db)


def yedek_durumu(db: Any, *, simdi: datetime | None = None) -> YedekDurumu:
    """
    Hatırlatma açısından yedeğin durumunu döndürür. UYARI GÖSTERMEZ.

    Args:
        simdi: Testlerin saati sabitleyebilmesi için.
    """
    esik = esik_gun(db)
    hedef_ham = db.get_setting(HEDEF_AYARI, "")
    hedef = Path(hedef_ham) if hedef_ham else None

    if esik == 0:
        return YedekDurumu(YedekDurum.KAPALI, esik_gun=0, hedef=hedef)

    kapi = _kapi(esik)
    gecen = kapi.gecen_gun(db, simdi=simdi)

    # Hedef okunamıyorsa bunu "yedek yok" ile karıştırma — modül
    # docstring'indeki gerekçe. Kontrol yalnızca hedef AYARLIYSA yapılıyor.
    if hedef is not None and not hedef.is_dir():
        return YedekDurumu(
            YedekDurum.HEDEF_ERISILEMIYOR,
            gecen_gun=gecen, esik_gun=esik, hedef=hedef,
        )

    if not kapi.vakti_geldi_mi(db, simdi=simdi):
        return YedekDurumu(
            YedekDurum.GUNCEL, gecen_gun=gecen, esik_gun=esik, hedef=hedef
        )

    # Eşik aşılmış ama kullanıcı yakın zamanda "sonra" demiş olabilir.
    erteleme = ZamanKapisi(ERTELEME_AYARI, timedelta(days=esik))
    if not erteleme.vakti_geldi_mi(db, simdi=simdi):
        return YedekDurumu(
            YedekDurum.GUNCEL, gecen_gun=gecen, esik_gun=esik, hedef=hedef
        )

    durum = YedekDurum.HIC_YEDEK_YOK if gecen is None else YedekDurum.ESKI
    return YedekDurumu(durum, gecen_gun=gecen, esik_gun=esik, hedef=hedef)
