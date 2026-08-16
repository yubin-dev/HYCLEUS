"""
HYCLEUS — "son çalışma zamanı + kapı" deseni (④ grubu)

Masaüstü uygulamalarında periyodik iş neden zamanlayıcıya bırakılamaz
--------------------------------------------------------------------
APScheduler'ın `interval weeks=1` tetikleyicisi SÜREÇ ÖMRÜNE göre sayar.
HYCLEUS haftalarca açık kalmıyor; her gün kapanıp açılan bir kurulumda
haftalık bir tetikleyici HİÇ ateşlenmez. `cron` (ör. pazar 03:00) da işe
yaramaz — o saatte uygulama büyük ihtimalle kapalı.

Çözüm, `CORE/integrity.py` içinde zaten bulunmuş ve orada anlatılmıştı:
zamanlayıcı SIK ama UCUZ aralıklarla "vakti geldi mi" diye sorar, kapıyı
`settings` tablosundaki bir zaman damgası tutar. Böylece iş yeniden
başlatmayı aşar ve uygulama bir hafta sonra ilk açıldığında kısa süre
içinde çalışır.

Bu modül o deseni tek bir yerde topluyor.


Kimler kullanıyor — ve kimler KULLANMIYOR
-----------------------------------------
Kullananlar:

    integrity_last_sweep   haftalık bütünlük taraması (CORE/integrity.py)
    backup_last_run        yedekleme hatırlatması    (CORE/backup_reminder.py)

④ grubunun diğer iki maddesi bu deseni **kullanmıyor** ve zorlanmadı:

`B-004` (İmha sayacı) bir zaman damgası kapısı DEĞİL. Oradaki kapı global
değil dosya başına: her satırın kendi `expires_at`'i var ve zamanlayıcı
zaten 10 dakikada bir bakıyor. Sorun "iş yeterince sık çalışmıyor" değildi,
"iş yalnızca arayüzdeki bir sekme açıkken çalışıyordu". Global bir "son
çalışma" damgası eklemek orada yalnızca ZARAR verirdi: süresi dolmuş bir
dosyanın silinmesini gereksiz yere geciktirirdi.

`B-006` (zincir doğrulama düğmesi) hiç zamanlanmış iş değil — kullanıcının
istediği anda bastığı bir düğme. Periyodik bir tarafı yok.

Yani üç maddenin ortak yanı *belirtiydi* ("mekanizma var, tetikleyicisi
yok"), *çözümü* değil. Ortak yardımcı yalnızca gerçekten aynı şekli
paylaşan ikisi için çıkarıldı.


Zaman damgası NE ZAMAN yazılır
------------------------------
`isaretle()` yalnızca iş BAŞARIYLA bittiğinde çağrılmalı. `integrity`
bunu zaten böyle yapıyordu ve gerekçesi önemli: yarıda kesilen bir tarama
sayacı ilerletirse, bir kez yarıda kalan iş bir hafta boyunca tekrar
denenmez. Kapı "en son ne zaman DENEDİK" değil "en son ne zaman BAŞARDIK"
sorusunu tutuyor.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

_log = logging.getLogger("hycleus.scheduled_checks")

#: `settings` tablosuna yazılan zaman damgası biçimi. `CORE/integrity.py`
#: bu biçimi kullanıyordu ve DEĞİŞTİRİLMEDİ — değişseydi mevcut
#: kurulumlardaki damgalar ayrıştırılamaz olur, kapı açık kalır ve
#: tarama bir kez fazladan çalışırdı. Zararsız ama sebepsiz.
TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def utcnow() -> datetime:
    """Testlerin tek noktadan sabitleyebilmesi için ayrı fonksiyon."""
    return datetime.now(timezone.utc)


def simdi_damgasi() -> str:
    """Şimdiyi `TS_FORMAT` biçiminde döndürür."""
    return utcnow().strftime(TS_FORMAT)


@dataclass(frozen=True)
class ZamanKapisi:
    """
    Bir `settings` anahtarına bağlı "en az N günde bir" kapısı.

    Args:
        anahtar:  `settings` tablosundaki anahtar adı.
        aralik:   İki başarılı çalışma arasındaki asgari süre.
        ad:       Günlük mesajlarında görünen insan okunur ad.

    Örnek:
        >>> KAPI = ZamanKapisi("backup_last_run", timedelta(days=7), "yedek")
        >>> if KAPI.vakti_geldi_mi(db):
        ...     ...
        ...     KAPI.isaretle(db)
    """

    anahtar: str
    aralik: timedelta
    ad: str = ""

    # ── Okuma ────────────────────────────────────────────────────────────────
    #
    # Zamana bağlı metotlar `simdi` parametresi alıyor. Sebebi somut:
    # `CORE/integrity.py`'nin testleri modülün kendi `_utcnow`'unu
    # monkeypatch'liyor. Kapı kendi saatini dayatsaydı o yama sessizce
    # etkisiz kalırdı — çağıranın saatini kabul etmek, paylaşılan bir
    # yardımcının çağıranın test edilebilirliğini bozmaması demek.

    def son_calisma(self, db: Any) -> datetime | None:
        """
        En son BAŞARILI çalışmanın zamanı; hiç çalışmadıysa None.

        Bozuk bir damga da None sayılıyor — yani kapı açılıyor, iş bir kez
        fazladan çalışıyor. Ters yön (bozuk damgayı "yakın zamanda çalıştı"
        saymak) işi süresiz olarak susturmak olurdu ve sessiz kalan bir
        bütünlük taraması, hiç olmayanla aynı şey.
        """
        ham = db.get_setting(self.anahtar, "")
        if not ham:
            return None
        try:
            return datetime.strptime(ham, TS_FORMAT).replace(tzinfo=timezone.utc)
        except ValueError:
            _log.warning("%s ayrıştırılamadı: %r", self.anahtar, ham)
            return None

    def gecen_sure(self, db: Any, *, simdi: datetime | None = None) -> timedelta | None:
        """Son başarılı çalışmadan bu yana geçen süre; hiç çalışmadıysa None."""
        son = self.son_calisma(db)
        return None if son is None else (simdi or utcnow()) - son

    def vakti_geldi_mi(self, db: Any, *, simdi: datetime | None = None) -> bool:
        """Aralık dolduysa (ya da hiç çalışmadıysa) True."""
        gecen = self.gecen_sure(db, simdi=simdi)
        return True if gecen is None else gecen >= self.aralik

    def gecen_gun(self, db: Any, *, simdi: datetime | None = None) -> int | None:
        """
        Son başarılı çalışmadan bu yana geçen TAM gün sayısı.

        Kullanıcıya gösterilecek metin için: "12 gündür yedek almadınız".
        """
        gecen = self.gecen_sure(db, simdi=simdi)
        return None if gecen is None else gecen.days

    def hic_calismadi_mi(self, db: Any) -> bool:
        """
        Hiç çalışmadıysa True.

        `vakti_geldi_mi()`'den ayrı, çünkü kullanıcıya söylenecek şey
        farklı: "12 gündür yedek almadınız" ile "hiç yedek almadınız"
        aynı cümle değil.
        """
        return self.son_calisma(db) is None

    # ── Yazma ────────────────────────────────────────────────────────────────

    def isaretle(self, db: Any, *, zaman: str | None = None) -> str:
        """
        İşin BAŞARIYLA bittiğini işaretler ve yazılan damgayı döndürür.

        Args:
            zaman: Verilirse bu damga yazılır (`integrity` tamamlanan
                   taramanın kendi `finished_at`'ini kullanıyor). Verilmezse
                   şimdi.
        """
        damga = zaman or simdi_damgasi()
        db.set_setting(self.anahtar, damga)
        return damga

    def sifirla(self, db: Any) -> None:
        """
        Damgayı siler — kapı bir sonraki turda açılır.

        Yalnızca testler ve elle müdahale için. Üretim kodunda bir işi
        "yeniden çalıştırmak" isteniyorsa bu değil, işin kendisi
        çağrılmalı.
        """
        db.set_setting(self.anahtar, "")
