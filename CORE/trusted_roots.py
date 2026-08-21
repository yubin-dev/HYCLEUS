"""
HYCLEUS — güvenilir zaman damgası kökü deposu (kurumsal kullanım)

Kapattığı boşluk
----------------
`verify_timestamp()` 3.1b'den beri `trusted_roots` alıyor ama YALNIZCA
komut satırından (`--trusted-root ca.pem`). Arayüzden doğrulayan bir
kullanıcı hiçbir zaman kök veremiyordu, yani her sonuç
`anchor_trusted=False` ile dönüyordu ve SECURITY.md §4.9'un anlattığı sınır
— "güven kökü doğrulanan dosyanın kendisinden geliyor" — arayüzde KALICI
bir durumdu.

Bu modül kökleri `settings` tablosunda saklıyor. Kurum kendi TSA kökünü bir
kez ekliyor, sonraki her doğrulama onu kullanıyor.


Bu depo neyi ÇÖZÜYOR, neyi ÇÖZMÜYOR
------------------------------------
Çözdüğü şey gerçek ve dar: güven kökü artık DOĞRULANAN DOSYANIN İÇİNDEN
gelmiyor. Dosyayı yeniden yazabilen biri kendi CA'sını uydurup kendi
tarihini imzalayamıyor — çünkü karşılaştırma dosyanın dışındaki bir
listeyle yapılıyor.

Çözmediği şey de aynı ölçüde net: **liste şifresiz veritabanında.**
SECURITY.md §3 SQLite'ın düz metin olduğunu söylüyor ve §4.5 uygulama
seviyesi kontrollerin diskten geçen birini bağlamadığını. Veritabanına
yazabilen biri (M3) kendi kökünü ekleyip sahte bir damgayı "tam geçerli"
gösterebilir.

Yani kazanım, denetim çıpasınınkiyle (§4.6) tam olarak aynı şekli taşıyor:
kanıt ile onu doğrulama aracı artık AYNI DOSYADA değil, ama hâlâ AYNI
MAKİNEDE. Maliyeti yükseltiyor, kapatmıyor. Gerçekten farklı bir güven
alanı, listenin makine dışında tutulmasını ister; o yapılmadı ve B-044'te
kayıtlı.

Kök EKLEMEK ve SİLMEK denetim kaydına düşüyor (`tsa_root_added` /
`tsa_root_removed`) — bu iki işlem, doğrulamanın cevabını değiştiren tek
yönetici eylemi.


Neden komut satırı bu depoyu KULLANMIYOR
-----------------------------------------
Bilinçli. `CORE/verify_timestamp_cli.py` hâlâ yalnızca `--trusted-root`
ile verilen kökleri kullanıyor ve bu depoya hiç bakmıyor.

Gerekçe: CLI'ın kitlesi denetçi ve denetçi tam olarak BU MAKİNEYİ
denetliyor. Aracın, denetlediği veritabanından güven listesi okuması,
sorulan sorunun cevabını sorunun kaynağına sordurmak olurdu. Denetçi kendi
kökünü kendi getiriyor.

Ortaklaşan tek şey AYRIŞTIRICI (`der_coz`): PEM/DER okuma mantığının iki
kopyası zamanla ayrışırdı — bu deponun defalarca ürettiği kusur. CLI o
fonksiyonu buradan alıyor, denetimi `tests/test_trusted_roots.py`'de.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

_log = logging.getLogger("hycleus.trusted_roots")

#: Köklerin tutulduğu `settings` anahtarı.
SETTING = "tsa_trusted_roots"

#: Denetim kaydı eylemleri.
EYLEM_EKLENDI = "tsa_root_added"
EYLEM_SILINDI = "tsa_root_removed"

#: Tek bir kökün makul üst sınırı. Kurcalanmış bir ayar satırı yüzünden
#: megabaytlarca veri ayrıştırılmaya çalışılmasın.
AZAMI_KOK = 64 * 1024

#: Depodaki kök sayısı sınırı — bir kurumun kök sayısı tek hanelidir.
AZAMI_ADET = 32

_PEM_BAS = b"-----BEGIN CERTIFICATE-----"


class TrustedRootError(Exception):
    """Kök okunamadı, ayrıştırılamadı ya da depoya yazılamadı."""


@dataclass(frozen=True)
class Kok:
    """Depodaki tek bir güvenilir kök."""

    ad: str
    #: Sertifikanın konusu — insan okunur, `timestamp_verify` ile aynı biçim.
    konu: str
    der: bytes
    eklendi: str

    @property
    def parmak_izi(self) -> str:
        """
        DER'in SHA-256'sı (hex). Kökün KİMLİĞİ bu, adı değil.

        Ad kullanıcıdan geliyor ve iki farklı sertifika aynı adı taşıyabilir;
        silme işlemi ada göre yapılsaydı yanlış kök silinebilirdi.
        """
        return hashlib.sha256(self.der).hexdigest()

    def kisa_izi(self) -> str:
        return self.parmak_izi[:16]


# ══════════════════════════════════════════════════════════════════════════════
# 1. Ayrıştırma — CLI ile ORTAK tek uygulama
# ══════════════════════════════════════════════════════════════════════════════


def der_coz(veri: bytes, *, kaynak: str = "") -> bytes:
    """
    Sertifika baytlarını DER'e çevirir. PEM de kabul ediliyor.

    PEM desteği şart: sertifikalar pratikte öyle dağıtılıyor ve dışarıya
    "önce DER'e çevir" demek aracı kullanılmaz yapardı.

    Args:
        veri:   Dosyadan okunan ham baytlar.
        kaynak: Hata mesajında görünecek ad (dosya adı gibi).

    Raises:
        TrustedRootError — boş, çok büyük ya da geçerli bir X.509 değil.
    """
    nereden = f" ({kaynak})" if kaynak else ""
    if not veri:
        raise TrustedRootError(f"Sertifika dosyası boş{nereden}.")
    if len(veri) > AZAMI_KOK:
        raise TrustedRootError(
            f"Sertifika beklenenden çok büyük{nereden}: {len(veri)} bayt "
            f"(sınır {AZAMI_KOK}). Bu bir sertifika dosyası olmayabilir."
        )

    if _PEM_BAS in veri:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding

        try:
            cert = x509.load_pem_x509_certificate(veri)
        except Exception as exc:
            raise TrustedRootError(f"PEM ayrıştırılamadı{nereden}: {exc}") from exc
        return cert.public_bytes(Encoding.DER)

    # DER varsayılıyor — ama gerçekten sertifika mı, DOĞRULANIYOR. Rastgele
    # bir dosyayı depoya almak, hiçbir zaman eşleşmeyecek bir "güvenilir
    # kök" satırı bırakırdı ve kullanıcı korunduğunu sanırdı.
    from cryptography import x509

    try:
        x509.load_der_x509_certificate(veri)
    except Exception as exc:
        raise TrustedRootError(
            f"Dosya geçerli bir sertifika değil{nereden} (ne PEM ne DER): {exc}"
        ) from exc
    return veri


def konu_metni(der: bytes) -> str:
    """
    Sertifikanın konusu — `timestamp_verify._subject_of` ile AYNI biçim.

    Aynı biçim olması önemli: kullanıcı AdminPanel'deki listede gördüğü
    adı, doğrulama ekranındaki "Zincirin kökü" satırında da görmeli. İki
    farklı biçim, aynı sertifikayı iki farklı şeymiş gibi gösterirdi.
    """
    from asn1crypto import x509 as asn1_x509

    try:
        cert = asn1_x509.Certificate.load(der)
        name = cert.subject.native
        return str(
            name.get("common_name")
            or name.get("organization_name")
            or cert.subject.human_friendly
        )
    except Exception:  # pragma: no cover — der_coz zaten doğruladı
        return "<konu okunamadı>"


# ══════════════════════════════════════════════════════════════════════════════
# 2. Depo
# ══════════════════════════════════════════════════════════════════════════════


def oku(db: Any) -> list[Kok]:
    """
    Depodaki kökleri okur. Ayar yoksa ya da bozuksa BOŞ liste.

    Bozuk bir ayar satırı doğrulamayı ÇÖKERTMEMELİ: sonuç, kök
    doğrulanmamış bir "geçerli" olur — yani fail-closed değil ama
    fail-safe. Bozukluk loglanıyor.
    """
    ham = ""
    try:
        ham = db.get_setting(SETTING, "") or ""
    except Exception as exc:  # pragma: no cover — DB erişilemezse
        _log.warning("tsa_roots_read_failed  exc=%s", exc)
        return []
    if not ham:
        return []

    try:
        kayitlar = json.loads(ham)
        if not isinstance(kayitlar, list):
            raise ValueError("liste bekleniyordu")
    except (json.JSONDecodeError, ValueError) as exc:
        _log.error("tsa_roots_bozuk  exc=%s — depo BOŞ sayılıyor", exc)
        return []

    kokler: list[Kok] = []
    for kayit in kayitlar[:AZAMI_ADET]:
        try:
            der = base64.b64decode(kayit["der"], validate=True)
        except (KeyError, TypeError, binascii.Error) as exc:
            _log.error("tsa_root_atlandi  exc=%s", exc)
            continue
        kokler.append(Kok(
            ad=str(kayit.get("ad", "")),
            konu=str(kayit.get("konu", "")),
            der=der,
            eklendi=str(kayit.get("eklendi", "")),
        ))
    return kokler


def der_listesi(db: Any) -> list[bytes]:
    """
    `verify_timestamp(trusted_roots=...)`'a verilecek DER listesi.

    Doğrulama çağıran her yer BURADAN geçmeli; `oku()`'yu çağırıp kendi
    listesini kuran ikinci bir yer, deponun bir yerde uygulanıp başka
    yerde uygulanmadığı bir duruma yol açardı.
    """
    return [k.der for k in oku(db)]


def _yaz(db: Any, kokler: list[Kok]) -> None:
    db.set_setting(SETTING, json.dumps([
        {
            "ad": k.ad,
            "konu": k.konu,
            "der": base64.b64encode(k.der).decode("ascii"),
            "eklendi": k.eklendi,
        }
        for k in kokler
    ], ensure_ascii=False))


def _kaydet(db: Any, eylem: str, *, user_id: int | None, detay: str) -> None:
    """Denetim kaydı — hatası işlemi başarısız YAPMIYOR (`pin_rotation` deseni)."""
    try:
        db.log(eylem, user_id=user_id, target_type="tsa_root", detail=detay)
    except Exception as exc:  # pragma: no cover — kayıt, sonucu engellemez
        _log.warning("tsa_root_log_failed  eylem=%s  exc=%s", eylem, exc)


def ekle(db: Any, veri: bytes, *, ad: str, user_id: int | None = None) -> Kok:
    """
    Ham sertifika baytlarını depoya ekler.

    Aynı sertifika zaten varsa YENİDEN EKLENMİYOR, mevcut kayıt dönüyor —
    kimlik DER'in özeti, adı değil. Aksi hâlde aynı kök farklı adlarla
    listede birden çok kez görünür ve kullanıcı hangisini sileceğini
    bilemezdi.

    Raises:
        TrustedRootError — sertifika ayrıştırılamazsa ya da depo doluysa.
    """
    der = der_coz(veri, kaynak=ad)
    mevcut = oku(db)
    izi = hashlib.sha256(der).hexdigest()
    for k in mevcut:
        if k.parmak_izi == izi:
            _log.info("tsa_root_zaten_var  iz=%s", k.kisa_izi())
            return k

    if len(mevcut) >= AZAMI_ADET:
        raise TrustedRootError(
            f"Güvenilir kök listesi dolu ({AZAMI_ADET}). Kullanılmayan bir "
            "kökü kaldırın."
        )

    kok = Kok(
        ad=ad or "(adsız)",
        konu=konu_metni(der),
        der=der,
        eklendi=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    _yaz(db, [*mevcut, kok])
    _log.info("tsa_root_eklendi  konu=%s iz=%s", kok.konu, kok.kisa_izi())
    _kaydet(db, EYLEM_EKLENDI, user_id=user_id,
            detay=f"konu={kok.konu} iz={kok.kisa_izi()} ad={kok.ad} toplam={len(mevcut) + 1}")
    return kok


def sil(db: Any, parmak_izi: str, *, user_id: int | None = None) -> bool:
    """
    Parmak izine göre bir kökü kaldırır.

    Returns:
        True silindi, False böyle bir kök yoktu.
    """
    mevcut = oku(db)
    kalan = [k for k in mevcut if k.parmak_izi != parmak_izi]
    if len(kalan) == len(mevcut):
        return False
    silinen = next(k for k in mevcut if k.parmak_izi == parmak_izi)
    _yaz(db, kalan)
    _log.info("tsa_root_silindi  konu=%s iz=%s", silinen.konu, silinen.kisa_izi())
    _kaydet(db, EYLEM_SILINDI, user_id=user_id,
            detay=f"konu={silinen.konu} iz={silinen.kisa_izi()} kalan={len(kalan)}")
    return True


__all__ = [
    "AZAMI_ADET",
    "AZAMI_KOK",
    "EYLEM_EKLENDI",
    "EYLEM_SILINDI",
    "SETTING",
    "Kok",
    "TrustedRootError",
    "der_coz",
    "der_listesi",
    "ekle",
    "konu_metni",
    "oku",
    "sil",
]
