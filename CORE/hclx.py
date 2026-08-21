"""
HYCLEUS — `.hclx` imzalı teslim paketi (kullanıcı verisi paylaşımı)

Ne İÇİN — ve ne için DEĞİL
---------------------------
`.hclx`, kasadaki belgelerin kasa DIŞINA, süreli ve doğrulanabilir biçimde
verilmesi için. Uygulama güncellemesiyle hiçbir ilgisi YOK ve olmamalı:
güncelleme paketi kod çalıştırır, bu paket yalnızca veri taşır. Ayrı format
kararı bu yüzden verildi ve `MAGIC` bilerek farklı — bir teslim paketini
güncelleyici bir akışa besleyen kod, ilk baytta durur.

Üç ayrı iş, üç ayrı format; karıştırılmasınlar:

    .hcl   → kasadaki tek dosya          (CORE/crypto.py)
    yedek  → medya kaybı, tüm kasa       (CORE/backup.py)
    .hclx  → dışarıya süreli teslim      (bu modül)


Biçim
-----
    [6B ] magic        = b"HYCLX\\x00"
    [1B ] version      = 0x01
    [4B ] manifest_len (big-endian uint32)
    [xB ] manifest     = kanonik JSON — DÜZ METİN, anahtarsız okunabilir
    [nB ] payload      = eksiksiz bir `.hcl` kabı (encrypt_file çıktısı)

Manifesto neden DÜZ METİN: alıcı, paketi açmayı denemeden önce "bu paket
bana mı, penceresi geçmiş mi" sorusunu yanıtlayabilmeli. Anahtarı olmayan
biri de bir denetim kaydı üretebilmeli — süresi dolmuş bir paketin
reddedildiğini loglamak için paketi ÇÖZMEK gerekmiyor.

Düz metin olduğu için DEĞİŞTİRİLEBİLİR. Karşı önlem yeni bir şey değil,
`CORE/backup.py`'deki kararın aynısı: aynı manifesto şifreli gövdenin
İÇİNDE de duruyor ve açılışta ikisi BAYT BAYT karşılaştırılıyor. Dıştaki
kopyayı düzenleyen biri (örneğin pencereyi uzatmak için) içtekini
düzenleyemiyor, çünkü o GCM tag'inin altında.


İMZA — yeni bir şema İCAT EDİLMEDİ
-----------------------------------
Paketin bütünlüğünü ve kaynağını doğrulayan şey, `CORE/crypto.py`'nin zaten
kullandığı mekanizma: **AES-256-GCM kimlik doğrulama tag'i**. Gövde
`encrypt_file()` ile şifreleniyor, açılış `decrypt_file()` ile yapılıyor;
bu modül tek bir kripto ilkelini kendisi çağırmıyor.

Bunun DÜRÜST anlamı, ve abartılmaması gereken sınır:

  ✔ **Bütünlük gerçek.** Tek bayt değişse `AuthenticationError`. Gövde,
    manifesto ve dosya adları GCM'in kapsamında.
  ✔ **Kaynak, KASA düzeyinde gerçek.** Paketi ancak bu kasanın master
    key'ini elinde tutan biri üretebilir. Rastgele biri üretemez.
  ✘ **Kaynak, KULLANICI düzeyinde DEĞİL.** Kasaya erişimi olan herkes aynı
    anahtarı paylaşıyor. Manifestodaki `sender_user_id` kurcalanamaz ama
    bir BEYANDIR: kasaya erişimi olan bir kullanıcı, kendini bir başkası
    olarak yazan bir paket üretebilir. Simetrik bir MAC'in yapabileceğinin
    sınırı burası.

Kullanıcı düzeyinde kaynak kanıtı asimetrik imza ister ve bu depoda
asimetrik bir kimlik yok (TPM anahtarı bilerek yalnızca çözme yetkili,
bkz. `CORE/tpm_sealing.py`). Uydurmak yerine sınır yazıldı.

Paketin ÜRETİM ZAMANI da beyandır: `created_at` manifestodan geliyor ve
üreten taraf onu istediği gibi yazabilir. RFC 3161 damgası (§4.9) bunu
güvenilir bir ALT SINIRA çevirirdi; bu sürümde YAPILMADI, bkz. B-035.


SÜRE DOLUNCA NE OLUYOR — karar: **AÇILMAZ, SİLİNMEZ**
------------------------------------------------------
Pencere kapandığında HYCLEUS paketi açmayı reddediyor. Dosyayı DİSKTEN
SİLMİYOR. İki davranış farklı garanti veriyor ve seçilen bu; gerekçe:

1. **Silmek, verilemeyecek bir garantiyi ilan etmek olurdu.** Alıcı paketi
   pencere içinde açtıysa düz metin ZATEN elinde: kaydetmiş, yazdırmış ya
   da kopyalamış olabilir. Paketi sonradan yok etmek, çoktan çıkmış olan
   içeriği geri getirmiyor. "Süre dolunca veri yok olur" cümlesi yanlış
   olurdu ve yanlış bir güvenlik cümlesi, hiç cümle kurmamaktan kötü.
2. **Silmek, bizim olmayan bir diskte yıkıcı bir işlem.** `.hclx` alıcının
   makinesinde, alıcının dosyası. HYCLEUS'un onu imha etmesi, kullanıcının
   meşru olarak sakladığı bir şeyi haber vermeden yok etmek demek.
3. **Deponun kendi doktrini bunu söylüyor.** `CORE/disposal.py`: "Saklama
   süresi dolmak, dosyanın silinmesi GEREKTİĞİ anlamına gelmez; yalnızca
   artık silinmesinin SERBEST olduğu anlamına gelir. Kararı insan verir."
4. **Silme zaten en iyi çaba.** SSD wear levelling, kopyala-yaz dosya
   sistemleri ve anlık görüntüler (SECURITY.md §3) "silindi"yi "gitti"
   yapmıyor. Güçlü görünen, aslında zayıf bir garanti üretirdi.

Yani pencere bir **uygulama seviyesi kontrol** — SECURITY.md §4.5'in
sınıfından, kriptografik bir kontrol DEĞİL:

  · Alıcı anahtarı zaten tutuyor (yoksa hiç açamazdı), dolayısıyla
    değiştirilmiş bir istemci pencereyi yok sayabilir.
  · Pencere YEREL SAATE bakıyor. Saati geri almak pencereyi geri açar —
    SECURITY.md §3 aynı çekinceyi giriş kilidi için zaten kabul ediyor.
    Güvenilir bir "şimdi" çevrimdışı bir uygulamada yok.

Pencerenin gerçekten verdiği şey: dürüst bir alıcının makinesinde belgenin
süresiz açık kalmaması, ve her açılış denemesinin — başarılı ya da
başarısız — denetim kaydına düşmesi.


Açılış SIRASI — pencere, çözmeden ÖNCE
---------------------------------------
Süresi geçmiş bir paketin düz metni HİÇ ÜRETİLMİYOR: pencere kontrolü
çözme adımından önce, dıştaki manifesto üzerinden yapılıyor. Dıştaki
manifesto tek başına güvenilir değil — ona yetkiyi, çözmeden sonra yapılan
bayt bayt dış/iç karşılaştırması veriyor.

  · Pencereyi KISALTMAK için dış manifestoyu düzenlemek → erken reddedilir
    (fail-closed, zararsız).
  · Pencereyi UZATMAK için düzenlemek → çözme geçer, sonra dış/iç
    manifesto karşılaştırması tutmaz ve paket reddedilir.

Yani pencerenin yetkisi, kontrolün İKİ KEZ yapılmasından değil,
karşılaştırmanın pencere alanlarını kapsamasından geliyor.


Boyut sınırı
------------
Gövde, dosyaları base64 taşıyan kanonik bir JSON — yani düz metin bellekte
~%33 fazlasıyla duruyor ve `decrypt_file()` zaten tamamını belleğe alıyor.
Bu format BELGE teslimi için; arşiv taşımak için değil. `AZAMI_TOPLAM`
sınırı aşılırsa üretim net bir hatayla duruyor ve kullanıcıyı yedeklemeye
yönlendiriyor (`CORE/backup.py` dosyaları kopyalıyor, belleğe almıyor).
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import struct
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from CORE.crypto import AuthenticationError, decrypt_file, encrypt_file
from CORE import rehber
from CORE.safezone import safezone_file

_log = logging.getLogger("hycleus.hclx")

#: Kabın ilk baytları. `.hcl`'in b"HYCL" magic'inden BİLEREK farklı: bir
#: teslim paketini kasa okuyucusuna (ya da tersini) veren kod ilk baytta
#: durur, yarı yolda değil.
MAGIC = b"HYCLX\x00"
VERSION = 1
SUPPORTED_VERSIONS = frozenset({VERSION})

#: Manifestodaki biçim damgası — `CORE/backup.py::FORMAT` ile aynı desen.
FORMAT = "HYCLEUS-DELIVERY-V1"

UZANTI = ".hclx"

#: Varsayılan geçerlilik penceresi.
VARSAYILAN_SAAT = 72

#: Toplam düz metin sınırı. Gerekçe modül başlığında ("Boyut sınırı").
AZAMI_TOPLAM = 64 * 1024 * 1024

#: Manifesto için üst sınır — kurcalanmış bir uzunluk alanı yüzünden
#: gigabaytlık bir okuma denemesi yapılmasın.
_AZAMI_MANIFEST = 4 * 1024 * 1024

_ZAMAN = "%Y-%m-%dT%H:%M:%SZ"

# ── Denetim kaydı eylemleri ──────────────────────────────────────────────────
EYLEM_URETILDI = "hclx_created"
EYLEM_ACILDI = "hclx_opened"
EYLEM_REDDEDILDI = "hclx_rejected"

# ── Red kodları — denetim kaydına ve kullanıcıya aynı sözcük gidiyor ─────────
RED_BICIM = "bicim"
RED_ERKEN = "pencere_baslamadi"
RED_SURE_DOLDU = "pencere_kapandi"
RED_IMZA = "imza"
RED_MANIFEST = "manifest_uyusmuyor"
RED_ICERIK = "icerik_ozeti"


class HclxError(Exception):
    """
    Paket üretilemedi ya da açılamadı.

    `kod` alanı yukarıdaki `RED_*` sabitlerinden biri (üretim hatalarında
    boş). Mesaj doğrudan kullanıcıya gösterilebilir.
    """

    def __init__(self, mesaj: str, *, kod: str = "") -> None:
        super().__init__(mesaj)
        self.kod = kod


@dataclass(frozen=True)
class PaketDosya:
    """Paketten çıkan tek bir dosya."""

    ad: str
    veri: bytes
    sha256: str


@dataclass(frozen=True)
class Manifest:
    """
    Paketin anahtarsız okunabilen tanıtım bilgisi.

    Alanların hepsi GCM kapsamında DEĞİL — dıştaki kopya düz metin. Yetkili
    olan, gövdenin içindeki aynı manifesto; `open_package()` ikisini
    karşılaştırıyor.
    """

    package_id: str
    created_at: str
    valid_from: str
    valid_until: str
    sender_user_id: int | None
    sender_hwid: str
    payload_sha256: str
    dosyalar: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    note: str = ""

    def sozluk(self) -> dict[str, Any]:
        """Kanonik JSON'a girecek sözlük — alan sırası `sort_keys` ile sabit."""
        return {
            "format": FORMAT,
            "package_id": self.package_id,
            "created_at": self.created_at,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "sender_user_id": self.sender_user_id,
            "sender_hwid": self.sender_hwid,
            "payload_sha256": self.payload_sha256,
            "files": [dict(d) for d in self.dosyalar],
            "note": self.note,
        }

    def pencere_metni(self) -> str:
        return f"{self.valid_from}..{self.valid_until}"


def _kanonik(veri: dict[str, Any]) -> bytes:
    """Kanonik JSON — `CORE/backup.py` ile aynı ayarlar."""
    return json.dumps(
        veri, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def _simdi() -> datetime:
    """Şimdiki UTC. Testler bunu monkeypatch'liyor (`CORE/expiry.py` deseni)."""
    return datetime.now(timezone.utc)


def _damga(an: datetime) -> str:
    return an.astimezone(timezone.utc).strftime(_ZAMAN)


def _coz_damga(metin: str, *, alan: str) -> datetime:
    try:
        return datetime.strptime(metin, _ZAMAN).replace(tzinfo=timezone.utc)
    except (ValueError, TypeError) as exc:
        raise HclxError(
            f"Manifestodaki '{alan}' alanı okunamadı: {metin!r}", kod=RED_BICIM
        ) from exc


def _kaydet(db: Any, eylem: str, *, user_id: int | None, detay: str) -> None:
    """
    Denetim kaydı — burada oluşan hata İŞLEMİ BAŞARISIZ YAPMIYOR.

    `CORE/pin_rotation.py::_kaydet` ile aynı gerekçe: kayıt yazılamadı diye
    açılmış bir paketi "açılmadı" diye bildirmek, kullanıcıyı yanlış
    bilgilendirir. Kayıt hatası loglanıyor.
    """
    if db is None:
        return
    try:
        db.log(eylem, user_id=user_id, target_type="hclx", detail=detay)
    except Exception as exc:  # pragma: no cover — kayıt, sonucu engellemez
        _log.warning("hclx_log_failed  eylem=%s  exc=%s", eylem, exc)


# ══════════════════════════════════════════════════════════════════════════════
# 1. Üretim — sistemde TEK yer
# ══════════════════════════════════════════════════════════════════════════════
#
# `tests/test_hclx.py` bu fonksiyonun `.hclx` üreten TEK yol olduğunu AST
# ile denetliyor: ikinci bir üretim yolu, sessizce başka bir imza şeması
# (ya da hiç imza) kullanan ikinci bir paket türü demek olurdu.


def create_package(
    dosyalar: list[Path | str],
    key: bytes,
    *,
    user_id: int | None,
    hwid: str,
    dst: Path | str,
    gecerlilik_saat: int = VARSAYILAN_SAAT,
    note: str = "",
    rehber_ekle: bool = False,
    db: Any = None,
    simdi: datetime | None = None,
) -> Manifest:
    """
    Verilen dosyalardan imzalı, süreli bir `.hclx` üretir.

    Args:
        dosyalar:        Paketlenecek DÜZ METİN dosya yolları.
        key:             Kasanın master key'i (32 bayt). İmza bunun altında.
        user_id:         Manifestoya yazılan gönderen — BEYAN, kimlik kanıtı
                         değil (bkz. modül başlığı, "İMZA").
        hwid:            Üreten cihazın HWID'i.
        dst:             Yazılacak `.hclx` yolu.
        gecerlilik_saat: Pencere uzunluğu. `0` ya da negatif kabul EDİLMİYOR:
                         hiç açılamayan bir paket üretmek sessiz bir hata
                         olurdu.
        note:            Alıcıya serbest metin not (manifestoya girer,
                         yani düz metin okunabilir — sır yazmayın).
        rehber_ekle:     `True` ise kullanıcı rehberinin PDF kopyası da
                         pakete girer. Paket, kasayı hiç tanımayan birine
                         gidiyor olabilir; rehberin ÜÇÜNCÜ erişim yolu bu.
                         Kopya `CORE/rehber.py::PDF`'ten OKUNUYOR, burada
                         ÜRETİLMİYOR — tek üretim yolu kuralı (bkz.
                         `CORE/rehber.py` modül başlığı).
        db:              Verilirse denetim kaydı düşülür.
        simdi:           Testler için; verilmezse UTC şimdi.

    Returns:
        Yazılan paketin manifestosu.

    Raises:
        HclxError — dosya yok, boş liste, boyut sınırı aşıldı, pencere
            geçersiz ya da yazma başarısız.
    """
    if len(key) != 32:
        raise HclxError(f"Anahtar 32 bayt olmalı, {len(key)} bayt verildi.")
    if not dosyalar:
        raise HclxError("Paket en az bir dosya içermeli.")
    if gecerlilik_saat <= 0:
        raise HclxError(
            f"Geçerlilik penceresi pozitif olmalı, {gecerlilik_saat} verildi — "
            "hiç açılamayacak bir paket üretilmez."
        )

    yollar = [Path(p) for p in dosyalar]
    if rehber_ekle:
        # Rehber SON sırada: alıcının kendi dosyaları listede önce görünsün.
        #
        # Eksikse SESSİZCE ATLANMIYOR. Atlamak, "rehber de gitti" sanan bir
        # göndericiye yanlış bilgi vermek olurdu — B-025'in dersi: sessizce
        # devre dışı kalan bir yetenek, hiç olmayandan kötü.
        if not rehber.PDF.is_file():
            raise HclxError(
                f"Rehber PDF'i yok: {rehber.PDF}. "
                "Üretmek için: python CORE/rehber.py --uret")
        if any(y.name == rehber.PAKET_ADI for y in yollar):
            raise HclxError(
                f"Pakette zaten {rehber.PAKET_ADI} adlı bir dosya var — "
                "rehber eklenirse hangisinin hangisi olduğu belirsizleşir.")
        yollar.append(rehber.PDF)

    icerik: list[dict[str, Any]] = []
    ozet: list[dict[str, Any]] = []
    toplam = 0
    for yol in yollar:
        if not yol.is_file():
            raise HclxError(f"Dosya bulunamadı: {yol}")
        ham = yol.read_bytes()
        toplam += len(ham)
        if toplam > AZAMI_TOPLAM:
            raise HclxError(
                f"Paket {AZAMI_TOPLAM // (1024 * 1024)} MB sınırını aşıyor. "
                "Teslim paketi belge paylaşımı için; toplu veri taşımak "
                "gerekiyorsa yedekleme akışını kullanın."
            )
        sha = hashlib.sha256(ham).hexdigest()
        icerik.append({"name": yol.name, "sha256": sha,
                       "data": base64.b64encode(ham).decode("ascii")})
        ozet.append({"name": yol.name, "size": len(ham), "sha256": sha})

    an = simdi or _simdi()
    manifest_taslak = Manifest(
        package_id=uuid.uuid4().hex,
        created_at=_damga(an),
        valid_from=_damga(an),
        valid_until=_damga(an + timedelta(hours=gecerlilik_saat)),
        sender_user_id=user_id,
        sender_hwid=hwid,
        payload_sha256="",          # gövde yazıldıktan sonra doluyor
        dosyalar=tuple(ozet),
        note=note,
    )

    # Gövde: manifestonun KENDİSİ de içeride. Dıştaki düz metin kopyanın
    # kurcalanmasını yakalayan şey bu — bkz. modül başlığı.
    govde = {"manifest": manifest_taslak.sozluk(), "files": icerik}

    # Düz metin diske inmek zorunda (encrypt_file bir YOL alıyor). Sistem
    # TEMP'i değil SafeZone kullanılıyor ve blok biterken imha ediliyor —
    # SECURITY.md §4.8.
    with safezone_file(suffix=".json", prefix="hclx") as gecici:
        gecici.write_bytes(_kanonik(govde))
        with safezone_file(suffix=".hcl", prefix="hclx") as sifreli:
            encrypt_file(
                gecici, key, user_id if user_id is not None else 0,
                hwid=hwid, dst=sifreli, filename=f"{manifest_taslak.package_id}.json",
            )
            payload = sifreli.read_bytes()

    manifest = Manifest(
        **{**manifest_taslak.__dict__,
           "payload_sha256": hashlib.sha256(payload).hexdigest()}
    )
    ham_manifest = _kanonik(manifest.sozluk())

    hedef = Path(dst)
    hedef.parent.mkdir(parents=True, exist_ok=True)
    with open(hedef, "wb") as fout:
        fout.write(MAGIC)
        fout.write(bytes([VERSION]))
        fout.write(struct.pack(">I", len(ham_manifest)))
        fout.write(ham_manifest)
        fout.write(payload)

    _log.info("hclx_created  paket=%s dosya=%d pencere=%s",
              manifest.package_id[:8], len(yollar), manifest.pencere_metni())
    _kaydet(db, EYLEM_URETILDI, user_id=user_id,
            detay=(f"paket={manifest.package_id[:8]} dosya={len(yollar)} "
                   f"pencere={manifest.pencere_metni()} boyut={len(payload)} "
                   f"rehber={int(rehber_ekle)}"))
    return manifest


# ══════════════════════════════════════════════════════════════════════════════
# 2. Anahtarsız okuma
# ══════════════════════════════════════════════════════════════════════════════


def read_manifest(path: Path | str) -> tuple[Manifest, bytes, bytes]:
    """
    Dıştaki manifestoyu ANAHTARSIZ okur.

    Returns:
        (manifest, ham_manifest_baytlari, payload_baytlari)

    Bu manifesto DOĞRULANMIŞ DEĞİL — düz metin ve düzenlenebilir. Yetkili
    kopya gövdenin içinde; `open_package()` ikisini karşılaştırıyor. Burada
    okunmasının sebebi, anahtar olmadan da "bu paket ne, penceresi ne" diye
    sorulabilmesi ve reddin loglanabilmesi.

    Raises:
        HclxError — magic, sürüm, uzunluk ya da JSON bozuksa (kod=RED_BICIM).
    """
    yol = Path(path)
    try:
        ham = yol.read_bytes()
    except OSError as exc:
        raise HclxError(f"Paket okunamadı: {exc}", kod=RED_BICIM) from exc

    bas = len(MAGIC) + 1 + 4
    if len(ham) < bas:
        raise HclxError("Paket çok kısa — başlık eksik.", kod=RED_BICIM)
    if ham[: len(MAGIC)] != MAGIC:
        raise HclxError(
            "Bu bir HYCLEUS teslim paketi değil (magic tutmuyor).", kod=RED_BICIM
        )
    surum = ham[len(MAGIC)]
    if surum not in SUPPORTED_VERSIONS:
        raise HclxError(
            f"Desteklenmeyen paket sürümü: {surum} "
            f"(bu yapı {sorted(SUPPORTED_VERSIONS)} okuyor)", kod=RED_BICIM
        )
    (uzunluk,) = struct.unpack(">I", ham[len(MAGIC) + 1: bas])
    if uzunluk > _AZAMI_MANIFEST:
        raise HclxError(
            f"Manifesto uzunluğu makul değil ({uzunluk} bayt) — paket bozuk.",
            kod=RED_BICIM,
        )
    if len(ham) < bas + uzunluk:
        raise HclxError("Manifesto bloğu eksik, paket kesilmiş.", kod=RED_BICIM)

    ham_manifest = ham[bas: bas + uzunluk]
    payload = ham[bas + uzunluk:]
    if not payload:
        raise HclxError("Paket gövdesi boş.", kod=RED_BICIM)

    try:
        veri = json.loads(ham_manifest.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HclxError(f"Manifesto JSON olarak okunamadı: {exc}", kod=RED_BICIM) from exc
    if veri.get("format") != FORMAT:
        raise HclxError(
            f"Manifesto biçimi tanınmıyor: {veri.get('format')!r}", kod=RED_BICIM
        )

    try:
        manifest = Manifest(
            package_id=str(veri["package_id"]),
            created_at=str(veri["created_at"]),
            valid_from=str(veri["valid_from"]),
            valid_until=str(veri["valid_until"]),
            sender_user_id=veri["sender_user_id"],
            sender_hwid=str(veri["sender_hwid"]),
            payload_sha256=str(veri["payload_sha256"]),
            dosyalar=tuple(veri.get("files", ())),
            note=str(veri.get("note", "")),
        )
    except KeyError as exc:
        raise HclxError(f"Manifestoda zorunlu alan eksik: {exc}", kod=RED_BICIM) from exc
    return manifest, ham_manifest, payload


def pencere_durumu(manifest: Manifest, *, simdi: datetime | None = None) -> str:
    """
    `""` (pencere içinde), `RED_ERKEN` ya da `RED_SURE_DOLDU`.

    Sınırlar DAHİL: tam `valid_until` anında paket hâlâ açılıyor. Kapalı
    aralık bilinçli — saniye sınırında "bir an önce açılıyordu" gibi
    açıklanamaz bir davranış üretmemek için.
    """
    an = simdi or _simdi()
    if an < _coz_damga(manifest.valid_from, alan="valid_from"):
        return RED_ERKEN
    if an > _coz_damga(manifest.valid_until, alan="valid_until"):
        return RED_SURE_DOLDU
    return ""


# ══════════════════════════════════════════════════════════════════════════════
# 3. Açılış
# ══════════════════════════════════════════════════════════════════════════════


def open_package(
    path: Path | str,
    key: bytes,
    *,
    db: Any = None,
    user_id: int | None = None,
    hwid: str | None = None,
    simdi: datetime | None = None,
) -> list[PaketDosya]:
    """
    Paketi doğrular, penceresini denetler ve içindeki dosyaları döndürür.

    Sıra (her adım bir öncekine güveniyor):

      1. Başlık + dış manifesto — anahtarsız
      2. Gövde özeti (`payload_sha256`) — anahtarsız bozulma tespiti
      3. **Pencere ön eleği** — dış manifestodan. Geçmişse burada durur ve
         DÜZ METİN HİÇ ÜRETİLMEZ.
      4. Çözme + GCM doğrulaması — imza burada denetleniyor
      5. Dış/iç manifesto karşılaştırması — dış kopyanın kurcalanması
      6. Yetkili manifestonun kurulması (pencere BURADA tekrar
         kontrol edilmiyor — gerekçe 6. adımın yanında yazılı)
      7. Dosya özetleri

    3. adım kurcalanabilir bir veri üzerinde ve tek başına yetkili değil;
    yetkiyi ona 5. adımdaki bayt bayt karşılaştırma veriyor. Ayrıntı modül
    başlığında.

    HER SONUÇ denetim kaydına düşüyor — başarı da, her red de.

    Raises:
        HclxError — `kod` alanı hangi adımda durulduğunu söylüyor.
    """
    yol = Path(path)

    def _red(hata: HclxError, manifest: Manifest | None) -> HclxError:
        parcalar = [f"dosya={yol.name}", f"sonuc={hata.kod or 'bilinmiyor'}"]
        if manifest is not None:
            parcalar[1:1] = [f"paket={manifest.package_id[:8]}",
                             f"gonderen={manifest.sender_user_id}",
                             f"pencere={manifest.pencere_metni()}"]
        _log.warning("hclx_rejected  %s", "  ".join(parcalar))
        _kaydet(db, EYLEM_REDDEDILDI, user_id=user_id, detay=" ".join(parcalar))
        return hata

    # ── 1 + 2 ────────────────────────────────────────────────────────────
    try:
        manifest, ham_manifest, payload = read_manifest(yol)
    except HclxError as exc:
        raise _red(exc, None) from None

    gercek = hashlib.sha256(payload).hexdigest()
    if gercek != manifest.payload_sha256:
        raise _red(HclxError(
            "Paket gövdesi manifestodaki özetle uyuşmuyor — dosya bozulmuş "
            "ya da değiştirilmiş.", kod=RED_BICIM), manifest) from None

    # ── 3. Pencere ön eleği ──────────────────────────────────────────────
    an = simdi or _simdi()
    durum = pencere_durumu(manifest, simdi=an)
    if durum:
        raise _red(HclxError(_pencere_mesaji(durum, manifest), kod=durum),
                   manifest) from None

    # ── 4. Çözme = imza doğrulaması ──────────────────────────────────────
    with safezone_file(suffix=".hcl", prefix="hclx") as gecici:
        gecici.write_bytes(payload)
        try:
            duz, _meta = decrypt_file(gecici, key, hwid=hwid)
        except AuthenticationError as exc:
            raise _red(HclxError(
                "Paketin imzası doğrulanmadı — içerik değiştirilmiş ya da "
                "paket bu kasaya ait değil.", kod=RED_IMZA), manifest) from exc
        except (ValueError, OSError) as exc:
            raise _red(HclxError(
                f"Paket gövdesi okunamadı: {exc}", kod=RED_BICIM), manifest) from exc

    try:
        # ── 5. Dış/iç manifesto ──────────────────────────────────────────
        try:
            govde = json.loads(duz.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _red(HclxError(
                f"Paket gövdesi JSON olarak okunamadı: {exc}",
                kod=RED_BICIM), manifest) from exc

        ic = dict(govde.get("manifest") or {})
        # Dış manifesto gövde yazıldıktan SONRA `payload_sha256` kazanıyor;
        # iç kopyada o alan boş. Karşılaştırma bu tek alan hariç yapılıyor
        # ve alanın kendisi 2. adımda zaten doğrulandı.
        dis = json.loads(ham_manifest.decode("utf-8"))
        dis.pop("payload_sha256", None)
        ic.pop("payload_sha256", None)
        if _kanonik(dis) != _kanonik(ic):
            raise _red(HclxError(
                "Paketin dış manifestosu içindekiyle uyuşmuyor — düz metin "
                "bilgi (gönderen ya da geçerlilik penceresi) sonradan "
                "değiştirilmiş.", kod=RED_MANIFEST), manifest) from None

        # ── 6. Yetkili manifesto ─────────────────────────────────────────
        # Pencere burada TEKRAR KONTROL EDİLMİYOR ve bu bilinçli.
        #
        # İlk yazımda ediliyordu ("dıştaki kurcalanabilir, içtekine de
        # bakalım") — sonra mutasyon testi o kontrolü kaldırmanın HİÇBİR
        # testi düşürmediğini gösterdi. Sebep: 5. adımdaki karşılaştırma
        # bayt bayt ve `valid_from`/`valid_until` onun kapsamında. İki
        # değer AYNI olmak zorunda olduğu için ikinci kontrolün farklı bir
        # cevap vermesi MÜMKÜN DEĞİL.
        #
        # Gözlenemeyen bir koruma, zamanla "bu neden burada" diye sorulan
        # ölü koda dönüşür. Yerine, karşılaştırmanın pencere alanlarını
        # gerçekten kapsadığı test ediliyor:
        # `test_karsilastirma_PENCERE_alanlarini_kapsiyor`. Karşılaştırma
        # bir gün gevşetilirse o test düşer — sessiz kalmaz.
        yetkili = Manifest(
            package_id=str(ic["package_id"]),
            created_at=str(ic["created_at"]),
            valid_from=str(ic["valid_from"]),
            valid_until=str(ic["valid_until"]),
            sender_user_id=ic["sender_user_id"],
            sender_hwid=str(ic["sender_hwid"]),
            payload_sha256=manifest.payload_sha256,
            dosyalar=tuple(ic.get("files", ())),
            note=str(ic.get("note", "")),
        )

        # ── 7. Dosya özetleri ────────────────────────────────────────────
        cikan: list[PaketDosya] = []
        for kayit in govde.get("files", ()):
            veri = base64.b64decode(kayit["data"])
            sha = hashlib.sha256(veri).hexdigest()
            if sha != kayit["sha256"]:
                raise _red(HclxError(
                    f"'{kayit['name']}' dosyasının özeti tutmuyor.",
                    kod=RED_ICERIK), yetkili) from None
            cikan.append(PaketDosya(ad=str(kayit["name"]), veri=veri, sha256=sha))
    finally:
        del duz

    _log.info("hclx_opened  paket=%s dosya=%d", yetkili.package_id[:8], len(cikan))
    _kaydet(db, EYLEM_ACILDI, user_id=user_id,
            detay=(f"paket={yetkili.package_id[:8]} "
                   f"gonderen={yetkili.sender_user_id} "
                   f"pencere={yetkili.pencere_metni()} "
                   f"acilis={_damga(an)} dosya={len(cikan)} sonuc=pencere_icinde"))
    return cikan


def _pencere_mesaji(durum: str, manifest: Manifest) -> str:
    """Kullanıcıya gösterilecek metin — dosyanın SİLİNMEDİĞİNİ de söylüyor."""
    if durum == RED_ERKEN:
        return (f"Bu paketin geçerlilik penceresi henüz başlamadı "
                f"({manifest.valid_from}).")
    return (
        f"Bu paketin geçerlilik penceresi {manifest.valid_until} tarihinde "
        "kapandı ve paket artık açılamıyor.\n\n"
        "Dosya silinmedi — yerinde duruyor; yalnızca HYCLEUS onu açmıyor. "
        "Yeniden erişmek için gönderenden yeni bir paket isteyin."
    )


__all__ = [
    "AZAMI_TOPLAM",
    "EYLEM_ACILDI",
    "EYLEM_REDDEDILDI",
    "EYLEM_URETILDI",
    "FORMAT",
    "MAGIC",
    "RED_BICIM",
    "RED_ERKEN",
    "RED_ICERIK",
    "RED_IMZA",
    "RED_MANIFEST",
    "RED_SURE_DOLDU",
    "SUPPORTED_VERSIONS",
    "UZANTI",
    "VARSAYILAN_SAAT",
    "VERSION",
    "HclxError",
    "Manifest",
    "PaketDosya",
    "create_package",
    "open_package",
    "pencere_durumu",
    "read_manifest",
]
