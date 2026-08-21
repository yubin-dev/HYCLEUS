"""
CORE.hclx — imzalı, süreli teslim paketi (`.hclx`).

Testler GERÇEK kripto kullanıyor: `encrypt_file`/`decrypt_file` sahte
değil, kasadakiyle aynı AES-256-GCM yolu. Sahte bir imzayla "imza
doğrulandı" demek, doğrulanmadığını fark etmemek olurdu — bu paketin en
önemli iddiası zaten kurcalanmış bir paketin AÇILMAMASI.

Zaman her yerde ENJEKTE ediliyor (`simdi=`), `sleep` yok: pencere
davranışını gerçek saatle sınamak testi hem yavaş hem kırılgan yapardı ve
sınır anlarını (tam `valid_until`) hiç ölçemezdi.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import re
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from CORE import hclx
from CORE.hclx import (
    EYLEM_ACILDI,
    EYLEM_REDDEDILDI,
    EYLEM_URETILDI,
    MAGIC,
    RED_BICIM,
    RED_ERKEN,
    RED_ICERIK,
    RED_IMZA,
    RED_MANIFEST,
    RED_SURE_DOLDU,
    HclxError,
    create_package,
    open_package,
    pencere_durumu,
    read_manifest,
)

KOK = Path(__file__).resolve().parent.parent

_KEY = b"k" * 32
_BASKA_KEY = b"x" * 32
_AN = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
_SAAT = 24


@pytest.fixture(autouse=True)
def izole_safezone(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    SafeZone'u `tmp_path`'e taşır.

    Paket üretimi ve açılışı düz metni GEÇİCİ olarak diske indiriyor;
    testler kullanıcının gerçek SafeZone dizinine dokunmamalı.
    """
    monkeypatch.setenv("HYCLEUS_SAFEZONE", str(tmp_path / "safezone"))


@pytest.fixture
def kaynak(tmp_path: Path) -> list[Path]:
    a = tmp_path / "sozlesme.txt"
    b = tmp_path / "ek.bin"
    a.write_bytes("Gizli sözleşme içeriği — ÇĞİÖŞÜ".encode("utf-8"))
    b.write_bytes(bytes(range(256)) * 4)
    return [a, b]


@pytest.fixture
def paket(tmp_path: Path, kaynak: list[Path]) -> Path:
    yol = tmp_path / "teslim.hclx"
    create_package(kaynak, _KEY, user_id=7, hwid="HW-GONDEREN",
                   dst=yol, gecerlilik_saat=_SAAT, simdi=_AN, note="deneme")
    return yol


@pytest.fixture
def kullanicili_db(db):  # type: ignore[no-untyped-def]
    """
    `audit_log.user_id` bir YABANCI ANAHTAR (`REFERENCES users(id)`).

    Satır yoksa `db.log()` FK ihlaliyle düşüyor ve `_kaydet()` onu
    yutuyor — yani kayıt SESSİZCE yazılmıyor. Üretimde satır garanti
    (B-011, `sync_session_user`); testte elle kuruluyor.
    """
    for uid, ad in ((7, "gonderen"), (42, "alici")):
        db.execute(
            "INSERT INTO users (id, username, password_hash, role, status, hwid)"
            " VALUES (?, ?, '', 'admin', 'approved', 'H')", (uid, ad))
    return db


def _kayitlar(db, eylem: str) -> list[str]:  # type: ignore[no-untyped-def]
    return [r["detail"] for r in db.fetchall(
        "SELECT detail FROM audit_log WHERE action = ? ORDER BY id", (eylem,))]


def _paket_yaz(yol: Path, manifest: dict, payload: bytes) -> None:
    """Elle paket kurar — kurcalama senaryoları için."""
    ham = json.dumps(manifest, sort_keys=True, ensure_ascii=False,
                     separators=(",", ":")).encode("utf-8")
    yol.write_bytes(MAGIC + bytes([hclx.VERSION]) + struct.pack(">I", len(ham))
                    + ham + payload)


def _govde_manifesti(yol: Path) -> dict:
    """Şifreli gövdedeki manifesto — anahtarla çözülerek okunuyor."""
    from CORE.crypto import decrypt_file
    from CORE.safezone import safezone_file
    _, payload = _parcala(yol)
    with safezone_file(suffix=".hcl", prefix="test") as gecici:
        gecici.write_bytes(payload)
        duz, _meta = decrypt_file(gecici, _KEY)
    return dict(json.loads(duz.decode("utf-8"))["manifest"])


def _parcala(yol: Path) -> tuple[dict, bytes]:
    ham = yol.read_bytes()
    bas = len(MAGIC) + 1 + 4
    (n,) = struct.unpack(">I", ham[len(MAGIC) + 1:bas])
    return json.loads(ham[bas:bas + n]), ham[bas + n:]


# ══════════════════════════════════════════════════════════════════════════════
# 1. Tur: üret → aç
# ══════════════════════════════════════════════════════════════════════════════


def test_pencere_icinde_acilir_ve_icerik_AYNI(paket: Path, kaynak: list[Path]) -> None:
    cikan = open_package(paket, _KEY, simdi=_AN + timedelta(hours=1))
    assert [c.ad for c in cikan] == [y.name for y in kaynak]
    for c, y in zip(cikan, kaynak):
        assert c.veri == y.read_bytes(), f"{c.ad} içeriği bozuldu"


def test_paket_duz_metni_ICERMIYOR(paket: Path, kaynak: list[Path]) -> None:
    """
    Asıl gizlilik iddiası. Gövde şifreli; dosya adları manifestoda AÇIK
    (bilinçli, `.hcl` başlığındaki AAD ile aynı takas) ama İÇERİK değil.
    """
    ham = paket.read_bytes()
    for y in kaynak:
        assert y.read_bytes() not in ham, f"{y.name} içeriği düz metin duruyor"
    assert "Gizli sözleşme".encode("utf-8") not in ham


def test_manifest_ANAHTARSIZ_okunuyor(paket: Path) -> None:
    """
    Alıcı, açmayı denemeden önce "bu paket ne, penceresi ne" diyebilmeli —
    ve anahtarı olmayan biri de reddi loglayabilmeli.
    """
    manifest, _, _ = read_manifest(paket)
    assert manifest.sender_user_id == 7
    assert manifest.sender_hwid == "HW-GONDEREN"
    assert [d["name"] for d in manifest.dosyalar] == ["sozlesme.txt", "ek.bin"]
    assert manifest.valid_until == "2026-01-02T12:00:00Z"


def test_tekrar_acilabilir(paket: Path) -> None:
    """Açmak tüketmiyor — pencere içinde kaç kez açılırsa açılsın çalışıyor."""
    for _ in range(3):
        assert open_package(paket, _KEY, simdi=_AN + timedelta(hours=1))


def test_bos_liste_ve_gecersiz_pencere_REDDEDILIYOR(tmp_path: Path,
                                                    kaynak: list[Path]) -> None:
    with pytest.raises(HclxError, match="en az bir dosya"):
        create_package([], _KEY, user_id=1, hwid="H", dst=tmp_path / "x.hclx")
    with pytest.raises(HclxError, match="pozitif"):
        create_package(kaynak, _KEY, user_id=1, hwid="H",
                       dst=tmp_path / "x.hclx", gecerlilik_saat=0)


def test_boyut_siniri_net_hata_veriyor(tmp_path: Path,
                                       monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Sessizce belleği doldurmak yerine kullanıcıyı yedeklemeye yönlendiren
    bir hata. Sınır monkeypatch'leniyor — 64 MB'lık gerçek dosya yazmak
    testi saniyelerce yavaşlatırdı ve ölçtüğü şey aynı `if`.
    """
    monkeypatch.setattr(hclx, "AZAMI_TOPLAM", 10)
    buyuk = tmp_path / "buyuk.bin"
    buyuk.write_bytes(b"a" * 100)
    with pytest.raises(HclxError, match="sınırını aşıyor"):
        create_package([buyuk], _KEY, user_id=1, hwid="H", dst=tmp_path / "x.hclx")


# ══════════════════════════════════════════════════════════════════════════════
# 2. Pencere — sınırlar dâhil
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("kayma,beklenen", [
    (timedelta(seconds=-1), RED_ERKEN),
    (timedelta(0), ""),                       # tam valid_from — AÇILIR
    (timedelta(hours=12), ""),
    (timedelta(hours=_SAAT), ""),             # tam valid_until — AÇILIR
    (timedelta(hours=_SAAT, seconds=1), RED_SURE_DOLDU),
])
def test_pencere_sinirlari(paket: Path, kayma: timedelta, beklenen: str) -> None:
    """
    Sınırlar KAPALI aralık. Açık olsaydı `valid_until` anında paket bir
    saniye önce açılıp o an açılmıyor olurdu — açıklanamaz bir davranış.
    """
    manifest, _, _ = read_manifest(paket)
    assert pencere_durumu(manifest, simdi=_AN + kayma) == beklenen


def test_suresi_dolmus_paket_acilmiyor(paket: Path) -> None:
    with pytest.raises(HclxError) as ex:
        open_package(paket, _KEY, simdi=_AN + timedelta(hours=_SAAT + 1))
    assert ex.value.kod == RED_SURE_DOLDU


def test_suresi_DOLMAMIS_paket_erken_acilmiyor(paket: Path) -> None:
    with pytest.raises(HclxError) as ex:
        open_package(paket, _KEY, simdi=_AN - timedelta(hours=1))
    assert ex.value.kod == RED_ERKEN


def test_sure_dolunca_dosya_SILINMIYOR(paket: Path) -> None:
    """
    Belgelenmiş karar: pencere kapanınca paket AÇILMIYOR, SİLİNMİYOR.
    Gerekçesi modül başlığında ve SECURITY.md §4.14'te.

    Bu test o kararın sabitlemesi: birisi "süre dolunca imha edelim" diye
    davranışı çevirirse, karar sessizce değişmiş olmaz.
    """
    once = paket.read_bytes()
    with pytest.raises(HclxError):
        open_package(paket, _KEY, simdi=_AN + timedelta(days=365))
    assert paket.exists(), "süresi dolan paket SİLİNMİŞ — karar değişmiş"
    assert paket.read_bytes() == once, "paket değiştirilmiş"


def test_sure_dolma_mesaji_silinmedigini_SOYLUYOR(paket: Path) -> None:
    """
    Kullanıcı "dosyam yok mu oldu" diye düşünmemeli; mesaj bunu açıkça
    söylemeli, yoksa panikleyen kullanıcı yanlış yere bakar.
    """
    with pytest.raises(HclxError) as ex:
        open_package(paket, _KEY, simdi=_AN + timedelta(days=2))
    mesaj = str(ex.value).lower()
    assert "silinmedi" in mesaj
    assert "gönderenden" in mesaj


def test_suresi_dolmus_paketin_duz_metni_HIC_uretilmiyor(
    paket: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Pencere elemesi ÇÖZMEDEN ÖNCE. Süresi geçmiş bir paketi çözüp sonra
    "ama göstermiyorum" demek, düz metni bir kez daha üretmek olurdu.
    """
    cagrildi = []
    monkeypatch.setattr(hclx, "decrypt_file",
                        lambda *a, **k: cagrildi.append(1) or (b"", {}))
    with pytest.raises(HclxError):
        open_package(paket, _KEY, simdi=_AN + timedelta(days=2))
    assert not cagrildi, "süresi dolmuş paket ÇÖZÜLDÜ"


# ══════════════════════════════════════════════════════════════════════════════
# 3. İmza ve kurcalama
# ══════════════════════════════════════════════════════════════════════════════


def test_baska_kasanin_anahtari_ACAMIYOR(paket: Path) -> None:
    with pytest.raises(HclxError) as ex:
        open_package(paket, _BASKA_KEY, simdi=_AN + timedelta(hours=1))
    assert ex.value.kod == RED_IMZA


def test_govde_kurcalanmasi_ozetle_yakalaniyor(paket: Path, tmp_path: Path) -> None:
    """Manifestodaki ciphertext özeti — anahtar OLMADAN bozulma tespiti."""
    ham = bytearray(paket.read_bytes())
    ham[-3] ^= 0x01
    bozuk = tmp_path / "bozuk.hclx"
    bozuk.write_bytes(bytes(ham))
    with pytest.raises(HclxError) as ex:
        open_package(bozuk, _KEY, simdi=_AN + timedelta(hours=1))
    assert ex.value.kod == RED_BICIM


def test_govde_kurcalanip_ozet_GUNCELLENSE_de_imza_yakaliyor(
    paket: Path, tmp_path: Path
) -> None:
    """
    Asıl imza testi. Saldırgan gövdeyi bozup manifestodaki özeti de
    düzeltirse özet kontrolü geçer — GCM tag'i geçmez.
    """
    manifest, payload = _parcala(paket)
    bozuk_payload = bytearray(payload)
    bozuk_payload[-3] ^= 0x01
    manifest["payload_sha256"] = hashlib.sha256(bytes(bozuk_payload)).hexdigest()
    hedef = tmp_path / "akilli.hclx"
    _paket_yaz(hedef, manifest, bytes(bozuk_payload))

    with pytest.raises(HclxError) as ex:
        open_package(hedef, _KEY, simdi=_AN + timedelta(hours=1))
    assert ex.value.kod == RED_IMZA


def test_pencereyi_UZATMAK_icin_dis_manifesto_duzenlenemez(
    paket: Path, tmp_path: Path
) -> None:
    """
    Bu maddenin can alıcı noktası. Dış manifesto düz metin ve pencereyi
    uzatmak için düzenlenebilir — ama aynı manifesto gövdenin İÇİNDE de
    duruyor ve GCM'in altında.
    """
    manifest, payload = _parcala(paket)
    manifest["valid_until"] = "2099-01-01T00:00:00Z"
    hedef = tmp_path / "uzatilmis.hclx"
    _paket_yaz(hedef, manifest, payload)

    with pytest.raises(HclxError) as ex:
        open_package(hedef, _KEY, simdi=_AN + timedelta(days=365))
    assert ex.value.kod == RED_MANIFEST


def test_karsilastirma_PENCERE_alanlarini_kapsiyor(paket: Path) -> None:
    """
    Pencerenin YETKİSİ buradan geliyor.

    `open_package()` pencereyi yalnızca BİR kez, dıştaki (kurcalanabilir)
    manifestodan kontrol ediyor. İlk yazımda içteki kopyadan bir kez daha
    kontrol ediliyordu; mutasyon testi o ikinci kontrolü kaldırmanın hiçbir
    testi düşürmediğini gösterdi — çünkü bayt bayt karşılaştırma iki
    değerin farklı olmasını zaten imkânsız kılıyor.

    İkinci kontrol KALDIRILDI (gözlenemeyen koruma ölü koda dönüşür) ve
    yerine ilişkinin kendisi sabitlendi: karşılaştırma DIŞARIDA bırakılan
    tek alan `payload_sha256` olmalı. Biri bir gün `valid_until`'i de
    dışarıda bırakırsa bu test düşer.
    """
    _, payload = _parcala(paket)
    ic = json.loads(
        # gövdedeki manifesto — anahtarla çözülüp okunuyor
        json.dumps(_govde_manifesti(paket))
    )
    dis, _ = _parcala(paket)
    fark = {k for k in set(dis) | set(ic) if dis.get(k) != ic.get(k)}
    assert fark == {"payload_sha256"}, (
        f"Dış ve iç manifesto {fark} alanlarında ayrışıyor. Karşılaştırma "
        "yalnızca `payload_sha256`'yı dışarıda bırakmalı — pencere alanları "
        "kapsamda KALMALI, yoksa pencere kurcalanabilir hâle gelir."
    )
    assert "valid_until" not in fark and "valid_from" not in fark
    assert len(payload) > 0


def test_desteklenmeyen_SURUM_reddediliyor(paket: Path, tmp_path: Path) -> None:
    """
    Biçimsiz girdi testleri bunu KAÇIRIYORDU: oradaki örnekler sürüm
    kontrolü olmasa da manifesto/JSON adımında düşüyordu, yani sürüm
    kontrolünü kaldırmak hiçbir testi düşürmüyordu (mutasyonla ölçüldü).

    Bu test tam olarak o farkı ölçüyor: her yönüyle GEÇERLİ bir paketin
    yalnızca sürüm baytı değiştiriliyor.
    """
    ham = bytearray(paket.read_bytes())
    ham[len(MAGIC)] = 0x99
    hedef = tmp_path / "gelecek_surum.hclx"
    hedef.write_bytes(bytes(ham))
    with pytest.raises(HclxError, match="Desteklenmeyen paket sürümü") as ex:
        read_manifest(hedef)
    assert ex.value.kod == RED_BICIM


def test_GONDERENI_degistirmek_de_yakalaniyor(paket: Path, tmp_path: Path) -> None:
    """
    Kaynak iddiası kasa düzeyinde; ama manifestodaki beyanın SONRADAN
    değiştirilmesi ayrı bir şey ve yakalanıyor.
    """
    manifest, payload = _parcala(paket)
    manifest["sender_user_id"] = 999
    hedef = tmp_path / "sahte_gonderen.hclx"
    _paket_yaz(hedef, manifest, payload)

    with pytest.raises(HclxError) as ex:
        open_package(hedef, _KEY, simdi=_AN + timedelta(hours=1))
    assert ex.value.kod == RED_MANIFEST


def test_icerik_ozeti_tutmazsa_reddediliyor(tmp_path: Path, kaynak: list[Path],
                                            monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Gövde içindeki dosya özetleri. GCM zaten bütünü koruyor; bu, kendi
    üretimimizde bir hata olursa (yanlış dosya, yanlış özet) sessiz
    kalmamasını sağlıyor — savunma değil, tutarlılık denetimi.
    """
    yol = tmp_path / "p.hclx"
    create_package(kaynak, _KEY, user_id=1, hwid="H", dst=yol, simdi=_AN)

    gercek = hclx._kanonik

    def bozan(veri):  # type: ignore[no-untyped-def]
        if "files" in veri and veri.get("files") and "data" in veri["files"][0]:
            veri = json.loads(json.dumps(veri))
            veri["files"][0]["sha256"] = "0" * 64
        return gercek(veri)

    monkeypatch.setattr(hclx, "_kanonik", bozan)
    yol2 = tmp_path / "p2.hclx"
    create_package(kaynak, _KEY, user_id=1, hwid="H", dst=yol2, simdi=_AN)
    monkeypatch.setattr(hclx, "_kanonik", gercek)

    with pytest.raises(HclxError) as ex:
        open_package(yol2, _KEY, simdi=_AN + timedelta(hours=1))
    assert ex.value.kod == RED_ICERIK


@pytest.mark.parametrize("bozuk", [
    b"", b"HYCL", b"HYCLX\x00", b"HYCLX\x00\x01",
    b"HYCLX\x00\x99" + b"\x00" * 8,             # desteklenmeyen sürüm
    b"HYCLX\x00\x01" + b"\xff\xff\xff\xff",     # akıl dışı manifesto uzunluğu
    b"HYCLX\x00\x01" + struct.pack(">I", 4) + b"{{{{",   # bozuk JSON
])
def test_bicimsiz_girdiler_TEMIZ_hata_veriyor(tmp_path: Path, bozuk: bytes) -> None:
    """İzleme (traceback) değil, anlaşılır `HclxError` — fuzzing sınıfı."""
    yol = tmp_path / "bozuk.hclx"
    yol.write_bytes(bozuk)
    with pytest.raises(HclxError) as ex:
        read_manifest(yol)
    assert ex.value.kod == RED_BICIM


def test_hcl_dosyasi_hclx_diye_acilmiyor(tmp_path: Path, kaynak: list[Path]) -> None:
    """
    MAGIC bilerek farklı: bir kasa dosyasını teslim okuyucusuna vermek ilk
    baytta durmalı, yarı yolda değil.
    """
    from CORE.crypto import encrypt_file
    hedef = tmp_path / "kasa.hcl"
    encrypt_file(kaynak[0], _KEY, 1, hwid="H", dst=hedef)
    with pytest.raises(HclxError, match="teslim paketi değil"):
        read_manifest(hedef)


# ══════════════════════════════════════════════════════════════════════════════
# 4. Denetim kaydı — ÜÇ senaryonun hepsi
# ══════════════════════════════════════════════════════════════════════════════


def test_uretim_kayda_geciyor(kullanicili_db, tmp_path: Path, kaynak: list[Path]) -> None:  # type: ignore[no-untyped-def]
    create_package(kaynak, _KEY, user_id=7, hwid="H",
                   dst=tmp_path / "p.hclx", simdi=_AN, db=kullanicili_db)
    (detay,) = _kayitlar(kullanicili_db, EYLEM_URETILDI)
    assert "dosya=2" in detay
    assert "pencere=2026-01-01T12:00:00Z..2026-01-04T12:00:00Z" in detay


def test_basarili_acilis_kayda_geciyor(kullanicili_db, paket: Path) -> None:  # type: ignore[no-untyped-def]
    open_package(paket, _KEY, db=kullanicili_db, user_id=42, simdi=_AN + timedelta(hours=2))
    (detay,) = _kayitlar(kullanicili_db, EYLEM_ACILDI)
    assert "sonuc=pencere_icinde" in detay
    assert "acilis=2026-01-01T14:00:00Z" in detay      # NE ZAMAN açıldı
    assert "gonderen=7" in detay
    assert "pencere=2026-01-01T12:00:00Z..2026-01-02T12:00:00Z" in detay
    assert not _kayitlar(kullanicili_db, EYLEM_REDDEDILDI)

    satir = kullanicili_db.fetchone(
        "SELECT user_id, target_type FROM audit_log WHERE action = ?",
        (EYLEM_ACILDI,))
    assert satir["user_id"] == 42, "KİM açtı kaydedilmemiş"
    assert satir["target_type"] == "hclx"


def test_suresi_dolmus_deneme_BASARISIZ_olarak_kayda_geciyor(kullanicili_db, paket: Path) -> None:  # type: ignore[no-untyped-def]
    """
    Süresi dolmuş bir paketi açmaya çalışmak sessiz kalmamalı: kimin ne
    zaman denediği, uyumluluk açısından başarılı açılış kadar önemli.
    """
    with pytest.raises(HclxError):
        open_package(paket, _KEY, db=kullanicili_db, user_id=42,
                     simdi=_AN + timedelta(hours=_SAAT + 1))
    (detay,) = _kayitlar(kullanicili_db, EYLEM_REDDEDILDI)
    assert f"sonuc={RED_SURE_DOLDU}" in detay
    assert "pencere=2026-01-01T12:00:00Z..2026-01-02T12:00:00Z" in detay
    assert not _kayitlar(kullanicili_db, EYLEM_ACILDI), "reddedilen deneme AÇILDI diye yazılmış"


def test_bozuk_imza_da_kayda_geciyor(kullanicili_db, paket: Path) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(HclxError):
        open_package(paket, _BASKA_KEY, db=kullanicili_db, user_id=42,
                     simdi=_AN + timedelta(hours=1))
    (detay,) = _kayitlar(kullanicili_db, EYLEM_REDDEDILDI)
    assert f"sonuc={RED_IMZA}" in detay


def test_okunamayan_paket_de_kayda_geciyor(kullanicili_db, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """
    Manifesto hiç okunamasa bile bir kayıt düşmeli — yoksa bozuk paket
    göndererek denetim kaydından kaçmak mümkün olurdu.
    """
    yol = tmp_path / "cop.hclx"
    yol.write_bytes(b"tamamen alakasiz veri")
    with pytest.raises(HclxError):
        open_package(yol, _KEY, db=kullanicili_db, user_id=42, simdi=_AN)
    (detay,) = _kayitlar(kullanicili_db, EYLEM_REDDEDILDI)
    assert f"sonuc={RED_BICIM}" in detay
    assert "dosya=cop.hclx" in detay


def test_denetim_kaydi_DUZ_METIN_sizdirmiyor(kullanicili_db, paket: Path, kaynak: list[Path]) -> None:  # type: ignore[no-untyped-def]
    """Denetim günlüğü şifresiz veritabanında (SECURITY.md §3)."""
    open_package(paket, _KEY, db=kullanicili_db, user_id=42, simdi=_AN + timedelta(hours=1))
    hepsi = " ".join(r["detail"] or "" for r in kullanicili_db.fetchall("SELECT detail FROM audit_log"))
    assert "Gizli sözleşme" not in hepsi
    assert base64.b64encode(kaynak[0].read_bytes()).decode() not in hepsi


def test_kayit_hatasi_ACILISI_engellemiyor(paket: Path) -> None:
    """
    `CORE/pin_rotation.py` ile aynı karar: kayıt yazılamadı diye açılmış
    bir paketi "açılmadı" diye bildirmek kullanıcıyı yanlış bilgilendirir.
    """
    class BozukDB:
        def log(self, *a, **k):  # type: ignore[no-untyped-def]
            raise RuntimeError("veritabanı yok")

    assert open_package(paket, _KEY, db=BozukDB(), simdi=_AN + timedelta(hours=1))


# ══════════════════════════════════════════════════════════════════════════════
# 5. TEK ÜRETİM YOLU — AST denetimleri
# ══════════════════════════════════════════════════════════════════════════════
#
# Korunan invaryant: `.hclx` üretimi tek bir modülden geçiyor. İkinci bir
# üretim yolu, sessizce farklı bir imza şeması (ya da hiç imza) kullanan
# ikinci bir paket türü demek olurdu ve alıcı ikisini ayırt edemezdi.


def _kaynak_metni(yol: str) -> str:
    return (KOK / yol).read_text(encoding="utf-8")


def _cagri_adi(dugum: ast.Call) -> str:
    if isinstance(dugum.func, ast.Name):
        return dugum.func.id
    if isinstance(dugum.func, ast.Attribute):
        return dugum.func.attr
    return ""


#: Nokta ile ayrılmış geçerli bir Python modül yolu — `CORE.hclx` gibi.
_MODUL_YOLU = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$")


def _uzanti_gibi(deger: str) -> bool:
    """
    Bu dize `.hclx` UZANTISINI mı yazıyor, yoksa yalnızca içinde mi geçiyor.

    Gerekçe ÖLÇÜLDÜ: ilk yazımda `"CORE.hclx"` (main.py'deki MODÜL ADI)
    ihlal sayıldı — `".hclx" in deger` alt dize kontrolü onu yakalıyordu.
    Bu deponun tekrar tekrar ürettiği hata sınıfı; burada nokta ile
    ayrılmış geçerli bir modül yolu ELENEREK kapatılıyor.

    Yakalanması İSTENENLER: `".hclx"`, `"*.hclx"`,
    `"HYCLEUS Teslim (*.hclx)"` — hiçbiri geçerli bir modül yolu değil.
    """
    if ".hclx" not in deger:
        return False
    return not _MODUL_YOLU.match(deger)


def _docstring_dugumleri(agac: ast.AST) -> set[int]:
    """
    Docstring olan `Constant` düğümlerinin kimlikleri.

    Gerekçesi ÖLÇÜLDÜ: ilk yazımda tarayıcı `DB/migrations.py` ve
    `main.py`'nin docstring'lerini ihlal saydı — ikisi de v3.0 planında
    `.hclx`'ten SÖZ EDİYOR, üretmiyor. Bu deponun defalarca yaşadığı
    hata: kuralı ANLATAN metnin kuralın kendisine takılması (B-024).
    """
    bulunan: set[int] = set()
    for d in ast.walk(agac):
        if not isinstance(d, (ast.Module, ast.ClassDef, ast.FunctionDef,
                              ast.AsyncFunctionDef)):
            continue
        govde = d.body
        if (govde and isinstance(govde[0], ast.Expr)
                and isinstance(govde[0].value, ast.Constant)
                and isinstance(govde[0].value.value, str)):
            bulunan.add(id(govde[0].value))
    return bulunan


def _uygulama_dosyalari() -> list[Path]:
    return [
        yol for kok in ("CORE", "DB", "UI")
        for yol in sorted((KOK / kok).rglob("*.py"))
    ] + [KOK / "main.py"]


def test_MAGIC_yalnizca_hclx_modulunde() -> None:
    """
    En güçlü denetim: geçerli bir `.hclx` MAGIC yazmadan üretilemez. MAGIC
    tek modüldeyse üretim de tek modülde.
    """
    ihlal = []
    for yol in _uygulama_dosyalari():
        bagil = yol.relative_to(KOK).as_posix()
        if bagil == "CORE/hclx.py":
            continue
        for d in ast.walk(ast.parse(yol.read_text(encoding="utf-8"))):
            if isinstance(d, ast.Constant) and isinstance(d.value, bytes) \
                    and MAGIC[:5] in d.value:
                ihlal.append(f"{bagil}:{d.lineno}")
    assert not ihlal, (
        f"`.hclx` magic'i hclx dışında bir modülde yazılıyor: {ihlal}. "
        "Paket üretimi CORE/hclx.py::create_package üzerinden geçmeli."
    )


def test_uzanti_dizesi_tek_yerde() -> None:
    """
    `.hclx` uzantısını elle yazan bir modül, kendi paketleme yolunu
    kurmanın ilk adımı. Uzantı gereken yerler `hclx.UZANTI` kullanmalı.
    """
    ihlal = []
    for yol in _uygulama_dosyalari():
        bagil = yol.relative_to(KOK).as_posix()
        if bagil == "CORE/hclx.py":
            continue
        agac = ast.parse(yol.read_text(encoding="utf-8"))
        belge = _docstring_dugumleri(agac)
        for d in ast.walk(agac):
            if (isinstance(d, ast.Constant) and isinstance(d.value, str)
                    and _uzanti_gibi(d.value) and id(d) not in belge):
                ihlal.append(f"{bagil}:{d.lineno} → {d.value!r}")
    assert not ihlal, (
        f"`.hclx` uzantısı elle yazılmış: {ihlal}. Uzantı gereken yerler "
        "`hclx.UZANTI` kullanmalı."
    )


def test_imza_giris_noktasi_TEK() -> None:
    """
    `encrypt_file` modül içinde YALNIZCA `create_package` içinde ve
    YALNIZCA bir kez çağrılıyor. İkinci bir çağrı, ikinci bir imzalama
    yolu demek — ve ikisi zamanla ayrışır (B-012'nin sınıfı).
    """
    agac = ast.parse(_kaynak_metni("CORE/hclx.py"))
    yerler = []
    for fn in ast.walk(agac):
        if isinstance(fn, ast.FunctionDef):
            for d in ast.walk(fn):
                if isinstance(d, ast.Call) and _cagri_adi(d) == "encrypt_file":
                    yerler.append(fn.name)
    assert yerler == ["create_package"], (
        f"`encrypt_file` beklenmeyen yerlerde çağrılıyor: {yerler}"
    )


def test_denetim_eylemleri_yalnizca_hclx_modulunden() -> None:
    """
    İkinci bir yer `hclx_opened` yazabilseydi, hiç doğrulama yapmadan
    "açıldı" kaydı düşen bir yol olurdu ve denetim günlüğü yalan söylerdi.
    """
    ihlal = []
    for yol in _uygulama_dosyalari():
        bagil = yol.relative_to(KOK).as_posix()
        if bagil == "CORE/hclx.py":
            continue
        metin = yol.read_text(encoding="utf-8")
        for d in ast.walk(ast.parse(metin)):
            if isinstance(d, ast.Constant) and isinstance(d.value, str) \
                    and d.value in (EYLEM_URETILDI, EYLEM_ACILDI, EYLEM_REDDEDILDI):
                ihlal.append(f"{bagil}:{d.lineno} → {d.value}")
    assert not ihlal, f"hclx denetim eylemleri başka modülden yazılıyor: {ihlal}"


def test_denetimler_GERCEKTEN_bir_sey_buluyor() -> None:
    """
    Üç denetim de boş küme dönen bir tarayıcıyla sessizce geçebilirdi; bu
    depoda o sınıftan kaza yaşandı (B-024).
    """
    agac = ast.parse(_kaynak_metni("CORE/hclx.py"))
    sabitler = [d.value for d in ast.walk(agac) if isinstance(d, ast.Constant)]
    assert any(isinstance(v, bytes) and MAGIC[:5] in v for v in sabitler), \
        "MAGIC tarayıcısı kör — hclx.py'de bile bulamıyor"
    assert any(isinstance(v, str) and _uzanti_gibi(v) for v in sabitler), \
        "uzantı tarayıcısı kör"
    # Eleyici DOĞRU şeyi eliyor mu: modül yolu geçmeli, uzantı geçmemeli.
    assert not _uzanti_gibi("CORE.hclx"), "eleyici modül yolunu uzantı sanıyor"
    assert _uzanti_gibi("*.hclx") and _uzanti_gibi(".hclx"), "eleyici fazla eliyor"
    assert EYLEM_ACILDI in sabitler, "eylem tarayıcısı kör"
    assert any(_cagri_adi(d) == "encrypt_file"
               for d in ast.walk(agac) if isinstance(d, ast.Call)), \
        "imza tarayıcısı kör"


def test_hclx_UI_ve_DB_ye_bagli_degil() -> None:
    agac = ast.parse(_kaynak_metni("CORE/hclx.py"))
    moduller = {
        (d.module or "") for d in ast.walk(agac) if isinstance(d, ast.ImportFrom)
    } | {
        a.name for d in ast.walk(agac) if isinstance(d, ast.Import) for a in d.names
    }
    yasak = {m for m in moduller if m.startswith(("UI", "DB", "PySide6"))}
    assert not yasak, f"hclx yasak katmanlara bağlı: {yasak}"


def test_kendi_kripto_ilkelini_CAGIRMIYOR() -> None:
    """
    "Yeni imza şeması icat etme" kuralının sabitlemesi: bu modül AES/GCM
    ilkellerini kendisi kurmuyor, `CORE/crypto.py` üzerinden geçiyor.
    """
    agac = ast.parse(_kaynak_metni("CORE/hclx.py"))
    # İKİ biçim de taranıyor. Mutasyonla ölçüldü: yalnızca `from x import y`
    # bakan bir tarama, düz `import hmac` satırını GÖRMÜYORDU.
    moduller = {
        (d.module or "") for d in ast.walk(agac) if isinstance(d, ast.ImportFrom)
    } | {
        a.name for d in ast.walk(agac) if isinstance(d, ast.Import) for a in d.names
    }
    yasak = {m for m in moduller
             if m.split(".")[0] in ("cryptography", "hmac", "hashlib_shim")}
    assert not yasak, (
        f"hclx kendi kripto ilkelini kuruyor: {yasak}. İmza `CORE/crypto.py`'nin "
        "GCM tag'i olmalı — ikinci bir şema alıcıyı ikisini ayırt edemez hâle "
        "getirirdi."
    )


# ══════════════════════════════════════════════════════════════════════════════
# 6. Belgelenen karar ile kod aynı şeyi mi söylüyor
# ══════════════════════════════════════════════════════════════════════════════


def test_SILINMEZ_karari_docstringde_yazili() -> None:
    """
    Madde 4 açıkça "hangisini seçtiğini docstring'e yaz" diyor. Karar
    kodda uygulanıyor (yukarıdaki test) ama okunabilir de olmalı — aksi
    hâlde bir sonraki geliştirici tersini varsayar.
    """
    metin = _kaynak_metni("CORE/hclx.py")
    assert "AÇILMAZ, SİLİNMEZ" in metin
    for gerekce in ("uygulama seviyesi kontrol", "saati geri almak",
                    "disposal.py"):
        assert gerekce.lower() in metin.lower(), f"gerekçe eksik: {gerekce}"


def test_SECURITY_md_teslim_paketini_anlatiyor() -> None:
    """İki dilde de — `tests/test_belge_dil_paritesi.py` yapıyı denetliyor."""
    metin = (KOK / "SECURITY.md").read_text(encoding="utf-8")
    assert metin.count("### 4.14") == 2, "SECURITY.md §4.14 iki dilde olmalı"
    assert metin.count(".hclx") >= 2
