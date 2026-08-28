"""
`CORE/hclx.py` ve `CORE/merkle.py`'nin YAZMA tarafı — üretime BAĞLI DEĞİL.

Neden bu dosya var
------------------
İkisi de test edilmiş, çalışan kod, ama ikisi de üretim akışından hiçbir
yerden ÇAĞRILMIYOR — `BACKLOG.md` B-035 (`timestamp_file`/`timestamp_batch`,
2026-08-20) ve B-043 (`.hclx` — `create_package`/`open_package`,
2026-08-21) bunu bulduğunda tek seferlik bir `grep` ile ölçtü. Bir kod
tabanı büyüdükçe böyle bir bulgu SESSİZCE eskiyebilir iki yönde de:

  - Biri bu fonksiyonları bir menüye/CLI'a bağlar ama SECURITY.md/BACKLOG'u
    güncellemeyi unutur — belge artık YANLIŞ ("bağlı değil" derken aslında
    bağlı).
  - Biri "zaten kullanılmıyor" diye yanlışlıkla SİLER ya da bozar — modül
    dosyaları başlarındaki DENEYSEL/BAĞLI-DEĞİL notu artık konu dışı olur.

Bu test B-035/B-043'ün tek seferlik ölçümünü KALICI hale getiriyor: aynı
iddiayı her koşuda AST ile yeniden doğruluyor. Biri bu fonksiyonları
gerçekten bir üretim dosyasından çağırırsa (menü, CLI, zamanlanmış iş),
bu test KIRILIR — sessiz drift yerine, belgeleri (SECURITY.md §4.9/§4.14,
BACKLOG B-035/B-043, README proje ağacı, ve modüllerin kendi DENEYSEL
başlıkları) bilinçli olarak güncellemeye zorlar.

Yöntem
------
`ast` ile CORE/, UI/, DB/ ve main.py altındaki HER üretim dosyası
taranıyor (tests/ ve docs/ hariç), hedef fonksiyon adına yapılan her
`Call` düğümü toplanıyor — hem `create_package(...)` hem
`hclx.create_package(...)` biçimleri (isim ya da attribute). Fonksiyonu
TANIMLAYAN dosyanın kendisi hariç tutuluyor (`def` satırı bir çağrı
değil, ama modül içi yardımcı çağrılar da varsa onlar sayılmamalı diye
yine de dışlanıyor — bu iki modülde öyle bir iç çağrı zaten yok, ölçüldü).
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

KOK = Path(__file__).resolve().parent.parent

#: Üretim yüzeyi — burada taranan HER dosya "gerçekten çalışan uygulama"
#: sayılıyor. tests/, docs/, packaging/ kasıtlı olarak dışında: onlarda
#: geçen bir çağrı "üretimde kullanılıyor" anlamına gelmez.
_URETIM_KOKLERI: tuple[Path, ...] = (
    KOK / "CORE",
    KOK / "UI",
    KOK / "DB",
)
_URETIM_TEK_DOSYALAR: tuple[Path, ...] = (KOK / "main.py",)


def _uretim_dosyalari(haric: Path) -> list[Path]:
    dosyalar = [
        p
        for kok in _URETIM_KOKLERI
        for p in kok.rglob("*.py")
    ]
    dosyalar.extend(_URETIM_TEK_DOSYALAR)
    return [p for p in dosyalar if p.resolve() != haric.resolve()]


def _cagri_isimlerini_topla(dosya: Path) -> set[str]:
    """Bu dosyadaki her `Call` düğümünün çağırdığı adın (ör. `create_package`
    ya da `x.create_package`) son bileşenini döndürür."""
    kaynak = dosya.read_text(encoding="utf-8")
    agac = ast.parse(kaynak, filename=str(dosya))
    isimler: set[str] = set()
    for dugum in ast.walk(agac):
        if not isinstance(dugum, ast.Call):
            continue
        hedef = dugum.func
        if isinstance(hedef, ast.Name):
            isimler.add(hedef.id)
        elif isinstance(hedef, ast.Attribute):
            isimler.add(hedef.attr)
    return isimler


def _uretimde_cagrilan_mi(fonksiyon_adi: str, *, tanimlayan_dosya: Path) -> tuple[bool, list[str]]:
    """(çağrıldı mı, çağıran dosyaların listesi)."""
    caganlar: list[str] = []
    for dosya in _uretim_dosyalari(haric=tanimlayan_dosya):
        if fonksiyon_adi in _cagri_isimlerini_topla(dosya):
            caganlar.append(str(dosya.relative_to(KOK)))
    return (len(caganlar) > 0, caganlar)


def _testlerde_gercekten_cagriliyor_mu(fonksiyon_adi: str) -> bool:
    """Denetimin KENDİSİ çalışıyor mu: fonksiyon adı bir yazım hatasıysa
    (ör. yeniden adlandırıldıysa) bu test hem üretimde hem testte SIFIR
    eşleşme bulur ve "bağlı değil" YANLIŞLIKLA hep doğru çıkar. Testlerde
    en az bir GERÇEK çağrı bulunması, adın hâlâ doğru olduğunu kanıtlıyor."""
    for dosya in (KOK / "tests").rglob("*.py"):
        if fonksiyon_adi in _cagri_isimlerini_topla(dosya):
            return True
    return False


# ══════════════════════════════════════════════════════════════════════════════
# 0. Denetimin KENDİSİ çalışıyor mu
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize(
    "fonksiyon_adi",
    ["create_package", "open_package", "timestamp_file", "timestamp_batch"],
)
def test_hedef_fonksiyonlar_testlerde_GERCEKTEN_cagriliyor(fonksiyon_adi: str) -> None:
    """Bu, "bağlı değil" bulgusunun bir yazım hatasından kaynaklanmadığını
    kanıtlıyor — fonksiyon adı testlerde en az bir kez gerçekten geçiyor."""
    assert _testlerde_gercekten_cagriliyor_mu(fonksiyon_adi), (
        f"'{fonksiyon_adi}' testlerde hiç çağrılmıyor — bu testin ismi ya da "
        "hedef fonksiyonun kendisi değişmiş olabilir, alttaki 'bağlı değil' "
        "iddiaları artık bir şey ÖLÇMÜYOR olabilir"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 1. `.hclx` — B-043: create_package()/open_package() üretimde çağrılmıyor
# ══════════════════════════════════════════════════════════════════════════════


def test_hclx_create_package_uretimde_HICBIR_YERDEN_cagrilmiyor() -> None:
    """BACKLOG B-043 madde 1'in kalıcı hâli. Kırılırsa: `.hclx` gönderme
    akışı bir yere bağlanmış demektir — SECURITY.md §4.14, BACKLOG B-043,
    README proje ağacı VE `CORE/hclx.py`'nin DENEYSEL başlığı bilinçli
    olarak güncellenmeli, bu testin kendisi de o zaman güncellenmeli."""
    cagriliyor, caganlar = _uretimde_cagrilan_mi(
        "create_package", tanimlayan_dosya=KOK / "CORE" / "hclx.py"
    )
    assert not cagriliyor, (
        "create_package() artık üretimde çağrılıyor "
        f"({', '.join(caganlar)}) — BACKLOG B-043, SECURITY.md §4.14, "
        "README ve CORE/hclx.py'nin DENEYSEL notu artık YANLIŞ; hepsini "
        "güncelle, sonra bu testi kaldır ya da gevşet"
    )


def test_hclx_open_package_uretimde_HICBIR_YERDEN_cagrilmiyor() -> None:
    """Aynı gerekçe, paketin AÇILMA tarafı için."""
    cagriliyor, caganlar = _uretimde_cagrilan_mi(
        "open_package", tanimlayan_dosya=KOK / "CORE" / "hclx.py"
    )
    assert not cagriliyor, (
        "open_package() artık üretimde çağrılıyor "
        f"({', '.join(caganlar)}) — BACKLOG B-043, SECURITY.md §4.14, "
        "README ve CORE/hclx.py'nin DENEYSEL notu artık YANLIŞ; hepsini "
        "güncelle, sonra bu testi kaldır ya da gevşet"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 2. Merkle — B-035: timestamp_file()/timestamp_batch() üretimde çağrılmıyor
# ══════════════════════════════════════════════════════════════════════════════
#
# `CORE/merkle.py`'nin kendisi (build_leaves/build_tree/verify_proof) hiçbir
# üretim dosyasından DOĞRUDAN çağrılmıyor — üretimdeki TEK gerçek çağıran
# `CORE/timestamp_verify.py::verify_merkle_path()` (merkle.verify_proof'u
# sarmalıyor) ve o GERÇEKTEN üretime bağlı (bkz. test_verify_merkle_path_...
# aşağıda). Ama bu fonksiyonun hiçbir zaman gerçek bir ağacı GÖRMEMESİNİN
# nedeni burada ölçülüyor: bir Merkle-damgalı (v2) fragman üretebilecek TEK
# fonksiyonlar (`timestamp_file`, `timestamp_batch` — ikisi de
# `CORE/merkle.py::build_leaves/build_tree`'yi çağırıyor) üretimde hiç
# çağrılmıyor. Yani ağaç KURULMUYOR, dolayısıyla doğrulanacak gerçek bir
# ağaç da hiç yok.


def test_timestamp_file_uretimde_HICBIR_YERDEN_cagrilmiyor() -> None:
    """BACKLOG B-035'in kalıcı hâli — tekil (v1) damgalama tarafı."""
    cagriliyor, caganlar = _uretimde_cagrilan_mi(
        "timestamp_file", tanimlayan_dosya=KOK / "CORE" / "timestamp.py"
    )
    assert not cagriliyor, (
        "timestamp_file() artık üretimde çağrılıyor "
        f"({', '.join(caganlar)}) — BACKLOG B-035 ve SECURITY.md §4.9 "
        "artık YANLIŞ; hepsini güncelle, sonra bu testi kaldır ya da gevşet"
    )


def test_timestamp_batch_uretimde_HICBIR_YERDEN_cagrilmiyor() -> None:
    """
    BACKLOG B-035'in kalıcı hâli — toplu (v2/Merkle) damgalama tarafı.
    Bu, `CORE/merkle.py::build_leaves`/`build_tree`'ye giden TEK üretim
    yolu; kırılırsa merkle.py'nin YAZMA tarafı artık gerçekten üretime
    bağlanmış demektir — `CORE/merkle.py`'nin DENEYSEL notu da güncellenmeli.
    """
    cagriliyor, caganlar = _uretimde_cagrilan_mi(
        "timestamp_batch", tanimlayan_dosya=KOK / "CORE" / "timestamp.py"
    )
    assert not cagriliyor, (
        "timestamp_batch() artık üretimde çağrılıyor "
        f"({', '.join(caganlar)}) — BACKLOG B-035, SECURITY.md §4.9 ve "
        "CORE/merkle.py'nin DENEYSEL notu artık YANLIŞ; hepsini güncelle, "
        "sonra bu testi kaldır ya da gevşet"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 3. Karşı-kanıt: merkle.py TAMAMEN kör değil — verify_merkle_path GERÇEKTEN bağlı
# ══════════════════════════════════════════════════════════════════════════════


def test_verify_merkle_path_uretimde_GERCEKTEN_cagriliyor() -> None:
    """
    merkle.py'yi hclx.py ile AYNI kefeye koymamak için: doğrulama tarafı
    GERÇEKTEN üretime bağlı — iki sıçramalı gerçek zincir, ikisi de burada
    ayrı ayrı doğrulanıyor:

        UI/main_window_files.py  --çağırır-->  CORE.timestamp_verify.verify_timestamp()
        CORE/timestamp_verify.py --çağırır-->  CORE.timestamp.verify_merkle_path()
                                                (merkle.verify_proof/leaf_hash'i sarmalıyor)

    Yani asıl tabloda merkle.py "hiç bağlı değil" değil, "doğrulama tarafı
    bağlı ama hiçbir zaman gerçek bir ağaç görmüyor, çünkü onu üretecek yol
    (timestamp_batch, yukarıda) yok" — SECURITY.md §4.9'un yazdığı ayrım tam
    olarak bu.
    """
    dogrulama_cagriliyor, dogrulama_caganlar = _uretimde_cagrilan_mi(
        "verify_merkle_path", tanimlayan_dosya=KOK / "CORE" / "timestamp.py"
    )
    assert dogrulama_cagriliyor, (
        "verify_merkle_path() artık hiçbir üretim dosyasından çağrılmıyor — "
        "SECURITY.md §4.9'daki 'doğrulama tarafı bağlı' iddiası artık "
        "YANLIŞ olabilir, güncellenmeli"
    )
    assert any("timestamp_verify.py" in c for c in dogrulama_caganlar), (
        f"verify_merkle_path() çağrılıyor ama beklenen sarmalayıcıdan değil "
        f"({dogrulama_caganlar}) — bu testin açıklamasını güncelle"
    )

    giris_cagriliyor, giris_caganlar = _uretimde_cagrilan_mi(
        "verify_timestamp", tanimlayan_dosya=KOK / "CORE" / "timestamp_verify.py"
    )
    assert giris_cagriliyor and any(
        "main_window_files.py" in c for c in giris_caganlar
    ), (
        f"verify_timestamp() artık UI/main_window_files.py'den çağrılmıyor "
        f"({giris_caganlar}) — 'Damgayı Doğrula' bağlantısı taşınmış ya da "
        "kaldırılmış olabilir, zincirin ikinci sıçraması artık kanıtsız"
    )
