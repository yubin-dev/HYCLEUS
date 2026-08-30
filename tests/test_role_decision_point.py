"""
HYCLEUS — rol kararının TEK NOKTADA kalması (B-028 / B-033)

Tek kural: **`CORE/roles.py` dışında hiçbir yerde bir rol adıyla
karşılaştırma yapılmamalı.**

Neden bu dosya var
------------------
Rol karşılaştırması 19 yerde, üç farklı normalizasyonla yapılıyordu ve
üçü aynı girdide farklı cevaplar veriyordu:

    == "Yönetici"                        ×11   ASCII "Yonetici"e HAYIR der
    .strip().lower() == "..."             ×7   "YÖNETİCİ"ye HAYIR der (*)
    .strip().lower().replace("_", " ")    ×1

(*) Ölçüldü: `"YÖNETİCİ".lower()` on karakter üretiyor, sekiz değil —
`İ` (U+0130) küçük harfi `i` + U+0307 birleşen nokta.

Bunun erişilebilir sonucu, kasa kurtarma sonrası yöneticinin sessizce
yönetici olmayan gibi davranılmasıydı. Düzeltme hepsini `CORE/roles.py`
altında topladı; bu test o birleşmenin GERİ ALINAMAMASINI sağlıyor.

Neden AST, neden metin araması değil
------------------------------------
Bu depoda düz metin denetimi DÖRT KEZ yanlış yere takıldı — en sonuncusu
bu turda: `assert "upx=True" in metin`, `upx=False`'a çevrilmiş bir spec'te
bile geçiyordu çünkü dosyanın AÇIKLAMASI da "upx=True" yazıyordu
(bkz. B-024). Bir kuralı metinle denetlemek, kuralı ANLATAN metni de
eşleştirir — ve bu dosyalarda kuralı anlatan yorum bol.

AST yalnızca gerçek `Compare` düğümlerini görüyor; docstring'ler,
yorumlar ve kullanıcıya gösterilen mesajlar doğal olarak dışarıda kalıyor.
"""
from __future__ import annotations

import ast
import unicodedata
from pathlib import Path

import pytest

KOK = Path(__file__).resolve().parent.parent

#: Rol kararının verildiği kanonik modül.
#:
#: MUAF DEĞİL — ve bu bir tasarım kazanımı. İlk hâlde bu dosya denetimin
#: dışında bırakılmıştı ("kararı o veriyor, doğal olarak karşılaştırma
#: içerir" diye). Ölçünce yanlış çıktı: `roles.py` rol adı SABİTLERİYLE
#: karşılaştırmıyor, `ROL_YONETICI` gibi ADLANDIRILMIŞ sabitlerle
#: karşılaştırıyor — yani denetimden kendi başına temiz geçiyor.
#:
#: Dolayısıyla kuralın hiçbir istisnası yok. Bir istisna, "burada
#: kurala uyulmuyor ama sebebi var" demektir ve zamanla sebebi kimse
#: hatırlamaz.
KANONIK = KOK / "CORE" / "roles.py"

#: Denetlenen katmanlar.
KATMANLAR = ("CORE", "DB", "UI")

#: Rol adı sayılan diziler — katlanmış (normalize) biçimde.
#: `users.role` sütununun değerleri (`admin`/`user`) BURADA DEĞİL: onlar
#: veritabanı sabitleri ve `CORE/roles.py` üzerinden import ediliyor;
#: `DB_ADMIN` kullanan bir karşılaştırma zaten literal taşımıyor.
ROL_ADLARI = {"yonetici", "salt okunur", "standart"}


def _katla(s: str) -> str:
    """`CORE.roles._katla` ile aynı indirgeme — burada bilerek KOPYA.

    Denetimin, denetlediği koda bağlı olmaması gerekiyor: `roles.py`
    bozulursa bu test onu yakalamalı, aynı bozuk fonksiyonu kullanıp
    sessizce onaylamamalı.
    """
    s = s.strip().lower().replace("ı", "i").replace("İ", "i")
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    return " ".join(s.replace("_", " ").replace("-", " ").split())


def _rol_sabiti_mi(dugum: ast.AST) -> bool:
    return (
        isinstance(dugum, ast.Constant)
        and isinstance(dugum.value, str)
        and _katla(dugum.value) in ROL_ADLARI
    )


def _dosyalar() -> list[Path]:
    bulunan: list[Path] = []
    for katman in KATMANLAR:
        bulunan += sorted((KOK / katman).rglob("*.py"))
    bulunan.append(KOK / "main.py")
    return bulunan


def rol_karsilastirmalari(agac: ast.AST) -> list[tuple[int, str]]:
    """Bir ağaçtaki rol kararlarını `(satır, sebep)` olarak döndürür.

    ÜÇ şekil yakalanıyor:

    1. Bir rol adı sabitiyle `==` / `!=` / `in` karşılaştırması.
    2. `.lower()` / `.casefold()` sonucuyla yapılan karşılaştırma —
       sabit rol adı taşımasa bile. Buradaki niyet bir rolü normalize
       etmek; normalizasyon `CORE/roles.py`'nin işi.
    3. ANAHTARI rol adı olan sözlük sabiti. Bu üçüncüsü mutasyon
       testinden geldi: ilk hâl yalnızca `Compare` arıyordu ve
       `{"Yönetici": "admin"}.get(role, "user")` mutasyonu HAYATTA
       KALDI — oysa B-030'un düzeltilen şekli tam olarak buydu. Bir
       arama tablosu da bir karardır.

    Yalnızca ANAHTARLARA bakılıyor, değerlere değil: kanonik değerden
    görünen ada çeviren sözlükler (`{"admin": "Yönetici"}`) karar
    vermiyor, biçimlendirme yapıyor.
    """
    bulgular: list[tuple[int, str]] = []
    for dugum in ast.walk(agac):
        if isinstance(dugum, ast.Dict):
            for anahtar in dugum.keys:
                if anahtar is not None and _rol_sabiti_mi(anahtar):
                    bulgular.append((
                        dugum.lineno,
                        f"anahtarı rol adı olan sözlük ({anahtar.value!r}) — "
                        f"arama tablosu da karardır",
                    ))
            continue
        if not isinstance(dugum, ast.Compare):
            continue
        parcalar = [dugum.left, *dugum.comparators]

        for parca in parcalar:
            adaylar = [parca]
            if isinstance(parca, (ast.Tuple, ast.List, ast.Set)):
                adaylar = list(parca.elts)
            for aday in adaylar:
                if _rol_sabiti_mi(aday):
                    bulgular.append(
                        (dugum.lineno, f"rol adı sabiti {aday.value!r} ile karşılaştırma")
                    )

        for parca in parcalar:
            if (
                isinstance(parca, ast.Call)
                and isinstance(parca.func, ast.Attribute)
                and parca.func.attr in ("lower", "casefold")
                and "role" in ast.dump(parca).lower()
            ):
                bulgular.append(
                    (dugum.lineno, f".{parca.func.attr}() ile rol normalizasyonu")
                )
    return bulgular


# ── Denetimin BOŞ KÜMEYİ dolaşmadığı ──────────────────────────────────────────

def test_denetim_gercekten_dosya_geziyor():
    """
    Dosyalar taşınırsa `_dosyalar()` boş dönebilir ve aşağıdaki test hiçbir
    şey sınamadan yeşil kalırdı — sessizce kaybolan bir koruma, hiç olmayan
    korumadan kötüdür.
    """
    yollar = _dosyalar()
    assert len(yollar) >= 40
    adlar = {p.name for p in yollar}
    assert {"main_window.py", "UsbTokensView.py", "session_user.py"} <= adlar
    # Kanonik modül de taranıyor — kuralın istisnası yok.
    assert KANONIK.resolve() in {p.resolve() for p in yollar}


def test_kanonik_modul_gercekten_var():
    assert KANONIK.is_file(), "CORE/roles.py yok — kural dayanaksız kalır"


# ── ASIL KURAL ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("yol", _dosyalar(), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_rol_karsilastirmasi_yalnizca_rolespy_de(yol: Path):
    """
    KURALIN DENETİMİ: rol kararı `CORE/roles.py` dışında verilemez.

    Yeni bir yerde rol karşılaştırmak gerekirse yapılacak şey tek satır:
    `from CORE.roles import is_admin_role` (ya da `is_readonly_role`,
    `can_write`, `normalize_role`).
    """
    agac = ast.parse(yol.read_text(encoding="utf-8"))
    bulgular = rol_karsilastirmalari(agac)
    assert not bulgular, (
        f"{yol.relative_to(KOK)} rol kararını kendisi veriyor (B-028):\n  "
        + "\n  ".join(f"satır {ln}: {sebep}" for ln, sebep in bulgular)
        + "\n\nCORE/roles.py'deki is_admin_role() / is_readonly_role() / "
          "can_write() kullanın."
    )


# ── Denetimin GERÇEKTEN yakaladığı ────────────────────────────────────────────

@pytest.mark.parametrize("ihlal", [
    'if role == "Yönetici":\n    pass',
    'if role != "Yönetici":\n    pass',
    'if self._role == "Yonetici":\n    pass',          # ASCII yazım
    'if self._role == "YÖNETİCİ":\n    pass',          # Türkçe büyük harf
    'if r.strip().lower() == "salt okunur":\n    pass',
    'if role in ("yönetici", "yonetici", "admin"):\n    pass',
    'x = "admin" if role == "Yönetici" else "user"',
    'if role.lower() == kanonik:\n    pass',           # sabitsiz normalizasyon
])
def test_denetim_ihlali_yakaliyor(ihlal: str):
    """
    Kuralın YAŞADIĞINI göster. Liste, düzeltilen 19 çağrı yerinin gerçek
    şekillerinden türetildi — uydurma değil.
    """
    assert rol_karsilastirmalari(ast.parse(ihlal)), f"yakalanmadı: {ihlal!r}"


@pytest.mark.parametrize("temiz", [
    'if is_admin_role(role):\n    pass',
    'if not is_readonly_role(self._role):\n    pass',
    'db_role = rol_db(role)',
    'if row["role"] == DB_ADMIN:\n    pass',            # sabit, literal değil
    'if verdict == "clean":\n    pass',                 # rol değil
    'if label == "Karantina":\n    pass',               # rol değil
    '_ROLE_BADGE = {ROL_YONETICI: ("#fff", "#000")}',   # anahtar ADLANDIRILMIŞ sabit
    'role_map = {"admin": "Yönetici", "user": "Kullanıcı"}',  # kanonikten görünen ada
    'x = "Yönetici rolü değiştirilemez."',              # kullanıcı mesajı
])
def test_denetim_temiz_kodu_isaretlemiyor(temiz: str):
    """
    Yanlış pozitif yok. Özellikle son iki satır önemli: kullanıcıya
    gösterilen mesajlar ve sözlük anahtarları rol adı İÇERİYOR ama karar
    VERMİYOR.
    """
    assert not rol_karsilastirmalari(ast.parse(temiz)), f"yanlış pozitif: {temiz!r}"


def test_yorum_ve_docstringler_denetimi_tetiklemiyor():
    """
    B-024'te düz metin denetimi tam olarak buradan kırılmıştı: kuralı
    ANLATAN yorum, kuralın ihlali sanılmıştı.
    """
    kaynak = (
        '"""Eskiden burada `role == "Yönetici"` vardı (B-028)."""\n'
        '# if role == "Yönetici": kaldırıldı\n'
        'if is_admin_role(role):\n'
        '    pass\n'
    )
    assert not rol_karsilastirmalari(ast.parse(kaynak))


# ── Kanonik modülün kendisi ───────────────────────────────────────────────────

def test_kanonik_modul_de_kurala_UYUYOR():
    """
    `CORE/roles.py` denetimden MUAF DEĞİL ve muafiyete ihtiyacı da yok.

    Kararı o veriyor ama rol adı SABİTLERİYLE değil, `ROL_YONETICI` gibi
    adlandırılmış sabitlerle karşılaştırıyor. Yani kural istisnasız
    uygulanabiliyor — bir denetimin istisnası ne kadar azsa, sonradan
    kimsenin hatırlamadığı bir boşluk bırakma ihtimali o kadar düşük.
    """
    agac = ast.parse(KANONIK.read_text(encoding="utf-8"))
    assert not rol_karsilastirmalari(agac)


def test_kanonik_modul_kararı_gercekten_veriyor():
    """
    Yukarıdaki testin ters okunmasını engeller: `roles.py` denetimden
    temiz geçiyor diye BOŞ olduğu sanılmasın. Karar fonksiyonları var ve
    adlandırılmış sabitlerle karşılaştırıyorlar.
    """
    agac = ast.parse(KANONIK.read_text(encoding="utf-8"))
    fonksiyonlar = {d.name for d in ast.walk(agac) if isinstance(d, ast.FunctionDef)}
    assert {"normalize_role", "is_admin_role", "is_readonly_role", "db_role"} <= fonksiyonlar

    sabitle_karsilastirma = [
        d for d in ast.walk(agac)
        if isinstance(d, ast.Compare)
        and any(isinstance(k, ast.Name) and k.id.startswith("ROL_")
                for k in [d.left, *d.comparators])
    ]
    assert sabitle_karsilastirma, "roles.py rol sabitleriyle karşılaştırma yapmıyor"
