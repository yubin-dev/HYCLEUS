"""
Kullanıcı rehberi — ÜÇ KOPYA, TEK KAYNAK.

Neden bu dosya var
------------------
Rehbere üç yerden ulaşılıyor: web/PDF (asıl kopya), uygulamanın hamburger
menüsü, ve `.hclx` teslim paketine gömülen kopya. Üç kopya elle tutulsaydı
ayrışırlardı ve ayrışma SESSİZ olurdu — hiçbir linter iki dosyanın farklı
şey söylediğini fark etmez.

B-017 tam olarak bu sınıftandı (sürüm dizesi beş yerde, beşi farklı) ve
6.3 turu aynı mantığı kod↔belge eksenine taşımıştı. Burada eksen üçüncü
kez genişliyor: BELGE ↔ BELGE'nin türevleri.

Denetlenen zincir:

    kullanici-rehberi.md ──SHA-256──▶ PDF'in /Subject alanına gömülü özet
    kullanici-rehberi.pdf ──BAYT BAYT──▶ .hclx içindeki kopya

Üçünden biri güncellenip diğerleri unutulursa bu paket düşüyor —
mutasyonla doğrulandı.

Bu dosya Qt'ye DOKUNMUYOR (menü davranışı `test_rehber_menu.py`'de):
senkron denetiminin, Qt yüklenemeyen bir runner'da da koşması gerekiyor.
"""
from __future__ import annotations

import ast
import hashlib
import os
import re
from pathlib import Path

import pytest

from CORE import hclx, rehber
from CORE.crypto import generate_key

KOK = Path(__file__).resolve().parent.parent

#: Rehberin PDF'ini üretmesine izin verilen TEK dosya.
_URETICI = KOK / "CORE" / "rehber.py"

#: PDF üreten ama rehberle ilgisi olmayan modül — KVKK envanter raporu.
#: Denetim onu rehber üreticisi sanmamalı.
_MUAF = {"inventory.py"}


# ══════════════════════════════════════════════════════════════════════════════
# 1. Kaynak → PDF: gömülü özet sözleşmesi
# ══════════════════════════════════════════════════════════════════════════════


def test_kaynak_ve_pdf_ikisi_de_var():
    """Boş bir depoda aşağıdaki testler sessizce geçmesin."""
    assert rehber.KAYNAK.is_file(), f"Rehber kaynağı yok: {rehber.KAYNAK}"
    assert rehber.PDF.is_file(), (
        f"Rehber PDF'i yok: {rehber.PDF}\n"
        "Üretmek için: python CORE/rehber.py --uret")


def test_PDF_kaynakla_GUNCEL():
    """
    Rehberin ANA senkron testi.

    PDF, hangi Markdown'dan üretildiğini kendi `/Subject` alanında
    taşıyor. Markdown değişip PDF yeniden üretilmezse özetler ayrışıyor.
    """
    kaynak = rehber.kaynak_ozeti()
    gomulu = rehber.pdf_kaynak_ozeti()
    assert gomulu is not None, (
        "PDF'te kaynak özeti yok — bu dosya CORE/rehber.py ile üretilmemiş.")
    assert gomulu == kaynak, (
        "docs/kullanici-rehberi.pdf, docs/kullanici-rehberi.md ile AYRIŞMIŞ.\n"
        f"  kaynak : {kaynak}\n"
        f"  pdf    : {gomulu}\n"
        "Çözüm: python CORE/rehber.py --uret")


def test_guncel_mi_AYRISMAYI_goruyor(tmp_path: Path):
    """`guncel_mi()` gerçekten karşılaştırıyor mu — sahte kaynakla ölçülüyor."""
    baska = tmp_path / "baska.md"
    baska.write_text("# Bambaska bir belge\n", encoding="utf-8")
    assert rehber.guncel_mi() is True
    assert rehber.guncel_mi(kaynak=baska) is False


def test_PDF_bayt_bayt_yeniden_uretilebiliyor(tmp_path: Path):
    """
    Depodaki PDF, kaynaktan yeniden üretilenle BAYT EŞ mi.

    Gömülü özet tek başına yetmez: birisi PDF'in gövdesini düzenleyip
    `/Subject` alanına dokunmasaydı üstteki test geçerdi. Bu test gövdeyi
    de kapsıyor.

    Yalnızca AYNI reportlab sürümünde anlamlı — `invariant=1` belge
    kimliğini ve tarihi sabitliyor ama sürüm yükseldiğinde çıktı
    değişebilir. Sürüm farklıysa test ATLANIYOR ve neden atlandığını
    söylüyor; sessizce geçmiyor (B-023 tarzı "ölçülmedi" notu).
    """
    import reportlab

    uretilen_surum = rehber.pdf_uretici_surumu()
    if uretilen_surum != reportlab.Version:
        pytest.skip(
            f"PDF reportlab {uretilen_surum} ile üretilmiş, kurulu sürüm "
            f"{reportlab.Version} — bayt karşılaştırması ÖLÇÜLMEDİ. "
            "Gömülü özet denetimi (test_PDF_kaynakla_GUNCEL) hâlâ geçerli.")

    yeniden = rehber.pdf_uret(tmp_path / "yeniden.pdf")
    assert yeniden.read_bytes() == rehber.PDF.read_bytes(), (
        "Depodaki PDF, kaynaktan üretilenle bayt eş değil — elle "
        "düzenlenmiş olabilir. Çözüm: python CORE/rehber.py --uret")


def test_uretim_DETERMINIST(tmp_path: Path):
    """
    Aynı girdi iki kez → aynı baytlar.

    Bu olmadan üstteki bayt karşılaştırması her koşuda düşerdi ve
    "değişti mi" sorusu hiç yanıtlanamazdı.
    """
    a = rehber.pdf_uret(tmp_path / "a.pdf").read_bytes()
    b = rehber.pdf_uret(tmp_path / "b.pdf").read_bytes()
    assert hashlib.sha256(a).hexdigest() == hashlib.sha256(b).hexdigest()


# ── Satır sonu: iki platform, tek özet ──────────────────────────────────────
#
# CI 71 ve 72'de dört test ubuntu'da düştü, Windows'ta hepsi yeşildi.
# Ölçülen sebep:
#
#     Windows çalışma ağacı : 14210 bayt, 368 CRLF, 13be125c...
#     git blob (= Linux)    : 13842 bayt,   0 CRLF, 552117f7...
#
# `text=auto` deponun içinde LF tutuyor ama Windows'a CRLF veriyor
# (`.gitattributes` bu tuzağı kabuk betikleri için zaten anlatıyordu).
# Özet ham baytları imzaladığı için iki ortam hiçbir zaman anlaşamazdı.


def test_ozet_SATIR_SONUNDAN_bagimsiz(tmp_path: Path):
    """Aynı belge, üç farklı satır sonu → aynı özet."""
    govde = "# Başlık\n\nBir satır.\nİkinci satır.\n"
    ozetler = set()
    for ad, ham in (("lf", govde.encode()),
                    ("crlf", govde.replace("\n", "\r\n").encode()),
                    ("cr", govde.replace("\n", "\r").encode())):
        yol = tmp_path / f"{ad}.md"
        yol.write_bytes(ham)
        ozetler.add(rehber.kaynak_ozeti(yol))
    assert len(ozetler) == 1, "satır sonu özeti değiştiriyor — CI 71/72 tekrarı"


def test_ozet_GERCEK_degisikligi_HALA_goruyor(tmp_path: Path):
    """
    Normalleştirme bir GEVŞETME değil.

    Tek harf, tek boşluk ya da tek satır eklense özet yine değişiyor;
    yalnızca "aynı belge, farklı satır sonu" durumu ayrışma sayılmıyor.
    """
    temel = tmp_path / "t.md"
    temel.write_bytes(b"# Baslik\n\nGovde.\n")
    ilk = rehber.kaynak_ozeti(temel)
    for degisiklik in (b"# Baslik\n\nGovde!\n",      # tek karakter
                       b"# Baslik\n\nGovde. \n",     # sondaki boşluk
                       b"# Baslik\n\n\nGovde.\n",    # fazladan satır
                       b"# Baslik\n\nGovde.",        # eksik son satır sonu
                       ):
        temel.write_bytes(degisiklik)
        assert rehber.kaynak_ozeti(temel) != ilk, f"değişiklik gizlendi: {degisiklik!r}"


def test_CRLF_ve_LF_kaynaktan_AYNI_PDF(tmp_path: Path):
    """
    İki satır sonundan üretilen PDF'ler BAYT EŞ olmalı.

    `akis()` metni zaten normalleştiriyordu; tek fark gömülü özetti. Yani
    özet, PDF'in taşımadığı bir özelliği belgeliyordu — bu test o
    tutarsızlığın geri gelmesini engelliyor.
    """
    ham = rehber.KAYNAK.read_bytes().replace(b"\r\n", b"\n")
    (tmp_path / "lf.md").write_bytes(ham)
    (tmp_path / "crlf.md").write_bytes(ham.replace(b"\n", b"\r\n"))
    a = rehber.pdf_uret(tmp_path / "a.pdf", tmp_path / "lf.md").read_bytes()
    b = rehber.pdf_uret(tmp_path / "b.pdf", tmp_path / "crlf.md").read_bytes()
    assert a == b, "satır sonu PDF baytlarını değiştiriyor"


def test_KAYNAK_dosyasi_calisma_agacinda_LF():
    """
    Ortam tarafı da sabitleniyor: `.gitattributes` bu dosyaya `eol=lf`
    veriyor, yani Windows'ta da LF açılıyor.

    Normalleştirme tek başına yeterdi; bu satır ikinci katman. İkisi ayrı
    şeyi koruyor: normalleştirme dosyayı depo dışında düzenleyen araçları,
    `eol=lf` çalışma ağacının kendisini.
    """
    ham = rehber.KAYNAK.read_bytes()
    assert b"\r\n" not in ham, (
        "docs/kullanici-rehberi.md çalışma ağacında CRLF taşıyor — "
        ".gitattributes kuralı uygulanmamış. Çözüm: git add --renormalize .")


def test_gitattributes_kurali_YERINDE():
    """Kural silinirse yukarıdaki test bir sonraki temiz klonda düşerdi."""
    metin = (KOK / ".gitattributes").read_text(encoding="utf-8")
    assert "docs/kullanici-rehberi.md" in metin
    assert "eol=lf" in metin.split("docs/kullanici-rehberi.md")[1].split("\n")[0]
    assert "*.pdf" in metin and "binary" in metin


def test_uretim_ozeti_TEK_yerden():
    """
    `pdf_uret()` özeti kendisi HESAPLAMAMALI.

    İlk yazımda satır içi bir `sha256(read_bytes())` vardı: doğrulayan
    taraf normalleştirip üreten taraf normalleştirmeseydi sorun çözülmez,
    yalnızca yer değiştirirdi.
    """
    agac = ast.parse((KOK / "CORE" / "rehber.py").read_text(encoding="utf-8"))
    govde = next(d for d in ast.walk(agac)
                 if isinstance(d, ast.FunctionDef) and d.name == "pdf_uret")
    adlar = {getattr(d.func, "attr", getattr(d.func, "id", ""))
             for d in ast.walk(govde) if isinstance(d, ast.Call)}
    assert "sha256" not in adlar, "pdf_uret özeti kendisi hesaplıyor"
    assert "kaynak_ozeti" in adlar, "pdf_uret özeti ortak fonksiyondan almıyor"


def test_pdf_kaynak_ozeti_YABANCI_dosyada_None(tmp_path: Path):
    """Başka bir yerden gelen PDF "güncel" sayılmamalı."""
    sahte = tmp_path / "sahte.pdf"
    sahte.write_bytes(b"%PDF-1.4\n/Subject (bambaska)\n")
    assert rehber.pdf_kaynak_ozeti(sahte) is None
    assert rehber.guncel_mi(pdf=sahte) is False
    assert rehber.pdf_kaynak_ozeti(tmp_path / "hicyok.pdf") is None


# ══════════════════════════════════════════════════════════════════════════════
# 2. Yazı tipi kapsaması — boş kutu çıkmasın
# ══════════════════════════════════════════════════════════════════════════════


def _vera_karakterleri() -> set[int]:
    import reportlab
    from reportlab.pdfbase.ttfonts import TTFont

    yol = Path(reportlab.__file__).parent / "fonts" / "Vera.ttf"
    return set(TTFont("VeraDenetim", str(yol)).face.charToGlyph)


def test_simge_tablosu_EKSIKSIZ():
    """
    Rehberdeki HER karakter, çeviriden sonra yazı tipinde olmalı.

    Yoksa PDF'te sessizce boş kutu çıkar — okuyucu bir şeyin eksik
    olduğunu bile anlamaz. Rehbere yeni bir emoji girerse bu test düşüyor
    ve `CORE/rehber.py::_SIMGE` tablosuna karşılık eklenmesi gerekiyor.
    """
    kapsam = _vera_karakterleri()
    metin = rehber.simgeleri_cevir(rehber.KAYNAK.read_text(encoding="utf-8"))
    eksik = sorted({c for c in metin if ord(c) not in kapsam and c not in "\n\r\t"})
    assert not eksik, (
        "Rehberde yazı tipinin tanımadığı karakter(ler) var — PDF'te boş "
        f"kutu çıkar: {[f'U+{ord(c):04X} {c!r}' for c in eksik]}\n"
        "Çözüm: CORE/rehber.py::_SIMGE tablosuna ASCII karşılık ekleyin.")


def test_simge_denetimi_YENI_emojiyi_yakaliyor(tmp_path: Path):
    """Denetimin kendisi çalışıyor mu — tabloda olmayan bir simge uyduruluyor."""
    kapsam = _vera_karakterleri()
    yabanci = "\U0001f680"          # 🚀 — tabloda yok
    assert ord(yabanci) not in kapsam, "seçilen simge yazı tipinde VAR, test anlamsız"
    cevrilmis = rehber.simgeleri_cevir(f"Metin {yabanci} devam")
    assert yabanci in cevrilmis, "tablo bu simgeyi çeviriyor — test eskimiş"


def test_stiller_TAMAMEN_Vera():
    """
    Her stil — madde imleri DÂHİL — Vera kullanmalı.

    reportlab'ın varsayılan `bulletFontName`'i Helvetica ve o yüz Türkçe
    taşımıyor. Madde imi "•" ile rakamlar Helvetica'da VAR, yani hata
    görünmez olurdu: numaralı bir maddeye Türkçe karakter girdiği gün
    sessizce boş kutu çıkardı.

    Çıktıdaki `/BaseFont /Helvetica` girdisi bundan DEĞİL: ölçüldü,
    yalnızca Vera kullanan en küçük belgede bile var (reportlab tuvalin
    başlangıç yazı tipini koşulsuz yazıyor) ve hiçbir metin onu
    kullanmıyor.
    """
    rehber.yazi_tipleri_kur()
    for ad, stil in rehber._stiller().items():
        assert stil.fontName.startswith("Vera"), f"{ad}: {stil.fontName}"
        assert (stil.bulletFontName or "").startswith("Vera"), (
            f"{ad} madde imi {stil.bulletFontName!r} kullanıyor — Türkçe taşımaz")


def test_turkce_harfler_yazi_tipinde_VAR():
    """Standart yazı tipleri Türkçe taşımıyor; Vera'ya geçişin sebebi bu."""
    kapsam = _vera_karakterleri()
    eksik = [c for c in "çğıİöşüÇĞÖŞÜ" if ord(c) not in kapsam]
    assert not eksik, f"Vera Türkçe harfleri taşımıyor: {eksik}"


# ══════════════════════════════════════════════════════════════════════════════
# 3. Menü etiketi ↔ gerçek dosya/bağlantı  (6.3 turundaki desen)
# ══════════════════════════════════════════════════════════════════════════════


def test_menu_etiketi_ARAYUZDE_var():
    """
    Etiket tek yerde tanımlı ve arayüz onu KULLANIYOR mu.

    `main_window.py` etiketi elle yazsaydı, `CORE/rehber.py`'deki tanım
    değiştiğinde menü eski yazıyı göstermeye devam ederdi.
    """
    kaynak = (KOK / "UI" / "main_window.py").read_text(encoding="utf-8")
    assert "_REHBER_ETIKETI" in kaynak, (
        "Arayüz menü etiketini CORE/rehber.py'den almıyor")
    assert 'menu.addAction("📘' not in kaynak, (
        "Etiket arayüzde ELLE yazılmış — tek tanım kuralı bozuldu")


def test_menu_etiketi_REHBERDE_anlatiliyor():
    """
    Rehber "menüden şunu seç" diyorsa etiket ekrandakiyle aynı olmalı.

    Mevcut desen: `tests/test_kullanici_rehberi.py`
    ::test_rehberdeki_menu_etiketleri_arayuzde_VAR. Karşılaştırma boşluk
    sayısına duyarsız — rehberde tek, arayüzde iki boşluk var.
    """
    sade = re.sub(r"\s+", " ", rehber.MENU_ETIKETI)
    metin = re.sub(r"\s+", " ", rehber.KAYNAK.read_text(encoding="utf-8"))
    assert sade in metin, f"Rehber {sade!r} menü maddesinden söz etmiyor"


def test_menu_maddesi_ISLEYICIYE_bagli():
    """
    Etiketin görünmesi yetmez; tıklandığında bir şey OLMALI.

    AST ile: hamburger menüsünde `act_rehber` üretiliyor ve yönlendirme
    zinciri onu `_on_open_rehber`'e bağlıyor.
    """
    kaynak = (KOK / "UI" / "main_window.py").read_text(encoding="utf-8")
    agac = ast.parse(kaynak)
    govde = next(
        d for d in ast.walk(agac)
        if isinstance(d, ast.FunctionDef) and d.name == "_on_hamburger_menu")
    metin = ast.unparse(govde)
    assert "act_rehber = menu.addAction(_REHBER_ETIKETI)" in metin.replace("  ", " ")
    assert "action == act_rehber" in metin
    assert "self._on_open_rehber()" in metin

    assert any(
        isinstance(d, ast.FunctionDef) and d.name == "_on_open_rehber"
        for d in ast.walk(agac)), "_on_open_rehber tanımlı değil"


def test_erisim_yolu_GERCEK_hedef_donduruyor():
    """Menünün açacağı hedef gerçekten var mı."""
    tur, hedef = rehber.erisim_yolu()
    assert tur == "pdf", "PDF depoda olmalı; erişim yolu web'e düşmemeli"
    assert Path(hedef).is_file()
    assert Path(hedef) == rehber.PDF


def test_erisim_yolu_PDF_yokken_WEBE_dusuyor(monkeypatch: pytest.MonkeyPatch,
                                             tmp_path: Path):
    """
    PDF yoksa menü çalışmaya devam etmeli — ikinci erişim yolu bu.

    Düşüş SESSİZ değil: kullanıcı web adresine gidiyor, "bir şey olmadı"
    yaşamıyor.
    """
    monkeypatch.setattr(rehber, "PDF", tmp_path / "yok.pdf")
    tur, hedef = rehber.erisim_yolu()
    assert tur == "web"
    assert hedef == rehber.WEB
    assert hedef.startswith("https://")


# ══════════════════════════════════════════════════════════════════════════════
# 4. .hclx içine gömülen kopya
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def kasa(tmp_path: Path) -> tuple[bytes, Path]:
    (tmp_path / "belge.txt").write_text("paylasilan icerik", encoding="utf-8")
    return generate_key(), tmp_path


def _paketten_cikar(paket: Path, key: bytes, ad: str) -> bytes | None:
    """Paketi açıp içindeki bir dosyanın HAM baytlarını döndürür."""
    for dosya in hclx.open_package(paket, key):
        if dosya.ad == ad:
            return dosya.veri
    return None


def test_rehber_VARSAYILAN_olarak_pakete_girmiyor(kasa):
    """Saf ekleme: mevcut çağıranların paketleri değişmemeli."""
    key, dizin = kasa
    paket = dizin / "a.hclx"
    m = hclx.create_package([dizin / "belge.txt"], key, user_id=1,
                            hwid="H", dst=paket)
    assert [d["name"] for d in m.dosyalar] == ["belge.txt"]


def test_gomulu_rehber_PDF_ile_BAYT_ES(kasa):
    """
    Zincirin ikinci halkası: pakete giren kopya, asıl kopyanın AYNISI.

    Bayt bayt — "aynı içerik" değil "aynı dosya". İkinci bir üretim yolu
    açılsaydı (paket kendi PDF'ini üretseydi) baytlar kaçınılmaz olarak
    ayrışırdı, çünkü üretim zamanı ve belge kimliği farklı olurdu.
    """
    key, dizin = kasa
    paket = dizin / "b.hclx"
    m = hclx.create_package([dizin / "belge.txt"], key, user_id=1,
                            hwid="H", dst=paket, rehber_ekle=True)
    assert [d["name"] for d in m.dosyalar] == ["belge.txt", rehber.PAKET_ADI]

    cikan = _paketten_cikar(paket, key, rehber.PAKET_ADI)
    assert cikan is not None, "rehber pakete girmemiş"
    assert cikan == rehber.PDF.read_bytes(), (
        "Pakete gömülen kopya, docs/kullanici-rehberi.pdf ile bayt eş değil")


def test_gomulu_kopya_KAYNAKLA_da_guncel(kasa, tmp_path: Path):
    """Zincirin tamamı: paketten çıkan PDF, Markdown'ın özetini taşıyor."""
    key, dizin = kasa
    paket = dizin / "c.hclx"
    hclx.create_package([dizin / "belge.txt"], key, user_id=1,
                        hwid="H", dst=paket, rehber_ekle=True)
    cikan = _paketten_cikar(paket, key, rehber.PAKET_ADI)
    assert cikan is not None
    kopya = tmp_path / "cikan.pdf"
    kopya.write_bytes(cikan)
    assert rehber.pdf_kaynak_ozeti(kopya) == rehber.kaynak_ozeti()


def test_rehber_YOKSA_sessizce_atlanmiyor(kasa, monkeypatch: pytest.MonkeyPatch,
                                          tmp_path: Path):
    """
    Eksik rehber SESSİZ bir eksiltmeye dönmemeli.

    B-025'in dersi: sessizce devre dışı kalan bir yetenek, hiç
    olmayandan kötü — gönderen "rehber de gitti" sanır.
    """
    key, dizin = kasa
    monkeypatch.setattr(rehber, "PDF", tmp_path / "yok.pdf")
    with pytest.raises(hclx.HclxError) as exc:
        hclx.create_package([dizin / "belge.txt"], key, user_id=1,
                            hwid="H", dst=dizin / "d.hclx", rehber_ekle=True)
    assert "python CORE/rehber.py --uret" in str(exc.value)


def test_AD_CAKISMASI_reddediliyor(kasa):
    """Aynı adda iki dosya, alıcı için hangisinin hangisi olduğunu belirsizleştirir."""
    key, dizin = kasa
    sahte = dizin / rehber.PAKET_ADI
    sahte.write_bytes(b"%PDF-1.4 sahte")
    with pytest.raises(hclx.HclxError) as exc:
        hclx.create_package([sahte], key, user_id=1, hwid="H",
                            dst=dizin / "e.hclx", rehber_ekle=True)
    assert rehber.PAKET_ADI in str(exc.value)


# ══════════════════════════════════════════════════════════════════════════════
# 5. TEK ÜRETİM YOLU — AST denetimi
# ══════════════════════════════════════════════════════════════════════════════


def _kaynak_dosyalar() -> list[Path]:
    dosyalar = [KOK / "main.py"]
    for katman in ("CORE", "DB", "UI"):
        dosyalar += [p for p in (KOK / katman).rglob("*.py")
                     if "__pycache__" not in p.parts]
    return sorted(dosyalar)


def _belge_kuranlar(yol: Path) -> list[int]:
    """`SimpleDocTemplate(...)` ÇAĞRISI yapan satırlar — AST, metin değil."""
    agac = ast.parse(yol.read_text(encoding="utf-8"), filename=str(yol))
    return [
        d.lineno for d in ast.walk(agac)
        if isinstance(d, ast.Call) and isinstance(d.func, ast.Name)
        and d.func.id == "SimpleDocTemplate"
    ]


def test_PDF_uretimi_TEK_yerden():
    """
    Rehberin PDF'ini üreten ikinci bir yol olmamalı.

    Metin araması değil AST: bu dosyanın ve `CORE/rehber.py`'nin
    docstring'lerinde "SimpleDocTemplate" geçiyor ve metin araması onlara
    takılırdı (B-024 sınıfı).
    """
    ihlal = {
        yol.name: satirlar
        for yol in _kaynak_dosyalar()
        if (satirlar := _belge_kuranlar(yol))
        and yol != _URETICI and yol.name not in _MUAF
    }
    assert not ihlal, (
        f"Rehber dışında PDF üreten dosya(lar): {ihlal}\n"
        "PDF'i üreten tek yer CORE/rehber.py::pdf_uret olmalı.")


def test_uretim_denetimi_KOR_degil():
    """Tarayıcı gerçekten bir şey buluyor mu — bulmasaydı kural boş olurdu."""
    assert _belge_kuranlar(_URETICI), "CORE/rehber.py'de SimpleDocTemplate yok"
    assert _belge_kuranlar(KOK / "CORE" / "inventory.py"), (
        "inventory.py artık PDF üretmiyor — muafiyet listesi eskimiş")


def test_hclx_rehberi_URETMIYOR_okuyor():
    """
    Paket, PDF'i üretmemeli — okumalı.

    Üretseydi baytlar asıl kopyadan ayrışırdı ve "gömülü kopya = asıl
    kopya" garantisi çökerdi. AST ile: `hclx.py` içinde `pdf_uret`
    çağrısı ya da içe aktarımı yok.
    """
    agac = ast.parse((KOK / "CORE" / "hclx.py").read_text(encoding="utf-8"))
    for dugum in ast.walk(agac):
        if isinstance(dugum, ast.Call):
            ad = getattr(dugum.func, "attr", getattr(dugum.func, "id", ""))
            assert ad != "pdf_uret", "hclx.py PDF üretiyor — okumalı, üretmemeli"
        if isinstance(dugum, ast.ImportFrom) and dugum.module == "CORE.rehber":
            adlar = {a.name for a in dugum.names}
            assert "pdf_uret" not in adlar, "hclx.py pdf_uret'i içe aktarıyor"


def test_rehber_yolu_TEK_yerde_yaziyor():
    """
    `kullanici-rehberi` dizesi yalnızca `CORE/rehber.py`'de geçmeli.

    İkinci bir yerde elle yazılsaydı, dosya taşındığında biri güncellenip
    diğeri unutulurdu — B-017'nin tam mekanizması.
    """
    ihlal = []
    for yol in _kaynak_dosyalar():
        if yol == _URETICI:
            continue
        agac = ast.parse(yol.read_text(encoding="utf-8"), filename=str(yol))
        for dugum in ast.walk(agac):
            if (isinstance(dugum, ast.Constant) and isinstance(dugum.value, str)
                    and "kullanici-rehberi" in dugum.value):
                ihlal.append(f"{yol.name}:{dugum.lineno}")
    assert not ihlal, f"Rehber yolu elle yazılmış: {ihlal}"


# ══════════════════════════════════════════════════════════════════════════════
# 6. Denetimin kendisi çalışıyor mu — sahte dosyalarla
# ══════════════════════════════════════════════════════════════════════════════


def test_uretim_denetimi_IKINCI_yolu_yakaliyor(tmp_path: Path):
    """İkinci bir üretici uydurulup tarayıcıya gösteriliyor."""
    ikinci = tmp_path / "ikinci_uretici.py"
    ikinci.write_text(
        "from reportlab.platypus import SimpleDocTemplate\n"
        "def uret(yol):\n"
        "    SimpleDocTemplate(str(yol)).build([])\n",
        encoding="utf-8")
    assert _belge_kuranlar(ikinci) == [3]


def test_YORUMDAKI_uretici_denetimi_kandirmiyor(tmp_path: Path):
    """Kuralı ANLATAN metin kurala takılmamalı (B-024 sınıfı)."""
    sahte = tmp_path / "sahte.py"
    sahte.write_text(
        '"""SimpleDocTemplate(...) çağırmayın."""\n'
        "# SimpleDocTemplate(yol) <- yasak\n"
        "SABIT = 'SimpleDocTemplate'\n",
        encoding="utf-8")
    assert _belge_kuranlar(sahte) == []


def test_ortam_degiskeni_gerekmiyor():
    """
    Bu paket Qt'siz koşmalı — senkron denetimi, ekransız bir runner'da da
    çalışan tek güvencedir. `QT_QPA_PLATFORM` kurulu olsun ya da olmasın
    burada hiçbir şey değişmiyor; kayıt için sabitleniyor.
    """
    onceki = os.environ.get("QT_QPA_PLATFORM")
    assert rehber.guncel_mi() is True
    assert os.environ.get("QT_QPA_PLATFORM") == onceki
