"""
HYCLEUS — Dosya listeleme sorguları testleri

Bu SQL daha önce `UI/main_window.py` içinde satır içi duruyordu ve Qt
olmadan çalıştırılamadığı için HİÇ test edilmemişti. 2.7 Faz 1'in asıl
kazancı bu: sorgular artık başsız sınanabiliyor.

Testler mevcut davranışı SABİTLİYOR, iyileştirmiyor. Bilinen tutarsızlıklar
(mahrem etiket filtresinin yalnızca iki görünümde olması) burada bilerek
"böyle olmalı" diye değil, "bugün böyle" diye yazılı — düzeltildiğinde bu
testlerin güncellenmesi gerekecek ve bu da düzeltmeyi bilinçli bir karar
hâline getiriyor.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from CORE.file_queries import (
    files_by_folder,
    files_by_label,
    files_by_tag,
    search_files,
)


# ── Kurulum yardımcıları ──────────────────────────────────────────────────────


def _add_file(db, filename: str, *, label: str = "Genel", folder_id: int | None = None,
              sha: str | None = None, size: int = 100, added_at: str | None = None) -> int:
    cur = db.execute(
        "INSERT INTO files (filename, filepath, label, size_bytes,"
        " original_sha256, folder_id, added_at)"
        " VALUES (?, ?, ?, ?, ?, ?, COALESCE(?, strftime('%Y-%m-%dT%H:%M:%SZ','now')))",
        (filename, f"/vault/{filename}.hcl", label, size, sha, folder_id, added_at),
    )
    return int(cur.lastrowid)


def _add_tag(db, name: str, *, private: bool = False) -> int:
    cur = db.execute(
        "INSERT INTO tags (name, is_private) VALUES (?, ?)", (name, int(private))
    )
    return int(cur.lastrowid)


def _assign(db, file_id: int, tag_id: int) -> None:
    db.execute(
        "INSERT INTO file_tags (file_id, tag_id) VALUES (?, ?)", (file_id, tag_id)
    )


def _add_folder(db, name: str) -> int:
    cur = db.execute("INSERT INTO folders (name) VALUES (?)", (name,))
    return int(cur.lastrowid)


def _names(rows) -> list[str]:
    return [r["filename"] for r in rows]


# ══════════════════════════════════════════════════════════════════════════════
# 1. Dönen sütun kümesi — arayüzün sözleşmesi
# ══════════════════════════════════════════════════════════════════════════════

_BEKLENEN_SUTUNLAR = {
    "id", "filename", "label", "size_bytes", "added_at",
    "filepath", "original_sha256", "expires_at", "scan_reason",
}


def test_every_view_returns_the_same_columns(db):
    """
    Dört görünüm de aynı sütunları döndürmeli.

    `_populate_table()` bu sütunlara ADA GÖRE erişiyor; biri eksik dönerse
    arayüz KeyError ile düşer. Dört sorgu tek bir sabitten üretildiği için
    bu artık yapısal olarak garanti, ama sözleşme yine de sabitleniyor.
    """
    fid = _add_file(db, "a.pdf")
    tid = _add_tag(db, "etiket")
    _assign(db, fid, tid)
    klasor = _add_folder(db, "Klasor")
    _add_file(db, "b.pdf", folder_id=klasor)

    for rows in (
        files_by_label(db, "Genel"),
        files_by_tag(db, tid),
        files_by_folder(db, klasor),
        search_files(db, "pdf"),
    ):
        assert rows, "test verisi beklenen satırı üretmedi"
        assert set(rows[0].keys()) == _BEKLENEN_SUTUNLAR


def test_scan_reason_returns_the_latest_quarantine_entry(db):
    """
    scan_reason ilişkili alt sorgu: EN SON karantina kaydı gelmeli.

    Alt sorgudaki ORDER BY / LIMIT düşerse eski gerekçe dönerdi ve kullanıcı
    tarama rozetinde eski sonucu görürdü.
    """
    fid = _add_file(db, "taranan.pdf")
    db.execute(
        "INSERT INTO quarantine (file_id, reason, quarantined_at)"
        " VALUES (?, ?, '2026-01-01T00:00:00Z')",
        (fid, '{"verdict":"clean"}'),
    )
    db.execute(
        "INSERT INTO quarantine (file_id, reason, quarantined_at)"
        " VALUES (?, ?, '2026-08-01T00:00:00Z')",
        (fid, '{"verdict":"malicious"}'),
    )
    rows = files_by_label(db, "Genel")
    assert '"verdict":"malicious"' in rows[0]["scan_reason"]


def test_scan_reason_is_null_without_a_quarantine_record(db):
    _add_file(db, "temiz.pdf")
    assert files_by_label(db, "Genel")[0]["scan_reason"] is None


# ══════════════════════════════════════════════════════════════════════════════
# 2. files_by_label
# ══════════════════════════════════════════════════════════════════════════════


def test_label_filter_selects_only_that_label(db):
    _add_file(db, "genel.pdf", label="Genel")
    _add_file(db, "kritik.pdf", label="Kritik")
    _add_file(db, "karantina.pdf", label="Karantina")

    assert _names(files_by_label(db, "Genel")) == ["genel.pdf"]
    assert _names(files_by_label(db, "Kritik")) == ["kritik.pdf"]


@pytest.mark.parametrize("label", ["Genel", "Kritik", "Karantina", "Imha"])
def test_every_label_is_queryable(db, label: str):
    _add_file(db, f"{label}.pdf", label=label)
    assert _names(files_by_label(db, label)) == [f"{label}.pdf"]


def test_empty_label_returns_empty_list(db):
    assert files_by_label(db, "Imha") == []


def test_results_are_newest_first(db):
    _add_file(db, "eski.pdf", added_at="2026-01-01T00:00:00Z")
    _add_file(db, "yeni.pdf", added_at="2026-08-01T00:00:00Z")
    _add_file(db, "orta.pdf", added_at="2026-04-01T00:00:00Z")
    assert _names(files_by_label(db, "Genel")) == ["yeni.pdf", "orta.pdf", "eski.pdf"]


# ══════════════════════════════════════════════════════════════════════════════
# 3. Mahrem etiket filtresi — mevcut davranış sabitleniyor
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def mahrem_kurulum(db):
    """Biri mahrem, biri normal etiketli iki dosya; ikisi de aynı klasörde."""
    klasor = _add_folder(db, "Ortak")
    gizli_id = _add_file(db, "gizli.pdf", folder_id=klasor)
    acik_id = _add_file(db, "acik.pdf", folder_id=klasor)
    mahrem_tag = _add_tag(db, "Mahrem", private=True)
    normal_tag = _add_tag(db, "Normal", private=False)
    _assign(db, gizli_id, mahrem_tag)
    _assign(db, acik_id, normal_tag)
    return {"klasor": klasor, "mahrem_tag": mahrem_tag, "normal_tag": normal_tag}


def test_label_view_hides_private_files_when_asked(db, mahrem_kurulum):
    assert _names(files_by_label(db, "Genel", include_private=False)) == ["acik.pdf"]


def test_label_view_shows_private_files_for_admins(db, mahrem_kurulum):
    assert set(_names(files_by_label(db, "Genel", include_private=True))) == {
        "gizli.pdf", "acik.pdf"
    }


def test_include_private_defaults_to_true(db, mahrem_kurulum):
    """Varsayılan GÖSTERMEK — çağıran açıkça kısıtlamalı."""
    assert len(files_by_label(db, "Genel")) == 2


def test_search_hides_private_files_when_asked(db, mahrem_kurulum):
    assert _names(search_files(db, "pdf", include_private=False)) == ["acik.pdf"]


def test_search_shows_private_files_for_admins(db, mahrem_kurulum):
    assert len(search_files(db, "pdf", include_private=True)) == 2


def test_folder_view_hides_private_files_when_asked(db, mahrem_kurulum):
    """
    B-007 DÜZELTMESİ — bu testin adı ve iddiası BİLEREK tersine çevrildi.

    Eski hâli `test_folder_view_does_NOT_filter_private_files` idi ve
    boşluğu SABİTLİYORDU: klasör görünümünde mahrem filtresi yoktu ve
    arayüz tarafında da engel yoktu, yani yönetici olmayan bir kullanıcı
    klasöre girip mahrem dosyaları gerçekten görüyordu.

    Sabitleme testi bir onay değil bir işaretti; düzeltme geldiğinde
    kırılsın diye yazılmıştı. Kırıldı ve burası onun yerini aldı.
    """
    rows = files_by_folder(db, mahrem_kurulum["klasor"], include_private=False)
    assert _names(rows) == ["acik.pdf"]


def test_folder_view_shows_private_files_for_admins(db, mahrem_kurulum):
    """Yönetici tarafında hiçbir şey değişmemeli."""
    rows = files_by_folder(db, mahrem_kurulum["klasor"], include_private=True)
    assert set(_names(rows)) == {"gizli.pdf", "acik.pdf"}


def test_tag_view_hides_private_files_when_asked(db, mahrem_kurulum):
    """
    B-007 DÜZELTMESİ — eski adı `test_tag_view_does_NOT_filter_private_files`.

    Mahrem ETİKETİN KENDİSİ sorgulandığında sonuç boş dönüyor: dosya, tam
    olarak o etiket yüzünden mahrem sayılıyor. Filtre "bu dosya mahrem mi"
    sorusunu yanıtlıyor, "hangi etiketten geldi" sorusunu değil.

    Bu görünüme ulaşmanın arayüzde zaten yolu yoktu (mahrem etiketler
    kenar çubuğunda çizilmiyor). O engel KALDIRILMADI — artık iki katman
    birlikte duruyor.
    """
    rows = files_by_tag(db, mahrem_kurulum["mahrem_tag"], include_private=False)
    assert rows == []


def test_tag_view_shows_private_files_for_admins(db, mahrem_kurulum):
    rows = files_by_tag(db, mahrem_kurulum["mahrem_tag"], include_private=True)
    assert _names(rows) == ["gizli.pdf"]


def test_tag_view_normal_etiketteki_mahrem_dosyayi_da_gizliyor(db):
    """
    Asıl senaryo: NORMAL bir etikete tıklandığında mahrem dosya sızmamalı.

    Bir dosya hem "Proje" (normal) hem "Mahrem" etiketi taşıyorsa,
    "Proje" etiketine tıklayan yönetici olmayan kullanıcı onu GÖRMEMELİ.
    Bir önceki test tek başına bunu kanıtlamıyor — orada sorgulanan
    etiketin kendisi mahremdi.
    """
    fid = _add_file(db, "karma.pdf")
    normal = _add_tag(db, "Proje", private=False)
    _assign(db, fid, normal)
    _assign(db, fid, _add_tag(db, "Mahrem", private=True))

    assert files_by_tag(db, normal, include_private=False) == []
    assert _names(files_by_tag(db, normal, include_private=True)) == ["karma.pdf"]


def test_dort_gorunumun_dordu_de_ayni_dosyayi_gizliyor(db, mahrem_kurulum):
    """
    B-007'NİN ÖZÜ: tutarlılık.

    Bulgu "klasör görünümü filtrelemiyor" değildi aslında — bulgu, AYNI
    dosyanın bir görünümde gizlenip başkasında görünmesiydi. Dördünü tek
    testte yan yana koymak, ileride biri ayrışırsa bunu tek bir kırılmayla
    gösterir.
    """
    klasor = mahrem_kurulum["klasor"]
    normal_tag = mahrem_kurulum["normal_tag"]

    gorunumler = {
        "label": _names(files_by_label(db, "Genel", include_private=False)),
        "search": _names(search_files(db, "pdf", include_private=False)),
        "folder": _names(files_by_folder(db, klasor, include_private=False)),
        "tag": _names(files_by_tag(db, normal_tag, include_private=False)),
    }
    for ad, isimler in gorunumler.items():
        assert "gizli.pdf" not in isimler, f"{ad} görünümü mahrem dosyayı sızdırıyor"
        assert "acik.pdf" in isimler, f"{ad} görünümü normal dosyayı da gizliyor"


@pytest.mark.parametrize("gorunum", ["folder", "tag"])
def test_yeni_parametrelerin_varsayilani_da_true(db, mahrem_kurulum, gorunum):
    """
    Varsayılan GÖSTERMEK olarak kaldı — bilerek.

    Ters çevirmek daha güvenli görünürdü ama sessiz bir davranış
    değişikliği olurdu: parametre geçmeyen her çağrı aniden veri gizlemeye
    başlardı ve fark edilme yolu kullanıcının dosyasını kaybetmesi olurdu.
    Güvenliği veren şey varsayılan değil, çağrı yerlerinin parametreyi
    AÇIKÇA vermesi — bunu bir sonraki test denetliyor.
    """
    if gorunum == "folder":
        satirlar = files_by_folder(db, mahrem_kurulum["klasor"])
    else:
        satirlar = files_by_tag(db, mahrem_kurulum["mahrem_tag"])
    assert "gizli.pdf" in _names(satirlar)


def test_dort_cagri_yeri_de_include_private_geciyor():
    """
    ASIL KORUMA — arayüz dört sorguyu da role bağlamalı.

    Varsayılan `True` olduğu için, bir çağrı yerinden `include_private`
    düşerse hiçbir şey patlamaz: mahrem dosyalar sessizce görünür olur.
    B-007'nin ilk hâli tam olarak buydu. Çalışma zamanı testi bunu
    yakalayamaz (Qt penceresi gerekir), o yüzden kaynak ağacı denetleniyor.
    """
    import ast
    from pathlib import Path

    hedefler = {"files_by_label", "files_by_tag", "files_by_folder", "search_files"}
    ui = Path(__file__).resolve().parent.parent / "UI"

    bulunan: dict[str, int] = {}
    eksik: list[str] = []
    for yol in ui.rglob("*.py"):
        agac = ast.parse(yol.read_text(encoding="utf-8"))
        for dugum in ast.walk(agac):
            if not (isinstance(dugum, ast.Call) and isinstance(dugum.func, ast.Name)):
                continue
            if dugum.func.id not in hedefler:
                continue
            bulunan[dugum.func.id] = bulunan.get(dugum.func.id, 0) + 1
            if "include_private" not in {k.arg for k in dugum.keywords}:
                eksik.append(f"{yol.name}:{dugum.lineno} {dugum.func.id}")

    assert not eksik, f"include_private geçmeyen çağrı: {eksik}"
    assert set(bulunan) == hedefler, (
        f"arayüzde çağrılmayan görünüm var: {hedefler - set(bulunan)}"
    )


def test_private_filter_excludes_a_file_carrying_both_tag_kinds(db):
    """Bir dosya hem mahrem hem normal etiket taşıyorsa GİZLENMELİ."""
    fid = _add_file(db, "karma.pdf")
    _assign(db, fid, _add_tag(db, "Mahrem", private=True))
    _assign(db, fid, _add_tag(db, "Normal"))
    assert files_by_label(db, "Genel", include_private=False) == []
    assert len(files_by_label(db, "Genel", include_private=True)) == 1


# ══════════════════════════════════════════════════════════════════════════════
# 4. files_by_tag / files_by_folder
# ══════════════════════════════════════════════════════════════════════════════


def test_tag_view_returns_only_assigned_files(db):
    tid = _add_tag(db, "Sozlesme")
    atanan = _add_file(db, "atanan.pdf")
    _add_file(db, "atanmayan.pdf")
    _assign(db, atanan, tid)
    assert _names(files_by_tag(db, tid)) == ["atanan.pdf"]


def test_tag_view_spans_labels(db):
    """Etiket görünümü etiketten bağımsız — dört etiketi de kapsar."""
    tid = _add_tag(db, "Karma")
    for label in ("Genel", "Kritik", "Karantina", "Imha"):
        _assign(db, _add_file(db, f"{label}.pdf", label=label), tid)
    assert len(files_by_tag(db, tid)) == 4


def test_unknown_tag_returns_empty(db):
    assert files_by_tag(db, 9999) == []


def test_folder_view_returns_only_that_folder(db):
    a = _add_folder(db, "A")
    b = _add_folder(db, "B")
    _add_file(db, "a1.pdf", folder_id=a)
    _add_file(db, "b1.pdf", folder_id=b)
    _add_file(db, "koksuz.pdf")
    assert _names(files_by_folder(db, a)) == ["a1.pdf"]


def test_folder_view_excludes_files_without_a_folder(db):
    klasor = _add_folder(db, "A")
    _add_file(db, "koksuz.pdf")
    assert files_by_folder(db, klasor) == []


def test_unknown_folder_returns_empty(db):
    assert files_by_folder(db, 9999) == []


# ══════════════════════════════════════════════════════════════════════════════
# 5. search_files
# ══════════════════════════════════════════════════════════════════════════════


def test_search_matches_filename_substring(db):
    _add_file(db, "rapor_2026.pdf")
    _add_file(db, "sozlesme.docx")
    assert _names(search_files(db, "rapor")) == ["rapor_2026.pdf"]
    assert _names(search_files(db, "2026")) == ["rapor_2026.pdf"]


def test_search_matches_sha256(db):
    _add_file(db, "a.pdf", sha="abc123def456")
    _add_file(db, "b.pdf", sha="999888777")
    assert _names(search_files(db, "abc123")) == ["a.pdf"]


def test_search_matches_tag_name(db):
    fid = _add_file(db, "etiketli.pdf")
    _add_file(db, "etiketsiz.pdf")
    _assign(db, fid, _add_tag(db, "Muhasebe"))
    assert _names(search_files(db, "Muhasebe")) == ["etiketli.pdf"]


def test_search_is_case_insensitive_for_ascii(db):
    """SQLite LIKE ASCII'de harf katlaması yapar — mevcut davranış."""
    _add_file(db, "Rapor.pdf")
    assert _names(search_files(db, "rapor")) == ["Rapor.pdf"]
    assert _names(search_files(db, "RAPOR")) == ["Rapor.pdf"]


def test_search_does_not_fold_turkish_characters(db):
    """
    SQLite'ın LIKE'ı ASCII dışında harf katlaması YAPMAZ.

    Mevcut davranış bu; sabitleniyor ki ileride ICU/collation eklenirse
    değişiklik fark edilsin.
    """
    _add_file(db, "İSTANBUL.pdf")
    assert search_files(db, "istanbul") == []
    assert _names(search_files(db, "İSTANBUL")) == ["İSTANBUL.pdf"]


def test_search_returns_each_file_once_even_with_multiple_matches(db):
    """Ad VE etiket birden eşleşse bile dosya tek satır dönmeli."""
    fid = _add_file(db, "rapor.pdf")
    _assign(db, fid, _add_tag(db, "rapor"))
    assert _names(search_files(db, "rapor")) == ["rapor.pdf"]


def test_search_spans_all_labels(db):
    for label in ("Genel", "Kritik", "Karantina", "Imha"):
        _add_file(db, f"ortak_{label}.pdf", label=label)
    assert len(search_files(db, "ortak")) == 4


def test_search_with_no_match_returns_empty(db):
    _add_file(db, "a.pdf")
    assert search_files(db, "bulunamayacak") == []


def test_search_percent_is_treated_literally_enough_to_not_crash(db):
    """
    LIKE joker karakteri içeren terim SQL hatası vermemeli.

    Mevcut davranış: `%` kullanıcı terimine gömülü geldiği için joker gibi
    davranıyor (kaçış yok). Sabitleniyor — bir güvenlik sorunu değil
    (parametreli sorgu, enjeksiyon yok), ama beklenmedik eşleşme üretebilir.
    """
    _add_file(db, "a.pdf")
    _add_file(db, "b.pdf")
    assert len(search_files(db, "%")) == 2


def test_search_term_is_parameterised_not_interpolated(db):
    """SQL enjeksiyon denemesi veri olarak ele alınmalı."""
    _add_file(db, "a.pdf")
    assert search_files(db, "'; DROP TABLE files; --") == []
    assert len(files_by_label(db, "Genel")) == 1, "files tablosu duruyor olmalı"


# ══════════════════════════════════════════════════════════════════════════════
# 6. Hata sözleşmesi
# ══════════════════════════════════════════════════════════════════════════════


def test_queries_raise_instead_of_swallowing(db, tmp_path: Path):
    """
    CORE hata GÖSTERMEZ, fırlatır.

    Arayüz istisnayı yakalayıp QMessageBox açıyor; bu ayrım katman kuralının
    (tests/test_layering.py) pratikteki karşılığı.
    """
    import sqlite3

    db.execute("DROP TABLE file_tags")
    with pytest.raises(sqlite3.Error):
        files_by_label(db, "Genel", include_private=False)
