"""
Tekrar uyarısının arayüz tarafı — uyarı ENGELLEYİCİ DEĞİL (Qt).

CORE tarafı (`tests/test_duplicates.py`) tespitin doğru çalıştığını
sınıyor. Burada sınanan şey KARARIN uygulanması: kullanıcı "Yine de Ekle"
dediğinde dosyaların gerçekten yüklemeye gittiği, "Tekrarları Atla"
dediğinde yalnızca TEKRAR OLANLARIN elendiği.

Bu ayrım test edilmeye değer çünkü kolayca yanlış yapılabilir: "atla"
seçeneği bütün partiyi iptal etseydi, kullanıcı tek bir mükerrer dosya
yüzünden 149 sağlam dosyayı da kaybederdi.

`_check_duplitates` gerçek metot; etrafındaki pencere kurulumu (DB,
anahtar, USB) atlanıyor — tests/test_lock_overlay.py ile aynı desen.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# Qt import'ları TEK korumanın altında — çıplak bir Linux runner'ında
# alt modüller sistem kütüphanelerine bağlı ve modül seviyesinde patlayan
# bir import TOPLAMA HATASI olur (çıkış kodu 2), atlama değil.
try:
    from PySide6.QtWidgets import QApplication, QMessageBox, QWidget

    from UI.main_window_table import TableMixin
except ImportError as _exc:  # pragma: no cover — ortama bağlı
    pytest.skip(
        f"Qt katmanı bu ortamda yüklenemedi ({_exc}) — testler atlanıyor",
        allow_module_level=True,
    )

_ICERIK = b"ayni icerik" * 100
_SHA = hashlib.sha256(_ICERIK).hexdigest()


@pytest.fixture(scope="module")
def qapp():
    try:
        app = QApplication.instance() or QApplication([])
    except Exception as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"QApplication kurulamadı ({exc}) — Qt katmanı atlanıyor")
    yield app


class _Sahne(QWidget):
    """`_check_duplicates`'in dokunduğu asgari yüzey."""

    _check_duplicates = TableMixin._check_duplicates

    def __init__(self, rol: str = "Yönetici") -> None:
        super().__init__()
        self._role = rol
        self._user_id = 1


def _kullanici(db) -> None:
    """
    Oturum açmış kullanıcının `users` satırı.

    Gerekli, çünkü `audit_log.user_id` yabancı anahtarı gerçek bir satır
    istiyor. Uygulamada bu satır zaten var — `files.added_by` de aynı
    tabloya bakıyor, yani satır olmadan dosya kaydı da yazılamazdı.
    Olmadığında `_check_duplicates` denetim kaydını sessizce düşürüyor
    (yükleme engellenmesin diye) ve testler yanlış yere yeşil kalırdı.
    """
    db.execute(
        "INSERT OR IGNORE INTO users (id, username, password_hash, role, status, hwid)"
        " VALUES (1, 'test', '', 'admin', 'approved', 'H')"
    )


@pytest.fixture
def sahne(qapp, db):
    _kullanici(db)
    return _Sahne()


@pytest.fixture
def tiklat(monkeypatch):
    """
    Diyaloğu açmadan, adı verilen düğmeye tıklanmış gibi yapar.

    `exec()` boşa alınıyor (offscreen'de bile bloklardı) ve
    `clickedButton()` metnine göre GERÇEK düğme nesnesini döndürüyor —
    kod kimlik karşılaştırması (`is`) yaptığı için sahte bir nesne işe
    yaramazdı.
    """
    def _kur(metin: str) -> list[QMessageBox]:
        acilanlar: list[QMessageBox] = []

        def _exec(self) -> int:
            acilanlar.append(self)
            return 0

        def _clicked(self):
            for b in self.buttons():
                if b.text() == metin:
                    return b
            return None

        monkeypatch.setattr(QMessageBox, "exec", _exec)
        monkeypatch.setattr(QMessageBox, "clickedButton", _clicked)
        return acilanlar

    return _kur


def _kayit(db, ad: str, sha: str = _SHA, *, label: str = "Genel") -> int:
    cur = db.execute(
        "INSERT INTO files (filename, filepath, label, original_sha256)"
        " VALUES (?, ?, ?, ?)", (ad, f"/kasa/{ad}.hcl", label, sha))
    return int(cur.lastrowid)


def _dosya(tmp_path: Path, ad: str, icerik: bytes = _ICERIK) -> Path:
    p = tmp_path / ad
    p.write_bytes(icerik)
    return p


# ══════════════════════════════════════════════════════════════════════════════
# 1. Uyarı engelleyici değil
# ══════════════════════════════════════════════════════════════════════════════


def test_add_anyway_keeps_every_file(sahne, db, tmp_path, tiklat) -> None:
    """ASIL TEST: uyarı bir kilit değil — kullanıcı devam edebilmeli."""
    _kayit(db, "zaten-var")
    tiklat("Yine de Ekle")

    girdi = [(_dosya(tmp_path, "kopya.docx"), "Karantina", None)]
    assert sahne._check_duplicates(girdi) == girdi


def test_skip_removes_only_the_duplicates(sahne, db, tmp_path, tiklat) -> None:
    """
    "Atla" YALNIZCA tekrar olanları elemeli.

    Bütün partiyi iptal etseydi, tek bir mükerrer dosya yüzünden sağlam
    dosyalar da kaybolurdu.
    """
    _kayit(db, "zaten-var")
    tiklat("Tekrarları Atla")

    tekrar = _dosya(tmp_path, "kopya.docx")
    yeni = _dosya(tmp_path, "yeni.docx", b"bambaska icerik")
    kalan = sahne._check_duplicates([(tekrar, "Genel", None), (yeni, "Genel", None)])

    assert [p for p, _l, _f in kalan] == [yeni]


def test_add_anyway_is_the_default_button(sahne, db, tmp_path, tiklat) -> None:
    """
    Varsayılan düğme "Yine de Ekle": mükerrer belgelerin bilerek tutulması
    gereken durumlar var, dolayısıyla Enter'a basmak dosyayı ELEMEMELİ.
    """
    _kayit(db, "zaten-var")
    acilanlar = tiklat("Yine de Ekle")
    sahne._check_duplicates([(_dosya(tmp_path, "k.docx"), "Genel", None)])

    assert len(acilanlar) == 1
    assert acilanlar[0].defaultButton().text() == "Yine de Ekle"


# ══════════════════════════════════════════════════════════════════════════════
# 2. Uyarı ne zaman ÇIKMIYOR
# ══════════════════════════════════════════════════════════════════════════════


def test_no_dialog_when_there_is_no_duplicate(sahne, db, tmp_path, tiklat) -> None:
    acilanlar = tiklat("Yine de Ekle")
    girdi = [(_dosya(tmp_path, "yepyeni.docx", b"esi benzeri yok"), "Genel", None)]

    assert sahne._check_duplicates(girdi) == girdi
    assert acilanlar == []


def test_no_dialog_for_an_empty_batch(sahne, db, tiklat) -> None:
    acilanlar = tiklat("Yine de Ekle")
    assert sahne._check_duplicates([]) == []
    assert acilanlar == []


def test_a_destroyed_copy_raises_no_warning(sahne, db, tmp_path, tiklat) -> None:
    """İmha Odası'ndaki kopya tekrar sayılmıyor — diyalog hiç açılmamalı."""
    _kayit(db, "imhadaki", label="Imha")
    acilanlar = tiklat("Yine de Ekle")

    girdi = [(_dosya(tmp_path, "k.docx"), "Genel", None)]
    assert sahne._check_duplicates(girdi) == girdi
    assert acilanlar == []


def test_an_unreadable_file_does_not_block_the_batch(sahne, db, tmp_path, tiklat) -> None:
    """
    Okunamayan dosya burada durdurulmuyor: asıl hata şifreleme adımında
    zaten raporlanacak ve oradaki mesaj daha doğru.
    """
    tiklat("Yine de Ekle")
    yok = tmp_path / "olmayan.docx"
    girdi = [(yok, "Genel", None)]
    assert sahne._check_duplicates(girdi) == girdi


# ══════════════════════════════════════════════════════════════════════════════
# 3. Mahrem etiket arayüz tarafında da gizli
# ══════════════════════════════════════════════════════════════════════════════


def test_a_non_admin_gets_no_warning_for_a_private_match(db, tmp_path, tiklat, qapp) -> None:
    """
    Rolün `include_private`'a doğru çevrildiğini sınıyor.

    CORE tarafı doğru olsa bile arayüz `include_private=True` geçseydi
    sızıntı yine olurdu — bağlantının kendisi test edilmeli.
    """
    fid = _kayit(db, "gizli-karar")
    cur = db.execute(
        "INSERT INTO tags (name, color, is_private) VALUES ('Yönetim', '#fff', 1)")
    db.execute("INSERT INTO file_tags (file_id, tag_id) VALUES (?, ?)",
               (fid, cur.lastrowid))

    _kullanici(db)
    sahne = _Sahne(rol="Standart")
    acilanlar = tiklat("Yine de Ekle")
    girdi = [(_dosya(tmp_path, "k.docx"), "Genel", None)]

    assert sahne._check_duplicates(girdi) == girdi
    assert acilanlar == [], "mahrem eşleşme yönetici olmayana uyarı üretmemeli"


def test_an_admin_does_get_the_warning(db, tmp_path, tiklat, qapp) -> None:
    fid = _kayit(db, "gizli-karar")
    cur = db.execute(
        "INSERT INTO tags (name, color, is_private) VALUES ('Yönetim', '#fff', 1)")
    db.execute("INSERT INTO file_tags (file_id, tag_id) VALUES (?, ?)",
               (fid, cur.lastrowid))

    _kullanici(db)
    sahne = _Sahne(rol="Yönetici")
    acilanlar = tiklat("Yine de Ekle")
    sahne._check_duplicates([(_dosya(tmp_path, "k.docx"), "Genel", None)])

    assert len(acilanlar) == 1


# ══════════════════════════════════════════════════════════════════════════════
# 4. Denetim kaydı
# ══════════════════════════════════════════════════════════════════════════════


def test_the_decision_is_audited(sahne, db, tmp_path, tiklat) -> None:
    _kayit(db, "zaten-var")
    tiklat("Yine de Ekle")
    sahne._check_duplicates([(_dosya(tmp_path, "k.docx"), "Genel", None)])

    row = db.fetchone("SELECT action FROM audit_log ORDER BY id DESC LIMIT 1")
    assert row["action"] == "duplicate_added_anyway"


def test_skipping_is_audited_too(sahne, db, tmp_path, tiklat) -> None:
    _kayit(db, "zaten-var")
    tiklat("Tekrarları Atla")
    sahne._check_duplicates([(_dosya(tmp_path, "k.docx"), "Genel", None)])

    row = db.fetchone("SELECT action FROM audit_log ORDER BY id DESC LIMIT 1")
    assert row["action"] == "duplicate_skipped"


# ══════════════════════════════════════════════════════════════════════════════
# 5. Uyarı metni
# ══════════════════════════════════════════════════════════════════════════════


def test_the_dialog_names_the_existing_location(sahne, db, tmp_path, tiklat) -> None:
    db.execute(
        "INSERT OR IGNORE INTO users (id, username, password_hash, role, status, hwid)"
        " VALUES (1, 't', '', 'admin', 'approved', 'H')")
    cur = db.execute("INSERT INTO folders (name, owner_id) VALUES ('2026 Kararlar', 1)")
    db.execute(
        "INSERT INTO files (filename, filepath, label, original_sha256, folder_id)"
        " VALUES ('karar', '/k.hcl', 'Genel', ?, ?)", (_SHA, cur.lastrowid))

    acilanlar = tiklat("Yine de Ekle")
    sahne._check_duplicates([(_dosya(tmp_path, "kopya.docx"), "Genel", None)])

    metin = acilanlar[0].text()
    assert "kopya.docx" in metin
    assert "2026 Kararlar" in metin


def test_many_duplicates_are_summarised(sahne, db, tmp_path, tiklat) -> None:
    """150 dosyalık bir klasörde diyalog taşmamalı."""
    for i in range(8):
        _kayit(db, f"var{i}", sha=hashlib.sha256(f"i{i}".encode()).hexdigest())
    acilanlar = tiklat("Yine de Ekle")

    girdi = [
        (_dosya(tmp_path, f"d{i}.bin", f"i{i}".encode()), "Genel", None)
        for i in range(8)
    ]
    sahne._check_duplicates(girdi)

    metin = acilanlar[0].text()
    assert "8 dosya" in metin
    assert metin.rstrip().endswith("…")
