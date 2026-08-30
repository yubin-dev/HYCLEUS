"""
HYCLEUS — denetim zinciri raporu testleri (B-006)

Zincir doğrulaması üç yerden çağrılabiliyordu ama arayüzde düğmesi yoktu ve
TXT dışa aktarımı zincirden habersizdi. Kurcalama kanıtı, ancak birileri
kanıta BAKABİLİYORSA işe yarar.

Buradaki testler rapor METNİNİ sınıyor (CORE); düğmenin ve dışa aktarımın
o metni gerçekten kullandığı AST ile denetleniyor.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from CORE.audit_chain import write_anchor
from CORE.audit_report import ZincirRaporu, txt_basligi, zincir_raporu

_SIMDI = datetime(2026, 8, 17, 10, 30, 0, tzinfo=timezone.utc)


@pytest.fixture
def cipa(tmp_path: Path) -> Path:
    return tmp_path / "anchor.log"


def _kayitlar(db, n: int = 5) -> None:
    for i in range(n):
        db.log("test_action", detail=f"n={i}")


def _zinciri_kir(db) -> int:
    """Bir kaydın detayını doğrudan değiştirir — hash artık tutmaz."""
    satir = db.fetchone(
        "SELECT id FROM audit_log ORDER BY id LIMIT 1 OFFSET 2"
    )
    db.conn.execute(
        "UPDATE audit_log SET detail = 'KURCALANDI' WHERE id = ?", (satir["id"],)
    )
    db.conn.commit()
    return int(satir["id"])


# ══════════════════════════════════════════════════════════════════════════════
# 1. Sağlam zincir
# ══════════════════════════════════════════════════════════════════════════════


def test_saglam_zincir_saglam_diyor(db, cipa):
    _kayitlar(db)
    rapor = zincir_raporu(db, cipa_yolu=cipa)
    assert rapor.zincir.ok is True
    assert "SAĞLAM" in rapor.baslik()


def test_cipa_yoksa_saglam_ama_gorunuyor(db, cipa):
    """
    "Doğrulandı" ile "karşılaştıracak bir şey yoktu" AYNI CÜMLE DEĞİL.

    `AnchorCheck.ok` çıpa hiç yokken de True dönüyor. Rapor bunu
    `cipa_var` ile ayrı tutuyor, yoksa dış referansı olmayan bir kurulum
    kendini tam doğrulanmış sanırdı.
    """
    _kayitlar(db)
    rapor = zincir_raporu(db, cipa_yolu=cipa)
    assert rapor.cipa_var is False
    assert "dış referans" in rapor.ayrinti() or "DIŞINDAKİ" in rapor.ayrinti()


def test_cipa_varsa_dogrulaniyor(db, cipa):
    _kayitlar(db)
    write_anchor(db, "test", path=cipa)
    rapor = zincir_raporu(db, cipa_yolu=cipa)
    assert rapor.cipa_var is True
    assert rapor.saglam is True


# ══════════════════════════════════════════════════════════════════════════════
# 2. Kırık zincir — "hangi id'den" sorusunun yanıtı
# ══════════════════════════════════════════════════════════════════════════════


def test_kirik_zincir_ilk_kirilmayi_soyluyor(db, cipa):
    """B-015'te istenen: kırıksa HANGİ id'den kırık."""
    _kayitlar(db)
    kirik_id = _zinciri_kir(db)

    rapor = zincir_raporu(db, cipa_yolu=cipa)
    assert rapor.saglam is False
    assert "KIRIK" in rapor.baslik()
    assert str(kirik_id) in rapor.baslik()
    assert rapor.ilk_kirilma_id == kirik_id


def test_kirik_zincir_ayrintida_kirilmalari_listeliyor(db, cipa):
    _kayitlar(db)
    _zinciri_kir(db)
    ayrinti = zincir_raporu(db, cipa_yolu=cipa).ayrinti()
    assert "KIRIK" in ayrinti


def test_zincir_saglam_cipa_uyusmuyorsa_ayirt_ediliyor(db, cipa):
    """
    `verify_audit_chain()`'in YAKALAYAMADIĞI durum.

    Zincir baştan yeniden yazılırsa kendi içinde tutarlı olur; tek
    referans çıpadır. Rapor bu durumu üçüncü bir cümleyle söylüyor —
    "kırık" demek yanlış olurdu, "sağlam" demek daha da yanlış.
    """
    _kayitlar(db)
    write_anchor(db, "test", path=cipa)
    # Çıpalanan son kaydı sil — zincir kendi içinde tutarlı kalır.
    son = db.fetchone("SELECT MAX(id) AS m FROM audit_log")["m"]
    db.conn.execute("DELETE FROM audit_log WHERE id = ?", (son,))
    db.conn.commit()

    rapor = zincir_raporu(db, cipa_yolu=cipa)

    # KOŞULSUZ. İlk yazılışında bu üç satır `if rapor.zincir.ok:` altındaydı
    # ve koşul tutmasa test sessizce hiçbir şey ölçmeden geçerdi — bu
    # dosyanın kovaladığı hatanın ta kendisi. Dalın gerçekten girildiği
    # ölçüldü, `if` kaldırıldı: zincir kendi içinde tutarlı KALMALI, yoksa
    # test zaten yanlış senaryoyu kuruyor demektir.
    assert rapor.zincir.ok, "senaryo kurulamadı: zincir kendi içinde de kırıldı"
    assert rapor.saglam is False
    assert "ÇIPA UYUŞMUYOR" in rapor.baslik()


# ══════════════════════════════════════════════════════════════════════════════
# 3. TXT başlığı
# ══════════════════════════════════════════════════════════════════════════════


def test_txt_basligi_zincir_durumunu_iceriyor(db, cipa):
    _kayitlar(db)
    rapor = zincir_raporu(db, cipa_yolu=cipa)
    metin = "\n".join(txt_basligi(rapor, kayit_sayisi=5, simdi=_SIMDI))

    assert "Zincir durumu" in metin
    assert "SAĞLAM" in metin
    assert "2026-08-17 10:30:00 UTC" in metin


def test_txt_basligi_son_hashi_yaziyor(db, cipa):
    """
    Zincirin son ucu olmadan dosya bir kanıt değil, yalnızca bir liste.

    Dışa aktarılan dosyayla veritabanının tutarlılığı ancak bu hash
    üzerinden gösterilebilir.
    """
    _kayitlar(db)
    rapor = zincir_raporu(db, cipa_yolu=cipa)
    metin = "\n".join(txt_basligi(rapor, kayit_sayisi=5))

    assert rapor.zincir.last_hash
    assert rapor.zincir.last_hash in metin
    assert f"id={rapor.zincir.last_id}" in metin


def test_txt_basligi_kirik_zinciri_gizlemiyor(db, cipa):
    _kayitlar(db)
    kirik_id = _zinciri_kir(db)
    metin = "\n".join(
        txt_basligi(zincir_raporu(db, cipa_yolu=cipa), kayit_sayisi=5)
    )
    assert "KIRIK" in metin
    assert f"İlk kırılma   : id={kirik_id}" in metin


def test_txt_basligi_imzali_olmadigini_soyluyor(db, cipa):
    """
    DÜRÜST SINIR: bu dosya imzalı değil.

    Başlık "zincir sağlam" diyor ve okuyan biri bunu dosyanın kendisinin
    doğrulandığı sanabilir. Satır, o yanlış anlamayı önlemek için var.
    """
    _kayitlar(db)
    metin = "\n".join(
        txt_basligi(zincir_raporu(db, cipa_yolu=cipa), kayit_sayisi=5)
    )
    assert "imzalı DEĞİLDİR" in metin


def test_txt_basligi_cipa_yoksa_soyluyor(db, cipa):
    _kayitlar(db)
    metin = "\n".join(
        txt_basligi(zincir_raporu(db, cipa_yolu=cipa), kayit_sayisi=5)
    )
    assert "Çıpa" in metin
    assert "yok" in metin


def test_txt_basligi_kayit_sayisini_yaziyor(db, cipa):
    _kayitlar(db)
    metin = "\n".join(
        txt_basligi(zincir_raporu(db, cipa_yolu=cipa), kayit_sayisi=42)
    )
    assert "42" in metin


# ══════════════════════════════════════════════════════════════════════════════
# 4. Katman ve bağlantı denetimleri
# ══════════════════════════════════════════════════════════════════════════════


def test_rapor_katmani_qt_bilmiyor():
    import ast
    from pathlib import Path as _P

    kaynak = _P(__file__).resolve().parent.parent / "CORE" / "audit_report.py"
    agac = ast.parse(kaynak.read_text(encoding="utf-8"))
    moduller = {
        (d.module or "") for d in ast.walk(agac) if isinstance(d, ast.ImportFrom)
    }
    assert not any("PySide6" in m for m in moduller)


def test_adminpanel_dugmesi_raporu_cagiriyor():
    """
    B-006'nın birinci yarısı: düğme GERÇEKTEN var ve raporu çağırıyor.

    Düğme eklenip sinyali bağlanmasa hiçbir şey patlamazdı — tam olarak
    "mekanizma var, görünürlüğü yok" sınıfının tekrarı olurdu.

    `UI/AdminPanel.py` üçe bölündü (kaldırıldı) — "Zinciri Doğrula"
    düğmesi "USB Tokenlar" sayfasında kaldı (`UI/UsbTokensView.py`).
    """
    import ast
    from pathlib import Path as _P

    src = (_P(__file__).resolve().parent.parent / "UI" / "UsbTokensView.py").read_text(
        encoding="utf-8"
    )
    agac = ast.parse(src)
    adlar = {n.name for n in ast.walk(agac) if isinstance(n, ast.FunctionDef)}
    assert "_on_verify_chain" in adlar

    hedef = next(
        n for n in ast.walk(agac)
        if isinstance(n, ast.FunctionDef) and n.name == "_on_verify_chain"
    )
    govde = ast.get_source_segment(src, hedef) or ""

    # GÖVDE ARTIK PANELDE DEĞİL. Aynı doğrulama Güvenlik sekmesinden de
    # çağrılıyor (`UI/GuvenlikView.py`) ve iki ayrı uygulama bu deponun
    # beş kez ürettiği kusur olurdu; gövde
    # `UI/security_actions.zinciri_dogrula()`'ya taşındı.
    #
    # Bu testin SORDUĞU ŞEY değişmedi: düğme gerçekten raporu üretiyor mu.
    # Cevap artık bir adım derinde ve ZİNCİRİN TAMAMI izleniyor — panelin
    # ortak gövdeyi çağırdığı, ortak gövdenin de raporu ürettiği.
    assert "zinciri_dogrula" in govde, "panel ortak gövdeyi çağırmıyor"

    ortak = (_P(__file__).resolve().parent.parent / "UI" / "security_actions.py"
             ).read_text(encoding="utf-8")
    assert "zincir_raporu" in ortak
    assert "kullanici_bilgisi" in ortak, "doğrulayan kullanıcı gösterilmiyor (B-011)"
    assert "audit_chain_verified" in ortak, "doğrulama denetim kaydına düşmüyor"

    # Sinyal bağlı mı — düğme var ama tıklanınca hiçbir şey olmasın olmaz.
    assert "_btn_chain.clicked.connect(self._on_verify_chain)" in src


def test_txt_disa_aktarimi_zincir_basligini_kullaniyor():
    """
    B-006'nın ikinci yarısı: dışa aktarım zincirden haberdar.

    ÇAĞRI aranıyor, metin değil. İlk yazılışında bu test gövdede
    `"txt_basligi" in govde` diyordu ve çağrıyı söken bir mutasyon hayatta
    kaldı: fonksiyonun İÇİNDEKİ `from CORE.audit_report import ...` satırı
    adı taşımaya devam ediyordu. Aynı yanlış pozitif sınıfı bu turda
    üçüncü kez çıktı (B-011 docstring'i, B-004 docstring'i, burada import).

    2026-08-29: `UI/AuditLogDialog.py` (modal) `UI/AuditLogView.py` (tam
    sayfa) oldu ve `zincir_raporu()` çağrısı `_export_txt()`'in İÇİNDEN
    `_load()`'a taşındı — `_export_txt()` artık `self._load()`'u çağırıp
    onun az önce hesapladığı `self._son_rapor`'u KULLANIYOR, ikinci bir
    `zincir_raporu()` çağrısı YAPMIYOR (B-073'ün "iki kaynak aynı ana ait
    olmalı" dersinin daha sıkı hâli — tek hesaplama, iki kullanım). Bu
    yüzden denetim iki ADIMA ayrıldı: `_export_txt()` gerçekten `_load()`'u
    çağırıyor mu, `_load()` gerçekten `zincir_raporu()`'yu çağırıyor mu.
    """
    import ast
    from pathlib import Path as _P

    src = (
        _P(__file__).resolve().parent.parent / "UI" / "AuditLogView.py"
    ).read_text(encoding="utf-8")
    agac = ast.parse(src)

    def _cagrilar(fn: ast.FunctionDef) -> set[str]:
        return {
            (d.func.attr if isinstance(d.func, ast.Attribute) else
             d.func.id if isinstance(d.func, ast.Name) else "")
            for d in ast.walk(fn) if isinstance(d, ast.Call)
        }

    export_fn = next(
        n for n in ast.walk(agac)
        if isinstance(n, ast.FunctionDef) and n.name == "_export_txt"
    )
    load_fn = next(
        n for n in ast.walk(agac)
        if isinstance(n, ast.FunctionDef) and n.name == "_load"
    )

    export_cagrilari = _cagrilar(export_fn)
    assert "txt_basligi" in export_cagrilari, "dışa aktarım zincir başlığını ÇAĞIRMIYOR"
    assert "_load" in export_cagrilari, (
        "dışa aktarım tabloyu/zinciri TAZELEMİYOR — B-073'ün bayat veri riski geri geldi"
    )
    assert "zincir_raporu" in _cagrilar(load_fn), (
        "_load() zinciri doğrulamıyor — HALKA sütunu ve TXT başlığı artık bu sonuca dayanıyor"
    )


def test_kullanici_bilgisi_yan_etki_uretmiyor(db):
    """
    "Bu işlemi kim yaptı" sorusu bir satır OLUŞTURMAMALI.

    `sync_session_user()` çağrılsaydı her doğrulama denetim kaydına bir
    `session_user_linked` daha düşerdi — gürültü, ve daha kötüsü, satır
    yoksa sessizce yenisini açardı.
    """
    from CORE.session_user import kullanici_bilgisi

    def _say(tablo: str) -> int:
        return db.fetchone(f"SELECT COUNT(*) AS n FROM {tablo}")["n"]  # noqa: S608

    # Mutlak sayı DEĞİL fark ölçülüyor: `db` fikstürü bağlanırken zincir
    # başlangıç kaydını zaten yazıyor. İlk yazılışında bu test "0 kayıt"
    # bekliyordu ve fikstürün kendi satırına takıldı.
    onceki = (_say("users"), _say("audit_log"))

    assert kullanici_bilgisi(db, "HIC-YOK") is None

    assert (_say("users"), _say("audit_log")) == onceki


def test_kullanici_bilgisi_mevcut_satiri_buluyor(db):
    from CORE.session_user import sync_session_user, kullanici_bilgisi

    uid = sync_session_user(db, hwid="USB-1", role="Yönetici")
    assert kullanici_bilgisi(db, "USB-1") == (uid, "vault:USB-1")


def test_bos_hwid_none_donuyor(db):
    from CORE.session_user import kullanici_bilgisi

    assert kullanici_bilgisi(db, "") is None


def test_zincir_raporu_dataclass_donuyor(db, cipa):
    assert isinstance(zincir_raporu(db, cipa_yolu=cipa), ZincirRaporu)
