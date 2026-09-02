"""
HYCLEUS — denetim zinciri raporu testleri (B-006)

Zincir doğrulaması üç yerden çağrılabiliyordu ama arayüzde düğmesi yoktu ve
TXT dışa aktarımı zincirden habersizdi. Kurcalama kanıtı, ancak birileri
kanıta BAKABİLİYORSA işe yarar.

Buradaki testler rapor METNİNİ sınıyor (CORE); düğmenin ve dışa aktarımın
o metni gerçekten kullandığı AST ile denetleniyor.
"""
from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path

import pytest

from CORE.audit_chain import write_anchor
from CORE.audit_report import (
    DenetimSatiri,
    HALKA_METNI,
    ZincirRaporu,
    export_csv,
    export_pdf,
    txt_basligi,
    zincir_raporu,
)

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


def test_csv_pdf_disa_aktarimi_da_load_export_ve_denetim_kaydini_cagiriyor():
    """
    `test_txt_disa_aktarimi_zincir_basligini_kullaniyor()`'un AYNI denetimi
    — CSV/PDF dışa aktarımı da (1) `_load()`'u (B-073 tazelik garantisi),
    (2) kendi CORE fonksiyonunu (`export_csv`/`export_pdf` — ikinci bir
    veri/render yolu AÇILMADI), (3) `_log_disa_aktarim()`'i (görevin
    istediği "indirme eylemi denetim kaydına yazılsın") GERÇEKTEN
    ÇAĞIRIYOR mu — üçü de ÇAĞRI aranarak, metin değil (bkz. üstteki
    testin B-011/B-004 yanlış-pozitif dersi).
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

    for fn_adi, cagrilmasi_gereken in (
        ("_export_csv", "export_csv"), ("_export_pdf", "export_pdf"),
    ):
        fn = next(
            n for n in ast.walk(agac)
            if isinstance(n, ast.FunctionDef) and n.name == fn_adi
        )
        cagrilar = _cagrilar(fn)
        assert "_load" in cagrilar, f"{fn_adi} tabloyu/zinciri TAZELEMİYOR"
        assert cagrilmasi_gereken in cagrilar, (
            f"{fn_adi} {cagrilmasi_gereken}() ÇAĞIRMIYOR"
        )
        assert "_log_disa_aktarim" in cagrilar, (
            f"{fn_adi} indirme eylemini denetim kaydına YAZMIYOR"
        )

    # TXT de aynı üçüncü garantiyi (denetim kaydı) taşımalı — eskiden
    # taşımıyordu, bu turda eklendi.
    export_txt_fn = next(
        n for n in ast.walk(agac)
        if isinstance(n, ast.FunctionDef) and n.name == "_export_txt"
    )
    assert "_log_disa_aktarim" in _cagrilar(export_txt_fn), (
        "_export_txt indirme eylemini denetim kaydına YAZMIYOR"
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


# ══════════════════════════════════════════════════════════════════════════════
# Üç format — Tablo (CSV) ve İmzalı Rapor (PDF) dışa aktarımı
# ══════════════════════════════════════════════════════════════════════════════
#
# Görev: mockup üç dışa aktarım seçeneği istiyor — Düz Metin (TXT, üstteki
# testler), Tablo (CSV — Excel/SIEM için ayrık, kırpılmamış sütunlar),
# İmzalı Rapor (PDF — özet + zincir doğrulama sonucu + dış çıpa, RFC 3161
# mührü KASITLI OLARAK kapsam dışı, bkz. BACKLOG.md B-087 / SECURITY.md
# §4.25). Bu testler CORE katmanındaki `export_csv()`/`export_pdf()`'in
# doğru VERİYİ içerdiğini ölçüyor; UI kablolaması (düğme → sayfa filtresi
# → bu fonksiyonlar) ve indirme eyleminin denetim kaydına yazıldığı
# `tests/test_audit_log_view.py`'de.


def _satir(**kw: object) -> DenetimSatiri:
    varsayilan: dict[str, object] = dict(
        id=1, zaman="2026-08-30T12:00:00Z", islem="test_islem",
        kullanici="test.kullanici", kullanici_id=1,
        hwid="HWID-TAM-DEGERI-1234567890",
        detay="hwid=HWID-TAM-DEGERI-1234567890 role=Standart", halka="intact",
    )
    varsayilan.update(kw)
    return DenetimSatiri(**varsayilan)  # type: ignore[arg-type]


# ── CSV ──────────────────────────────────────────────────────────────────────


def test_csv_tum_sutunlari_yaziyor(tmp_path: Path):
    out = export_csv([_satir()], tmp_path / "d.csv")
    metin = out.read_text(encoding="utf-8-sig")
    satirlar = metin.splitlines()
    assert satirlar[0] == ",".join(
        ["ID", "Zaman (UTC)", "İşlem", "Kullanıcı", "Kullanıcı ID", "HWID",
         "Detay", "Zincir Halkası"]
    )
    assert satirlar[1] == (
        "1,2026-08-30T12:00:00Z,test_islem,test.kullanici,1,"
        "HWID-TAM-DEGERI-1234567890,hwid=HWID-TAM-DEGERI-1234567890 "
        "role=Standart,Sağlam"
    )


def test_csv_hwid_KIRPILMADAN_yaziyor(tmp_path: Path):
    """
    Asıl iddia: "Tablo" (CSV) UI tablosunun 16 karakterlik kırpmasını
    MİRAS ALMIYOR — SIEM/Excel için ayrık, TAM sütun (bkz. `DenetimSatiri`
    docstring'i).
    """
    uzun_hwid = "A" * 40
    out = export_csv([_satir(hwid=uzun_hwid)], tmp_path / "d.csv")
    metin = out.read_text(encoding="utf-8-sig")
    assert uzun_hwid in metin
    assert "…" not in metin


def test_csv_halka_metnini_kullaniyor(tmp_path: Path):
    out = export_csv(
        [_satir(id=1, halka="intact"), _satir(id=2, halka="broken"),
         _satir(id=3, halka="out_of_scope")],
        tmp_path / "d.csv",
    )
    metin = out.read_text(encoding="utf-8-sig")
    assert HALKA_METNI["intact"] in metin
    assert HALKA_METNI["broken"] in metin
    assert HALKA_METNI["out_of_scope"] in metin


def test_csv_excelde_dogru_acilmasi_icin_utf8_sig(tmp_path: Path):
    """`export_inventory_csv()` ile AYNI kodlama kararı — BOM'lu UTF-8."""
    out = export_csv([_satir(kullanici="Öğüt Çelik")], tmp_path / "d.csv")
    ham = out.read_bytes()
    assert ham.startswith(b"\xef\xbb\xbf"), "utf-8-sig BOM'u eksik"
    assert "Öğüt Çelik" in out.read_text(encoding="utf-8-sig")


def test_csv_bos_liste_yine_baslik_satirini_yaziyor(tmp_path: Path):
    out = export_csv([], tmp_path / "bos.csv")
    metin = out.read_text(encoding="utf-8-sig")
    assert metin.splitlines() == [
        "ID,Zaman (UTC),İşlem,Kullanıcı,Kullanıcı ID,HWID,Detay,Zincir Halkası"
    ]


def test_csv_ozel_karakterli_detay_dosyayi_bozmuyor(tmp_path: Path):
    """CSV mini-HTML kaçışına İHTİYAÇ duymuyor (PDF'in aksine) — `csv`
    modülü zaten virgül/tırnak kaçışını kendisi yönetiyor; yine de
    '&'/'<' içeren bir detay alanı dosyayı BOZMAMALI (çökme yok, satır
    kayıp değil)."""
    out = export_csv(
        [_satir(detay="filename=<script>alert(1)</script> & diger, virgullu")],
        tmp_path / "d.csv",
    )
    metin = out.read_text(encoding="utf-8-sig")
    assert "<script>alert(1)</script> & diger, virgullu" in metin


# ── CSV formül enjeksiyonu (CWE-1236) ────────────────────────────────────────
#
# Kod incelemesi: `csv.writer`'ın kendi kaçışlaması (RFC 4180 — virgül/
# tırnak/satır-içi-yenisatır) CSV SÖZDİZİMİNİ koruyor, hedef uygulamanın
# (Excel/LibreOffice Calc) bir hücreyi FORMÜL sanmasını KAPSAMIYOR — bu
# tamamen ayrı bir kusur sınıfı ve `export_csv()`/`export_inventory_csv()`
# bu turdan ÖNCE ona karşı HİÇBİR ŞEY yapmıyordu (satırlar `writer.
# writerow([s.id, s.zaman, ..., s.kullanici, ..., s.detay, ...])` ile
# doğrudan, kaçışlanmadan yazılıyordu — bkz. bu dosyanın Git geçmişi).
# Gerçek veriyle ölçüldü: kullanıcı adı `=1+1` olan bir kullanıcının
# denetim kaydı dışa aktarıldığında, üretilen CSV'nin o hücresi TAM
# OLARAK `=1+1` olarak, `csv.reader` ile geri okununca bile hâlâ ham
# hâliyle çıkıyordu — Excel/LibreOffice Calc'te açıldığında FORMÜL olarak
# değerlendirilirdi (OWASP CSV Injection / CWE-1236, yerleşik bir kusur
# sınıfı — bu depoda YENİDEN üretilmesi gerekmedi, doğrudan ölçüldü).
#
# Düzeltme: `CORE/csv_utils.py::csv_hucre_guvenli()` — tehlikeli bir
# önekle (`=`/`+`/`-`/`@`/sekme/CR) başlayan hücrenin BAŞINA tek bir
# tek-tırnak (`'`) ekliyor, standart CSV-injection savunması. Hem
# `export_csv()` (bu turun konusu) hem `export_inventory_csv()` (AYNI
# kusur, yol boyunca kardeş fonksiyonda bulundu) artık bu fonksiyonu
# kullanıyor — ikinci bir düzeltme kopyası YAZILMADI.


_TEHLIKELI_PAYLOADLAR = [
    "=1+1",
    "+cmd|'/c calc'!A1",
    "-2+3+cmd|'/c calc'!A1",
    "@SUM(1+1)",
    "\t=1+1",
    "\r=1+1",
]


def _csv_hucreleri(out: Path) -> list[list[str]]:
    """Üretilen CSV'yi GERÇEK `csv.reader` ile geri okur — ham metin
    araması değil, hücrenin bir CSV ayrıştırıcısının göreceği TAM
    değeri (bkz. görev notu: LibreOffice/openpyxl/pandas bu ortamda
    kurulu değil; `csv.reader` CSV-sözdizimi katmanını doğru şekilde
    çözüyor, bir sonraki katman — Excel/LibreOffice'in bir hücreyi
    formül SAYIP saymadığı — belgelenmiş, endüstri standardı bir kural:
    hücrenin HAM metni `=`/`+`/`-`/`@` ile başlıyorsa formül olarak
    değerlendirilir; `csv_hucre_guvenli()`'nin ürettiği baştaki `'`
    Excel/LibreOffice'in "bu hücre KESİNLİKLE metin" işaretidir)."""
    with out.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.reader(handle))


@pytest.mark.parametrize("payload", _TEHLIKELI_PAYLOADLAR)
def test_csv_formul_enjeksiyonu_kullanici_alaninda_etkisizlestiriliyor(
    tmp_path: Path, payload: str,
):
    """
    Asıl kanıt: kullanıcının KENDİ SEÇTİĞİ kullanıcı adı (kayıt sırasında
    serbestçe girilebiliyor — dosya adının aksine dosya sistemi
    kısıtlamalarına da tabi değil) tehlikeli bir önekle başlıyorsa, dışa
    aktarılan CSV'deki hücre artık ham DEĞİL — başında `'` var.
    """
    out = export_csv([_satir(kullanici=payload)], tmp_path / "d.csv")
    satirlar = _csv_hucreleri(out)
    hucre = satirlar[1][3]  # sütun 3 = Kullanıcı
    assert hucre == "'" + payload, (
        f"GUARD REGRESYONU: {payload!r} kaçışlanmadan yazılmış — "
        f"hücre: {hucre!r}"
    )
    assert not hucre.startswith(("=", "+", "-", "@", "\t", "\r")), (
        "kaçışlama sonrası hücre HÂLÂ tehlikeli bir önekle başlıyor"
    )


@pytest.mark.parametrize("payload", _TEHLIKELI_PAYLOADLAR)
def test_csv_formul_enjeksiyonu_detay_alaninda_etkisizlestiriliyor(
    tmp_path: Path, payload: str,
):
    """AYNI denetim, `detay` (audit_log.detail — dosya adı gibi kullanıcı
    girdisi taşıyabilen ham alan) için."""
    out = export_csv([_satir(detay=payload)], tmp_path / "d.csv")
    satirlar = _csv_hucreleri(out)
    hucre = satirlar[1][6]  # sütun 6 = Detay
    assert hucre == "'" + payload


def test_csv_formul_enjeksiyonu_hwid_alaninda_da_etkisizlestiriliyor(tmp_path: Path):
    out = export_csv([_satir(hwid="=1+1")], tmp_path / "d.csv")
    satirlar = _csv_hucreleri(out)
    assert satirlar[1][5] == "'=1+1"  # sütun 5 = HWID


def test_csv_zararsiz_degerler_DEGISMIYOR(tmp_path: Path):
    """
    Negatif test — yanlış pozitif üretmiyor: tehlikeli bir önekle
    BAŞLAMAYAN değerler (isim, tarih, ORTASINDA `=` geçen bir detay
    alanı) `csv_hucre_guvenli()`'den ETKİLENMEDEN geçiyor.
    """
    out = export_csv(
        [_satir(
            id=1, zaman="2026-08-30T12:00:00Z", kullanici="Ahmet Yılmaz",
            hwid="ABCDEF1234567890", detay="hwid=ABCDEF1234567890 role=Standart",
        )],
        tmp_path / "d.csv",
    )
    satirlar = _csv_hucreleri(out)
    satir = satirlar[1]
    assert satir[1] == "2026-08-30T12:00:00Z"
    assert satir[3] == "Ahmet Yılmaz"
    assert satir[5] == "ABCDEF1234567890"
    assert satir[6] == "hwid=ABCDEF1234567890 role=Standart", (
        "ORTASINDA '=' geçen ama BAŞINDA geçmeyen bir alan yanlışlıkla "
        "değiştirilmiş"
    )


def test_csv_hucre_guvenli_yalnizca_baslangictaki_oneke_bakiyor():
    """Birim düzeyinde — dosya I/O olmadan, `csv_hucre_guvenli()`'nin
    kendisi: hem pozitif hem negatif uçlar."""
    from CORE.csv_utils import csv_hucre_guvenli

    for tehlikeli in _TEHLIKELI_PAYLOADLAR:
        assert csv_hucre_guvenli(tehlikeli) == "'" + tehlikeli
    for zararsiz in ("Ahmet Yılmaz", "2026-08-30", "a=b", "dosya (1).hcl", ""):
        assert csv_hucre_guvenli(zararsiz) == zararsiz
    # Sayılar/None hiç dokunulmadan dönüyor.
    assert csv_hucre_guvenli(42) == 42
    assert csv_hucre_guvenli(None) is None


def test_csv_hucre_guvenli_bozuk_bir_onek_kumesi_yakalanir(
    monkeypatch: pytest.MonkeyPatch,
):
    """
    Mutasyon testi (b) — kapsamı EKSİK bir düzeltme (yalnızca `=`'i
    kontrol edip `+`/`-`/`@`'yi ATLAYAN bozuk bir versiyon) testte
    GERÇEKTEN yakalanıyor mu.
    """
    import CORE.csv_utils as cu

    monkeypatch.setattr(cu, "_TEHLIKELI_ONEKLER", ("=",))  # bilerek eksik

    assert cu.csv_hucre_guvenli("=1+1") == "'=1+1"  # bu hâlâ yakalanır
    for atlanan in ("+cmd|'/c calc'!A1", "-2+3+cmd|'/c calc'!A1", "@SUM(1+1)"):
        yakalanmadi = cu.csv_hucre_guvenli(atlanan)
        assert yakalanmadi == atlanan, (
            "test kurulumu hatalı — eksik önek kümesiyle bile kaçışlanmış"
        )
        assert yakalanmadi.startswith(("+", "-", "@")), (
            f"MUTASYON KONTRASTI BAŞARISIZ: eksik önek kümesi {atlanan!r}'i "
            "hâlâ yakalıyor gibi görünüyor — bu test kapsam eksikliğini "
            "GERÇEKTEN ölçmüyor olabilir"
        )


def test_inventory_csv_da_formul_enjeksiyonuna_karsi_korunuyor(tmp_path: Path):
    """
    Yol boyunca bulunan AYNI kusur, kardeş fonksiyonda: `CORE/
    inventory.py::export_inventory_csv()` da kullanıcı girdisi taşıyan
    sütunlar (dosya adı, sahip) için `csv_hucre_guvenli()`'yi kullanıyor
    mu — ikinci bir kopya, iki ayrı düzeltme YAZILMADI.
    """
    from CORE.inventory import InventoryRow, export_inventory_csv

    satir = InventoryRow(
        file_id=1, filename="=1+1", filepath="/vault/x.hcl",
        profile_id=None, profile_name="—", owner="+cmd|'/c calc'!A1",
        added_at="2026-08-30T12:00:00Z", destruction_date=None,
        status="aktif", last_activity=None,
    )
    out = export_inventory_csv([satir], tmp_path / "envanter.csv")
    with out.open(encoding="utf-8-sig", newline="") as handle:
        satirlar = list(csv.reader(handle))
    veri_satiri = satirlar[1]
    assert veri_satiri[0] == "'=1+1", "dosya adı kaçışlanmamış"
    assert veri_satiri[3] == "'+cmd|'/c calc'!A1", "sahip alanı kaçışlanmamış"


# ── PDF ──────────────────────────────────────────────────────────────────────
#
# `pageCompression=0` (bkz. `CORE/audit_report.py::export_pdf()`'in yorumu)
# gövde metnini ham baytlarda aranabilir kılıyor — `tests/test_inventory.py::
# test_baslik_gomulu`'nun AYNI deseni, burada gövdeye de genişletildi. Türkçe
# özel karakterler (Ğ/İ/Ş/ı) reportlab'ın yazı tipi kodlamasında ham UTF-8
# baytlarıyla EŞLEŞMİYOR — ölçüldü — bu yüzden aranan alt dizeler BİLEREK
# ASCII-güvenli (action adları, ID'ler, HWID'ler, "Denetim zinciri", "RFC 3161").


@pytest.fixture
def rapor_saglam(db, cipa) -> ZincirRaporu:
    _kayitlar(db)
    return zincir_raporu(db, cipa_yolu=cipa)


def test_pdf_gercek_pdf_uretiyor(rapor_saglam, tmp_path: Path):
    out = export_pdf([_satir()], rapor_saglam, tmp_path / "r.pdf")
    raw = out.read_bytes()
    assert raw.startswith(b"%PDF-")
    assert b"%%EOF" in raw[-1024:]


def test_pdf_satir_verisini_iceriyor(rapor_saglam, tmp_path: Path):
    out = export_pdf(
        [_satir(id=42, islem="usb_role_changed_TEST", kullanici="ayse.yilmaz",
                hwid="HWID-PDF-TEST-99999999")],
        rapor_saglam, tmp_path / "r.pdf",
    )
    raw = out.read_bytes()
    for beklenen in (b"42", b"usb_role_changed_TEST", b"ayse.yilmaz",
                     b"HWID-PDF-TEST-99999999"):
        assert beklenen in raw, f"{beklenen!r} PDF gövdesinde bulunamadı"


def test_pdf_zincir_durumunu_iceriyor(rapor_saglam, tmp_path: Path):
    """Görevin istediği "zincir doğrulama sonucu" — `rapor.baslik()`/
    `rapor.ayrinti()` PDF'e GERÇEKTEN gömülü mü."""
    out = export_pdf([_satir()], rapor_saglam, tmp_path / "r.pdf")
    raw = out.read_bytes()
    assert b"Denetim zinciri" in raw


def test_pdf_kirik_zincirde_kirik_diyor(db, cipa, tmp_path: Path):
    _kayitlar(db)
    _zinciri_kir(db)
    rapor = zincir_raporu(db, cipa_yolu=cipa)
    assert rapor.zincir.ok is False

    out = export_pdf([_satir()], rapor, tmp_path / "r.pdf")
    raw = out.read_bytes()
    assert b"KIRIK" in raw, "PDF kırık zinciri SAĞLAM gibi göstermiş olabilir"


def test_pdf_dis_cipa_ciktiyi_degistiriyor(db, cipa, tmp_path: Path):
    """
    Görevin istediği "dış çıpa dahil" — anchor yazılıp doğrulanınca PDF
    çıktısı GERÇEKTEN değişiyor mu (`rapor.ayrinti()` → `cipa.summary()`
    üzerinden). Metin karşılaştırması yerine BAYT karşılaştırması: Türkçe
    özel karakterler yüzünden tam metni ham baytlarda aramak güvenilmez
    (bkz. modül notu), ama "aynı zaman damgasıyla üretilen iki PDF'in TEK
    farkı çıpa durumuysa, çıktıları da FARKLI olmalı" iddiası kodlamadan
    bağımsız ve daha güçlü.
    """
    _kayitlar(db)
    rapor_cipasiz = zincir_raporu(db, cipa_yolu=cipa)
    assert rapor_cipasiz.cipa_var is False
    out1 = export_pdf([_satir()], rapor_cipasiz, tmp_path / "r1.pdf",
                       generated_at=_SIMDI)

    write_anchor(db, "test", path=cipa)
    rapor_cipali = zincir_raporu(db, cipa_yolu=cipa)
    assert rapor_cipali.cipa_var is True
    out2 = export_pdf([_satir()], rapor_cipali, tmp_path / "r2.pdf",
                       generated_at=_SIMDI)

    assert out1.read_bytes() != out2.read_bytes(), (
        "dış çıpa durumu PDF çıktısını hiç etkilemedi"
    )


def test_pdf_rfc3161_muhurlenmedigini_acikca_soyluyor(rapor_saglam, tmp_path: Path):
    """
    K4-20 kapsam kararı — kasıtlı, SESSİZ DEĞİL (bkz. BACKLOG.md B-087,
    SECURITY.md §4.25): PDF kendini RFC 3161 ile mühürlenmiş gibi
    GÖSTERMİYOR, açıkça YALANLIYOR — `txt_basligi()`'nin "bu dosya imzalı
    DEĞİLDİR" notuyla AYNI dürüstlük ilkesi.

    B-106: bu, `export_pdf()`'in VARSAYILANI (`sealed=False`) için hâlâ
    doğru — mühür artık GERÇEK olarak eklenebiliyor (`export_sealed_pdf()`,
    `sealed=True` metniyle), ama bu fonksiyonun kendi varsayılanı
    DEĞİŞMEDİ. Mühürlü yol testleri `tests/test_report_seal.py`'de.
    """
    out = export_pdf([_satir()], rapor_saglam, tmp_path / "r.pdf")
    assert b"RFC 3161" in out.read_bytes()


def test_pdf_bos_satir_listesi_yine_pdf_uretiyor(rapor_saglam, tmp_path: Path):
    out = export_pdf([], rapor_saglam, tmp_path / "bos.pdf")
    assert out.read_bytes().startswith(b"%PDF-")


def test_pdf_html_karakterleri_bozmuyor(rapor_saglam, tmp_path: Path):
    """`test_inventory.py::test_html_karakterleri_pdf_i_bozmuyor` ile AYNI
    denetim — denetim `detail`/`action`/`username` alanları da kullanıcı
    girdisi taşıyabilir ve reportlab Paragraph mini-HTML ayrıştırıyor."""
    out = export_pdf(
        [_satir(kullanici="a&b<script>x</script>", islem="file_added<tag>")],
        rapor_saglam, tmp_path / "kacis.pdf",
    )
    assert out.read_bytes().startswith(b"%PDF-")


def test_pdf_filtre_notu_yaziliyor(rapor_saglam, tmp_path: Path):
    out = export_pdf(
        [_satir()], rapor_saglam, tmp_path / "f.pdf",
        filters_note="sekme=Kimlik ISLEM_FILTRE_MARKER",
    )
    assert b"ISLEM_FILTRE_MARKER" in out.read_bytes()


def test_pdf_olmayan_dizin_olusturuluyor(rapor_saglam, tmp_path: Path):
    out = export_pdf([_satir()], rapor_saglam, tmp_path / "yeni" / "alt" / "e.pdf")
    assert out.exists()


def test_pdf_reportlab_yoksa_actikca_RuntimeError_veriyor(
    rapor_saglam, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """`export_inventory_pdf()`'in AYNI deseni: reportlab içe aktarımı
    fonksiyon İÇİNDE, ki eksikse TXT/CSV dışa aktarımı çalışmaya devam
    etsin — burada da eksik olduğunda anlaşılır bir hata veriyor mu."""
    import builtins

    gercek_import = builtins.__import__

    def _sahte_import(name, *a, **kw):
        if name == "reportlab" or name.startswith("reportlab."):
            raise ImportError("sahte: reportlab kurulu değil")
        return gercek_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", _sahte_import)
    with pytest.raises(RuntimeError, match="reportlab"):
        export_pdf([_satir()], rapor_saglam, tmp_path / "r.pdf")
