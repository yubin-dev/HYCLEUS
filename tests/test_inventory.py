"""
KVKK saklama envanteri — rapor içeriği, filtreler ve dışa aktarım.

CSV testleri dosyayı GERİ OKUYUP parse ediyor; PDF testleri üretilen dosyanın
gerçekten PDF olduğunu ve içeriğinin okunabildiğini doğruluyor.
"""
from __future__ import annotations

import csv
import itertools
import sqlite3
from datetime import date, datetime, timedelta, timezone

import pytest

from CORE.disposal import LABEL_IMHA, move_to_imha, sweep_retention_expired
from CORE.inventory import (
    COLUMN_HEADERS,
    NO_PROFILE_TEXT,
    STATUS_ACTIVE,
    STATUS_EXPIRED_PENDING,
    STATUS_IN_IMHA,
    STATUS_NO_PROFILE,
    STATUS_UNKNOWN,
    UNKNOWN_OWNER_TEXT,
    export_inventory_csv,
    export_inventory_pdf,
    generate_retention_inventory,
    inventory_summary,
)
from CORE.retention import (
    START_DOCUMENT,
    START_UPLOAD,
    UNIT_UNLIMITED,
    UNIT_YEAR,
    assign_profile,
    create_profile,
    destruction_date_for_file,
)

_sayac = itertools.count(1)


# ──────────────────────────────────────────────────────────────────────────────
# Yardımcılar
# ──────────────────────────────────────────────────────────────────────────────


def _mk_user(db, username=None, role="user"):
    username = username or f"kullanici{next(_sayac)}"
    cur = db.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        (username, "x", role),
    )
    return int(cur.lastrowid)


def _mk_file(db, tmp_path, *, filename="belge.pdf", added_at=None, label="Genel",
             added_by=None):
    added_at = added_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    hcl = tmp_path / f"{filename}.hcl"
    hcl.write_bytes(b"x")
    cur = db.execute(
        "INSERT INTO files (filename, filepath, label, added_at, added_by)"
        " VALUES (?, ?, ?, ?, ?)",
        (filename, str(hcl), label, added_at, added_by),
    )
    return int(cur.lastrowid), hcl


def _profile(db, *, years=10, protected=True, name=None, unlimited=False,
             start_type=START_UPLOAD):
    name = name or f"profil{next(_sayac)}"
    if unlimited:
        return create_profile(db, name=name, duration_value=None,
                              duration_unit=UNIT_UNLIMITED, start_type=start_type,
                              early_delete_protection=protected)
    return create_profile(db, name=name, duration_value=years,
                          duration_unit=UNIT_YEAR, start_type=start_type,
                          early_delete_protection=protected)


def _old_date(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _by_name(rows):
    return {r.filename: r for r in rows}


# ──────────────────────────────────────────────────────────────────────────────
# Rapor içeriği
# ──────────────────────────────────────────────────────────────────────────────


class TestRaporIcerigi:
    def test_bos_veritabani(self, db):
        assert generate_retention_inventory(db) == []

    def test_temel_alanlar(self, db, tmp_path):
        owner = _mk_user(db, "ayse")
        fid, hcl = _mk_file(db, tmp_path, filename="sozlesme.pdf",
                            added_at="2026-01-15T10:30:00Z", added_by=owner)
        pid = _profile(db, years=10, name="Mali müşavir - 10 yıl")
        assign_profile(db, fid, pid)

        row = generate_retention_inventory(db)[0]
        assert row.file_id == fid
        assert row.filename == "sozlesme.pdf"
        assert row.filepath == str(hcl)
        assert row.profile_id == pid
        assert row.profile_name == "Mali müşavir - 10 yıl"
        assert row.owner == "ayse"
        assert row.added_at == "2026-01-15T10:30:00Z"
        assert row.destruction_date == date(2036, 1, 15)
        assert row.status == STATUS_ACTIVE

    def test_dosya_adina_gore_sirali(self, db, tmp_path):
        for name in ("zebra.pdf", "ahmet.pdf", "mehmet.pdf"):
            _mk_file(db, tmp_path, filename=name)
        names = [r.filename for r in generate_retention_inventory(db)]
        assert names == sorted(names)

    def test_son_islem_audit_logdan(self, db, tmp_path):
        fid, _ = _mk_file(db, tmp_path)
        db.log("file_added", target_type="file", target_id=fid)
        db.execute(
            "UPDATE audit_log SET timestamp = ? WHERE target_id = ?",
            ("2026-03-01T09:00:00Z", fid),
        )
        db.log("file_label_changed", target_type="file", target_id=fid)
        db.execute(
            "UPDATE audit_log SET timestamp = ? WHERE action = 'file_label_changed'",
            ("2026-05-20T14:00:00Z",),
        )
        assert generate_retention_inventory(db)[0].last_activity == "2026-05-20T14:00:00Z"

    def test_audit_kaydi_yoksa_none(self, db, tmp_path):
        _mk_file(db, tmp_path)
        assert generate_retention_inventory(db)[0].last_activity is None

    def test_baska_dosyanin_audit_kaydi_karismiyor(self, db, tmp_path):
        f1, _ = _mk_file(db, tmp_path, filename="a.pdf")
        f2, _ = _mk_file(db, tmp_path, filename="b.pdf")
        db.log("file_added", target_type="file", target_id=f1)
        rows = _by_name(generate_retention_inventory(db))
        assert rows["a.pdf"].last_activity is not None
        assert rows["b.pdf"].last_activity is None

    def test_kullanici_turu_hedefi_karismiyor(self, db, tmp_path):
        """audit_log'da target_type='user' kaydı dosya satırına sızmamalı."""
        fid, _ = _mk_file(db, tmp_path)
        db.log("user_login", target_type="user", target_id=fid)
        assert generate_retention_inventory(db)[0].last_activity is None

    def test_ozet(self, db, tmp_path):
        _mk_file(db, tmp_path, filename="profilsiz.pdf")
        fid, _ = _mk_file(db, tmp_path, filename="aktif.pdf")
        assign_profile(db, fid, _profile(db, years=10))
        ozet = inventory_summary(generate_retention_inventory(db))
        assert ozet[STATUS_NO_PROFILE] == 1
        assert ozet[STATUS_ACTIVE] == 1
        assert ozet[STATUS_IN_IMHA] == 0


class TestProfilsizDosyalar:
    def test_profil_atanmamis_yaziyor(self, db, tmp_path):
        _mk_file(db, tmp_path)
        row = generate_retention_inventory(db)[0]
        assert row.profile_id is None
        assert row.profile_name == NO_PROFILE_TEXT
        assert row.status == STATUS_NO_PROFILE

    def test_imha_tarihi_yok(self, db, tmp_path):
        _mk_file(db, tmp_path)
        row = generate_retention_inventory(db)[0]
        assert row.destruction_date is None
        assert row.destruction_date_text == "—"

    def test_sahip_bilinmiyor(self, db, tmp_path):
        """added_by NULL — bugün tüm gerçek dosyalar böyle (bkz. B-005)."""
        _mk_file(db, tmp_path, added_by=None)
        assert generate_retention_inventory(db)[0].owner == UNKNOWN_OWNER_TEXT

    def test_silinen_kullanici_sonrasi(self, db, tmp_path):
        """ON DELETE SET NULL — kullanıcı silinince dosya kalır, sahip boşalır."""
        owner = _mk_user(db, "gidecek")
        _mk_file(db, tmp_path, added_by=owner)
        db.execute("DELETE FROM users WHERE id = ?", (owner,))
        assert generate_retention_inventory(db)[0].owner == UNKNOWN_OWNER_TEXT


# ──────────────────────────────────────────────────────────────────────────────
# Önceki turlarla tutarlılık — raporun en önemli özelliği
# ──────────────────────────────────────────────────────────────────────────────


class TestTutarlilik:
    def test_imha_tarihi_destruction_date_for_file_ile_ayni(self, db, tmp_path):
        """Rapor kendi tarih hesabını yapmamalı."""
        beklenen = {}
        for i, (gun, yil) in enumerate([(0, 10), (400, 1), (4000, 5)]):
            fid, _ = _mk_file(db, tmp_path, filename=f"d{i}.pdf", added_at=_old_date(gun))
            assign_profile(db, fid, _profile(db, years=yil))
            beklenen[f"d{i}.pdf"] = destruction_date_for_file(db, fid)

        for name, row in _by_name(generate_retention_inventory(db)).items():
            assert row.destruction_date == beklenen[name]

    def test_durum_check_disposal_ile_tutarli(self, db, tmp_path):
        """Rapordaki 'süresi doldu', disposal'ın 'serbest' dediğiyle aynı olmalı."""
        from CORE.disposal import check_disposal

        dolmus, _ = _mk_file(db, tmp_path, filename="dolmus.pdf", added_at=_old_date(4000))
        assign_profile(db, dolmus, _profile(db, years=1))
        aktif, _ = _mk_file(db, tmp_path, filename="aktif.pdf")
        assign_profile(db, aktif, _profile(db, years=10))

        rows = _by_name(generate_retention_inventory(db))
        assert rows["dolmus.pdf"].status == STATUS_EXPIRED_PENDING
        assert check_disposal(db, dolmus).retention_expired is True
        assert rows["aktif.pdf"].status == STATUS_ACTIVE
        assert check_disposal(db, aktif).needs_approval is True

    def test_supurmeden_sonra_durum_degisiyor(self, db, tmp_path):
        fid, _ = _mk_file(db, tmp_path, added_at=_old_date(4000))
        assign_profile(db, fid, _profile(db, years=1))
        assert generate_retention_inventory(db)[0].status == STATUS_EXPIRED_PENDING

        sweep_retention_expired(db)
        assert generate_retention_inventory(db)[0].status == STATUS_IN_IMHA

    def test_imha_odasi_etiketi_durumdan_once_geliyor(self, db, tmp_path):
        """Süresi dolmamış ama İmha Odası'na atılmış dosya 'imha_odasinda'."""
        fid, _ = _mk_file(db, tmp_path)
        assign_profile(db, fid, _profile(db, years=10, protected=False))
        move_to_imha(db, fid, user_confirmed=True)
        row = generate_retention_inventory(db)[0]
        assert row.status == STATUS_IN_IMHA
        # İmha tarihi yine de raporlanıyor: "erken mi taşınmış?" sorusu için
        assert row.destruction_date is not None

    def test_suresiz_profil(self, db, tmp_path):
        fid, _ = _mk_file(db, tmp_path)
        assign_profile(db, fid, _profile(db, unlimited=True))
        row = generate_retention_inventory(db)[0]
        assert row.status == STATUS_ACTIVE
        assert row.destruction_date is None
        assert row.destruction_date_text == "süresiz"

    def test_hesaplanamayan_satir_raporda_kaliyor(self, db, tmp_path):
        """Envanterden sessizce kaybolan dosya, raporun yakalaması gereken şey."""
        fid, _ = _mk_file(db, tmp_path, filename="bozuk.pdf")
        pid = _profile(db, years=5, start_type=START_DOCUMENT)
        db.execute("UPDATE files SET retention_profile_id = ? WHERE id = ?", (pid, fid))

        row = generate_retention_inventory(db)[0]
        assert row.status == STATUS_UNKNOWN
        assert row.destruction_date_text == "hesaplanamadı"
        assert "elle girilmeli" in row.note

    def test_profil_uzatilinca_rapor_guncelleniyor(self, db, tmp_path):
        """İmha tarihi türetilmiş — DB'de saklanmadığı için bayatlayamaz."""
        from CORE.retention import update_profile

        fid, _ = _mk_file(db, tmp_path, added_at=_old_date(4000))
        pid = _profile(db, years=1)
        assign_profile(db, fid, pid)
        assert generate_retention_inventory(db)[0].status == STATUS_EXPIRED_PENDING

        update_profile(db, pid, duration_value=50)
        assert generate_retention_inventory(db)[0].status == STATUS_ACTIVE


# ──────────────────────────────────────────────────────────────────────────────
# Filtreler
# ──────────────────────────────────────────────────────────────────────────────


class TestFiltreler:
    @pytest.fixture
    def veri(self, db, tmp_path):
        p10 = _profile(db, years=10, name="On yil")
        p1 = _profile(db, years=1, name="Bir yil")
        aktif, _ = _mk_file(db, tmp_path, filename="aktif.pdf",
                            added_at="2026-01-10T00:00:00Z")
        assign_profile(db, aktif, p10)
        dolmus, _ = _mk_file(db, tmp_path, filename="dolmus.pdf", added_at=_old_date(4000))
        assign_profile(db, dolmus, p1)
        profilsiz, _ = _mk_file(db, tmp_path, filename="profilsiz.pdf",
                                added_at="2026-06-20T00:00:00Z")
        return {"p10": p10, "p1": p1, "aktif": aktif,
                "dolmus": dolmus, "profilsiz": profilsiz}

    def test_filtresiz_hepsi(self, db, veri):
        assert len(generate_retention_inventory(db)) == 3

    def test_profile_gore(self, db, veri):
        rows = generate_retention_inventory(db, profile_id=veri["p10"])
        assert [r.filename for r in rows] == ["aktif.pdf"]

    def test_profile_gore_eslesme_yok(self, db, veri):
        assert generate_retention_inventory(db, profile_id=9999) == []

    def test_duruma_gore(self, db, veri):
        rows = generate_retention_inventory(db, status=STATUS_NO_PROFILE)
        assert [r.filename for r in rows] == ["profilsiz.pdf"]

    def test_coklu_durum(self, db, veri):
        rows = generate_retention_inventory(
            db, status=[STATUS_NO_PROFILE, STATUS_EXPIRED_PENDING]
        )
        assert sorted(r.filename for r in rows) == ["dolmus.pdf", "profilsiz.pdf"]

    def test_gecersiz_durum(self, db, veri):
        with pytest.raises(ValueError, match="Bilinmeyen durum"):
            generate_retention_inventory(db, status="sacma")

    def test_yukleme_tarihi_araligi(self, db, veri):
        rows = generate_retention_inventory(
            db, added_from="2026-01-01", added_to="2026-03-01"
        )
        assert [r.filename for r in rows] == ["aktif.pdf"]

    def test_yukleme_tarihi_alt_sinir(self, db, veri):
        rows = generate_retention_inventory(db, added_from="2026-06-01")
        assert [r.filename for r in rows] == ["profilsiz.pdf"]

    def test_yukleme_tarihi_uc_degerler_dahil(self, db, veri):
        rows = generate_retention_inventory(
            db, added_from="2026-01-10", added_to="2026-01-10"
        )
        assert [r.filename for r in rows] == ["aktif.pdf"]

    def test_imha_tarihi_araligi(self, db, veri):
        rows = generate_retention_inventory(
            db, destruction_from="2036-01-01", destruction_to="2036-12-31"
        )
        assert [r.filename for r in rows] == ["aktif.pdf"]

    def test_imha_tarihi_olmayanlar_eleniyor(self, db, veri):
        """Profilsiz/süresiz satır bir tarih aralığına giremez."""
        rows = generate_retention_inventory(db, destruction_from="1900-01-01",
                                            destruction_to="2999-12-31")
        assert "profilsiz.pdf" not in [r.filename for r in rows]

    def test_filtreler_ve_ile_birlesiyor(self, db, veri):
        rows = generate_retention_inventory(
            db, profile_id=veri["p10"], status=STATUS_NO_PROFILE
        )
        assert rows == []

    def test_bugun_enjekte_edilebiliyor(self, db, tmp_path):
        fid, _ = _mk_file(db, tmp_path, added_at="2020-01-15T00:00:00Z")
        assign_profile(db, fid, _profile(db, years=5))
        assert generate_retention_inventory(
            db, today=date(2025, 1, 14)
        )[0].status == STATUS_ACTIVE
        assert generate_retention_inventory(
            db, today=date(2025, 1, 15)
        )[0].status == STATUS_EXPIRED_PENDING


# ──────────────────────────────────────────────────────────────────────────────
# CSV dışa aktarımı — geri okuyup parse ederek doğrulanıyor
# ──────────────────────────────────────────────────────────────────────────────


class TestCSVExport:
    @pytest.fixture
    def rows(self, db, tmp_path):
        owner = _mk_user(db, "ayse")
        fid, _ = _mk_file(db, tmp_path, filename="sozlesme.pdf",
                          added_at="2026-01-15T10:30:00Z", added_by=owner)
        assign_profile(db, fid, _profile(db, years=10, name="On yillik"))
        _mk_file(db, tmp_path, filename="serbest.pdf")
        return generate_retention_inventory(db)

    def test_dosya_olusuyor(self, rows, tmp_path):
        out = export_inventory_csv(rows, tmp_path / "envanter.csv")
        assert out.exists() and out.stat().st_size > 0

    def test_geri_okunuyor(self, rows, tmp_path):
        out = export_inventory_csv(rows, tmp_path / "envanter.csv")
        with out.open(encoding="utf-8-sig", newline="") as fh:
            parsed = list(csv.reader(fh))
        assert parsed[0] == list(COLUMN_HEADERS)
        assert len(parsed) == len(rows) + 1

    def test_icerik_dogru(self, rows, tmp_path):
        out = export_inventory_csv(rows, tmp_path / "envanter.csv")
        with out.open(encoding="utf-8-sig", newline="") as fh:
            kayitlar = {r["Dosya adı"]: r for r in csv.DictReader(fh)}

        sozlesme = kayitlar["sozlesme.pdf"]
        assert sozlesme["Saklama profili"] == "On yillik"
        assert sozlesme["Sahip"] == "ayse"
        assert sozlesme["İlk kayıt tarihi"] == "2026-01-15T10:30:00Z"
        assert sozlesme["İmha tarihi"] == "2036-01-15"
        assert sozlesme["Durum"] == "Aktif"

        serbest = kayitlar["serbest.pdf"]
        assert serbest["Saklama profili"] == NO_PROFILE_TEXT
        assert serbest["Sahip"] == UNKNOWN_OWNER_TEXT
        assert serbest["İmha tarihi"] == "—"
        assert serbest["Durum"] == "Profil atanmamış"

    def test_turkce_karakterler_bozulmuyor(self, db, tmp_path):
        fid, _ = _mk_file(db, tmp_path, filename="şirket_özgeçmiş_İĞÜ.pdf")
        assign_profile(db, fid, _profile(db, name="Müşavir — 10 yıl"))
        out = export_inventory_csv(generate_retention_inventory(db),
                                   tmp_path / "tr.csv")
        with out.open(encoding="utf-8-sig", newline="") as fh:
            row = next(csv.DictReader(fh))
        assert row["Dosya adı"] == "şirket_özgeçmiş_İĞÜ.pdf"
        assert row["Saklama profili"] == "Müşavir — 10 yıl"

    def test_bom_yaziliyor(self, rows, tmp_path):
        """Excel'in UTF-8'i tanıması için — BOM'suz Türkçe karakterler bozuluyor."""
        out = export_inventory_csv(rows, tmp_path / "envanter.csv")
        assert out.read_bytes().startswith(b"\xef\xbb\xbf")

    def test_bos_satir_girmiyor(self, rows, tmp_path):
        """newline='' olmadan Windows'ta her satır arasına boş satır girerdi."""
        out = export_inventory_csv(rows, tmp_path / "envanter.csv")
        assert b"\r\r\n" not in out.read_bytes()

    def test_virgullu_dosya_adi_kaciriliyor(self, db, tmp_path):
        _mk_file(db, tmp_path, filename="rapor, nihai.pdf")
        out = export_inventory_csv(generate_retention_inventory(db),
                                   tmp_path / "virgul.csv")
        with out.open(encoding="utf-8-sig", newline="") as fh:
            assert next(csv.DictReader(fh))["Dosya adı"] == "rapor, nihai.pdf"

    def test_bos_envanter(self, db, tmp_path):
        out = export_inventory_csv(generate_retention_inventory(db),
                                   tmp_path / "bos.csv")
        with out.open(encoding="utf-8-sig", newline="") as fh:
            assert list(csv.reader(fh)) == [list(COLUMN_HEADERS)]

    def test_olmayan_dizin_olusturuluyor(self, rows, tmp_path):
        out = export_inventory_csv(rows, tmp_path / "yeni" / "alt" / "e.csv")
        assert out.exists()


# ──────────────────────────────────────────────────────────────────────────────
# PDF dışa aktarımı
# ──────────────────────────────────────────────────────────────────────────────


class TestPDFExport:
    @pytest.fixture
    def rows(self, db, tmp_path):
        owner = _mk_user(db, "ayse")
        fid, _ = _mk_file(db, tmp_path, filename="sozlesme.pdf",
                          added_at="2026-01-15T10:30:00Z", added_by=owner)
        assign_profile(db, fid, _profile(db, years=10, name="On yillik"))
        _mk_file(db, tmp_path, filename="serbest.pdf")
        return generate_retention_inventory(db)

    def test_dosya_olusuyor(self, rows, tmp_path):
        out = export_inventory_pdf(rows, tmp_path / "envanter.pdf")
        assert out.exists() and out.stat().st_size > 0

    def test_gercek_pdf(self, rows, tmp_path):
        out = export_inventory_pdf(rows, tmp_path / "envanter.pdf")
        raw = out.read_bytes()
        assert raw.startswith(b"%PDF-")
        assert b"%%EOF" in raw[-1024:]

    def test_baslik_gomulu(self, rows, tmp_path):
        out = export_inventory_pdf(rows, tmp_path / "envanter.pdf",
                                   title="KVKK Saklama Envanteri")
        assert b"KVKK" in out.read_bytes()

    def test_bos_envanter_yine_pdf_uretiyor(self, db, tmp_path):
        out = export_inventory_pdf([], tmp_path / "bos.pdf")
        assert out.read_bytes().startswith(b"%PDF-")

    def test_cok_satir_sayfalara_boluyor(self, db, tmp_path):
        for i in range(120):
            _mk_file(db, tmp_path, filename=f"dosya_{i:03d}.pdf")
        rows = generate_retention_inventory(db)
        out = export_inventory_pdf(rows, tmp_path / "cok.pdf")
        assert out.read_bytes().count(b"/Type /Page\n") > 1 or b"/Count" in out.read_bytes()
        assert len(rows) == 120

    def test_html_karakterleri_pdf_i_bozmuyor(self, db, tmp_path):
        """
        Dosya adı kullanıcı girdisi — Paragraph mini-HTML ayrıştırıyor.

        Satır doğrudan DB'ye yazılıyor: Windows '<' ve '>' içeren dosya adı
        oluşturmaya izin vermiyor, ama bu adlar DB'ye başka yollardan
        girebilir (taşınmış vault, elle kayıt, başka platform).
        """
        db.execute(
            "INSERT INTO files (filename, filepath) VALUES (?, ?)",
            ("a&b<script>x</script>.pdf", "/vault/a&b<script>.hcl"),
        )
        out = export_inventory_pdf(generate_retention_inventory(db),
                                   tmp_path / "kacis.pdf")
        assert out.read_bytes().startswith(b"%PDF-")

    def test_uzun_yol_uretimi_dusurmuyor(self, db, tmp_path):
        derin = tmp_path / ("uzun_" * 20)
        derin.mkdir(parents=True, exist_ok=True)
        _mk_file(db, derin, filename="derindeki.pdf")
        out = export_inventory_pdf(generate_retention_inventory(db),
                                   tmp_path / "uzun.pdf")
        assert out.read_bytes().startswith(b"%PDF-")

    def test_filtre_notu_yaziliyor(self, rows, tmp_path):
        out = export_inventory_pdf(rows, tmp_path / "f.pdf",
                                   filters_note="durum=aktif")
        assert out.exists()

    def test_olmayan_dizin_olusturuluyor(self, rows, tmp_path):
        out = export_inventory_pdf(rows, tmp_path / "yeni" / "alt" / "e.pdf")
        assert out.exists()

    def test_zaman_damgasi_enjekte_edilebiliyor(self, rows, tmp_path):
        out = export_inventory_pdf(
            rows, tmp_path / "z.pdf",
            generated_at=datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc),
        )
        assert out.exists()


# ──────────────────────────────────────────────────────────────────────────────
# Uçtan uca
# ──────────────────────────────────────────────────────────────────────────────


class TestUctanUca:
    def test_filtreli_rapor_iki_formatta(self, db, tmp_path):
        dolmus, _ = _mk_file(db, tmp_path, filename="dolmus.pdf", added_at=_old_date(4000))
        assign_profile(db, dolmus, _profile(db, years=1))
        aktif, _ = _mk_file(db, tmp_path, filename="aktif.pdf")
        assign_profile(db, aktif, _profile(db, years=10))

        rows = generate_retention_inventory(db, status=STATUS_EXPIRED_PENDING)
        assert [r.filename for r in rows] == ["dolmus.pdf"]

        csv_out = export_inventory_csv(rows, tmp_path / "f.csv")
        pdf_out = export_inventory_pdf(rows, tmp_path / "f.pdf")

        with csv_out.open(encoding="utf-8-sig", newline="") as fh:
            kayitlar = list(csv.DictReader(fh))
        assert len(kayitlar) == 1
        assert kayitlar[0]["Durum"] == "Süresi doldu — onay bekliyor"
        assert pdf_out.read_bytes().startswith(b"%PDF-")

    def test_supurulmus_dosya_envanterde_gorunuyor(self, db, tmp_path):
        """Süpürülen dosya hâlâ envanterde — silinmedi, onay bekliyor."""
        fid, hcl = _mk_file(db, tmp_path, added_at=_old_date(4000))
        assign_profile(db, fid, _profile(db, years=1))
        sweep_retention_expired(db)

        row = generate_retention_inventory(db)[0]
        assert row.status == STATUS_IN_IMHA
        assert hcl.exists()
        assert db.fetchone(
            "SELECT label FROM files WHERE id = ?", (fid,)
        )["label"] == LABEL_IMHA


# ══════════════════════════════════════════════════════════════════════════════
# Eşzamanlı yazma altında tutarlılık — 2026-08-29
# ══════════════════════════════════════════════════════════════════════════════
#
# `generate_retention_inventory()` tek bir `_BASE_QUERY` JOIN'iyle başlıyor
# (files + retention_profiles + users + audit_log alt sorgusu), ama HER
# satır için `_row_status_and_date()` → `check_disposal()` `files`/
# `retention_profiles`'ı N+1 deseninde AYRICA, YENİDEN okuyor (modülün kendi
# "Bu N+1 sorgu demektir" notu). İki okuma kümesi AYNI transaction'da
# olmazsa: rapor üretimi SIRASINDA bir dosyanın saklama profili
# değiştirilirse, o satırın `profile_name`'i (BAŞ sorgudan, ESKİ) ile
# `status`/`destruction_date`'i (check_disposal'dan, YENİ) BİRBİRİYLE
# ÇELİŞEBİLİR — modülün kendi "rapor ile uygulama ayrışamaz" güvencesini
# KIRAN, kendi içinde tutarsız bir KVKK denetim satırı.


class TestEszamanliYazmaAltindaTutarlilik:
    def _iki_dosya_ve_iki_profil(self, db, tmp_path):
        """`b_ikinci.pdf` 400 gün önce eklenmiş — `profil_eski` (10 yıl)
        altında hâlâ AKTİF, ama `profil_yeni` (1 yıl) altında SÜRESİ DOLMUŞ
        olurdu. İki profil arasında geçiş, `status`'u GÖZLE GÖRÜLÜR biçimde
        değiştiriyor — torn-read'i saklamayan bir kurulum."""
        profil_eski = _profile(db, years=10, protected=True, name="ESKI-PROFIL")
        profil_yeni = _profile(db, years=1, protected=False, name="YENI-PROFIL")
        fid1, _ = _mk_file(db, tmp_path, filename="a_birinci.pdf")
        assign_profile(db, fid1, profil_eski)
        fid2, _ = _mk_file(db, tmp_path, filename="b_ikinci.pdf", added_at=_old_date(400))
        assign_profile(db, fid2, profil_eski)
        return fid1, fid2, profil_eski, profil_yeni

    def _ikinci_dosyayi_eszamanli_profil_degistir(self, db_path, fid2, profil_yeni):
        yazan = sqlite3.connect(str(db_path))
        try:
            yazan.execute(
                "UPDATE files SET retention_profile_id = ? WHERE id = ?",
                (profil_yeni, fid2),
            )
            yazan.commit()
        finally:
            yazan.close()

    def test_building_block_is_torn_by_a_concurrent_profile_reassignment(
        self, db, tmp_path,
    ):
        """
        KALICI regresyon kilidi: temel sorgu + per-satır `check_disposal()`
        çağrılarını (`generate_retention_inventory()`'nin sarmalayıcısı
        OLMADAN, düzeltmeden ÖNCEki hâliyle) elle tekrarlamak, bir satırın
        `profile_name`'i (ESKİ) ile `status`'ünün (YENİ) ÇELİŞTİĞİ bir
        sonuç üretir.
        """
        from CORE.inventory import _BASE_QUERY, _row_status_and_date

        fid1, fid2, profil_eski, profil_yeni = self._iki_dosya_ve_iki_profil(db, tmp_path)

        ham_satirlar = {r["file_id"]: r for r in db.fetchall(_BASE_QUERY)}
        assert ham_satirlar[fid2]["profile_name"] == "ESKI-PROFIL"

        # "Eşzamanlı" yazma — temel sorgu ZATEN okundu, fid2'nin
        # check_disposal()'ı HENÜZ çalışmadı.
        self._ikinci_dosyayi_eszamanli_profil_degistir(db._db_path, fid2, profil_yeni)

        durum, imha_tarihi, _not = _row_status_and_date(db, ham_satirlar[fid2], None)

        # YIRTIK: profile_name hâlâ ESKİ profili gösteriyor (temel sorgudan,
        # yazmadan ÖNCE), ama status YENİ profile göre hesaplandı (yazmadan
        # SONRA) — 400 günlük dosya 1 yıllık profilde SÜRESİ DOLMUŞ olur.
        assert ham_satirlar[fid2]["profile_name"] == "ESKI-PROFIL"
        assert durum == STATUS_EXPIRED_PENDING, (
            "beklenen: sarmalanmamış çağrı, profile_name ESKİ'yi gösterirken "
            f"status'ün YENİ profile göre hesaplanmasına izin verir, bulunan: {durum}"
        )

    def test_generate_retention_inventory_is_a_single_consistent_snapshot(
        self, db, tmp_path, monkeypatch,
    ):
        """
        ANA TEST: gerçek `generate_retention_inventory()`, fid2'nin
        `check_disposal()`'ı ÜZERİNDEYKEN gelen bir eşzamanlı profil
        değişikliğine rağmen tek bir tutarlı anlık görüntü üretmeli —
        `profile_name` ve `status` AYNI (yazmadan ÖNCEki) profile göre
        hesaplanmalı, biri eski biri yeni bir karışım DEĞİL.
        """
        fid1, fid2, profil_eski, profil_yeni = self._iki_dosya_ve_iki_profil(db, tmp_path)

        orijinal_fetchone = db.fetchone
        tetiklendi = {"yazildi": False}

        def _fid2_okunurken_araya_gir(sql, params=()):
            if (
                "retention_profile_id FROM files WHERE id" in sql
                and params == (fid2,)
                and not tetiklendi["yazildi"]
            ):
                tetiklendi["yazildi"] = True
                self._ikinci_dosyayi_eszamanli_profil_degistir(
                    db._db_path, fid2, profil_yeni
                )
            return orijinal_fetchone(sql, params)

        monkeypatch.setattr(db, "fetchone", _fid2_okunurken_araya_gir)

        rows = generate_retention_inventory(db)
        assert tetiklendi["yazildi"], "test kurulumu hatalı — araya girme hiç tetiklenmedi"

        satir2 = _by_name(rows)["b_ikinci.pdf"]
        # Tutarlı = TAMAMEN eski (yazmadan ÖNCEki) hâl: hem profile_name
        # hem status ESKİ profile (10 yıl, henüz dolmamış → AKTİF) göre.
        assert satir2.profile_name == "ESKI-PROFIL", (
            f"profile_name beklenmedik biçimde yeni profili gösteriyor: "
            f"{satir2.profile_name}"
        )
        assert satir2.status == STATUS_ACTIVE, (
            f"status ESKİ profile göre AKTİF olmalıydı, bulunan: {satir2.status} "
            "(YIRTIK anlık görüntü — BEGIN...COMMIT sarmalayıcısı çalışmıyor demektir)"
        )

        satir1 = _by_name(rows)["a_birinci.pdf"]
        assert satir1.profile_name == "ESKI-PROFIL"
        assert satir1.status == STATUS_ACTIVE

    def test_transaction_closes_even_if_a_row_check_raises(self, db, tmp_path, monkeypatch):
        """
        Hata dayanıklılığı — `CORE/backup.py::create_backup()` için yazılan
        aynı kontrol burada da geçerli: `_row_status_and_date()`'in
        `RetentionError` DIŞINDAKİ bir hatayla patlaması, `BEGIN` edilmiş
        transaction'ı ASILI BIRAKMAMALI. `finally`'deki `COMMIT`'in HER
        İKİ yolda (hatalı/hatasız) da çalıştığı doğrulanıyor.
        """
        fid1, fid2, _eski, _yeni = self._iki_dosya_ve_iki_profil(db, tmp_path)

        orijinal_fetchone = db.fetchone

        def _fid2_okunurken_patla(sql, params=()):
            if "retention_profile_id FROM files WHERE id" in sql and params == (fid2,):
                raise RuntimeError("yapay hata — satır kontrolü sırasında")
            return orijinal_fetchone(sql, params)

        monkeypatch.setattr(db, "fetchone", _fid2_okunurken_patla)

        assert db.conn.in_transaction is False, "test öncesi zaten açık bir transaction var"

        with pytest.raises(RuntimeError, match="yapay hata"):
            generate_retention_inventory(db)

        assert db.conn.in_transaction is False, (
            "transaction ASILI/AÇIK kaldı — finally'deki COMMIT çalışmamış "
            "olabilir, bu sonraki bir checkpoint/WAL kısaltmasını bloklardı"
        )
        # Bağlantı hâlâ kullanılabilir olmalı.
        assert db.fetchone("SELECT COUNT(*) AS n FROM files")["n"] == 2
