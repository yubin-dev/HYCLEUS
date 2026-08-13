"""
Saklama profilleri — veri modeli, CRUD, şablon seed'i ve imha tarihi hesabı.

Silme akışı ve UI kapsam dışı (sonraki adımlar); burada yalnızca veri
modelinin kendisi sınanıyor.
"""
from __future__ import annotations

from datetime import date

import pytest

from CORE.retention import (
    BUILTIN_TEMPLATES,
    MANUAL_START_TYPES,
    START_DOCUMENT,
    START_EVENT,
    START_UPLOAD,
    UNIT_DAY,
    UNIT_MONTH,
    UNIT_UNLIMITED,
    UNIT_YEAR,
    DuplicateProfileNameError,
    RetentionError,
    add_duration,
    assign_profile,
    compute_destruction_date,
    create_profile,
    delete_profile,
    destruction_date_for_file,
    files_using_profile,
    get_profile,
    get_profile_by_name,
    list_profiles,
    resolve_start_date,
    seed_builtin_templates,
    update_profile,
)

# ──────────────────────────────────────────────────────────────────────────────
# Yardımcılar
# ──────────────────────────────────────────────────────────────────────────────


def _add_file(db, filename="belge.pdf", added_at="2026-01-15T10:30:00Z"):
    """Test için files satırı ekler ve id döndürür."""
    cur = db.execute(
        "INSERT INTO files (filename, filepath, added_at) VALUES (?, ?, ?)",
        (filename, f"/vault/{filename}.hcl", added_at),
    )
    return int(cur.lastrowid)


def _mk(db, **overrides):
    """Varsayılan geçerli alanlarla profil oluşturur."""
    fields = {
        "name": "Test profili",
        "duration_value": 5,
        "duration_unit": UNIT_YEAR,
        "start_type": START_UPLOAD,
    }
    fields.update(overrides)
    return create_profile(db, **fields)


# ──────────────────────────────────────────────────────────────────────────────
# Şema
# ──────────────────────────────────────────────────────────────────────────────


class TestSchema:
    def test_tablo_ve_kolonlar_olusuyor(self, db):
        cols = {r["name"] for r in db.fetchall("PRAGMA table_info(retention_profiles)")}
        assert cols == {
            "id", "name", "duration_value", "duration_unit", "start_type",
            "legal_basis", "early_delete_protection", "is_builtin",
            "created_at", "updated_at",
        }

    def test_files_kolonlari_eklendi(self, db):
        cols = {r["name"] for r in db.fetchall("PRAGMA table_info(files)")}
        assert "retention_profile_id" in cols
        assert "retention_start_date" in cols

    def test_expires_at_ayri_kaliyor(self, db):
        """expires_at İmha Odası TTL'i — saklama alanlarıyla karışmamalı."""
        cols = {r["name"] for r in db.fetchall("PRAGMA table_info(files)")}
        assert "expires_at" in cols

    def test_check_suresiz_deger_alamaz(self, db):
        """Şema seviyesinde: 'suresiz' + süre değeri temsil edilemez."""
        import sqlite3
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                "INSERT INTO retention_profiles (name, duration_value, duration_unit)"
                " VALUES ('kotu', 5, 'suresiz')"
            )

    def test_check_sureli_deger_zorunlu(self, db):
        import sqlite3
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                "INSERT INTO retention_profiles (name, duration_value, duration_unit)"
                " VALUES ('kotu', NULL, 'yil')"
            )

    def test_gecersiz_birim_reddediliyor(self, db):
        import sqlite3
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                "INSERT INTO retention_profiles (name, duration_value, duration_unit)"
                " VALUES ('kotu', 5, 'hafta')"
            )


# ──────────────────────────────────────────────────────────────────────────────
# CRUD
# ──────────────────────────────────────────────────────────────────────────────


class TestCRUD:
    def test_olustur_ve_oku(self, db):
        pid = _mk(db, name="Mali müşavir - 10 yıl", duration_value=10,
                  start_type=START_DOCUMENT, legal_basis="TTK m.82")
        row = get_profile(db, pid)
        assert row["name"] == "Mali müşavir - 10 yıl"
        assert row["duration_value"] == 10
        assert row["duration_unit"] == UNIT_YEAR
        assert row["start_type"] == START_DOCUMENT
        assert row["legal_basis"] == "TTK m.82"
        assert row["early_delete_protection"] == 1  # varsayılan True

    def test_erken_silme_korumasi_varsayilani_true(self, db):
        assert get_profile(db, _mk(db))["early_delete_protection"] == 1

    def test_erken_silme_korumasi_kapatilabilir(self, db):
        pid = _mk(db, early_delete_protection=False)
        assert get_profile(db, pid)["early_delete_protection"] == 0

    def test_zaman_damgalari_yaziliyor(self, db):
        row = get_profile(db, _mk(db))
        assert row["created_at"].endswith("Z")
        assert row["updated_at"].endswith("Z")

    def test_isim_tekil(self, db):
        _mk(db, name="Aynı")
        with pytest.raises(DuplicateProfileNameError):
            _mk(db, name="Aynı")

    def test_isim_bosluklari_kirpiliyor(self, db):
        pid = _mk(db, name="   Boşluklu   ")
        assert get_profile(db, pid)["name"] == "Boşluklu"

    def test_isimle_bul(self, db):
        pid = _mk(db, name="Bulunacak")
        assert get_profile_by_name(db, "Bulunacak")["id"] == pid
        assert get_profile_by_name(db, "Yok") is None

    def test_listele_isme_gore_sirali(self, db):
        _mk(db, name="Zebra")
        _mk(db, name="Ahmet")
        names = [r["name"] for r in list_profiles(db)]
        assert names == sorted(names)

    def test_guncelle(self, db):
        pid = _mk(db, duration_value=5)
        assert update_profile(db, pid, duration_value=15) is True
        assert get_profile(db, pid)["duration_value"] == 15

    def test_guncelle_yoksa_false(self, db):
        assert update_profile(db, 9999, duration_value=1) is False

    def test_guncelle_bilinmeyen_alan(self, db):
        with pytest.raises(RetentionError, match="Bilinmeyen alan"):
            update_profile(db, _mk(db), sacma_alan=1)

    def test_guncelle_bos_cagri(self, db):
        with pytest.raises(RetentionError, match="Güncellenecek alan"):
            update_profile(db, _mk(db))

    def test_guncelleme_birlesik_dogrulaniyor(self, db):
        """Tek başına 'suresiz' göndermek, satırdaki süre değeriyle çelişir."""
        pid = _mk(db, duration_value=5, duration_unit=UNIT_YEAR)
        with pytest.raises(RetentionError, match="süre değeri olamaz"):
            update_profile(db, pid, duration_unit=UNIT_UNLIMITED)
        # Birlikte gönderilirse geçerli
        assert update_profile(
            db, pid, duration_unit=UNIT_UNLIMITED, duration_value=None
        ) is True

    def test_guncelle_isim_cakismasi(self, db):
        _mk(db, name="Var olan")
        pid = _mk(db, name="Başka")
        with pytest.raises(DuplicateProfileNameError):
            update_profile(db, pid, name="Var olan")

    def test_sil(self, db):
        pid = _mk(db)
        assert delete_profile(db, pid) is True
        assert get_profile(db, pid) is None

    def test_sil_yoksa_false(self, db):
        assert delete_profile(db, 9999) is False

    def test_gecersiz_alanlar_reddediliyor(self, db):
        with pytest.raises(RetentionError, match="Profil adı boş"):
            _mk(db, name="   ")
        with pytest.raises(RetentionError, match="Geçersiz süre birimi"):
            _mk(db, duration_unit="hafta")
        with pytest.raises(RetentionError, match="Geçersiz başlangıç tipi"):
            _mk(db, start_type="rastgele")
        with pytest.raises(RetentionError, match="pozitif"):
            _mk(db, duration_value=0)
        with pytest.raises(RetentionError, match="pozitif"):
            _mk(db, duration_value=-5)
        with pytest.raises(RetentionError, match="süre değeri olamaz"):
            _mk(db, duration_unit=UNIT_UNLIMITED, duration_value=5)
        with pytest.raises(RetentionError, match="süre değeri zorunlu"):
            _mk(db, duration_unit=UNIT_YEAR, duration_value=None)


# ──────────────────────────────────────────────────────────────────────────────
# Şablon seed'i
# ──────────────────────────────────────────────────────────────────────────────


class TestSeed:
    def test_sablonlar_acilista_yazildi(self, db):
        """db fixture'ı connect() çağırır — seed orada çalışmış olmalı."""
        assert len(list_profiles(db)) == len(BUILTIN_TEMPLATES)

    def test_beklenen_yedi_sablon(self, db):
        assert len(BUILTIN_TEMPLATES) == 7
        units = [(t["duration_value"], t["duration_unit"]) for t in BUILTIN_TEMPLATES]
        assert (30, UNIT_DAY) in units
        assert (1, UNIT_YEAR) in units
        assert (2, UNIT_YEAR) in units
        assert (5, UNIT_YEAR) in units
        assert (10, UNIT_YEAR) in units
        assert (20, UNIT_YEAR) in units       # 15-20 yıl → üst sınır
        assert (None, UNIT_UNLIMITED) in units

    def test_sablonlar_builtin_isaretli(self, db):
        assert all(r["is_builtin"] == 1 for r in list_profiles(db))

    def test_seed_idempotent(self, db):
        before = len(list_profiles(db))
        assert seed_builtin_templates(db) == 0
        assert len(list_profiles(db)) == before

    def test_silinen_sablon_geri_gelmiyor(self, db):
        """En önemli seed davranışı: silme kalıcı olmalı."""
        target = get_profile_by_name(db, "Süresiz arşiv")
        delete_profile(db, target["id"])
        seed_builtin_templates(db)          # yeniden çalıştır
        assert get_profile_by_name(db, "Süresiz arşiv") is None

    def test_duzenlenen_sablon_geri_alinmiyor(self, db):
        pid = get_profile_by_name(db, "Mali müşavir — 10 yıl")["id"]
        update_profile(db, pid, duration_value=15)
        seed_builtin_templates(db)
        assert get_profile(db, pid)["duration_value"] == 15

    def test_force_ile_geri_getirilebiliyor(self, db):
        target = get_profile_by_name(db, "Süresiz arşiv")
        delete_profile(db, target["id"])
        assert seed_builtin_templates(db, force=True) == 1
        assert get_profile_by_name(db, "Süresiz arşiv") is not None

    def test_force_mevcutlari_cogaltmiyor(self, db):
        seed_builtin_templates(db, force=True)
        assert len(list_profiles(db)) == len(BUILTIN_TEMPLATES)

    def test_sablonlar_duzenlenebilir_ve_silinebilir(self, db):
        """is_builtin salt-okunur ANLAMINA GELMEZ."""
        pid = get_profile_by_name(db, "Vergi belgeleri — 5 yıl")["id"]
        assert update_profile(db, pid, name="Kendi adım", duration_value=7) is True
        assert delete_profile(db, pid) is True


# ──────────────────────────────────────────────────────────────────────────────
# İmha tarihi hesabı
# ──────────────────────────────────────────────────────────────────────────────


class TestDurationMath:
    def test_gun_ekleme(self):
        assert add_duration(date(2026, 1, 15), 30, UNIT_DAY) == date(2026, 2, 14)

    def test_ay_ekleme(self):
        assert add_duration(date(2026, 1, 15), 3, UNIT_MONTH) == date(2026, 4, 15)

    def test_yil_ekleme(self):
        assert add_duration(date(2026, 1, 15), 10, UNIT_YEAR) == date(2036, 1, 15)

    def test_suresiz_none_donuyor(self):
        assert add_duration(date(2026, 1, 15), None, UNIT_UNLIMITED) is None

    def test_yil_sinirini_asan_ay(self):
        assert add_duration(date(2026, 11, 10), 3, UNIT_MONTH) == date(2027, 2, 10)

    def test_tam_yil_ay_olarak(self):
        assert add_duration(date(2026, 5, 20), 24, UNIT_MONTH) == date(2028, 5, 20)

    def test_aralik_asimi(self):
        assert add_duration(date(2026, 12, 31), 1, UNIT_MONTH) == date(2027, 1, 31)

    # ── kenar durumlar: ay sonu kırpması ──────────────────────────────────

    def test_31_ocak_arti_1_ay(self):
        """Şubat'ın 31'i yok → ayın son gününe kırpılır."""
        assert add_duration(date(2026, 1, 31), 1, UNIT_MONTH) == date(2026, 2, 28)

    def test_31_ocak_arti_1_ay_artik_yil(self):
        assert add_duration(date(2028, 1, 31), 1, UNIT_MONTH) == date(2028, 2, 29)

    def test_31_mart_arti_1_ay(self):
        """Nisan 30 çeker."""
        assert add_duration(date(2026, 3, 31), 1, UNIT_MONTH) == date(2026, 4, 30)

    def test_kirpma_zincirlenmiyor(self):
        """31 Ocak + 3 ay = 30 Nisan — 28 Şubat üzerinden gidilmiyor."""
        assert add_duration(date(2026, 1, 31), 3, UNIT_MONTH) == date(2026, 4, 30)
        assert add_duration(date(2026, 1, 31), 2, UNIT_MONTH) == date(2026, 3, 31)

    def test_29_subat_arti_1_yil(self):
        """Artık gün → artık olmayan yıl: 28 Şubat'a kırpılır."""
        assert add_duration(date(2024, 2, 29), 1, UNIT_YEAR) == date(2025, 2, 28)

    def test_29_subat_arti_4_yil(self):
        """Bir sonraki artık yıl → gün korunur."""
        assert add_duration(date(2024, 2, 29), 4, UNIT_YEAR) == date(2028, 2, 29)

    def test_29_subat_gun_olarak_kirpilmiyor(self):
        """Gün birimi takvim kırpması yapmaz — 365 gün sonrası 28 Şubat 2025."""
        assert add_duration(date(2024, 2, 29), 365, UNIT_DAY) == date(2025, 2, 28)

    def test_artik_gun_uzerinden_gun_ekleme(self):
        assert add_duration(date(2024, 2, 28), 1, UNIT_DAY) == date(2024, 2, 29)

    def test_uzun_sure_yuzyil_kurali(self):
        """2100 artık yıl DEĞİL (yüzyıl kuralı)."""
        assert add_duration(date(2096, 2, 29), 4, UNIT_YEAR) == date(2100, 2, 28)

    def test_gecersiz_birim(self):
        with pytest.raises(RetentionError, match="Geçersiz süre birimi"):
            add_duration(date(2026, 1, 1), 5, "hafta")

    def test_sureli_ama_degersiz(self):
        with pytest.raises(RetentionError, match="süre değeri zorunlu"):
            add_duration(date(2026, 1, 1), None, UNIT_YEAR)


class TestComputeDestructionDate:
    def test_profil_ile_hesap(self, db):
        pid = _mk(db, duration_value=10, duration_unit=UNIT_YEAR)
        assert compute_destruction_date(
            get_profile(db, pid), "2026-01-15"
        ) == date(2036, 1, 15)

    def test_suresiz_profil_none(self, db):
        pid = _mk(db, duration_value=None, duration_unit=UNIT_UNLIMITED)
        assert compute_destruction_date(get_profile(db, pid), "2026-01-15") is None

    def test_zaman_damgasi_kabul_ediliyor(self, db):
        """files.added_at biçimi (…T…Z) doğrudan verilebilir."""
        pid = _mk(db, duration_value=30, duration_unit=UNIT_DAY)
        assert compute_destruction_date(
            get_profile(db, pid), "2026-01-15T10:30:00Z"
        ) == date(2026, 2, 14)

    def test_date_nesnesi_kabul_ediliyor(self, db):
        pid = _mk(db, duration_value=1, duration_unit=UNIT_YEAR)
        assert compute_destruction_date(
            get_profile(db, pid), date(2026, 1, 31)
        ) == date(2027, 1, 31)

    def test_dict_profil_de_calisiyor(self):
        assert compute_destruction_date(
            {"duration_value": 1, "duration_unit": UNIT_MONTH}, "2026-01-31"
        ) == date(2026, 2, 28)

    def test_bozuk_tarih(self, db):
        pid = _mk(db)
        with pytest.raises(RetentionError, match="çözümlenemedi"):
            compute_destruction_date(get_profile(db, pid), "15/01/2026")

    def test_bos_tarih(self, db):
        pid = _mk(db)
        with pytest.raises(RetentionError, match="boş"):
            compute_destruction_date(get_profile(db, pid), "   ")


# ──────────────────────────────────────────────────────────────────────────────
# Dosya ↔ profil bağı
# ──────────────────────────────────────────────────────────────────────────────


class TestFileAssignment:
    def test_yukleme_tarihi_profili_atama(self, db):
        fid = _add_file(db, added_at="2026-01-15T10:30:00Z")
        pid = _mk(db, duration_value=2, duration_unit=UNIT_YEAR, start_type=START_UPLOAD)
        assert assign_profile(db, fid, pid) is True
        assert destruction_date_for_file(db, fid) == date(2028, 1, 15)

    def test_belge_tarihi_elle_giris(self, db):
        fid = _add_file(db, added_at="2026-01-15T10:30:00Z")
        pid = _mk(db, duration_value=10, duration_unit=UNIT_YEAR,
                  start_type=START_DOCUMENT)
        assign_profile(db, fid, pid, start_date="2019-03-31")
        # Yükleme tarihinden DEĞİL, belge tarihinden işliyor
        assert destruction_date_for_file(db, fid) == date(2029, 3, 31)

    def test_olay_tarihi_elle_giris(self, db):
        fid = _add_file(db)
        pid = _mk(db, duration_value=20, duration_unit=UNIT_YEAR, start_type=START_EVENT)
        assign_profile(db, fid, pid, start_date="2020-02-29")
        assert destruction_date_for_file(db, fid) == date(2040, 2, 29)

    def test_elle_giris_zorunlulugu(self, db):
        fid = _add_file(db)
        pid = _mk(db, start_type=START_DOCUMENT)
        with pytest.raises(RetentionError, match="başlangıç tarihi zorunlu"):
            assign_profile(db, fid, pid)
        # Atama hiç yapılmamış olmalı
        assert db.fetchone(
            "SELECT retention_profile_id FROM files WHERE id = ?", (fid,)
        )["retention_profile_id"] is None

    def test_yukleme_profilinde_elle_tarih_yoksayiliyor(self, db):
        fid = _add_file(db, added_at="2026-01-15T10:30:00Z")
        pid = _mk(db, duration_value=1, duration_unit=UNIT_YEAR, start_type=START_UPLOAD)
        assign_profile(db, fid, pid, start_date="2000-01-01")
        assert db.fetchone(
            "SELECT retention_start_date FROM files WHERE id = ?", (fid,)
        )["retention_start_date"] is None
        assert destruction_date_for_file(db, fid) == date(2027, 1, 15)

    def test_bozuk_tarih_db_ye_girmiyor(self, db):
        fid = _add_file(db)
        pid = _mk(db, start_type=START_DOCUMENT)
        with pytest.raises(RetentionError, match="çözümlenemedi"):
            assign_profile(db, fid, pid, start_date="31-01-2026")

    def test_atamayi_kaldirma(self, db):
        fid = _add_file(db)
        pid = _mk(db, start_type=START_DOCUMENT)
        assign_profile(db, fid, pid, start_date="2020-01-01")
        assert assign_profile(db, fid, None) is True
        row = db.fetchone(
            "SELECT retention_profile_id, retention_start_date FROM files WHERE id = ?",
            (fid,),
        )
        assert row["retention_profile_id"] is None
        assert row["retention_start_date"] is None

    def test_profilsiz_dosya_none(self, db):
        assert destruction_date_for_file(db, _add_file(db)) is None

    def test_olmayan_dosya(self, db):
        assert assign_profile(db, 9999, None) is False
        with pytest.raises(RetentionError, match="Dosya bulunamadı"):
            destruction_date_for_file(db, 9999)

    def test_olmayan_profil(self, db):
        with pytest.raises(RetentionError, match="Profil bulunamadı"):
            assign_profile(db, _add_file(db), 9999)

    def test_profil_silinince_dosya_kaliyor(self, db):
        """ON DELETE SET NULL — profil silmek dosyayı SİLMEZ."""
        fid = _add_file(db)
        pid = _mk(db)
        assign_profile(db, fid, pid)
        delete_profile(db, pid)
        row = db.fetchone(
            "SELECT id, retention_profile_id FROM files WHERE id = ?", (fid,)
        )
        assert row is not None                      # dosya duruyor
        assert row["retention_profile_id"] is None  # yalnızca bağ koptu
        assert destruction_date_for_file(db, fid) is None

    def test_profil_kullanan_dosyalar(self, db):
        pid = _mk(db)
        f1 = _add_file(db, "a.pdf")
        f2 = _add_file(db, "b.pdf")
        _add_file(db, "c.pdf")
        assign_profile(db, f1, pid)
        assign_profile(db, f2, pid)
        assert [r["id"] for r in files_using_profile(db, pid)] == [f1, f2]

    def test_profil_guncellemesi_imha_tarihine_yansiyor(self, db):
        """İmha tarihi türetilmiş — profil değişince bayatlamamalı."""
        fid = _add_file(db, added_at="2026-01-15T10:30:00Z")
        pid = _mk(db, duration_value=10, duration_unit=UNIT_YEAR)
        assign_profile(db, fid, pid)
        assert destruction_date_for_file(db, fid) == date(2036, 1, 15)
        update_profile(db, pid, duration_value=15)
        assert destruction_date_for_file(db, fid) == date(2041, 1, 15)

    def test_resolve_start_date_elle_giris_eksik(self, db):
        """Doğrudan DB'ye yazılmış tutarsız satır sessizce yanlış hesaplanmamalı."""
        fid = _add_file(db)
        pid = _mk(db, start_type=START_EVENT)
        db.execute(
            "UPDATE files SET retention_profile_id = ? WHERE id = ?", (pid, fid)
        )
        with pytest.raises(RetentionError, match="elle girilmeli"):
            destruction_date_for_file(db, fid)

    def test_manual_start_types_dogru(self):
        assert MANUAL_START_TYPES == {START_DOCUMENT, START_EVENT}
        assert START_UPLOAD not in MANUAL_START_TYPES


# ──────────────────────────────────────────────────────────────────────────────
# Şablonlarla uçtan uca
# ──────────────────────────────────────────────────────────────────────────────


class TestTemplatesEndToEnd:
    def test_her_sablon_hesaplanabiliyor(self, db):
        """Seed'lenen her profil ya tarih ya None üretir — hiçbiri patlamaz."""
        for profile in list_profiles(db):
            result = compute_destruction_date(profile, "2026-01-31")
            if profile["duration_unit"] == UNIT_UNLIMITED:
                assert result is None
            else:
                assert isinstance(result, date)
                assert result > date(2026, 1, 31)

    def test_mali_musavir_sablonu(self, db):
        """Kullanıcının örneği: 'Mali müşavir - 10 yıl', belge tarihinden."""
        profile = get_profile_by_name(db, "Mali müşavir — 10 yıl")
        assert profile["duration_value"] == 10
        assert profile["start_type"] == START_DOCUMENT
        assert compute_destruction_date(profile, "2026-03-15") == date(2036, 3, 15)

    def test_seed_sonrasi_yeni_db_baglantisi(self, db, tmp_path):
        """Yeni bir DB dosyası açmak şablonları oradan da yazar."""
        from DB.db_manager import DBManager

        db.close()
        DBManager._instance = None
        fresh = DBManager(tmp_path / "ikinci.db")
        fresh.connect(hwid="TEST-HWID-2")
        try:
            assert len(list_profiles(fresh)) == len(BUILTIN_TEMPLATES)
        finally:
            fresh.close()
            DBManager._instance = None

    def test_resolve_start_date_dogrudan(self, db):
        fid = _add_file(db, added_at="2026-06-01T00:00:00Z")
        pid = _mk(db, start_type=START_UPLOAD)
        row = db.fetchone(
            "SELECT added_at, retention_start_date FROM files WHERE id = ?", (fid,)
        )
        assert resolve_start_date(row, get_profile(db, pid)) == date(2026, 6, 1)
