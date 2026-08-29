"""
İmha akışı — erken silme koruması ve süresi dolmuş dosyaların süpürülmesi.

En önemli test sınıfı TestSenaryoAyrimi: iki senaryonun birbirine
karışmadığını doğruluyor.
"""
from __future__ import annotations

import itertools
from datetime import date, datetime, timedelta, timezone

import pytest

from CORE.disposal import (
    DECISION_ALLOWED,
    DECISION_NEEDS_ADMIN,
    DECISION_NEEDS_WARNING,
    LABEL_IMHA,
    EarlyDeletionBlocked,
    check_disposal,
    is_admin,
    is_retention_protected,
    purge_expired_file,
    move_to_imha,
    purge_file,
    resume_pending_disposals,
    sweep_retention_expired,
)
from CORE.retention import (
    START_DOCUMENT,
    START_UPLOAD,
    UNIT_UNLIMITED,
    UNIT_YEAR,
    RetentionError,
    assign_profile,
    create_profile,
    update_profile,
)

# ──────────────────────────────────────────────────────────────────────────────
# Yardımcılar
# ──────────────────────────────────────────────────────────────────────────────


# Benzersiz ad üreteci — id(object()) adres geri kullandığı için çakışıyordu.
_sayac = itertools.count(1)


def _mk_user(db, role="user", username=None):
    username = username or f"kullanici_{role}_{next(_sayac)}"
    cur = db.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        (username, "x", role),
    )
    return int(cur.lastrowid)


def _mk_file(db, tmp_path, *, label="Genel", added_at=None, filename="belge.pdf"):
    """Diskte gerçek bir .hcl dosyasıyla birlikte files satırı oluşturur."""
    added_at = added_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    hcl = tmp_path / f"{filename}.hcl"
    hcl.write_bytes(b"sifreli-icerik")
    cur = db.execute(
        "INSERT INTO files (filename, filepath, label, added_at) VALUES (?, ?, ?, ?)",
        (filename, str(hcl), label, added_at),
    )
    return int(cur.lastrowid), hcl


def _profile(db, *, protected=True, years=10, name=None, unlimited=False):
    name = name or f"profil_{next(_sayac)}"
    if unlimited:
        return create_profile(
            db, name=name, duration_value=None, duration_unit=UNIT_UNLIMITED,
            start_type=START_UPLOAD, early_delete_protection=protected,
        )
    return create_profile(
        db, name=name, duration_value=years, duration_unit=UNIT_YEAR,
        start_type=START_UPLOAD, early_delete_protection=protected,
    )


def _expired_file(db, tmp_path, *, protected=True, filename="eski.pdf"):
    """Saklama süresi DOLMUŞ bir dosya: 10 yıl önce yüklenmiş, 1 yıllık profil."""
    old = (datetime.now(timezone.utc) - timedelta(days=3650)).strftime("%Y-%m-%dT%H:%M:%SZ")
    fid, hcl = _mk_file(db, tmp_path, added_at=old, filename=filename)
    pid = _profile(db, protected=protected, years=1)
    assign_profile(db, fid, pid)
    return fid, hcl, pid


def _active_file(db, tmp_path, *, protected=True, filename="yeni.pdf"):
    """Saklama süresi HÂLÂ İŞLEYEN bir dosya: bugün yüklenmiş, 10 yıllık profil."""
    fid, hcl = _mk_file(db, tmp_path, filename=filename)
    pid = _profile(db, protected=protected, years=10)
    assign_profile(db, fid, pid)
    return fid, hcl, pid


def _label(db, file_id):
    return db.fetchone("SELECT label FROM files WHERE id = ?", (file_id,))["label"]


def _actions(db, file_id):
    return [
        r["action"]
        for r in db.fetchall(
            "SELECT action FROM audit_log WHERE target_id = ? AND target_type = 'file'"
            " ORDER BY id",
            (file_id,),
        )
    ]


def _details(db, file_id):
    return " | ".join(
        r["detail"] or ""
        for r in db.fetchall(
            "SELECT detail FROM audit_log WHERE target_id = ? AND target_type = 'file'"
            " ORDER BY id",
            (file_id,),
        )
    )


# ──────────────────────────────────────────────────────────────────────────────
# Karar mantığı
# ──────────────────────────────────────────────────────────────────────────────


class TestCheckDisposal:
    def test_profilsiz_dosya_muaf(self, db, tmp_path):
        fid, _ = _mk_file(db, tmp_path)
        check = check_disposal(db, fid)
        assert check.decision == DECISION_ALLOWED
        assert check.has_profile is False
        assert check.needs_approval is False

    def test_suresi_dolmamis_korumali(self, db, tmp_path):
        fid, _, _ = _active_file(db, tmp_path, protected=True)
        assert check_disposal(db, fid).decision == DECISION_NEEDS_ADMIN

    def test_suresi_dolmamis_korumasiz(self, db, tmp_path):
        fid, _, _ = _active_file(db, tmp_path, protected=False)
        assert check_disposal(db, fid).decision == DECISION_NEEDS_WARNING

    def test_suresi_dolmus_serbest(self, db, tmp_path):
        fid, _, _ = _expired_file(db, tmp_path, protected=True)
        check = check_disposal(db, fid)
        assert check.decision == DECISION_ALLOWED
        assert check.retention_expired is True

    def test_suresiz_profil_kalici_korumali(self, db, tmp_path):
        """'Tarihi yok' ile 'tarihi geçti' aynı şey değil."""
        fid, _ = _mk_file(db, tmp_path)
        assign_profile(db, fid, _profile(db, unlimited=True, protected=True))
        check = check_disposal(db, fid)
        assert check.decision == DECISION_NEEDS_ADMIN
        assert check.destruction_date is None
        assert check.retention_expired is False

    def test_suresiz_profil_korumasiz_uyari(self, db, tmp_path):
        fid, _ = _mk_file(db, tmp_path)
        assign_profile(db, fid, _profile(db, unlimited=True, protected=False))
        assert check_disposal(db, fid).decision == DECISION_NEEDS_WARNING

    def test_tam_bugun_dolan_sure_serbest(self, db, tmp_path):
        """imha_tarihi == bugün → dolmuş sayılır (<=, < değil)."""
        fid, _ = _mk_file(db, tmp_path, added_at="2020-01-15T00:00:00Z")
        assign_profile(db, fid, _profile(db, years=5))
        assert check_disposal(db, fid, today=date(2025, 1, 15)).decision == DECISION_ALLOWED

    def test_bir_gun_once_hala_korumali(self, db, tmp_path):
        fid, _ = _mk_file(db, tmp_path, added_at="2020-01-15T00:00:00Z")
        assign_profile(db, fid, _profile(db, years=5))
        assert check_disposal(db, fid, today=date(2025, 1, 14)).decision == DECISION_NEEDS_ADMIN

    def test_olmayan_dosya(self, db):
        with pytest.raises(RetentionError, match="Dosya bulunamadı"):
            check_disposal(db, 9999)

    def test_hesaplanamayan_tarih_hata(self, db, tmp_path):
        """Elle giriş gereken profilde tarih boşsa sessizce 'dolmuş' sayılmamalı."""
        fid, _ = _mk_file(db, tmp_path)
        pid = create_profile(db, name="Belge", duration_value=5, duration_unit=UNIT_YEAR,
                             start_type=START_DOCUMENT)
        db.execute("UPDATE files SET retention_profile_id = ? WHERE id = ?", (pid, fid))
        with pytest.raises(RetentionError, match="elle girilmeli"):
            check_disposal(db, fid)


class TestIsAdmin:
    def test_admin_dogru(self, db):
        assert is_admin(db, _mk_user(db, "admin")) is True

    def test_normal_kullanici_yanlis(self, db):
        assert is_admin(db, _mk_user(db, "user")) is False

    def test_none_ve_olmayan_yanlis(self, db):
        assert is_admin(db, None) is False
        assert is_admin(db, 9999) is False


# ──────────────────────────────────────────────────────────────────────────────
# Senaryo 1 — erken silme koruması
# ──────────────────────────────────────────────────────────────────────────────


class TestErkenSilmeKorumasi:
    def test_korumali_engelleniyor(self, db, tmp_path):
        fid, _, _ = _active_file(db, tmp_path, protected=True)
        with pytest.raises(EarlyDeletionBlocked, match="Yönetici onayı"):
            move_to_imha(db, fid, user_id=_mk_user(db))
        assert _label(db, fid) != LABEL_IMHA          # dosyaya dokunulmadı
        assert "early_disposal_blocked" in _actions(db, fid)

    def test_korumali_yonetici_onayiyla_geciyor(self, db, tmp_path):
        fid, _, _ = _active_file(db, tmp_path, protected=True)
        admin = _mk_user(db, "admin")
        check = move_to_imha(db, fid, user_id=_mk_user(db), approved_by=admin)
        assert check.decision == DECISION_NEEDS_ADMIN
        assert _label(db, fid) == LABEL_IMHA
        assert "erken silme - yönetici onaylı" in _details(db, fid)

    def test_yonetici_olmayan_onay_reddediliyor(self, db, tmp_path):
        """approved_by verilmiş ama o kullanıcı admin değil."""
        fid, _, _ = _active_file(db, tmp_path, protected=True)
        with pytest.raises(EarlyDeletionBlocked):
            move_to_imha(db, fid, approved_by=_mk_user(db, "user"))
        assert _label(db, fid) != LABEL_IMHA

    def test_kullanici_onayi_yonetici_yerine_gecmiyor(self, db, tmp_path):
        fid, _, _ = _active_file(db, tmp_path, protected=True)
        with pytest.raises(EarlyDeletionBlocked):
            move_to_imha(db, fid, user_confirmed=True)

    def test_korumasiz_onaysiz_engelleniyor(self, db, tmp_path):
        fid, _, _ = _active_file(db, tmp_path, protected=False)
        with pytest.raises(EarlyDeletionBlocked, match="kullanıcı onayı"):
            move_to_imha(db, fid)
        assert _label(db, fid) != LABEL_IMHA

    def test_korumasiz_kullanici_onayiyla_geciyor(self, db, tmp_path):
        """Yönetici onayı GEREKMEZ."""
        fid, _, _ = _active_file(db, tmp_path, protected=False)
        check = move_to_imha(db, fid, user_confirmed=True)
        assert check.decision == DECISION_NEEDS_WARNING
        assert _label(db, fid) == LABEL_IMHA
        assert "erken silme - kullanici uyarildi" in _details(db, fid)

    def test_engellenen_islem_audit_log_a_dusuyor(self, db, tmp_path):
        fid, _, _ = _active_file(db, tmp_path, protected=True)
        user = _mk_user(db)
        with pytest.raises(EarlyDeletionBlocked):
            move_to_imha(db, fid, user_id=user)
        row = db.fetchone(
            "SELECT user_id, detail FROM audit_log WHERE action = 'early_disposal_blocked'"
        )
        assert row["user_id"] == user
        assert "move_to_imha" in row["detail"]

    def test_istisna_karari_tasiyor(self, db, tmp_path):
        fid, _, _ = _active_file(db, tmp_path, protected=True)
        with pytest.raises(EarlyDeletionBlocked) as exc:
            move_to_imha(db, fid)
        assert exc.value.check.decision == DECISION_NEEDS_ADMIN
        assert exc.value.check.destruction_date is not None


class TestProfilsizDosyaEskiDavranis:
    def test_onaysiz_imhaya_gidiyor(self, db, tmp_path):
        """retention_profile_id NULL → kontrol uygulanmaz, eski davranış."""
        fid, _ = _mk_file(db, tmp_path)
        check = move_to_imha(db, fid)
        assert check.decision == DECISION_ALLOWED
        assert check.has_profile is False
        assert _label(db, fid) == LABEL_IMHA

    def test_ttl_sayaci_kuruluyor(self, db, tmp_path):
        """Kullanıcı bilerek attıysa mevcut 24 saatlik sayaç doğru davranış."""
        fid, _ = _mk_file(db, tmp_path)
        move_to_imha(db, fid, ttl_hours=24)
        expires = db.fetchone("SELECT expires_at FROM files WHERE id = ?", (fid,))["expires_at"]
        assert expires is not None and expires.endswith("Z")

    def test_onaysiz_kalici_siliniyor(self, db, tmp_path):
        fid, hcl = _mk_file(db, tmp_path)
        purge_file(db, fid)
        assert not hcl.exists()
        assert db.fetchone("SELECT id FROM files WHERE id = ?", (fid,)) is None

    def test_audit_log_a_dusuyor(self, db, tmp_path):
        fid, _ = _mk_file(db, tmp_path)
        move_to_imha(db, fid)
        assert "file_moved_to_imha" in _actions(db, fid)


# ──────────────────────────────────────────────────────────────────────────────
# Senaryo 2 — süresi dolmuş dosyaların süpürülmesi
# ──────────────────────────────────────────────────────────────────────────────


class TestSuresiDolmusSupurme:
    def test_imha_odasina_dusuyor(self, db, tmp_path):
        fid, _, _ = _expired_file(db, tmp_path)
        assert sweep_retention_expired(db) == [fid]
        assert _label(db, fid) == LABEL_IMHA

    def test_diskten_silinmiyor(self, db, tmp_path):
        """En kritik güvence: süpürme veri imha etmez."""
        fid, hcl, _ = _expired_file(db, tmp_path)
        sweep_retention_expired(db)
        assert hcl.exists()
        assert db.fetchone("SELECT id FROM files WHERE id = ?", (fid,)) is not None

    def test_expires_at_null_kaliyor(self, db, tmp_path):
        """TTL sayacı KURULMAZ — yoksa 24 saat sonra onaysız silinirdi."""
        fid, _, _ = _expired_file(db, tmp_path)
        sweep_retention_expired(db)
        assert db.fetchone(
            "SELECT expires_at FROM files WHERE id = ?", (fid,)
        )["expires_at"] is None

    def test_karantina_intake_sayaci_da_temizleniyor(self, db, tmp_path):
        """Karantina'dan gelen eski expires_at süpürmede NULL'lanmalı."""
        fid, _, _ = _expired_file(db, tmp_path)
        db.execute(
            "UPDATE files SET label = 'Karantina', expires_at = ? WHERE id = ?",
            ("2020-01-01T00:00:00Z", fid),
        )
        sweep_retention_expired(db)
        assert db.fetchone(
            "SELECT expires_at FROM files WHERE id = ?", (fid,)
        )["expires_at"] is None

    def test_audit_log_a_dusuyor(self, db, tmp_path):
        fid, _, _ = _expired_file(db, tmp_path)
        sweep_retention_expired(db)
        assert "retention_sweep" in _actions(db, fid)
        assert "onay bekliyor" in _details(db, fid)

    def test_suresi_dolmamis_dokunulmuyor(self, db, tmp_path):
        fid, _, _ = _active_file(db, tmp_path)
        assert sweep_retention_expired(db) == []
        assert _label(db, fid) != LABEL_IMHA

    def test_profilsiz_dosya_dokunulmuyor(self, db, tmp_path):
        fid, _ = _mk_file(db, tmp_path)
        assert sweep_retention_expired(db) == []
        assert _label(db, fid) == "Genel"

    def test_suresiz_profil_dokunulmuyor(self, db, tmp_path):
        fid, _ = _mk_file(db, tmp_path)
        assign_profile(db, fid, _profile(db, unlimited=True))
        assert sweep_retention_expired(db) == []

    def test_zaten_imhada_olan_tekrar_islenmiyor(self, db, tmp_path):
        fid, _, _ = _expired_file(db, tmp_path)
        sweep_retention_expired(db)
        assert sweep_retention_expired(db) == []      # idempotent

    def test_hesaplanamayan_dosya_atlaniyor_supurme_devam_ediyor(self, db, tmp_path):
        """Bozuk tek satır tüm süpürmeyi durdurmamalı."""
        bad, _ = _mk_file(db, tmp_path, filename="bozuk.pdf")
        pid = create_profile(db, name="Belge tarihli", duration_value=1,
                             duration_unit=UNIT_YEAR, start_type=START_DOCUMENT)
        db.execute("UPDATE files SET retention_profile_id = ? WHERE id = ?", (pid, bad))
        good, _, _ = _expired_file(db, tmp_path, filename="iyi.pdf")

        assert sweep_retention_expired(db) == [good]
        assert _label(db, bad) != LABEL_IMHA          # bozuk olan korundu

    def test_coklu_dosya(self, db, tmp_path):
        ids = [_expired_file(db, tmp_path, filename=f"e{i}.pdf")[0] for i in range(3)]
        _active_file(db, tmp_path, filename="aktif.pdf")
        assert sorted(sweep_retention_expired(db)) == sorted(ids)

    def test_supurulen_dosya_hala_onay_bekliyor(self, db, tmp_path):
        """Süpürme sonrası kalıcı silme hâlâ purge_file() gerektirir."""
        fid, hcl, _ = _expired_file(db, tmp_path)
        sweep_retention_expired(db)
        assert hcl.exists()
        purge_file(db, fid, user_confirmed=True)      # açık onay
        assert not hcl.exists()


# ──────────────────────────────────────────────────────────────────────────────
# İKİ SENARYONUN AYRIMI — bu dosyanın en önemli bölümü
# ──────────────────────────────────────────────────────────────────────────────


class TestSenaryoAyrimi:
    def test_suresi_dolmus_dosya_erken_silme_kontrolune_takilmiyor(self, db, tmp_path):
        """
        Süresi dolmuş + erken_silme_koruması=True.

        Koruma bayrağı AÇIK olmasına rağmen süre dolduğu için süpürme
        engellenmemeli — 'erken' değil.
        """
        fid, _, _ = _expired_file(db, tmp_path, protected=True)
        assert check_disposal(db, fid).protected is True      # koruma gerçekten açık
        assert sweep_retention_expired(db) == [fid]           # yine de süpürüldü
        assert _label(db, fid) == LABEL_IMHA
        assert "early_disposal_blocked" not in _actions(db, fid)

    def test_suresi_dolmus_dosya_onaysiz_imhaya_tasinabiliyor(self, db, tmp_path):
        """Kullanıcı eliyle de taşınabilir — onay istenmez, çünkü erken değil."""
        fid, _, _ = _expired_file(db, tmp_path, protected=True)
        check = move_to_imha(db, fid)                 # hiçbir onay verilmedi
        assert check.decision == DECISION_ALLOWED
        assert _label(db, fid) == LABEL_IMHA

    def test_supurme_onay_parametresi_almiyor(self):
        """
        Süpürme onay alsaydı, erken silme kontrolünü atlatmanın yolu olurdu.
        """
        import inspect

        params = set(inspect.signature(sweep_retention_expired).parameters)
        assert params == {"db", "today"}
        assert "approved_by" not in params
        assert "user_confirmed" not in params

    def test_supurme_suresi_dolmamis_dosyayi_asla_tasimaz(self, db, tmp_path):
        """Koruma kapalı olsa bile: süpürmenin ölçütü koruma değil, TARİH."""
        fid, _, _ = _active_file(db, tmp_path, protected=False)
        assert sweep_retention_expired(db) == []
        assert _label(db, fid) != LABEL_IMHA

    def test_ayni_dosya_ikisi_birden_olamaz(self, db, tmp_path):
        """retention_expired ve needs_approval karşılıklı dışlayıcı."""
        expired, _, _ = _expired_file(db, tmp_path, filename="dolmus.pdf")
        active, _, _ = _active_file(db, tmp_path, filename="aktif.pdf")

        e = check_disposal(db, expired)
        a = check_disposal(db, active)
        assert (e.retention_expired, e.needs_approval) == (True, False)
        assert (a.retention_expired, a.needs_approval) == (False, True)

    def test_sinirin_iki_yani(self, db, tmp_path):
        """Aynı dosya, imha tarihinin bir gün öncesi ve tam günü."""
        fid, _ = _mk_file(db, tmp_path, added_at="2020-06-30T00:00:00Z")
        assign_profile(db, fid, _profile(db, years=5, protected=True))

        onceki = check_disposal(db, fid, today=date(2025, 6, 29))
        tam_gun = check_disposal(db, fid, today=date(2025, 6, 30))

        assert onceki.decision == DECISION_NEEDS_ADMIN
        assert onceki.needs_approval is True
        assert tam_gun.decision == DECISION_ALLOWED
        assert tam_gun.needs_approval is False

    def test_profil_suresi_uzatilinca_tekrar_korunuyor(self, db, tmp_path):
        """Türetilmiş tarih: profil uzatılırsa dosya erken silme alanına döner."""
        fid, _, pid = _expired_file(db, tmp_path)
        assert check_disposal(db, fid).decision == DECISION_ALLOWED
        update_profile(db, pid, duration_value=50)
        assert check_disposal(db, fid).decision == DECISION_NEEDS_ADMIN


# ──────────────────────────────────────────────────────────────────────────────
# Kalıcı silme onayı
# ──────────────────────────────────────────────────────────────────────────────


class TestPurgeFile:
    def test_koruma_altindaki_dosya_silinmiyor(self, db, tmp_path):
        fid, hcl, _ = _active_file(db, tmp_path, protected=True)
        with pytest.raises(EarlyDeletionBlocked):
            purge_file(db, fid)
        assert hcl.exists()
        assert db.fetchone("SELECT id FROM files WHERE id = ?", (fid,)) is not None

    def test_yonetici_onayiyla_siliniyor(self, db, tmp_path):
        fid, hcl, _ = _active_file(db, tmp_path, protected=True)
        purge_file(db, fid, approved_by=_mk_user(db, "admin"))
        assert not hcl.exists()

    def test_suresi_dolmus_onayla_siliniyor(self, db, tmp_path):
        fid, hcl, _ = _expired_file(db, tmp_path)
        purge_file(db, fid, user_confirmed=True)
        assert not hcl.exists()
        assert "file_purged" in [
            r["action"] for r in db.fetchall("SELECT action FROM audit_log")
        ]

    def test_imhaya_tasima_kalici_silmeyi_otomatik_onaylamiyor(self, db, tmp_path):
        """Taşımada alınan onay, silme için geçerli sayılmaz."""
        fid, hcl, pid = _active_file(db, tmp_path, protected=True)
        move_to_imha(db, fid, approved_by=_mk_user(db, "admin"))
        with pytest.raises(EarlyDeletionBlocked):
            purge_file(db, fid)                       # yeniden onay şart
        assert hcl.exists()

    def test_diskte_olmayan_dosya_kaydi_yine_siliniyor(self, db, tmp_path):
        fid, hcl = _mk_file(db, tmp_path)
        hcl.unlink()
        purge_file(db, fid)
        assert db.fetchone("SELECT id FROM files WHERE id = ?", (fid,)) is None

    def test_olmayan_dosya(self, db):
        with pytest.raises(RetentionError, match="Dosya bulunamadı"):
            purge_file(db, 9999)


# ──────────────────────────────────────────────────────────────────────────────
# Karantina otomatik temizliğiyle etkileşim
# ──────────────────────────────────────────────────────────────────────────────


class TestKarantinaTemizligiKorumasi:
    def test_saklama_altindaki_dosya_korumali(self, db, tmp_path):
        fid, _, _ = _active_file(db, tmp_path, protected=True)
        assert is_retention_protected(db, fid) is True

    def test_suresi_dolmus_korumasiz(self, db, tmp_path):
        fid, _, _ = _expired_file(db, tmp_path)
        assert is_retention_protected(db, fid) is False

    def test_profilsiz_korumasiz(self, db, tmp_path):
        fid, _ = _mk_file(db, tmp_path)
        assert is_retention_protected(db, fid) is False

    def test_hesaplanamayan_korumali_sayiliyor(self, db, tmp_path):
        """Belirsizlikte veri korunur."""
        fid, _ = _mk_file(db, tmp_path)
        pid = create_profile(db, name="Belge", duration_value=1,
                             duration_unit=UNIT_YEAR, start_type=START_DOCUMENT)
        db.execute("UPDATE files SET retention_profile_id = ? WHERE id = ?", (pid, fid))
        assert is_retention_protected(db, fid) is True

    def test_scheduler_karantina_temizligi_saklamayi_atliyor(self, db, tmp_path, monkeypatch):
        """
        _purge_expired, saklama süresi işleyen Karantina dosyasını SİLMEMELİ.

        Bu koruma olmadan retention sistemi tamamen atlatılabilirdi: dosya
        Karantina'dayken 24 saatlik giriş sayacı dolar ve dosya sessizce
        diskten silinirdi.
        """
        from CORE import scheduler
        from DB.db_manager import DBManager

        past = "2020-01-01T00:00:00Z"
        korumali, korumali_hcl, _ = _active_file(db, tmp_path, filename="korumali.pdf")
        serbest, serbest_hcl = _mk_file(db, tmp_path, filename="serbest.pdf")
        for fid in (korumali, serbest):
            db.execute(
                "UPDATE files SET label = 'Karantina', expires_at = ? WHERE id = ?",
                (past, fid),
            )

        monkeypatch.setattr(DBManager, "__new__", lambda cls, *a, **k: db)
        scheduler._purge_expired()

        assert korumali_hcl.exists()                             # korundu
        assert db.fetchone("SELECT id FROM files WHERE id = ?", (korumali,)) is not None
        assert "retention_hold" in _actions(db, korumali)

        assert not serbest_hcl.exists()                          # eski davranış sürüyor
        assert db.fetchone("SELECT id FROM files WHERE id = ?", (serbest,)) is None

    def test_imha_sayaci_da_saklamayi_atliyor(self, db, tmp_path):
        """
        B-008: ARAYÜZÜN İmha Odası sayacı da saklama korumasını uygulamalı.

        Eskiden iki ayrı uygulama vardı ve yalnızca zamanlayıcı bu kontrolü
        yapıyordu. Sonuç, kullanıcının göremeyeceği bir tutarsızlıktı:
        uygulama KAPALIYKEN dosya korunuyor, AÇIKKEN aynı dosya korumasız
        siliniyordu. Şimdi iki akış da `purge_expired_file()` çağırıyor.
        """
        korumali, korumali_hcl, _ = _active_file(db, tmp_path, filename="korumali.pdf")
        db.execute("UPDATE files SET label = 'Imha' WHERE id = ?", (korumali,))

        silindi = purge_expired_file(
            db, korumali, source="imha_countdown", filepath=str(korumali_hcl))

        assert silindi is False
        assert korumali_hcl.exists()
        assert db.fetchone("SELECT id FROM files WHERE id = ?", (korumali,)) is not None
        assert "retention_hold" in _actions(db, korumali)

    def test_imha_sayaci_korumasiz_dosyayi_siliyor(self, db, tmp_path):
        """Koruma yoksa sayaç işini yapmaya devam etmeli."""
        fid, hcl = _mk_file(db, tmp_path, label="Imha", filename="serbest.pdf")

        assert purge_expired_file(
            db, fid, source="imha_countdown", filepath=str(hcl)) is True
        assert not hcl.exists()
        assert db.fetchone("SELECT id FROM files WHERE id = ?", (fid,)) is None
        assert "expired_purge" in _actions(db, fid)

    def test_iki_akis_ayni_fonksiyonu_cagiriyor(self):
        """
        KÖK NEDENİN TESTİ. B-004 ve B-008'in ortak sebebi "aynı iş, iki
        uygulama, farklı güvenlik"tı. Bu test ikinci bir uygulamanın geri
        gelmesini yakalıyor: her iki çağrı yeri de tek fonksiyonu
        kullanmalı ve kendi DELETE'ini yazmamalı.
        """
        import ast
        from pathlib import Path as _P

        kok = _P(__file__).resolve().parent.parent
        for yol, fn in (
            ("CORE/scheduler.py", "_purge_expired"),
            ("UI/main_window_table.py", "_purge_expired_file"),
        ):
            src = (kok / yol).read_text(encoding="utf-8")
            agac = ast.parse(src)
            hedef = next(
                n for n in ast.walk(agac)
                if isinstance(n, ast.FunctionDef) and n.name == fn
            )
            govde = ast.get_source_segment(src, hedef) or ""
            assert "purge_expired_file" in govde, f"{yol}::{fn} ortak fonksiyonu çağırmıyor"
            assert "DELETE FROM files" not in govde, (
                f"{yol}::{fn} kendi silme SQL'ini yazmış — ikinci uygulama geri gelmiş")

    def test_purge_expired_file_bilinmeyen_dosyada_patlamiyor(self, db):
        """Döngü içinde çağrılıyor; tek bir kayıp satır turu durdurmamalı."""
        assert purge_expired_file(db, 9999, source="test") in (True, False)


# ──────────────────────────────────────────────────────────────────────────────
# B-004 — İmha sayacı arka planda da işliyor
# ──────────────────────────────────────────────────────────────────────────────


class TestImhaSayaciArkaPlanda:
    """
    B-004: İmha sayacı yalnızca arayüzde o sekme AÇIKKEN işliyordu.

    `UI/main_window_table.py::_tick_expiry` ilk satırında
    `if self._current_label != "Imha": return` yapıyor. Yani süresi dolmuş
    bir İmha Odası dosyası, kullanıcı o sekmeye girmediği sürece diskte
    kalıyordu — ve "24 saat içinde silinecek" diyen arayüz mesajı o süre
    boyunca doğru olmuyordu.
    """

    def test_imha_dosyasi_arka_planda_siliniyor(self, db, tmp_path, monkeypatch):
        """DÜZELTMENİN KENDİSİ — arayüz hiç açılmadan silinmeli."""
        from CORE import scheduler
        from DB.db_manager import DBManager

        fid, hcl = _mk_file(db, tmp_path, label="Imha", filename="imha.pdf")
        db.execute(
            "UPDATE files SET expires_at = ? WHERE id = ?",
            ("2020-01-01T00:00:00Z", fid),
        )

        monkeypatch.setattr(DBManager, "__new__", lambda cls, *a, **k: db)
        scheduler._purge_expired()

        assert not hcl.exists()
        assert db.fetchone("SELECT id FROM files WHERE id = ?", (fid,)) is None

    def test_saklama_supurmesi_ile_gelen_dosya_arka_planda_SILINMIYOR(
        self, db, tmp_path, monkeypatch
    ):
        """
        BU DÜZELTMENİN EN KRİTİK TESTİ.

        `sweep_retention_expired()` saklama süresi dolan dosyaları İmha
        Odası'na `expires_at = NULL` ile taşıyor ve bu bilerek böyle:
        sayaç kurmak, süresi dolan her dosyayı 24 saat sonra kimse
        onaylamadan yok ederdi (CORE/disposal.py modül docstring'i).

        İmha etiketi arka plan temizliğine eklendiği an o NULL disiplini
        tek koruma hâline geldi. Bu test onu sabitliyor: süpürülmüş dosya
        arka planda SİLİNMEMELİ, İmha Odası'nda süresiz beklemeli.
        """
        from CORE import scheduler
        from DB.db_manager import DBManager

        fid, hcl, _ = _expired_file(db, tmp_path, filename="supurulen.pdf")
        tasinan = sweep_retention_expired(db)
        assert fid in tasinan

        satir = db.fetchone(
            "SELECT label, expires_at FROM files WHERE id = ?", (fid,)
        )
        assert satir["label"] == "Imha"
        assert satir["expires_at"] is None, "süpürme sayaç kurmuş — B-004 tehlikede"

        monkeypatch.setattr(DBManager, "__new__", lambda cls, *a, **k: db)
        scheduler._purge_expired()

        assert hcl.exists(), "süpürülmüş dosya arka planda silindi — onaysız imha"
        assert db.fetchone("SELECT id FROM files WHERE id = ?", (fid,)) is not None

    def test_saklama_korumali_imha_dosyasi_arka_planda_atlaniyor(
        self, db, tmp_path, monkeypatch
    ):
        """
        Sayacı ELLE kurulmuş ama saklama süresi hâlâ işleyen dosya.

        Kullanıcı bir dosyayı İmha Odası'na taşıyabilir (sayaç kurulur) ama
        saklama süresi dolmamış olabilir. Karantina tarafındaki koruma
        neyse İmha tarafında da o olmalı.
        """
        from CORE import scheduler
        from DB.db_manager import DBManager

        fid, hcl, _ = _active_file(db, tmp_path, filename="korumali.pdf")
        db.execute(
            "UPDATE files SET label = 'Imha', expires_at = ? WHERE id = ?",
            ("2020-01-01T00:00:00Z", fid),
        )

        monkeypatch.setattr(DBManager, "__new__", lambda cls, *a, **k: db)
        scheduler._purge_expired()

        assert hcl.exists()
        assert "retention_hold" in _actions(db, fid)

    def test_suresi_dolmamis_imha_dosyasina_dokunulmuyor(
        self, db, tmp_path, monkeypatch
    ):
        """Sayaç henüz dolmadıysa dosya durmalı."""
        from CORE import scheduler
        from DB.db_manager import DBManager

        fid, hcl = _mk_file(db, tmp_path, label="Imha", filename="bekleyen.pdf")
        db.execute(
            "UPDATE files SET expires_at = ? WHERE id = ?",
            ("2099-01-01T00:00:00Z", fid),
        )

        monkeypatch.setattr(DBManager, "__new__", lambda cls, *a, **k: db)
        scheduler._purge_expired()

        assert hcl.exists()
        assert db.fetchone("SELECT id FROM files WHERE id = ?", (fid,)) is not None

    def test_iki_etiket_ayri_denetim_kaynagi_yaziyor(
        self, db, tmp_path, monkeypatch
    ):
        """
        "Bu dosya neden silindi" sorusunun yanıtı hangi sayacın işlediğini
        içermeli. İki etiket tek bir `source` altında toplanırsa denetim
        kaydı Karantina TTL'i ile İmha geri sayımını ayırt edemez.
        """
        from CORE import scheduler
        from DB.db_manager import DBManager

        past = "2020-01-01T00:00:00Z"
        k_id, _ = _mk_file(db, tmp_path, label="Karantina", filename="k.pdf")
        i_id, _ = _mk_file(db, tmp_path, label="Imha", filename="i.pdf")
        for fid in (k_id, i_id):
            db.execute("UPDATE files SET expires_at = ? WHERE id = ?", (past, fid))

        monkeypatch.setattr(DBManager, "__new__", lambda cls, *a, **k: db)
        scheduler._purge_expired()

        def _detay(fid: int) -> str:
            satir = db.fetchone(
                "SELECT detail FROM audit_log"
                " WHERE target_id = ? AND action = 'expired_purge'"
                " ORDER BY id DESC LIMIT 1",
                (fid,),
            )
            return satir["detail"] if satir else ""

        assert "quarantine_ttl" in _detay(k_id)
        assert "imha_ttl" in _detay(i_id)

    def test_sayaci_olmayan_imha_dosyasina_hic_dokunulmuyor(
        self, db, tmp_path, monkeypatch
    ):
        """
        ASIL KORUMANIN TESTİ — `expires_at IS NULL` satırı hiç seçilmemeli.

        Süpürme testi bunu dolaylı gösteriyor; bu test doğrudan, saklama
        profili hiç olmayan çıplak bir satırla gösteriyor. Fark önemli:
        korumanın kaynağı saklama mantığı DEĞİL, sorgunun NULL'ı hiç
        seçmemesi.

        Korumanın nasıl kırılacağı da buradan okunuyor: sorgu NULL'ı bir
        tarihe çevirirse (`COALESCE(expires_at, '1970-01-01')`) bu test
        düşer. `expires_at IS NOT NULL` koşulunun kendisini düşürmek ise
        davranışı değiştirmez — SQLite'ta `datetime(NULL) <= datetime('now')`
        zaten NULL, yani asla doğru değil. İlk yazılışında bu testin yerinde
        o koşulu KAYNAKTA arayan bir denetim vardı; koşulu silen mutasyon
        hayatta kaldı ve denetimin docstring'deki adı eşleştirdiği ortaya
        çıktı. Ölçen bir test, metin arayan bir testten iyidir.
        """
        from CORE import scheduler
        from DB.db_manager import DBManager

        fid, hcl = _mk_file(db, tmp_path, label="Imha", filename="sayacsiz.pdf")
        db.execute("UPDATE files SET expires_at = NULL WHERE id = ?", (fid,))

        monkeypatch.setattr(DBManager, "__new__", lambda cls, *a, **k: db)
        scheduler._purge_expired()

        assert hcl.exists(), "sayacı olmayan dosya silindi — onaysız imha"
        assert db.fetchone("SELECT id FROM files WHERE id = ?", (fid,)) is not None
        assert "expired_purge" not in _actions(db, fid)

    def test_arayuz_sayaci_kaldirilmadi(self):
        """
        Arka plan işi arayüz sayacının YERİNE geçmiyor, YANINA ekleniyor.

        Geri sayımı saniye saniye göstermek ve satırı tablodan düşürmek
        hâlâ arayüzün işi; 10 dakikalık bir arka plan turu onu yapamaz.
        """
        import ast
        from pathlib import Path as _P

        kok = _P(__file__).resolve().parent.parent
        src = (kok / "UI" / "main_window_table.py").read_text(encoding="utf-8")
        adlar = {
            n.name for n in ast.walk(ast.parse(src))
            if isinstance(n, ast.FunctionDef)
        }
        assert "_tick_expiry" in adlar
        assert "_purge_expired_file" in adlar


# ──────────────────────────────────────────────────────────────────────────────
# Scheduler entegrasyonu
# ──────────────────────────────────────────────────────────────────────────────


class TestSchedulerEntegrasyonu:
    def test_supurme_gorevi_kayitli(self, monkeypatch):
        from CORE import scheduler

        kayitli: list[str] = []

        class SahteScheduler:
            def __init__(self, *a, **k) -> None:
                pass

            def add_job(self, func, **kwargs):
                kayitli.append(kwargs["id"])

            def start(self) -> None:
                pass

            def shutdown(self, **kwargs) -> None:
                pass

        monkeypatch.setattr(scheduler, "BackgroundScheduler", SahteScheduler)
        monkeypatch.setattr(scheduler, "_scheduler", None)
        try:
            scheduler.start_scheduler()
            # Bu testin konusu süpürme görevinin AYRI bir iş olarak kayıtlı
            # olması (karantina temizliği düşerse süpürme çalışmaya devam
            # etsin). Listenin tamamını sabitlemek, ilgisiz her yeni görevde
            # bu testi kırardı — nitekim denetim çıpası eklenince kırıldı.
            assert "sweep_retention" in kayitli
            assert "purge_expired" in kayitli
            assert len(set(kayitli)) == len(kayitli)  # id çakışması yok
        finally:
            monkeypatch.setattr(scheduler, "_scheduler", None)

    def test_supurme_gorevi_hatayi_yutuyor(self, monkeypatch):
        """Bir çalıştırma patlarsa zamanlayıcı ölmemeli."""
        from CORE import scheduler

        def patla(*a, **k):
            raise RuntimeError("test")

        monkeypatch.setattr("CORE.disposal.sweep_retention_expired", patla)
        scheduler._sweep_retention()      # istisna dışarı sızmamalı


# ──────────────────────────────────────────────────────────────────────────────
# 2026-08-29 — çökmeye dayanıklı kalıcı silme kuyruğu (disposal_queue)
#
# purge_file()/purge_expired_file() bir dosyayı silerken iki bağımsız adım
# atıyor: disk unlink() ve `files` DELETE'i. Süreç TAM ARADA ölürse (güç
# kesintisi, kill -9), açılışta resume_pending_disposals() kuyrukta kalan
# satırı bulup kaldığı yerden bitirmeli. Testler burada gerçek bir process
# kill'i TAKLİT ETMİYOR (mümkün değil) — çökmenin DB'de bıraktığı durumu
# elle üretip yalnızca kurtarma tarafını doğruluyor; asıl kanıtlanması
# gereken şey kesintinin kendisi değil, kaldığı yerden tamamlanma.
# ──────────────────────────────────────────────────────────────────────────────


def _kuyruga_yaz(db, *, file_id, filename, filepath, action="purge_file", source="test"):
    """`_enqueue()`'un yaptığı INSERT'in testteki karşılığı — çökme ANINI kurar."""
    cur = db.execute(
        "INSERT INTO disposal_queue (file_id, filename, filepath, action, source)"
        " VALUES (?, ?, ?, ?, ?)",
        (file_id, filename, filepath, action, source),
    )
    return int(cur.lastrowid)


def _kuyruk_satirlari(db):
    return db.fetchall("SELECT * FROM disposal_queue")


class TestYarimKalanImhaKurtarmasi:
    def test_bos_kuyruk_hicbir_sey_yapmiyor(self, db):
        rapor = resume_pending_disposals(db)
        assert rapor.had_pending is False
        assert rapor.resumed == 0
        assert rapor.failed == 0

    def test_unlink_SONRASI_files_DELETE_ONCESI_kesilen_silme_tamamlaniyor(
        self, db, tmp_path
    ):
        """
        Süreç `unlink()` BAŞARILI OLDUKTAN hemen sonra, `files` satırı
        silinmeden ÖNCE öldürülmüş: disk dosyası zaten yok, `files` satırı
        hâlâ duruyor, kuyrukta niyet satırı var. Bu, docstring'deki 1-3
        adımlarının en kritik ara durumu — DB, artık var olmayan bir
        dosyayı hâlâ "var" sanıyor.
        """
        fid, hcl = _mk_file(db, tmp_path, filename="yarim_unlink_sonrasi.pdf")
        queue_id = _kuyruga_yaz(db, file_id=fid, filename="yarim_unlink_sonrasi.pdf",
                                 filepath=str(hcl))
        hcl.unlink()  # crash öncesi adım 2 zaten TAMAMLANMIŞTI

        assert hcl.exists() is False
        assert db.fetchone("SELECT id FROM files WHERE id = ?", (fid,)) is not None

        rapor = resume_pending_disposals(db)

        assert rapor.resumed == 1
        assert rapor.failed == 0
        assert "yarim_unlink_sonrasi.pdf" in rapor.names
        # Tutarlı son durum: disk YOK, files satırı YOK, kuyruk BOŞ.
        assert hcl.exists() is False
        assert db.fetchone("SELECT id FROM files WHERE id = ?", (fid,)) is None
        assert db.fetchone("SELECT id FROM disposal_queue WHERE id = ?", (queue_id,)) is None
        assert "disposal_resumed" in _actions(db, fid)

    def test_enqueue_SONRASI_unlink_ONCESI_kesilen_silme_tamamlaniyor(self, db, tmp_path):
        """
        Süreç niyet kuyruğa yazıldıktan HEMEN sonra, disk `unlink()` hiç
        başlamadan öldürülmüş: disk dosyası HÂLÂ DURUYOR. Kurtarma bu
        durumda diskten silmeyi KENDİSİ yapmalı — resume iki adımı da
        (unlink + DELETE) üstlenebilmeli, yalnızca ikinciyi değil.
        """
        fid, hcl = _mk_file(db, tmp_path, filename="yarim_enqueue_sonrasi.pdf")
        queue_id = _kuyruga_yaz(db, file_id=fid, filename="yarim_enqueue_sonrasi.pdf",
                                 filepath=str(hcl))

        assert hcl.exists() is True  # crash öncesi adım 2 HİÇ başlamamıştı

        rapor = resume_pending_disposals(db)

        assert rapor.resumed == 1
        assert hcl.exists() is False  # resume disk silmeyi kendisi yaptı
        assert db.fetchone("SELECT id FROM files WHERE id = ?", (fid,)) is None
        assert db.fetchone("SELECT id FROM disposal_queue WHERE id = ?", (queue_id,)) is None

    def test_birden_fazla_yarim_kalan_islem_tek_turda_tamamlaniyor(self, db, tmp_path):
        """Bir önceki oturum tek dosyada değil BİRDEN FAZLA imhanın ortasında ölmüş olabilir."""
        fid1, hcl1 = _mk_file(db, tmp_path, filename="c1.pdf")
        fid2, hcl2 = _mk_file(db, tmp_path, filename="c2.pdf")
        _kuyruga_yaz(db, file_id=fid1, filename="c1.pdf", filepath=str(hcl1))
        _kuyruga_yaz(db, file_id=fid2, filename="c2.pdf", filepath=str(hcl2))
        hcl1.unlink()  # biri unlink sonrası, diğeri unlink öncesi kesilmiş

        rapor = resume_pending_disposals(db)

        assert rapor.resumed == 2
        assert not hcl1.exists() and not hcl2.exists()
        for fid in (fid1, fid2):
            assert db.fetchone("SELECT id FROM files WHERE id = ?", (fid,)) is None
        assert _kuyruk_satirlari(db) == []

    def test_normal_akiste_kuyrukta_artik_kalmiyor(self, db, tmp_path):
        """Mutlu yol (çökme YOK): purge_file() biter bitmez kuyruk boş olmalı."""
        fid, hcl = _mk_file(db, tmp_path, filename="normal.pdf")
        purge_file(db, fid)
        assert _kuyruk_satirlari(db) == []

    def test_ikinci_calistirma_etkisiz(self, db, tmp_path):
        """Kurtarma iki kez çalışsa da (ör. açılış iki kez tetiklenirse) zarar vermemeli."""
        fid, hcl = _mk_file(db, tmp_path, filename="tekrar.pdf")
        _kuyruga_yaz(db, file_id=fid, filename="tekrar.pdf", filepath=str(hcl))

        birinci = resume_pending_disposals(db)
        ikinci = resume_pending_disposals(db)

        assert birinci.resumed == 1
        assert ikinci.had_pending is False
