"""
Dosya kaydının veritabanına yazılması — özellikle added_by (BACKLOG B-005).

Bu SQL daha önce UI/main_window.py içinde satır içi duruyordu ve tam da bu
yüzden test edilemiyordu; added_by kolonu INSERT listesinden düşmüş ve
kimse fark etmemişti. Artık CORE'da ve Qt gerektirmeden sınanıyor.
"""
from __future__ import annotations

import itertools

import pytest

from CORE.file_records import record_encrypted_file
from CORE.inventory import UNKNOWN_OWNER_TEXT, generate_retention_inventory

_sayac = itertools.count(1)


def _mk_user(db, username=None):
    username = username or f"kullanici{next(_sayac)}"
    cur = db.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')",
        (username, "x"),
    )
    return int(cur.lastrowid)


def _row(db, file_id):
    return db.fetchone("SELECT * FROM files WHERE id = ?", (file_id,))


class TestAddedBy:
    def test_yeni_kayitta_yaziliyor(self, db):
        """B-005'in özü: kullanıcı id'si gerçekten DB'ye ulaşıyor mu."""
        uid = _mk_user(db, "ayse")
        fid = record_encrypted_file(
            db, filename="belge.pdf", filepath="/vault/belge.hcl",
            label="Karantina", added_by=uid,
        )
        assert _row(db, fid)["added_by"] == uid

    def test_farkli_kullanicilar_ayri_yaziliyor(self, db):
        ayse = _mk_user(db, "ayse")
        mehmet = _mk_user(db, "mehmet")
        f1 = record_encrypted_file(db, filename="a.pdf", filepath="/vault/a.hcl",
                                   label="Genel", added_by=ayse)
        f2 = record_encrypted_file(db, filename="b.pdf", filepath="/vault/b.hcl",
                                   label="Genel", added_by=mehmet)
        assert _row(db, f1)["added_by"] == ayse
        assert _row(db, f2)["added_by"] == mehmet

    def test_added_by_none_kabul_ediliyor(self, db):
        """Kullanıcı bilinmiyorsa NULL yazılır — uydurma değer yok."""
        fid = record_encrypted_file(db, filename="a.pdf", filepath="/vault/a.hcl",
                                    label="Genel", added_by=None)
        assert _row(db, fid)["added_by"] is None

    def test_gecersiz_kullanici_fk_ile_reddediliyor(self, db):
        import sqlite3

        with pytest.raises(sqlite3.IntegrityError):
            record_encrypted_file(db, filename="a.pdf", filepath="/vault/a.hcl",
                                  label="Genel", added_by=9999)

    def test_kullanici_silininde_null_oluyor(self, db):
        """ON DELETE SET NULL — dosya kalır, sahip boşalır."""
        uid = _mk_user(db)
        fid = record_encrypted_file(db, filename="a.pdf", filepath="/vault/a.hcl",
                                    label="Genel", added_by=uid)
        db.execute("DELETE FROM users WHERE id = ?", (uid,))
        assert _row(db, fid)["added_by"] is None
        assert _row(db, fid) is not None


class TestOnConflictDali:
    def test_ayni_yol_yeni_satir_acmiyor(self, db):
        uid = _mk_user(db)
        f1 = record_encrypted_file(db, filename="a.pdf", filepath="/vault/a.hcl",
                                   label="Genel", added_by=uid)
        f2 = record_encrypted_file(db, filename="a_yeni.pdf", filepath="/vault/a.hcl",
                                   label="Kritik", added_by=uid)
        assert f1 == f2
        assert db.fetchone("SELECT COUNT(*) c FROM files")["c"] == 1

    def test_ilk_sahip_korunuyor(self, db):
        """
        Kararın özü: yeniden yükleyen kişi sahibi DEĞİŞTİRMEZ.

        added_at zaten güncellenmiyor ("ilk kayıt tarihi"); added_by da onunla
        çift olduğu için güncellenmiyor ("ilk kaydeden"). Biri korunup diğeri
        güncellenseydi kayıt kendi içinde tutarsız olurdu.
        """
        ilk = _mk_user(db, "ilk_sahip")
        sonraki = _mk_user(db, "sonraki")
        fid = record_encrypted_file(db, filename="a.pdf", filepath="/vault/a.hcl",
                                    label="Genel", added_by=ilk)
        record_encrypted_file(db, filename="a.pdf", filepath="/vault/a.hcl",
                              label="Kritik", added_by=sonraki)
        assert _row(db, fid)["added_by"] == ilk

    def test_ilk_kayit_tarihi_korunuyor(self, db):
        """added_by kararının dayandığı mevcut davranış."""
        uid = _mk_user(db)
        fid = record_encrypted_file(db, filename="a.pdf", filepath="/vault/a.hcl",
                                    label="Genel", added_by=uid)
        db.execute("UPDATE files SET added_at = '2020-01-01T00:00:00Z' WHERE id = ?",
                   (fid,))
        record_encrypted_file(db, filename="a.pdf", filepath="/vault/a.hcl",
                              label="Kritik", added_by=uid)
        assert _row(db, fid)["added_at"] == "2020-01-01T00:00:00Z"

    def test_eski_null_kayit_doldurulmuyor(self, db):
        """
        Geriye dönük dolgu YOK — sonradan dokunan kişi sahip yazılmaz.

        COALESCE(added_by, excluded.added_by) kullanılsaydı, kimin yüklediği
        gerçekte bilinmeyen eski kayıtlar dosyaya sonradan dokunan kişiye
        atfedilirdi. Bu tahmin olurdu.
        """
        eski = record_encrypted_file(db, filename="a.pdf", filepath="/vault/a.hcl",
                                     label="Genel", added_by=None)
        yeni_kullanici = _mk_user(db, "sonradan_gelen")
        record_encrypted_file(db, filename="a.pdf", filepath="/vault/a.hcl",
                              label="Kritik", added_by=yeni_kullanici)
        assert _row(db, eski)["added_by"] is None

    def test_diger_alanlar_tazeleniyor(self, db):
        uid = _mk_user(db)
        fid = record_encrypted_file(
            db, filename="a.pdf", filepath="/vault/a.hcl", label="Genel",
            size_bytes=100, original_sha256="aaa", aad_metadata="{}", added_by=uid,
        )
        record_encrypted_file(
            db, filename="a_yeni.pdf", filepath="/vault/a.hcl", label="Kritik",
            size_bytes=200, original_sha256="bbb", aad_metadata="{'x':1}", added_by=uid,
        )
        row = _row(db, fid)
        assert row["filename"] == "a_yeni.pdf"
        assert row["label"] == "Kritik"
        assert row["size_bytes"] == 200
        assert row["original_sha256"] == "bbb"


class TestEnvanterEtkisi:
    def test_yeni_dosya_sahibi_raporda_gorunuyor(self, db):
        """B-005 düzeltmesinin görünür sonucu."""
        uid = _mk_user(db, "ayse")
        record_encrypted_file(db, filename="belge.pdf", filepath="/vault/belge.hcl",
                              label="Genel", added_by=uid)
        assert generate_retention_inventory(db)[0].owner == "ayse"

    def test_eski_kayitlar_bilinmiyor_kaliyor(self, db):
        """Geriye dönük dolgu yapılmadı — dürüst davranış korunuyor."""
        record_encrypted_file(db, filename="eski.pdf", filepath="/vault/eski.hcl",
                              label="Genel", added_by=None)
        assert generate_retention_inventory(db)[0].owner == UNKNOWN_OWNER_TEXT


class TestDonusDegeri:
    def test_file_id_donuyor(self, db):
        fid = record_encrypted_file(db, filename="a.pdf", filepath="/vault/a.hcl",
                                    label="Genel")
        assert isinstance(fid, int)
        assert _row(db, fid)["filepath"] == "/vault/a.hcl"

    def test_opsiyonel_alanlar_atlanabiliyor(self, db):
        fid = record_encrypted_file(db, filename="a.pdf", filepath="/vault/a.hcl",
                                    label="Genel")
        row = _row(db, fid)
        assert row["size_bytes"] is None
        assert row["folder_id"] is None
        assert row["added_by"] is None
