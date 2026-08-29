"""
DB/db_manager.py — RBAC (yazma yetkisi) UI'ı ATLAYAN yollara da uygulanıyor.

Sorgu (2026-08-29): RBAC (`CORE/roles.py::can_write`) yalnızca UI'da
uygulanıyordu — düğme gizleme/pasifleştirme (`UI/main_window*.py::
_apply_role_restrictions`). `DBManager`'ın kendisi çağıranın rolünden
TAMAMEN HABERSİZDİ: `execute()` gelen her SQL'i sorgusuz sualsiz
çalıştırıyordu. ÖLÇÜLDÜ: `UI/TagDialog.py` bugün `is_readonly_role`'a HİÇ
bakmıyor (`tests/test_db_manager_rbac.py::
test_UI_katmaninin_kendisi_boslugu_kanitliyor_TagDialog_rol_kontrolu_yok`
bunu kod TARAMASIYLA sabitliyor) — yalnızca kendini açan düğmenin
gizlenmesine güveniyor. Yani "UI'ı atlayan" senaryo teorik değil: TagDialog
başka bir yoldan açılsaydı (ör. sağ tık menüsü genişlese), Salt Okunur bir
oturum hiçbir DB katmanı engeliyle karşılaşmadan etiket
oluşturabilir/silebilirdi.

Düzeltme: `DBManager.execute()` artık SQL'in hedef tablosunu ayrıştırıp
(_YAZMA_HEDEFI_DESENI) iş verisi tablolarında (_RBAC_KORUMALI_TABLOLAR)
`can_write(self._role)`'ı kontrol ediyor — `UI/main_window.py::
_apply_role_restrictions()` rolü `DBManager().set_active_role()` ile
bildirdikten SONRA. Böylece CLI'dan, doğrudan bir CORE çağrısından ya da
unutulmuş bir UI kontrolünden gelen hiçbir yazı bu son kontrolü atlayamıyor.

`users`/`login_attempts`/`settings` BİLİNÇLİ OLARAK dışarıda bırakıldı —
gerekçe `DB/db_manager.py::_RBAC_KORUMALI_TABLOLAR`'ın kendi yorumunda;
bu dosyadaki `test_oturum_defteri_tablolari_rolden_bagimsiz_calisiyor` o
kararı sabitliyor.

`CORE/disposal.py::purge_expired_file()` / `sweep_retention_expired()`
"kimseye sormadan" çalışması gereken otomatik temizleyiciler — ikisi de
`db.system_write()` ile rol denetimini bilerek atlıyor.
`test_otomatik_temizleyiciler_salt_okunur_oturumda_calismaya_devam_ediyor`
bunun GERÇEKTEN çalıştığını, salt okunur bir oturum ortasında bile,
ölçüyor.

Sorgu (2026-08-29, devam) — K1-14: `system_write()` bypass'ının kendisi
CANLI incelendi (thread-local sayaç, `try/finally`, iç içe çağrı) ve
sızıntı bulunamadı — ama o incelemede AYRI, gerçek bir boşluk ortaya
çıktı: reddedilen bir RBAC yazması `weak_hwid_binding_rejected`/
`usb_auth_rejected` ile AYNI "reddet ve kaydet" desenini izlemiyordu,
audit_log'a hiçbir iz düşmüyordu. `_yazma_yetkisini_dogrula()` artık
`raise` etmeden HEMEN önce `rbac_write_rejected` eylemiyle `self.log()`
çağırıyor — rol, hedef tablo, SQL fiili (INSERT/UPDATE/DELETE/REPLACE) ve
çağıran bağlamı (`modül.fonksiyon:satır`) `detail`'e yazılıyor.
Rekürsiyon riski YOK: `self.log()` `CORE.audit_chain.append_entry()`'ye
yönleniyor ve o `self.conn`'a (ham `sqlite3.Connection`) doğrudan
yazıyor — `self.execute()`'u hiç GÖRMÜYOR; ayrıca `audit_log` zaten
`_RBAC_KORUMALI_TABLOLAR`'ın dışında. İki bağımsız garanti.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from CORE.folders import create_folder
from CORE.roles import ROL_SALT_OKUNUR, ROL_STANDART, ROL_YONETICI
from DB.db_manager import YazmaYetkisiYokError

_KOK = Path(__file__).resolve().parent.parent


# ══════════════════════════════════════════════════════════════════════════════
# 1. Ham SQL — UI'ı TAMAMEN atlayarak doğrudan db_manager çağrısı
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize(
    "tablo,sql",
    [
        ("files", "INSERT INTO files (filename, filepath) VALUES ('x','y')"),
        ("folders", "INSERT INTO folders (name) VALUES ('yeni-klasor')"),
        ("tags", "INSERT INTO tags (name) VALUES ('yeni-etiket')"),
        ("file_tags", "INSERT INTO file_tags (file_id, tag_id) VALUES (1, 1)"),
        ("quarantine", "INSERT INTO quarantine (file_id, reason) VALUES (1, 'x')"),
        (
            "retention_profiles",
            "INSERT INTO retention_profiles (name, duration_value, duration_unit) "
            "VALUES ('p', 1, 'gun')",
        ),
        (
            "disposal_queue",
            "INSERT INTO disposal_queue (file_id, action) VALUES (1, 'purge_file')",
        ),
    ],
)
def test_salt_okunur_is_verisi_tablolarina_dogrudan_yazamiyor(
    db, tablo: str, sql: str,
) -> None:
    """
    UI HİÇ DEVREDE DEĞİL: hiçbir QDialog, hiçbir düğme yok — doğrudan
    `db.execute()`. Bu, "olası bir bug" ya da bir CLI script'in göreceği
    tam yol.
    """
    db.set_active_role(ROL_SALT_OKUNUR)
    with pytest.raises(YazmaYetkisiYokError, match=tablo):
        db.execute(sql)


@pytest.mark.parametrize("rol", [ROL_STANDART, ROL_YONETICI])
def test_yazabilen_roller_ayni_sorguda_engellenmiyor(db, rol: str) -> None:
    """Mutasyon kontrastı — kısıtlama role ÖZGÜ, tabloya değil."""
    db.set_active_role(rol)
    db.execute("INSERT INTO folders (name) VALUES ('standart-klasor')")
    row = db.fetchone("SELECT id FROM folders WHERE name = 'standart-klasor'")
    assert row is not None


def test_rol_hic_ayarlanmamissa_kisitlama_yok(db) -> None:
    """
    `set_active_role()` hiç çağrılmadıysa (açılış, göç, çoğu test) yazı
    SERBEST kalmalı — `_role` varsayılanı `None`, bkz. `__new__` gerekçesi.
    Bu, mevcut testlerin ve sistem/göç kodunun neden hiç kırılmadığının
    nedeni.
    """
    db.execute("INSERT INTO folders (name) VALUES ('rolsuz-klasor')")
    row = db.fetchone("SELECT id FROM folders WHERE name = 'rolsuz-klasor'")
    assert row is not None


def test_bilinmeyen_rol_de_yazamiyor(db) -> None:
    """`can_write()` bilinmeyen rolü de dar tutuyor (CORE/roles.py) — DB
    katmanı bunu MİRAS ALIYOR, ikinci bir varsayılan İCAT ETMİYOR."""
    db.set_active_role("uydurma-rol")
    with pytest.raises(YazmaYetkisiYokError):
        db.execute("INSERT INTO tags (name) VALUES ('x')")


def test_okuma_sorgulari_rolden_bagimsiz_her_zaman_calisiyor(db) -> None:
    """SELECT hiçbir zaman engellenmemeli — kısıtlama yalnızca yazıya."""
    db.set_active_role(ROL_SALT_OKUNUR)
    db.fetchall("SELECT * FROM files")
    db.fetchone("SELECT COUNT(*) AS n FROM folders")


# ══════════════════════════════════════════════════════════════════════════════
# 2. Gerçek bir CORE fonksiyonu üzerinden — "sadece ham SQL'i mi yakalıyor"
#    sorusuna karşı
# ══════════════════════════════════════════════════════════════════════════════


def test_salt_okunur_CORE_folders_create_folder_ile_de_engelleniyor(db) -> None:
    """
    Ham SQL değil, gerçek üretim kod yolu: `CORE.folders.create_folder()`
    — `UI/main_window_tree.py`'nin "Yeni Klasör" düğmesinin çağırdığı AYNI
    fonksiyon. Düğme gizlense de gizlenmese de bu fonksiyon artık kendi
    başına savunmasız değil.
    """
    db.set_active_role(ROL_SALT_OKUNUR)
    with pytest.raises(YazmaYetkisiYokError, match="folders"):
        create_folder(db, "salt-okunur-klasoru", owner_id=1, hwid="X")

    assert db.fetchone(
        "SELECT id FROM folders WHERE name = 'salt-okunur-klasoru'"
    ) is None, "reddedilen yazı yine de kalıcı olmuş"


# ══════════════════════════════════════════════════════════════════════════════
# 3. Bilinçli olarak dışarıda bırakılan tablolar — oturum defteri
# ══════════════════════════════════════════════════════════════════════════════


def test_oturum_defteri_tablolari_rolden_bagimsiz_calisiyor(db) -> None:
    """
    `users`/`login_attempts`/`settings` RBAC'ın DIŞINDA — BİLİNÇLİ bir
    sınır (bkz. DB/db_manager.py::_RBAC_KORUMALI_TABLOLAR yorumu), boşluk
    değil. Salt okunur bir oturumun GİRİŞ YAPABİLMESİ
    (`CORE.session_user.sync_session_user`), rate-limit sayacının
    (`CORE.rate_limit`) her rolde işlemesi ve "Yedek Al…" menüsünün
    (rolden bağımsız erişilebilir — ölçüldü) buna bağlı olması bu testin
    gerekçesi.
    """
    db.set_active_role(ROL_SALT_OKUNUR)

    db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid) "
        "VALUES ('vault:x', '!x', 'user', 'approved', 'HWID-RBAC-TEST')"
    )
    db.execute(
        "INSERT INTO login_attempts (hwid, fail_count, last_attempt) "
        "VALUES ('HWID-RBAC-TEST', 1, '2026-08-29T00:00:00Z')"
    )
    db.set_setting("app_mode_reminder_test", "ertelendi")

    assert db.fetchone(
        "SELECT id FROM users WHERE hwid = 'HWID-RBAC-TEST'"
    ) is not None
    assert db.get_setting("app_mode_reminder_test") == "ertelendi"


# ══════════════════════════════════════════════════════════════════════════════
# 4. system_write() — otomatik temizleyiciler salt okunur oturumda da çalışmalı
# ══════════════════════════════════════════════════════════════════════════════


def test_otomatik_temizleyiciler_salt_okunur_oturumda_calismaya_devam_ediyor(
    db,
) -> None:
    """
    `CORE.disposal.purge_expired_file()` / `sweep_retention_expired()`
    "kimseye sormadan" çalışan sayaçlar — APScheduler'ın arka plan iş
    parçacığından VE İmha Odası'nı izleyen kullanıcının UI zamanlayıcısından
    tetiklenirler. Salt okunur bir kullanıcı ekranda dururken sayaç sıfıra
    inerse silme YİNE gerçekleşmeli — `db.system_write()` bunu garanti
    ediyor. Bu test onun GERÇEKTEN çalıştığını ölçüyor, yalnızca varlığını
    değil.
    """
    from CORE.disposal import purge_expired_file, sweep_retention_expired

    # Kurulum YAZILARI rol henüz ayarlanmadan yapılıyor (bu testin konusu
    # değil — bkz. test_rol_hic_ayarlanmamissa_kisitlama_yok). Asıl ölçüm
    # aşağıda, rol Salt Okunur'a ayarlandıktan SONRA.
    cur = db.execute(
        "INSERT INTO files (filename, filepath, label) "
        "VALUES ('sona-eren.hcl', '/tmp/sona-eren.hcl', 'Imha')"
    )
    file_id = int(cur.lastrowid)
    cur2 = db.execute(
        "INSERT INTO retention_profiles (name, duration_value, duration_unit) "
        "VALUES ('rbac-test-profili', 1, 'gun')"
    )
    profil_id = int(cur2.lastrowid)
    cur3 = db.execute(
        "INSERT INTO files (filename, filepath, label, retention_profile_id, "
        "added_at, retention_start_date) VALUES "
        "('eski.hcl', '/tmp/eski.hcl', 'Genel', ?, "
        "'2000-01-01T00:00:00Z', NULL)",
        (profil_id,),
    )
    eski_file_id = int(cur3.lastrowid)

    db.set_active_role(ROL_SALT_OKUNUR)

    silindi = purge_expired_file(db, file_id, source="test_scheduler")
    assert silindi is True
    assert db.fetchone("SELECT id FROM files WHERE id = ?", (file_id,)) is None

    # sweep_retention_expired de aynı bypass'ı kullanıyor — bağımsız ölçüm.
    tasinanlar = sweep_retention_expired(db)
    assert eski_file_id in tasinanlar
    row = db.fetchone("SELECT label FROM files WHERE id = ?", (eski_file_id,))
    assert row["label"] == "Imha"


# ══════════════════════════════════════════════════════════════════════════════
# 5. Mutasyon kontrastı — kontrol GERÇEKTEN bir şey mi ölçüyor
# ══════════════════════════════════════════════════════════════════════════════


def test_kontrol_kaldirilirsa_yazma_gercekten_gecerdi(
    db, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Yukarıdaki testlerin sahte bir yeşil OLMADIĞINI kanıtlar: `execute()`
    içindeki `_yazma_yetkisini_dogrula()` çağrısı devre dışı bırakılırsa
    (eski, savunmasız davranış simüle edilirse) aynı senaryoda yazı
    GERÇEKTEN geçiyor.
    """
    monkeypatch.setattr(
        type(db), "_yazma_yetkisini_dogrula", lambda self, sql: None,
    )
    db.set_active_role(ROL_SALT_OKUNUR)
    db.execute("INSERT INTO folders (name) VALUES ('guard-kapali-klasor')")
    row = db.fetchone("SELECT id FROM folders WHERE name = 'guard-kapali-klasor'")
    assert row is not None, (
        "guard kapalıyken bile yazı reddedildi — üstteki testler bu "
        "korumayı gerçekten ölçmüyor olabilir"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 6. UI'daki boşluğun kendisi — bu düzeltmenin NEDEN gerekli olduğunun kanıtı
# ══════════════════════════════════════════════════════════════════════════════


def test_UI_katmaninin_kendisi_boslugu_kanitliyor_TagDialog_rol_kontrolu_yok() -> None:
    """
    Statik kanıt: `UI/TagDialog.py` hiçbir yerde `is_readonly_role` ya da
    `can_write` çağırmıyor — yalnızca kendini açan düğmenin
    gizlenmesine/pasifleştirilmesine güveniyor. Bu test kod TARAMASI: dosya
    bir gün rol kontrolü kazanırsa (iyi haber) burası kırılıp bu testin
    artık geçersiz olduğunu bildirir; şu an DB katmanı gerekliliğinin
    somut kanıtı bu.
    """
    kaynak = (_KOK / "UI" / "TagDialog.py").read_text(encoding="utf-8")
    agac = ast.parse(kaynak)
    cagrilan_adlar = {
        n.func.id for n in ast.walk(agac)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }
    assert not ({"is_readonly_role", "can_write"} & cagrilan_adlar), (
        "TagDialog.py artık rol kontrolü çağırıyor — bu testin gerekçesi "
        "(DB katmanı SON ÇARE) hâlâ geçerli ama üst yorum güncellenmeli"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 7. K1-14 — reddedilen yazı audit zincirine düşüyor mu
# ══════════════════════════════════════════════════════════════════════════════


def test_reddedilen_yazi_audit_loga_tam_bir_rbac_write_rejected_satiri_dusuyor(
    db,
) -> None:
    """
    `weak_hwid_binding_rejected` (CORE/vault_manager.py) ve
    `usb_auth_rejected` ile AYNI desen: reddet VE neden olduğunu kaydet.
    Reddedilen bir RBAC yazması artık izsiz geçmiyor — `detail` alanı
    rolü, hedef tabloyu, SQL fiilini ve çağıran bağlamını taşıyor.
    """
    onceki_sayi = db.fetchone("SELECT COUNT(*) AS n FROM audit_log")["n"]

    db.set_active_role(ROL_SALT_OKUNUR)
    with pytest.raises(YazmaYetkisiYokError):
        db.execute("INSERT INTO tags (name) VALUES ('reddedilecek-etiket')")

    sonraki_sayi = db.fetchone("SELECT COUNT(*) AS n FROM audit_log")["n"]
    assert sonraki_sayi == onceki_sayi + 1, (
        f"tam olarak 1 audit satırı beklenir, {sonraki_sayi - onceki_sayi} "
        "eklendi"
    )

    satir = db.fetchone(
        "SELECT action, detail FROM audit_log ORDER BY id DESC LIMIT 1"
    )
    assert satir["action"] == "rbac_write_rejected"
    detay = satir["detail"]
    assert f"role={ROL_SALT_OKUNUR!r}" in detay
    assert "table=tags" in detay
    assert "op=INSERT" in detay
    assert "caller=" in detay
    # Bağlam bu test fonksiyonunun kendisini işaret etmeli — "bilinmiyor"a
    # düşmemeli, çünkü sys._getframe(2) burada her zaman çözümlenebilir.
    assert "bilinmiyor" not in detay


def test_reddedilen_yazi_kaydi_yeniden_uretilebilir_tum_gatelenmis_tablolarda(
    db,
) -> None:
    """Tek tablo/tek SQL fiili değil — her gate'lenmiş tablo ve fiil için
    `detail` doğru üretiliyor mu (mutasyon kontrastına karşı ek kanıt)."""
    db.set_active_role(ROL_SALT_OKUNUR)

    with pytest.raises(YazmaYetkisiYokError):
        db.execute("UPDATE folders SET name = 'x' WHERE id = 1")
    satir = db.fetchone(
        "SELECT detail FROM audit_log WHERE action = 'rbac_write_rejected' "
        "ORDER BY id DESC LIMIT 1"
    )
    assert "table=folders" in satir["detail"]
    assert "op=UPDATE" in satir["detail"]

    with pytest.raises(YazmaYetkisiYokError):
        db.execute("DELETE FROM quarantine WHERE id = 1")
    satir = db.fetchone(
        "SELECT detail FROM audit_log WHERE action = 'rbac_write_rejected' "
        "ORDER BY id DESC LIMIT 1"
    )
    assert "table=quarantine" in satir["detail"]
    assert "op=DELETE" in satir["detail"]


def test_yazma_denemesi_reddedilmeden_once_kayit_dusuyor_yarim_kalmiyor(
    db,
) -> None:
    """
    `db.log()` çağrısı `raise`'DEN ÖNCE yapılıyor — böylece kayıt, red
    işlemin kendisiyle aynı anda düşüyor, sonradan "belki biri loglar"a
    bırakılmıyor. Reddedilen INSERT'in dosyanın kendisine hiç
    YAZILMADIĞI da (yalnızca audit_log'a yazıldığı) doğrulanıyor.
    """
    db.set_active_role(ROL_SALT_OKUNUR)
    with pytest.raises(YazmaYetkisiYokError):
        db.execute("INSERT INTO tags (name) VALUES ('hic-var-olmamali')")

    assert db.fetchone(
        "SELECT id FROM tags WHERE name = 'hic-var-olmamali'"
    ) is None, "reddedilen yazı yine de kalıcı olmuş"
    assert db.fetchone(
        "SELECT id FROM audit_log WHERE action = 'rbac_write_rejected' "
        "AND detail LIKE '%hic-var-olmamali%'"
    ) is None, "detail beklenmedik biçimde satır DEĞERLERİNİ taşıyor"
    # detail satır değerlerini değil YAPISAL bilgiyi taşımalı (rol/tablo/
    # fiil/bağlam) — bir SQL parametresi (dosya adı, etiket adı vb.) audit
    # detayına SIZMAMALI. Yukarıdaki negatif kontrol bunu doğruluyor;
    # aşağıdaki de kaydın GERÇEKTEN düştüğünü teyit ediyor.
    assert db.fetchone(
        "SELECT id FROM audit_log WHERE action = 'rbac_write_rejected'"
    ) is not None


# ══════════════════════════════════════════════════════════════════════════════
# 8. system_write() İÇİNDEKİ meşru yazı yanlışlıkla "reddedildi" diye
#    loglanmıyor — negatif test
# ══════════════════════════════════════════════════════════════════════════════


def test_system_write_icindeki_mesru_yazi_rbac_write_rejected_uretmiyor(
    db,
) -> None:
    """
    `purge_expired_file()`/`sweep_retention_expired()` gibi sistem
    yazıları `system_write()` bypass'ı sayesinde reddedilMİYOR — ve bu
    testin asıl konusu: reddedilmedikleri için `rbac_write_rejected`
    kaydı da ÜRETMEMELİLER. `_yazma_yetkisini_dogrula()`'nın erken
    `return`'ü (bypass derinliği > 0) `db.log()` çağrısından ÖNCE, yani
    meşru bir sistem yazısının yanlışlıkla "reddedildi" diye denetim
    kaydına düşmesi mümkün değil — bu test onu CANLI ölçüyor.
    """
    onceki_sayi = db.fetchone("SELECT COUNT(*) AS n FROM audit_log")["n"]

    db.set_active_role(ROL_SALT_OKUNUR)
    with db.system_write():
        db.execute("INSERT INTO folders (name) VALUES ('mesru-sistem-klasoru')")

    sonraki_sayi = db.fetchone("SELECT COUNT(*) AS n FROM audit_log")["n"]
    assert sonraki_sayi == onceki_sayi, (
        "system_write() içindeki meşru yazı audit_log'a bir satır "
        "eklemiş — reddedilmemesi gereken bir yazı 'reddedildi' gibi "
        "kaydedilmiş olabilir"
    )
    assert db.fetchone(
        "SELECT id FROM audit_log WHERE action = 'rbac_write_rejected'"
    ) is None, (
        "system_write() bypass'ı altında yanlış bir rbac_write_rejected "
        "kaydı üretilmiş"
    )
    # Ve yazının kendisi GERÇEKTEN geçti — bypass sessizce yazıyı da
    # engellemiyor, yalnızca kaydı da atlamıyor.
    assert db.fetchone(
        "SELECT id FROM folders WHERE name = 'mesru-sistem-klasoru'"
    ) is not None


def test_otomatik_temizleyiciler_calisirken_de_yanlis_red_kaydi_uretmiyor(
    db,
) -> None:
    """Yukarıdakinin gerçek üretim koduyla tekrarı: `purge_expired_file()`
    salt okunur bir oturum ortasında çalışırken hiçbir
    `rbac_write_rejected` kaydı BIRAKMAMALI — çalıştığı zaten
    `test_otomatik_temizleyiciler_salt_okunur_oturumda_calismaya_devam_ediyor`
    ile doğrulanmıştı; buradaki ek soru audit tarafının TEMİZ kalıp
    kalmadığı."""
    from CORE.disposal import purge_expired_file

    cur = db.execute(
        "INSERT INTO files (filename, filepath, label) "
        "VALUES ('temiz-red-testi.hcl', '/tmp/temiz-red-testi.hcl', 'Imha')"
    )
    file_id = int(cur.lastrowid)

    db.set_active_role(ROL_SALT_OKUNUR)
    assert purge_expired_file(db, file_id, source="test_scheduler") is True

    assert db.fetchone(
        "SELECT id FROM audit_log WHERE action = 'rbac_write_rejected'"
    ) is None
