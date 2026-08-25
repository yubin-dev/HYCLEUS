"""
HYCLEUS — oturum kullanıcısı eşleme testleri (B-011)

Bu modül bir kaçamağın YERİNE geçti. Eski kaçamak `create_folder()`
içinde duruyordu ve eksik `users` satırını uyduruyordu; testleri de onu
korumak için yazılmıştı. Buradaki testler asıl soruyu soruyor: oturum
gerçekten doğru kullanıcıya mı bağlanıyor?

En kritik test `test_kayitli_kullanici_kendi_idsini_aliyor` — eski kodda
kim giriş yaparsa yapsın `user_id` 1 kalıyordu, yani klasör sahipliği ve
denetim kaydı yanlış kişiyi gösteriyordu. Kaçamağın gizlediği asıl hata
buydu.
"""
from __future__ import annotations

import pytest

from CORE.folders import create_folder
from CORE.session_user import (
    PAROLASIZ,
    VAULT_USERNAME_PREFIX,
    db_role,
    sync_session_user,
    vault_username,
)

_HWID = "USB-SERI-001"
_HWID2 = "USB-SERI-002"


def _kayit(db, username: str, hwid: str, *, role: str = "user") -> int:
    """Kayıt akışının (RegisterDialog) yazdığı satırı taklit eder."""
    cur = db.execute(
        "INSERT INTO users (username, password_hash, role, status, hwid)"
        " VALUES (?, ?, ?, 'approved', ?)",
        (username, "argon2$sahte", role, hwid),
    )
    return int(cur.lastrowid)


def _eylem_var(db, action: str) -> bool:
    return db.fetchone(
        "SELECT id FROM audit_log WHERE action = ? LIMIT 1", (action,)
    ) is not None


# ══════════════════════════════════════════════════════════════════════════════
# 1. Mevcut kullanıcıya bağlanma — asıl düzeltme
# ══════════════════════════════════════════════════════════════════════════════


def test_kayitli_kullanici_kendi_idsini_aliyor(db):
    """
    B-011'İN ASIL BULGUSU.

    Kayıt akışı `users` satırını HWID ile yazıyordu ama giriş akışı onu
    hiç aramıyordu; `main.py` `user_id` geçmediği için değer varsayılan
    1'de kalıyordu. Yani ikinci kullanıcı giriş yaptığında açtığı klasör
    BİRİNCİ kullanıcıya ait görünüyordu.
    """
    _birinci = _kayit(db, "ahmet", _HWID)
    ikinci = _kayit(db, "ayse", _HWID2)

    assert sync_session_user(db, hwid=_HWID2, role="Personel") == ikinci
    assert ikinci != 1, "test kurgusu anlamsız — ikinci kullanıcı zaten 1"


def test_mevcut_satirin_hicbir_alani_uydurulmuyor(db):
    """Bulunan satır olduğu gibi bırakılmalı; yalnızca `last_login` değişir."""
    uid = _kayit(db, "ahmet", _HWID, role="admin")
    onceki = dict(
        db.fetchone(
            "SELECT username, password_hash, role, status FROM users WHERE id = ?",
            (uid,),
        )
    )

    # Rol BİLEREK farklı geçiliyor: oturum rolü DB satırını ezmemeli.
    sync_session_user(db, hwid=_HWID, role="Personel")

    sonraki = dict(
        db.fetchone(
            "SELECT username, password_hash, role, status FROM users WHERE id = ?",
            (uid,),
        )
    )
    assert sonraki == onceki


def test_last_login_guncelleniyor(db):
    uid = _kayit(db, "ahmet", _HWID)
    assert db.fetchone("SELECT last_login FROM users WHERE id = ?", (uid,))[
        "last_login"
    ] is None
    sync_session_user(db, hwid=_HWID)
    assert db.fetchone("SELECT last_login FROM users WHERE id = ?", (uid,))[
        "last_login"
    ] is not None


def test_ayni_hwid_ikinci_girişte_yeni_satir_acmiyor(db):
    ilk = sync_session_user(db, hwid=_HWID, role="Yönetici")
    ikinci = sync_session_user(db, hwid=_HWID, role="Yönetici")
    assert ilk == ikinci
    assert db.fetchone(
        "SELECT COUNT(*) AS n FROM users WHERE hwid = ?", (_HWID,)
    )["n"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# 2. Satır yoksa — uydurma DEĞİL, açıkça vault oturumu
# ══════════════════════════════════════════════════════════════════════════════


def test_yeni_satir_insan_taklit_etmiyor(db):
    """
    Eski kaçamak "yonetici" adlı, boş parola hash'li, `admin` rollü bir
    satır yazıyordu — sonradan bakan biri bunu gerçek bir hesap sanardı.
    Yeni satır makine ürünü olduğunu adından belli ediyor.
    """
    uid = sync_session_user(db, hwid=_HWID, role="Personel")
    row = db.fetchone(
        "SELECT username, password_hash, role, status, hwid FROM users WHERE id = ?",
        (uid,),
    )
    assert row["username"] == f"{VAULT_USERNAME_PREFIX}{_HWID}"
    assert row["username"] != "yonetici"
    assert row["hwid"] == _HWID
    assert row["status"] == "approved"


def test_yeni_satir_parola_yoluyla_giris_yapamiyor(db):
    """
    `password_hash` boş DEĞİL, ayrıştırılamaz bir sentinel.

    Boş dize ileride "hash yok, geç" gibi yorumlanabilirdi; Argon2
    biçiminde olmayan bir değer hiçbir doğrulayıcıyla eşleşemez.
    """
    uid = sync_session_user(db, hwid=_HWID)
    ph = db.fetchone("SELECT password_hash FROM users WHERE id = ?", (uid,))[
        "password_hash"
    ]
    assert ph == PAROLASIZ
    assert ph != ""
    assert not ph.startswith("$argon2")


@pytest.mark.parametrize(
    "oturum_rolu,beklenen",
    [
        ("Yönetici", "admin"),
        ("Personel", "user"),
        ("Bilinmeyen", "user"),
        (None, "user"),
        ("", "user"),
    ],
)
def test_rol_esleme_yetki_genisletmiyor(db, oturum_rolu, beklenen):
    """
    Eski kaçamak rol ne olursa olsun `admin` yazıyordu.

    Bilinmeyen rol `user`'a düşüyor — yanlış yön aşağı olmalı.
    """
    assert db_role(oturum_rolu) == beklenen
    uid = sync_session_user(db, hwid=f"HWID-{oturum_rolu}", role=oturum_rolu)
    assert db.fetchone("SELECT role FROM users WHERE id = ?", (uid,))[
        "role"
    ] == beklenen


def test_bos_hwid_reddediliyor(db):
    """
    Boş HWID ile açılan satırlar birbirinden ayırt edilemez.

    Sessizce bir satır açmak, kaçamağın farklı bir biçimi olurdu.
    """
    with pytest.raises(ValueError, match="HWID"):
        sync_session_user(db, hwid="", role="Yönetici")
    assert db.fetchone("SELECT COUNT(*) AS n FROM users")["n"] == 0


# ══════════════════════════════════════════════════════════════════════════════
# 3. Denetim kaydı — satırın nereden geldiği okunabilmeli
# ══════════════════════════════════════════════════════════════════════════════


def test_iki_dal_farkli_eylem_yaziyor(db):
    """
    Uydurma satırın en büyük sorunu İZSİZ belirmesiydi.

    İki dalın ayrı eylem adları olması önemli: "bu satır kayıttan mı
    geldi yoksa vault oturumu için mi açıldı" sorusu denetim kaydından
    yanıtlanabilmeli.
    """
    sync_session_user(db, hwid=_HWID, role="Yönetici")
    assert _eylem_var(db, "session_user_provisioned")
    assert not _eylem_var(db, "session_user_linked")

    sync_session_user(db, hwid=_HWID, role="Yönetici")
    assert _eylem_var(db, "session_user_linked")


def test_denetim_kaydi_zinciri_bozulmuyor(db):
    """Yeni kayıtlar hash zincirinden geçmeli — düz INSERT değil."""
    from CORE.audit_chain import verify_audit_chain

    sync_session_user(db, hwid=_HWID, role="Yönetici")
    sync_session_user(db, hwid=_HWID, role="Yönetici")
    assert verify_audit_chain(db.conn).ok


# ══════════════════════════════════════════════════════════════════════════════
# 4. Uçtan uca — kaçamağın çözdüğü sorun gerçekten çözüldü mü
# ══════════════════════════════════════════════════════════════════════════════


def test_esleme_sonrasi_klasor_olusturma_calisiyor(db):
    """
    KAÇAMAĞIN VAROLUŞ SEBEBİ buydu: FK hatası.

    Kaçamak kaldırıldıktan sonra akışın hâlâ çalıştığının kanıtı —
    `sync_session_user()` önce çağrıldığı sürece `create_folder()` FK
    hatası vermiyor.
    """
    uid = sync_session_user(db, hwid=_HWID, role="Yönetici")
    fid = create_folder(db, "Sozlesmeler", owner_id=uid, hwid=_HWID)
    assert db.fetchone("SELECT owner_id FROM folders WHERE id = ?", (fid,))[
        "owner_id"
    ] == uid


def test_klasor_dogru_kullaniciya_yaziliyor(db):
    """
    Uçtan uca: iki kullanıcı, iki klasör, sahiplik karışmamalı.

    Eski davranışta ikisi de `owner_id = 1` alırdı.
    """
    a = sync_session_user(db, hwid=_HWID, role="Yönetici")
    b = sync_session_user(db, hwid=_HWID2, role="Personel")
    assert a != b

    fa = create_folder(db, "A", owner_id=a, hwid=_HWID)
    fb = create_folder(db, "B", owner_id=b, hwid=_HWID2)

    assert db.fetchone("SELECT owner_id FROM folders WHERE id = ?", (fa,))["owner_id"] == a
    assert db.fetchone("SELECT owner_id FROM folders WHERE id = ?", (fb,))["owner_id"] == b


def test_vault_username_ve_prefix_tutarli():
    assert vault_username("X").startswith(VAULT_USERNAME_PREFIX)
    assert vault_username("X") == "vault:X"


# ══════════════════════════════════════════════════════════════════════════════
# 5. Bağlantının kopmasını engelleyen AST denetimleri
# ══════════════════════════════════════════════════════════════════════════════
#
# Bu iki test SESSİZ GERİLEMEYE karşı. `main.py`'den `user_id=user_id`
# argümanı düşerse hiçbir şey patlamaz: `HycleusWindow.__init__` varsayılanı
# 1 ve uygulama açılmaya devam eder. Tam olarak B-011'in ilk hâli bu — hata
# değil, EKSİK bir argüman. Çalışma zamanı testi bunu yakalayamaz (Qt penceresi
# gerekir), o yüzden kaynak ağacı denetleniyor.


def _main_agaci():
    import ast
    from pathlib import Path

    kok = Path(__file__).resolve().parent.parent
    return ast.parse((kok / "main.py").read_text(encoding="utf-8"))


def test_main_oturum_kullanicisini_esliyor():
    """`main.py` `sync_session_user()` çağırmalı."""
    import ast

    cagrilar = {
        d.func.id
        for d in ast.walk(_main_agaci())
        if isinstance(d, ast.Call) and isinstance(d.func, ast.Name)
    }
    assert "sync_session_user" in cagrilar, (
        "main.py oturum kullanıcısını artık eşlemiyor — B-011 geri geldi"
    )


def test_main_pencereye_user_id_geciyor():
    """
    `HycleusWindow(...)` çağrısı `user_id` argümanı taşımalı.

    Argüman düşerse sahiplik sessizce 1'e döner ve klasörler yanlış
    kullanıcıya yazılır — istisna fırlamadan.
    """
    import ast

    pencere_cagrilari = [
        d
        for d in ast.walk(_main_agaci())
        if isinstance(d, ast.Call)
        and isinstance(d.func, ast.Name)
        and d.func.id == "HycleusWindow"
    ]
    assert pencere_cagrilari, "main.py artık HycleusWindow kurmuyor"
    for cagri in pencere_cagrilari:
        anahtarlar = {k.arg for k in cagri.keywords}
        assert "user_id" in anahtarlar, (
            "HycleusWindow'a user_id geçilmiyor — sahiplik sessizce 1'e düşer"
        )


def test_main_pencereye_username_geciyor():
    """
    `HycleusWindow(...)` çağrısı `username` argümanı da taşımalı (B-065).

    Argüman düşerse `HycleusWindow`'un sabit varsayılanında ("Kullanıcı")
    sessizce kalınır — istisna fırlamadan, Profil ekranı ve avatar baş
    harfi gerçek kullanıcıyı hiç yansıtmaz. Çalışma zamanı testi bunu
    yakalayamaz (tam main() akışı LoginDialog.exec() gerektirir, bkz.
    tests/test_authz_invariants.py'deki B-065 testleri — onlar
    `HycleusWindow`'u DOĞRUDAN gerçek username ile kurup ekranın onu
    doğru gösterdiğini ölçüyor; main.py'nin o değeri gerçekten
    GEÇTİĞİNİ ise yalnızca bu kaynak ağacı denetimi kanıtlıyor).
    """
    import ast

    pencere_cagrilari = [
        d
        for d in ast.walk(_main_agaci())
        if isinstance(d, ast.Call)
        and isinstance(d.func, ast.Name)
        and d.func.id == "HycleusWindow"
    ]
    assert pencere_cagrilari, "main.py artık HycleusWindow kurmuyor"
    for cagri in pencere_cagrilari:
        anahtarlar = {k.arg for k in cagri.keywords}
        assert "username" in anahtarlar, (
            "HycleusWindow'a username geçilmiyor — B-065 geri geldi, "
            "Profil ekranı ve avatar sabit 'Kullanıcı' gösterir"
        )


def test_users_satiri_uyduran_ikinci_bir_yer_kalmadi():
    """
    Kaçamağın İKİ kopyası vardı: `CORE/folders.py` ve
    `UI/main_window_table.py`. İkincisi ilki düzeltilse bile ayakta
    kalırdı — B-008'de öğrenilen ders.

    Denetim, uydurma satırın imzasını arıyor: `users` tablosuna INSERT
    atan ve yanında `yonetici` sabiti geçen bir modül.

    DOCSTRING'LER HARİÇ. İlk yazılışında düz metin araması yapıyordu ve
    `CORE/session_user.py`'yi kendi suçladı — o dosyanın docstring'i
    kaldırılan kaçamağı ÖRNEK OLARAK gösteriyor. Bir kuralı belgeleyen
    metin, kuralı çiğnemiş sayılmamalı; yoksa tek çare belgeyi silmek
    olurdu.
    """
    import ast
    from pathlib import Path

    def _kod_dizeleri(agac: ast.AST) -> list[str]:
        """Docstring olmayan tüm dize sabitleri."""
        docstringler = {
            id(govde[0].value)
            for dugum in ast.walk(agac)
            if isinstance(
                dugum,
                (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
            )
            and (govde := dugum.body)
            and isinstance(govde[0], ast.Expr)
            and isinstance(govde[0].value, ast.Constant)
            and isinstance(govde[0].value.value, str)
        }
        return [
            d.value
            for d in ast.walk(agac)
            if isinstance(d, ast.Constant)
            and isinstance(d.value, str)
            and id(d) not in docstringler
        ]

    kok = Path(__file__).resolve().parent.parent
    suclular = []
    for yol in list((kok / "CORE").rglob("*.py")) + list((kok / "UI").rglob("*.py")):
        dizeler = _kod_dizeleri(ast.parse(yol.read_text(encoding="utf-8")))
        if any("INSERT INTO users" in d for d in dizeler) and any(
            "yonetici" == d for d in dizeler
        ):
            suclular.append(yol.name)
    assert not suclular, f"uydurma users satırı geri gelmiş: {suclular}"
