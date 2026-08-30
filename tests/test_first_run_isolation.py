"""
HYCLEUS — İlk kurulum/kayıt akışını üretim verisine dokunmadan test etme (B-067)

Kök neden (doğrulandı, kanıt: gerçek DB sorgusu)
-------------------------------------------------
`data/hycleus.db` VE paketlenmiş exe'nin kullandığı `dist/data/hycleus.db`
dosyalarının ikisinde de `users` tablosunda `status='approved'` satırlar
kalmış -- önceki gerçek test oturumlarından (B-058 doğrulama turu, PoC
kayıt denemeleri). `CORE.session_user.sistem_kurulmus_mu()` şu soruyu
soruyor: "sistemde en az bir onaylı kullanıcı var mı" -- bu satırlar
yüzünden her zaman `True` dönüyor, `main.py`'deki `_first_run` her zaman
`False` oluyor ve İlk Kurulum sihirbazı yerine normal giriş ekranı
geliyor. Mekanizmanın kendisi YANLIŞ DEĞİL (B-058'in kök neden düzeltmesi
tam olarak bunu ölçmek için tasarlandı) -- sorun, üzerinde tekrar tekrar
gerçek test yapılan TEK bir veritabanının artık "temiz" olmaması.

Düzeltme: `main.py`'ye üretim verisine hiç dokunmadan izole bir veri
dizinine yönlenebilen bir test bayrağı eklendi (`--test-data-dir <dizin>`
ya da doğrudan `HYCLEUS_TEST_DATA_DIR` ortam değişkeni,
bkz. `CORE/paths.py::data_dir()` ve `main.py`'nin en üstündeki
`_test_data_dir_bayragini_coz()`). Yalnızca DB değil, `data_dir()`'dan
türeyen HER ŞEY (vault dosyaları, TOTP göç dosyası, USB kimlik önbelleği,
PIN hash dosyası, denetim çıpası, SafeZone) izole edilir -- yalnızca
DBManager'ın yolunu değiştirmek yetmezdi, "Kayıt Ol" akışı gerçek vault
dosyasını yine üretim `data/vaults/`'a yazardı.

Neden alt-süreç (subprocess) ile test ediliyor
-----------------------------------------------
`DB/db_manager.py::_DEFAULT_DB_PATH`, `CORE/vault_manager.py::_VAULT_DIR`
gibi sabitler modül İÇE AKTARILDIĞI ANDA hesaplanıyor (bkz. CORE/paths.py
docstring'i). Bu modüller pytest oturumunun BAŞKA testleri tarafından
(ör. `db` fixture'ı üzerinden) neredeyse kesin olarak ÖNCEDEN içe
aktarılmış olacağı için, aynı süreç içinde `main.py`'yi (yeniden) içe
aktarmak `sys.modules` önbelleğini yeniden kullanır ve test ortam
değişkeninin hiçbir etkisi ÖLÇÜLEMEZ. Gerçek programın da her zaman
TAZE bir süreçte çalıştığı göz önüne alınırsa, taze bir alt-süreç hem
daha doğru hem de gerçek kullanımla birebir aynı.

`main.py`, alt-süreçte `runpy.run_path(..., run_name="hycleus_main_probe")`
ile çalıştırılıyor: dosyanın TÜM üst-seviye kodu (import'lar + bayrak
çözümü) çalışır ama `if __name__ == "__main__": main()` bloğu ATLANIR
(`__name__` "__main__" değil) -- yani QApplication/gerçek USB donanımı
hiç gerekmez, GUI hiç açılmaz.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

KOK = Path(__file__).resolve().parent.parent

_PROBE = r'''
import json
import os
import runpy
import sys

sys.path.insert(0, os.getcwd())
sys.argv = ["main.py"] + sys.argv[1:]

g = runpy.run_path("main.py", run_name="hycleus_main_probe")

import DB.db_manager as _dbm
import CORE.vault_manager as _vm

sonuc = {
    "test_env_set": os.environ.get(g["TEST_DATA_DIR_ENV"], ""),
    "data_dir": str(g["_gercek_veri_dizini"]()),
    "default_db_path": str(_dbm._DEFAULT_DB_PATH),
    "vault_dir": str(_vm._VAULT_DIR),
}

if "--probe-first-run" in sys.argv:
    _dbm.DBManager._instance = None
    db = _dbm.DBManager()
    db.connect(hwid="PROBE-HWID", key=None)
    kurulu = g["sistem_kurulmus_mu"](db)
    sonuc["sistem_kurulmus_mu"] = kurulu
    sonuc["first_run_tetiklenir_mi"] = not kurulu
    db.close()

print(json.dumps(sonuc))
'''


def _probe_calistir(tmp_path: Path, *argv: str) -> subprocess.CompletedProcess:
    probe = tmp_path / "_hycleus_probe.py"
    probe.write_text(_PROBE, encoding="utf-8")

    env = dict(os.environ)
    env["QT_QPA_PLATFORM"] = "offscreen"
    env.pop("HYCLEUS_TEST_DATA_DIR", None)  # dışarıdan sızmış kalıntı olmasın

    try:
        return subprocess.run(
            [sys.executable, str(probe), *argv],
            cwd=KOK, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=60, env=env,
        )
    except FileNotFoundError as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"alt-süreç başlatılamadı ({exc})")


def _son_json_satiri(cikti: str) -> dict:
    satirlar = [s for s in cikti.strip().splitlines() if s.strip()]
    assert satirlar, f"probe hiçbir çıktı üretmedi:\n{cikti}"
    return json.loads(satirlar[-1])


# ══════════════════════════════════════════════════════════════════════════════
# 1. --test-data-dir gerçekten izole ediyor ve first-run'ı sıfırdan tetikliyor
# ══════════════════════════════════════════════════════════════════════════════


def test_b067_test_data_dir_ile_first_run_sifirdan_tetikleniyor(
    tmp_path: Path,
) -> None:
    hedef = tmp_path / "izole-veri"
    sonuc = _probe_calistir(
        tmp_path, "--test-data-dir", str(hedef), "--probe-first-run",
    )
    assert sonuc.returncode == 0, sonuc.stdout + sonuc.stderr
    veri = _son_json_satiri(sonuc.stdout)

    hedef_cozulmus = hedef.resolve()
    assert Path(veri["data_dir"]) == hedef_cozulmus
    assert Path(veri["default_db_path"]).parent == hedef_cozulmus, (
        "DBManager izole dizine yönlenmedi"
    )
    assert Path(veri["vault_dir"]).parent == hedef_cozulmus, (
        "vault dizini izole dizine yönlenmedi -- 'Kayıt Ol' akışı gerçek "
        "vault dosyasını yine üretime yazardı"
    )
    assert veri["test_env_set"] == str(hedef_cozulmus)

    uretim_db = (KOK / "data" / "hycleus.db").resolve()
    assert Path(veri["default_db_path"]) != uretim_db, (
        "izole DB yolu üretim DB yoluyla AYNI çıktı"
    )

    assert veri["sistem_kurulmus_mu"] is False, (
        "B-067 REGRESYONU: izole/boş dizinde bile 'sistem kurulmuş' "
        "görünüyor -- first-run testi hâlâ imkânsız olurdu"
    )
    assert veri["first_run_tetiklenir_mi"] is True, (
        "B-067 REGRESYONU: izole dizinde İlk Kurulum sihirbazı tetiklenmiyor"
    )


def test_b067_ayni_izole_dizinde_ikinci_kosuda_first_run_artik_tetiklenmiyor(
    tmp_path: Path,
) -> None:
    """
    Mutasyon/tutarlılık kontrolü: aynı izole dizinde bir kullanıcı
    onaylanmış OLSAYDI (ikinci bir çalıştırma senaryosu), first-run bir
    daha tetiklenmemeli -- yoksa test mekanizmasının kendisi
    `sistem_kurulmus_mu()`'yu yanlış ölçüyor olurdu.
    """
    hedef = tmp_path / "izole-veri-2"
    ilk = _probe_calistir(tmp_path, "--test-data-dir", str(hedef), "--probe-first-run")
    assert ilk.returncode == 0, ilk.stdout + ilk.stderr
    ilk_veri = _son_json_satiri(ilk.stdout)
    assert ilk_veri["first_run_tetiklenir_mi"] is True

    # Aynı izole DB'ye elle onaylı bir kullanıcı ekle (gerçek "Kayıt Ol +
    # onay" akışının SONUCUNU simüle ediyor).
    import sqlite3

    conn = sqlite3.connect(Path(ilk_veri["default_db_path"]))
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, status, hwid)"
            " VALUES ('test.onaylandi', '!x', 'user', 'approved', 'PROBE-HWID-2')"
        )
        conn.commit()
    finally:
        conn.close()

    ikinci = _probe_calistir(tmp_path, "--test-data-dir", str(hedef), "--probe-first-run")
    assert ikinci.returncode == 0, ikinci.stdout + ikinci.stderr
    ikinci_veri = _son_json_satiri(ikinci.stdout)
    assert ikinci_veri["first_run_tetiklenir_mi"] is False, (
        "onaylı kullanıcı eklendikten SONRA bile first-run tetiklenmeye "
        "devam ediyor -- test mekanizması gerçek davranışı yansıtmıyor"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 2. Bayrak/değişken YOKSA üretim verisine kesinlikle dokunulmuyor
# ══════════════════════════════════════════════════════════════════════════════


def test_b067_bayraksiz_calistirmada_uretim_db_sine_dokunulmuyor(
    tmp_path: Path,
) -> None:
    uretim_db = KOK / "data" / "hycleus.db"
    if not uretim_db.exists():
        pytest.skip("bu geliştirme ağacında henüz bir üretim db'si yok")

    once_hash  = hashlib.sha256(uretim_db.read_bytes()).hexdigest()
    once_boyut = uretim_db.stat().st_size
    once_mtime = uretim_db.stat().st_mtime_ns

    sonuc = _probe_calistir(tmp_path)  # bayrak YOK -- yalnızca yol çözümü
    assert sonuc.returncode == 0, sonuc.stdout + sonuc.stderr
    veri = _son_json_satiri(sonuc.stdout)

    assert veri["test_env_set"] == "", (
        "bayraksız çalıştırma HYCLEUS_TEST_DATA_DIR'i kendiliğinden ayarlamış"
    )
    assert Path(veri["data_dir"]).resolve() == (KOK / "data").resolve(), (
        "bayraksız çalıştırmada data_dir() üretim dizininden SAPMIŞ"
    )

    assert hashlib.sha256(uretim_db.read_bytes()).hexdigest() == once_hash, (
        "B-067 REGRESYONU: bayraksız çalıştırma üretim db'sinin İÇERİĞİNİ "
        "değiştirdi"
    )
    assert uretim_db.stat().st_size == once_boyut
    assert uretim_db.stat().st_mtime_ns == once_mtime, (
        "B-067 REGRESYONU: bayraksız çalıştırma üretim db dosyasına DOKUNDU "
        "(mtime değişti) -- içerik aynı kalsa bile bu beklenmiyor"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 3. Üretim dizinini hedef göstermek reddediliyor (yanlışlıkla verilen gerçek yol)
# ══════════════════════════════════════════════════════════════════════════════


def test_b067_uretim_dizinini_hedef_gostermek_reddediliyor(tmp_path: Path) -> None:
    sonuc = _probe_calistir(tmp_path, "--test-data-dir", str(KOK / "data"))
    assert sonuc.returncode != 0, (
        "üretim dizinini --test-data-dir'e vermek REDDEDİLMEDİ -- "
        "üretim verisi kazayla 'izole' sanılabilirdi"
    )
    assert "AYNI" in sonuc.stderr or "reddedildi" in sonuc.stderr.lower(), (
        f"beklenmeyen hata mesajı:\n{sonuc.stderr}"
    )


def test_b067_test_data_dir_argumani_eksikse_hata_veriyor(tmp_path: Path) -> None:
    sonuc = _probe_calistir(tmp_path, "--test-data-dir")
    assert sonuc.returncode != 0


# ══════════════════════════════════════════════════════════════════════════════
# 4. `sahte_usb` yardımcısı (tests/conftest.py) — gerçek donanım olmadan
#    kayıt/ilk-kurulum/reauth akışlarını test etmenin kalıcı hâli
# ══════════════════════════════════════════════════════════════════════════════
#
# B-064/B-065/B-066 PoC scriptlerinde ve testlerinde tekrar tekrar elle
# yazılan `monkeypatch.setattr(<modül>, "get_usb_hwid", lambda: hwid)`
# deseni artık burada, `sahte_usb` fixture'ında toplu: bir HWID ile
# "takıyor", `.tak()`/`.cikar()` ile değiştiriyor -- TÜM hedef modüllerde
# (bkz. conftest.py::SahteUSB._HEDEF_MODULLER) AYNI ANDA.


def test_sahte_usb_birden_fazla_modulu_ayni_anda_ve_dinamik_olarak_kontrol_ediyor(
    sahte_usb,
) -> None:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        import UI.admin_common as ap
        import UI.main_window_lock as mwl
    except ImportError as exc:  # pragma: no cover — ortama bağlı
        pytest.skip(f"Qt katmanı bu ortamda yüklenemedi ({exc})")

    usb = sahte_usb("SAHTE-HWID-1")
    assert mwl.get_usb_hwid() == "SAHTE-HWID-1"
    assert ap.get_usb_hwid() == "SAHTE-HWID-1"

    # Aynı fiziksel USB çıkarılıp FARKLI biri takıldı -- TEK bir yerden
    # (usb.tak) değiştirmek, önceden ayrı ayrı yamalanmış TÜM modüllere
    # yeniden yamalama yapmadan yansımalı.
    usb.tak("SAHTE-HWID-2")
    assert mwl.get_usb_hwid() == "SAHTE-HWID-2"
    assert ap.get_usb_hwid() == "SAHTE-HWID-2"

    usb.cikar()
    assert mwl.get_usb_hwid() is None, "USB çıkarma admin_common'ın gördüğü modüle yansımadı"
    assert ap.get_usb_hwid() is None, "USB çıkarma main_window_lock'un gördüğü modüle yansımadı"
