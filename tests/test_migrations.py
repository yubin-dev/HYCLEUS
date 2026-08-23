"""
DB.migrations — göç kayıt defteri.

Bu tur bir belgelendirme turu: mevcut göçler geriye dönük kaydedildi ve
davranış değişmedi. Ama "belgelendirme" burada beyanla yetinemez —
`_apply_schema()` ile bu dosya iki ayrı kaynak ve ayrışmaları SESSİZ
olurdu.

En önemli test bu yüzden bir EŞDEĞERLİK ÖLÇÜMÜ: boş bir veritabanına
yalnızca kayıt defterindeki göçler uygulanıyor ve ortaya çıkan
`sqlite_master`, `_apply_schema()`'nınkiyle karşılaştırılıyor. Kayıt
yanlışsa test düşer.

İkinci grup, iskeletin v3.0'da GERÇEKTEN çalışacağını sınıyor: 22
numaralı sahte bir göç eklenip uygulandığı, iki kez uygulanmadığı, ve
düşen bir göçün öncekileri geri almadığı ölçülüyor.

Üçüncü grup tek bir kazayı kapatıyor: defterin `PRAGMA user_version`'a
dokunmaması. O alan `CORE/secret_migration.py`'ye ait ve paylaşılırsa
sır taşıma sessizce atlanır — düz metin sırlar yerinde kalır.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from DB import migrations as M
from DB.db_manager import DBManager


# ══════════════════════════════════════════════════════════════════════════════
# Yardımcılar
# ══════════════════════════════════════════════════════════════════════════════


def _sema_dokumu(conn: sqlite3.Connection) -> set[str]:
    """`sqlite_master`'ın karşılaştırılabilir dökümü.

    Boşluklar normalize ediliyor: aynı DDL farklı girintiyle yazılmış
    olabilir ve girinti farkı bir şema farkı DEĞİL.

    `sqlite_autoindex_*` dışarıda: bunları SQLite kendisi üretiyor
    (PRIMARY KEY / UNIQUE için) ve `sql` alanları NULL.

    Göç defteri tablosunun kendisi de dışarıda: `_apply_schema()` onu
    kuruyor ama `sifirdan_kur()` da kuruyor — karşılaştırmanın konusu
    UYGULAMA şeması.
    """
    satirlar = conn.execute(
        "SELECT type, name, sql FROM sqlite_master"
        " WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
    ).fetchall()
    cikti: set[str] = set()
    for tur, ad, sql in satirlar:
        if ad == M.LEDGER_TABLE:
            continue
        normal = " ".join((sql or "").split())
        cikti.add(f"{tur}|{ad}|{normal}")
    return cikti


@pytest.fixture
def bos_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")
    yield conn
    conn.close()


@pytest.fixture
def gercek_db(tmp_path: Path):
    """`_apply_schema()` ile kurulmuş gerçek bir veritabanı."""
    DBManager._instance = None  # type: ignore[attr-defined]
    db = DBManager(tmp_path / "gercek.db")
    db.connect(hwid="TEST-HWID-MIG")
    yield db
    db.close()
    DBManager._instance = None  # type: ignore[attr-defined]


# ══════════════════════════════════════════════════════════════════════════════
# 1. Kayıt defteri DOĞRU mu — ölçülen eşdeğerlik
# ══════════════════════════════════════════════════════════════════════════════


def test_kayit_defteri_apply_schema_ile_AYNI_semayi_uretiyor(
    bos_conn: sqlite3.Connection, gercek_db,
) -> None:
    """
    Bu paketin ana iddiası.

    Geriye dönük kayıt bir BEYAN değil: kayıt defterinden kurulan şema,
    `_apply_schema()`'nınkiyle bayt bayt (boşluk normalize edilerek) aynı
    olmak zorunda. Bir sütun yanlış yazıldıysa, bir indeks unutulduysa ya
    da bir CHECK kopyalanırken bozulduysa burada görünür.

    Eşdeğerlik ayrıca v3.0'ın ön koşulu: `_apply_schema()` bir gün bu
    listeye devredilecekse, listenin bugün de doğru olduğu ölçülmüş
    olmalı.
    """
    M.sifirdan_kur(bos_conn)

    defterden = _sema_dokumu(bos_conn)
    mevcuttan = _sema_dokumu(gercek_db.conn)

    eksik = sorted(mevcuttan - defterden)
    fazla = sorted(defterden - mevcuttan)
    assert not eksik, f"Kayıt defteri şunları ÜRETMİYOR: {eksik}"
    assert not fazla, f"Kayıt defteri fazladan şunları üretiyor: {fazla}"


def test_kayit_defteri_TOHUM_satirlarini_da_uretiyor(
    bos_conn: sqlite3.Connection, gercek_db,
) -> None:
    """
    Şema karşılaştırması `sqlite_master`'a bakıyor ve orada SATIRLAR yok.

    Mutasyon testinde bu boşluk ortaya çıktı: 16 numaralı göçten
    `imha_ttl_hours` tohum satırını silmek HİÇBİR testi düşürmedi. Oysa
    o satır bir varsayılan — eksikse İmha Odası TTL'i tanımsız kalır.

    `_apply_schema()` bir gün bu listeye devredilecekse, devredilen şey
    yalnızca tablolar değil kurulum verisi de olmalı.
    """
    M.sifirdan_kur(bos_conn)

    def _ayarlar(conn: sqlite3.Connection) -> dict[str, str]:
        return {k: v for k, v in conn.execute("SELECT key, value FROM settings")}

    defterden = _ayarlar(bos_conn)
    # Gerçek DB'de `seed_builtin_templates()` bir de bayrak yazıyor; o
    # göç DEĞİL, veri tohumu (CORE/retention.py). Karşılaştırma göçlerin
    # yazdığı anahtarlarla sınırlı.
    mevcuttan = _ayarlar(gercek_db.conn)

    assert defterden, "Kayıt defteri hiç ayar satırı üretmedi"
    for anahtar, deger in defterden.items():
        assert mevcuttan.get(anahtar) == deger, (
            f"{anahtar}: defter {deger!r} yazıyor, _apply_schema {mevcuttan.get(anahtar)!r}"
        )
    assert defterden.get("imha_ttl_hours") == "24"


def test_karsilastirma_gercekten_bir_sey_okuyor(gercek_db) -> None:
    """
    Boş küme dönerse yukarıdaki test kendiliğinden geçerdi.

    Bu depoda tam olarak bu sınıftan bir kaza yaşandı: bir denetim,
    ihlali göremediği için sessizce yeşil kalıyordu.
    """
    dokum = _sema_dokumu(gercek_db.conn)
    assert len(dokum) >= 20, f"Yalnızca {len(dokum)} şema nesnesi bulundu"
    assert any("|table|" in f"|{s.split('|')[0]}|" for s in dokum)
    adlar = {s.split("|")[1] for s in dokum}
    assert {"users", "files", "audit_log", "retention_profiles", "folders"} <= adlar


def test_gocler_iki_kez_calistirilabilir(bos_conn: sqlite3.Connection) -> None:
    """
    Her göç idempotent olmak ZORUNDA: yarıda kesilen bir açılış yeniden
    denenecek ve ikinci deneme düşerse kurulum kalıcı olarak kırılır.
    """
    M.sifirdan_kur(bos_conn)
    ilk = _sema_dokumu(bos_conn)

    # Defteri boşaltıp hepsini YENİDEN uygula — gerçek bir "yarıda kesildi
    # ve baştan denendi" senaryosu.
    bos_conn.execute(f"DELETE FROM {M.LEDGER_TABLE}")
    M.sifirdan_kur(bos_conn)

    assert _sema_dokumu(bos_conn) == ilk


def test_numaralar_kesintisiz_ve_sirali() -> None:
    """
    Boşluk ya da tekrar, "hangi göçler uygulandı" sorusunu belirsiz
    yapardı.
    """
    numaralar = [g.numara for g in M.MIGRATIONS]
    assert numaralar == list(range(1, len(numaralar) + 1)), numaralar


def test_adlar_benzersiz_ve_bos_degil() -> None:
    adlar = [g.ad for g in M.MIGRATIONS]
    assert len(set(adlar)) == len(adlar), "Yinelenen göç adı var"
    assert all(a.strip() for a in adlar)


def test_her_gocun_aciklamasi_var() -> None:
    """
    Açıklama süs değil: bir göçün NEDEN eklendiği yalnızca git
    geçmişinde kalırsa, altı ay sonra bakan kişi onu bulamaz.
    """
    for goc in M.MIGRATIONS:
        assert len(goc.aciklama.strip()) > 20, f"{goc.ad} açıklaması yetersiz"


def test_TEMEL_SURUM_listenin_sonunu_gosteriyor() -> None:
    """
    `TEMEL_SURUM`, `_apply_schema()`'nın karşılığı olan son göç. Yeni bir
    göç eklenip TEMEL_SURUM de yükseltilirse o göç ÇALIŞTIRILMADAN
    uygulanmış sayılır — yani sessizce hiç çalışmaz.
    """
    assert M.TEMEL_SURUM == 21, (
        "TEMEL_SURUM değişmiş. Yeni göçler bu sayının ÜSTÜNDE numaralanmalı; "
        "sayıyı yükseltmek yeni göçü çalıştırmadan 'uygulandı' saymak demektir."
    )
    assert M.TEMEL_SURUM <= len(M.MIGRATIONS)


# ══════════════════════════════════════════════════════════════════════════════
# 2. Defterin davranışı
# ══════════════════════════════════════════════════════════════════════════════


def test_gercek_veritabani_temel_gocleri_damgaliyor(gercek_db) -> None:
    """
    `_apply_schema()` çalıştıktan sonra 1..21 'uygulandı' olmalı — yoksa
    bir sonraki açılış onları yeniden çalıştırmaya kalkardı.
    """
    olan = M.uygulananlar(gercek_db.conn)
    assert olan >= set(range(1, M.TEMEL_SURUM + 1))


def test_temel_gocler_CALISTIRILMADAN_damgalanıyor(gercek_db) -> None:
    """
    Bu turun sözü: davranış değişmiyor. Temel göçler yeniden koşsaydı
    boot yolu değişmiş olurdu.

    Yalnızca 1..TEMEL_SURUM'a bakıyor: TEMEL_SURUM üstü (bkz. Migration 22)
    GERÇEKTEN çalışır ve 'gocmen' damgalanır — bu, iskeletin sözünün AYNI
    kısmı, ihlali değil.
    """
    kaynaklar = {
        kaynak for numara, _a, _t, kaynak in M.durum(gercek_db.conn)
        if numara <= M.TEMEL_SURUM
    }
    assert kaynaklar == {"temel"}, (
        f"Temel göçler 'gocmen' olarak işaretlenmiş — çalıştırılmışlar: {kaynaklar}"
    )


def test_temel_gocler_GERCEKTEN_cagrilmiyor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Bu turun sözünün asıl testi.

    Bir öncekiler yalnızca `kaynak` sütununa bakıyordu ve mutasyon
    testinde bu yetmedi: göçleri GERÇEKTEN çalıştırıp yine 'temel' diye
    damgalayan bir sürüm hayatta kaldı. Göçler idempotent olduğu için
    şema aynı kalıyor — fark yalnızca çağrılıp çağrılmadıklarında.

    Burada doğrudan o soruluyor: `_apply_schema()` sırasında hiçbir temel
    (1..TEMEL_SURUM) göç fonksiyonu çağrılmamalı. TEMEL_SURUM üstü (bkz.
    Migration 22) burada da GERÇEKTEN çağrılır — o ayrı bir sözün konusu,
    ihlal değil.
    """
    cagrilanlar: list[int] = []

    def _izleyen(numara: int, gercek):
        def _f(conn: sqlite3.Connection) -> None:
            cagrilanlar.append(numara)
            gercek(conn)
        return _f

    monkeypatch.setattr(M, "MIGRATIONS", tuple(
        M.Migration(g.numara, g.ad, g.aciklama, _izleyen(g.numara, g.uygula))
        for g in M.MIGRATIONS
    ))

    DBManager._instance = None  # type: ignore[attr-defined]
    db = DBManager(tmp_path / "izlenen.db")
    db.connect(hwid="TEST-HWID-MIG")
    try:
        temel_cagrilanlar = [n for n in cagrilanlar if n <= M.TEMEL_SURUM]
        assert temel_cagrilanlar == [], (
            f"Temel göçler çalıştırıldı: {temel_cagrilanlar}. Bu tur davranışı "
            "değiştirmemeliydi — `_apply_schema()` şemayı zaten kuruyor."
        )
    finally:
        db.close()
        DBManager._instance = None  # type: ignore[attr-defined]


def test_ikinci_acilis_hicbir_sey_uygulamiyor(gercek_db) -> None:
    """Açılış idempotent; defter her seferinde şişmemeli."""
    once = M.durum(gercek_db.conn)
    assert M.senkronize(gercek_db.conn) == []
    assert M.durum(gercek_db.conn) == once


def test_bekleyenler_bugun_BOS(gercek_db) -> None:
    """
    Bugün TEMEL_SURUM üstünde göç yok. Bu test, v3.0 göçleri eklendiğinde
    bilerek düşecek ve güncellenecek — o an "iskelet gerçekten devreye
    girdi" demektir.
    """
    assert M.bekleyenler(gercek_db.conn) == ()


def test_defter_gocun_ADINI_da_saklıyor(gercek_db) -> None:
    """
    "17 uygulanmış" bir kişiye hiçbir şey söylemiyor; "17
    retention-profiles-tablosu uygulanmış" söylüyor.
    """
    kayit = {n: ad for n, ad, _t, _k in M.durum(gercek_db.conn)}
    assert kayit[17] == "retention-profiles-tablosu"
    assert kayit[21] == "audit-log-entry-hash"


def test_defter_zaman_damgasi_yaziyor(gercek_db) -> None:
    for _n, _ad, zaman, _k in M.durum(gercek_db.conn):
        assert zaman.endswith("Z") and len(zaman) == 20, zaman


# ══════════════════════════════════════════════════════════════════════════════
# 3. İskelet v3.0'da GERÇEKTEN çalışıyor mu
# ══════════════════════════════════════════════════════════════════════════════


#: Testin kendi göçleri için, gerçek numaralarla (bkz. Migration 22 — artık
#: gerçekten var) hiç çakışmayacak, açıkça sahte bir aralık.
_SAHTE_NO = 9001


@pytest.fixture
def sahte_goc(monkeypatch: pytest.MonkeyPatch):
    """Listenin sonuna sahte numaralı bir göç ekler — v3.0'ın provası."""
    calisti: list[int] = []

    def _m(conn: sqlite3.Connection) -> None:
        calisti.append(_SAHTE_NO)
        conn.execute("CREATE TABLE IF NOT EXISTS tpm_anahtarlari (id INTEGER PRIMARY KEY)")

    goc = M.Migration(_SAHTE_NO, "tpm-anahtarlari",
                      "v3.0 provası — TPM ile korunan anahtar kayıtları.", _m)
    monkeypatch.setattr(M, "MIGRATIONS", (*M.MIGRATIONS, goc))
    return calisti


def test_TEMEL_SURUM_ustundeki_goc_GERCEKTEN_calisiyor(
    tmp_path: Path, sahte_goc,
) -> None:
    """
    İskeletin asıl işi. Sahte göç damgalanmakla kalmamalı, uygulanmalı.
    """
    DBManager._instance = None  # type: ignore[attr-defined]
    db = DBManager(tmp_path / "v3.db")
    db.connect(hwid="TEST-HWID-MIG")
    try:
        assert sahte_goc == [_SAHTE_NO], "Sahte göç hiç çalışmadı"
        tablolar = {
            r[0] for r in db.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert "tpm_anahtarlari" in tablolar
        kaynak = {n: k for n, _a, _t, k in M.durum(db.conn)}
        assert kaynak[_SAHTE_NO] == "gocmen", "Yeni göç 'temel' diye damgalanmış"
        assert kaynak[21] == "temel"
    finally:
        db.close()
        DBManager._instance = None  # type: ignore[attr-defined]


def test_yeni_goc_IKINCI_acilista_tekrar_calismiyor(
    tmp_path: Path, sahte_goc,
) -> None:
    """
    En pahalı göç hatası budur: veri taşıyan bir göçün iki kez koşması.
    """
    yol = tmp_path / "v3.db"
    for _ in range(2):
        DBManager._instance = None  # type: ignore[attr-defined]
        db = DBManager(yol)
        db.connect(hwid="TEST-HWID-MIG")
        db.close()
    DBManager._instance = None  # type: ignore[attr-defined]
    assert sahte_goc == [_SAHTE_NO], f"Göç {len(sahte_goc)} kez çalıştı"


def test_dusen_bir_goc_ONCEKILERI_geri_almiyor(
    bos_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Her göç kendi işleminde. Hepsi tek işlemde olsaydı, ilk sahte göç
    başarılıyken ikincisinin düşmesi ilkini de geri alır ve her açılış
    aynı yerden yeniden düşerdi — kurulum kalıcı olarak kırılırdı.
    """
    def _iyi(conn: sqlite3.Connection) -> None:
        conn.execute("CREATE TABLE IF NOT EXISTS iyi_tablo (id INTEGER PRIMARY KEY)")

    def _kotu(_conn: sqlite3.Connection) -> None:
        raise sqlite3.OperationalError("kasten düşürüldü")

    monkeypatch.setattr(M, "MIGRATIONS", (
        *M.MIGRATIONS,
        M.Migration(9001, "iyi", "Başarılı olacak göç — kalıcı olmalı.", _iyi),
        M.Migration(9002, "kotu", "Kasten düşen göç — sonrakini engellemeli.", _kotu),
    ))

    with pytest.raises(sqlite3.OperationalError):
        M.sifirdan_kur(bos_conn)

    # sifirdan_kur() sonda commit ediyor; düşen çağrıda o commit hiç
    # çalışmadı. Yine de ilk sahte göçün ETKİSİ bağlantıda görünür olmalı
    # ve senkronize() ile yeniden denendiğinde tekrar uygulanmalı.
    tablolar = {
        r[0] for r in bos_conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert "iyi_tablo" in tablolar, "Başarılı göçün etkisi kaybolmuş"


def test_basarili_goc_DISKTE_kaliyor_sonraki_dusse_bile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Her göç KENDİ işleminde — ve bu ancak diske yazıp yeniden okuyarak
    ölçülebilir.

    Mutasyon testi burayı yakaladı: `senkronize()` toplu commit'e
    çevrildiğinde hiçbir test düşmedi, çünkü mevcut testler aynı
    bağlantıda kalıyordu ve commit edilmemiş değişiklikler orada
    görünüyor.

    Toplu commit'in gerçek bedeli şu: ilk sahte göç başarılı, ikincisi
    düştü → ilki de geri alınır ve HER açılış aynı yerden yeniden düşer.
    Kurulum kalıcı olarak kırılır ve günlükte yalnızca ikincinin hatası
    görünür.

    NOT: bu test `senkronize()`'ı BOŞ (şemasız) bir bağlantıda çağırıyor
    — TEMEL_SURUM üstü göçler (Migration 22 dahil) gerçek şemaya ihtiyaç
    duyduğu için burada sahte numaralar TEMEL_SURUM'un çok üstünde
    seçildi; gerçek Migration 22 bu bağlantıda `settings` tablosu
    olmadan zaten patlardı — testin ölçmek istediği şey bu değil.
    """
    def _iyi(conn: sqlite3.Connection) -> None:
        conn.execute("CREATE TABLE IF NOT EXISTS kalici_tablo (id INTEGER PRIMARY KEY)")

    def _kotu(_conn: sqlite3.Connection) -> None:
        raise sqlite3.OperationalError("kasten düşürüldü")

    monkeypatch.setattr(M, "MIGRATIONS", tuple(
        g for g in M.MIGRATIONS if g.numara <= M.TEMEL_SURUM
    ) + (
        M.Migration(9001, "kalici", "Başarılı; diskte kalmalı.", _iyi),
        M.Migration(9002, "dusen", "Kasten düşen göç.", _kotu),
    ))

    yol = tmp_path / "islem.db"
    conn = sqlite3.connect(str(yol))
    try:
        with pytest.raises(sqlite3.OperationalError):
            M.senkronize(conn)
    finally:
        conn.close()

    # YENİDEN AÇ — commit edilmemiş her şey kaybolmuş olurdu.
    conn2 = sqlite3.connect(str(yol))
    try:
        tablolar = {
            r[0] for r in conn2.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert "kalici_tablo" in tablolar, (
            "Başarılı göç diske yazılmamış — toplu commit kullanılıyor olabilir."
        )
        damgali = {r[0] for r in conn2.execute(
            f"SELECT numara FROM {M.LEDGER_TABLE}")}
        assert 9001 in damgali, "Başarılı göç deftere kalıcı yazılmamış"
        assert 9002 not in damgali, "Düşen göç uygulanmış gibi damgalanmış"
    finally:
        conn2.close()


def test_senkronize_dusen_gocten_SONRAKILERI_denemiyor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Sıra anlamlı: bir göç düştüyse sonraki çalıştırılmamalı. Sonraki,
    düşenin eklediği bir sütuna dayanıyor olabilir ve sessizce bozuk bir
    şema üretirdi.

    `senkronize()` `_temeli_damgala()` ile 1..TEMEL_SURUM'u ÇALIŞTIRMADAN
    damgaladığı için bu bağlantıda gerçek şema hiç kurulmuyor — gerçek
    Migration 22 (`settings` tablosuna yazıyor) burada zaten patlardı.
    Testin ölçtüğü şey o değil, bu yüzden sahte göçler TEMEL_SURUM
    üstündeki gerçek göçlerin YERİNE geçiyor, yanına değil.
    """
    ucuncu: list[int] = []

    def _kotu(_conn: sqlite3.Connection) -> None:
        raise sqlite3.OperationalError("kasten düşürüldü")

    def _sonraki(_conn: sqlite3.Connection) -> None:
        ucuncu.append(9002)

    monkeypatch.setattr(M, "MIGRATIONS", tuple(
        g for g in M.MIGRATIONS if g.numara <= M.TEMEL_SURUM
    ) + (
        M.Migration(9001, "kotu", "Kasten düşen göç.", _kotu),
        M.Migration(9002, "sonraki", "Düşenden sonrakine geçilmemeli.", _sonraki),
    ))

    conn = sqlite3.connect(":memory:")
    try:
        M.defteri_kur(conn)
        with pytest.raises(sqlite3.OperationalError):
            M.senkronize(conn)
        assert ucuncu == [], "Düşen göçten sonraki göç yine de çalıştı"
    finally:
        conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# 4. user_version ÇAKIŞMASI — sessiz ve ciddi
# ══════════════════════════════════════════════════════════════════════════════


def test_defter_user_version_a_DOKUNMUYOR(gercek_db) -> None:
    """
    `PRAGMA user_version` `CORE/secret_migration.py`'ye ait.

    Göç defteri onu kullansaydı sayaç 21'e çıkardı, `secret_migration`
    `21 >= CURRENT_SCHEMA_VERSION` görüp **sır taşımayı tümüyle
    atlardı** — `usb_tokens.share_2` ve `data/totp_secret.json` düz metin
    olarak yerinde kalırdı ve kimse fark etmezdi.

    Bu, gördüğü ilk anda düzeltilebilecek bir hata değil: sessizce
    doğru görünür.
    """
    from CORE.secret_migration import CURRENT_SCHEMA_VERSION, get_schema_version

    surum = get_schema_version(gercek_db)
    assert surum <= CURRENT_SCHEMA_VERSION, (
        f"user_version {surum} — sır taşıma sayacının üstüne yazılmış. "
        "Göç defteri kendi tablosunu kullanmalı."
    )


def test_migrations_modulu_user_version_YAZMIYOR() -> None:
    """
    Kaynak düzeyinde sabitleniyor: birinin ileride "SQLite'ın ayırdığı
    alan burası" diye defteri oraya taşıması, yukarıdaki testin
    yakalayacağı ama sebebini söylemeyeceği bir kırılma olurdu.
    """
    kaynak = (Path(__file__).parent.parent / "DB" / "migrations.py").read_text(
        encoding="utf-8")
    kod = "\n".join(
        s for s in kaynak.splitlines() if not s.lstrip().startswith("#")
    )
    # Docstring'de ADI GEÇİYOR (gerekçe orada anlatılıyor) ama PRAGMA
    # olarak ÇALIŞTIRILMIYOR. Aranan şey çalıştırma biçimi.
    assert "PRAGMA user_version =" not in kod
    assert "user_version" not in kod.split('"""')[-1], (
        "Docstring dışındaki kodda user_version geçiyor"
    )


def test_sir_tasima_sayaci_hala_calisiyor(gercek_db) -> None:
    """
    Ters yön: defter eklendikten sonra sır taşıma hâlâ 0'dan başlamalı.
    Yeni bir veritabanında hiçbir sır taşınmamıştır.
    """
    from CORE.secret_migration import get_schema_version

    assert get_schema_version(gercek_db) == 0


# ══════════════════════════════════════════════════════════════════════════════
# 5. sutun_ekle() — yutulan hata sınırı
# ══════════════════════════════════════════════════════════════════════════════


def test_var_olan_sutun_sessizce_geciliyor(bos_conn: sqlite3.Connection) -> None:
    bos_conn.execute("CREATE TABLE t (a INTEGER)")
    M.sutun_ekle(bos_conn, "t", "b TEXT")
    M.sutun_ekle(bos_conn, "t", "b TEXT")  # ikinci kez — sessiz
    sutunlar = {r[1] for r in bos_conn.execute("PRAGMA table_info(t)")}
    assert sutunlar == {"a", "b"}


def test_GERCEK_hata_yutulmuyor(bos_conn: sqlite3.Connection) -> None:
    """
    `_apply_schema()`'daki çıplak `except OperationalError: pass`, "tablo
    yok" ya da sözdizimi hatasını da yutuyordu — göç sessizce hiçbir şey
    yapmamış olur ve bu aylar sonra fark edilirdi.

    `sutun_ekle()` yalnızca "duplicate column name" yutuyor.
    """
    with pytest.raises(sqlite3.OperationalError):
        M.sutun_ekle(bos_conn, "olmayan_tablo", "x TEXT")


def test_gecersiz_sozdizimi_de_yutulmuyor(bos_conn: sqlite3.Connection) -> None:
    bos_conn.execute("CREATE TABLE t (a INTEGER)")
    with pytest.raises(sqlite3.OperationalError):
        M.sutun_ekle(bos_conn, "t", "b NOT_A_TYPE CHECK(")
