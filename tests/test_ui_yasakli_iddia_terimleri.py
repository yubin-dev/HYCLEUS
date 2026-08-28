"""
UI string kaynakları — yasaklı, doğrulanmamış mimari iddia taraması.

Neden bu dosya var — B-056'nın uyguladığı YAPISAL çözümün aynısı
--------------------------------------------------------------------
"HYCLEUS v2.5 · AIR-GAPPED" ve "● ÇEVRİMDIŞI" — SECURITY.md §1.1'in M1
(ağ üzerinden erişilen TSA yanıtı) ile ÇELİŞEN, doğrulanmamış mimari
iddialar — bu koda İKİ KEZ sızdı: önce tema portlama turunda BİLEREK
dışarıda bırakıldı (`UI/main_window_palette.py`'nin `_AURORA_BOREALIS`
üstündeki yorum), sonra iki-sütunlu giriş ekranı turunda (2026-08-26)
mockup'tan olduğu gibi kopyalanarak `UI/login_dialog.py`'ye YİNE girdi.

O turda yazılan düzeltme (`tests/test_login_dogrulanmamis_iddia.py`,
şimdi bu dosyaya taşındı) TEK bir dosyayı (`login_dialog.py`) tarıyordu
— B-056'nın README'deki sabit modül sayısında tespit ettiği TAM AYNI
sınıf sorun: elle tutulan, dosyaya-özgü bir kontrol, YENİ bir UI dosyası
eklendiğinde sessizce eskir. B-056'nın kalıcı çözümü sürüklenen değeri
belgeden TAMAMEN kaldırmaktı; buradaki denk çözüm dosyaya-özgü taramayı
TÜM `UI/` dizinini kapsayan TEK bir taramaya genişletmek — üçüncü bir
dosyada aynı iddia sızarsa, o dosyanın var olduğunu bu test bilmek
ZORUNDA değil, yalnızca `UI/*.py` deseniyle eşleşmesi yeterli.

Yasaklı terim listesi — SECURITY.md §6.8'de belgeli
-----------------------------------------------------
  · **AIR-GAPPED / air-gapped** — koşulsuz yasak. Uygulama TSA'ya ağ
    üzerinden ulaşıyor (§1.1 M1); "hava boşluklu" iddiasının hiçbir
    meşru kullanımı yok.
  · **ZERO-TRUST / zero-trust** — koşulsuz yasak. Uygulanmayan, hiçbir
    yerde iddia edilmeyen bir mimari terim.
  · **ÇEVRİMDIŞI / çevrimdışı** — BAĞLAMA BAĞLI yasak. Belirli, doğrulanmış
    bir YETENEĞİ (RFC 3161 zaman damgası doğrulaması, §4.9 — gerçekten
    ağsız çalışıyor, ölçüldü) tanımlarken DOĞRU; uygulamanın TAMAMININ
    ağdan yalıtık olduğu genel bir iddia olarak YANLIŞ. Bu yüzden yalnızca
    "çevrimdışı doğrula-" bigramı (bir eylemi nitelerken) İZİN VERİLİYOR;
    başka her bağlamda (ör. bağımsız bir durum rozeti, "tamamen çevrimdışı
    çalışır" gibi genel bir iddia) yasak. Bkz. `UI/GuvenlikView.py` ve
    `UI/main_window_files.py`'deki mevcut, meşru kullanımlar — bu test
    ikisini de İZİN VERİLEN listesiyle geçiriyor, aşağıdaki
    `test_mevcut_UI_dosyalarindaki_mesru_kullanimlar_YANLIS_POZITIF_
    URETMIYOR` bunu doğrudan kanıtlıyor.

Yöntem — neden `ast`, neden ham metin taraması DEĞİL
-------------------------------------------------------
`UI/main_window_palette.py`'nin kendi yorumu ("... 'air-gapped'
doğrulanmamış bir güvenlik iddiası...") tam da YASAKLI TERİMİ, o terimin
NEDEN yasaklandığını açıklarken içeriyor — ham bir `terim in dosya_metni`
taraması bu YORUMU da bir ihlal sanırdı (kanıtlandı, bkz. bu dosyanın
geliştirme sürecindeki not). `ast` ile yalnızca gerçek STRING SABİTLERİ
(`ast.Constant`, dize değerli) taranıyor — Python yorumları hiçbir zaman
AST'ye girmiyor, yani "yasağı açıklayan bir yorum" asla yanlış pozitif
üretemiyor. Docstring'ler de tarama kapsamında (onlar da birer string
sabiti) — kasıtlı: bazı docstring'ler (ör. `_on_ctx_verify_timestamp`'in
kendisi) fiilen kullanıcıya gösterilen metnin yakınında duruyor ve aynı
titizliği hak ediyor.
"""
from __future__ import annotations

import ast
from pathlib import Path

KOK = Path(__file__).resolve().parent.parent
_UI_DIZINI = KOK / "UI"

#: 2026-08-29'da genişletildi — CORE/ ve DB/'de tanımlı exception sınıflarının
#: (`USBAuthError`, `VaultTamperedError`, `AuthenticationError`, `BackupError`,
#: `CheckoutError`, `TrustedRootError`, `PinRotationError`, ...) mesajları
#: `str(exc)`/`f"{exc}"` yoluyla HAM biçimde UI'de gösteriliyor mu diye
#: izlendi — ölçüldü, GÖSTERİLİYOR (kanıt: `AdminPanel.py:729,1282`,
#: `main_window_open.py:131,237,342`, `main_window_lock.py:230,234,258`,
#: `ProfileDialog.py:355,358`, `main_window_files.py:313`,
#: `login_dialog.py:1094`, `PinRotationDialog.py:207`). Yani CORE/DB'deki bir
#: exception mesajı da tıpkı bir UI string'i gibi kullanıcıya ulaşabilir —
#: taramaya dahil edilmezse aynı sızıntı (bkz. modül docstring'i) üçüncü kez
#: tekrarlanabilirdi, bu sefer bir exception mesajı üzerinden. Hangi
#: sınıfların sızdığını elle listelemek yerine (kırılgan — yeni bir sınıf
#: eklenip UI'de `str(exc)` ile gösterildiğinde sessizce eskir) TÜM CORE/ ve
#: DB/ string sabitleri taranıyor — B-056'nın aynı yapısal dersi.
_CORE_DIZINI = KOK / "CORE"
_DB_DIZINI = KOK / "DB"

#: Koşulsuz yasaklı terimler — hiçbir meşru bağlamları yok. Türkçe
#: noktalı/noktasız I sorunu bunlarda geçerli değil (ikisi de ASCII),
#: ama tutarlılık için yine de büyük/küçük harf varyantları elle
#: listeleniyor — `str.upper()/.lower()`'a güvenmiyoruz (bkz. altta).
_KOSULSUZ_YASAKLILAR: dict[str, tuple[str, ...]] = {
    "AIR-GAPPED": (
        "AIR-GAPPED", "air-gapped", "Air-Gapped", "Air-gapped",
        "AIR GAPPED", "air gapped", "Air Gapped",
    ),
    "ZERO-TRUST": (
        "ZERO-TRUST", "zero-trust", "Zero-Trust", "Zero-trust",
        "ZERO TRUST", "zero trust", "Zero Trust",
    ),
}

#: "ÇEVRİMDIŞI" büyük/küçük harf varyantları ELLE listelendi — Türkçe'nin
#: noktalı/noktasız I kuralları `str.upper()/.lower()`'ın yerleşik
#: (yerel ayardan bağımsız) Unicode eşlemesiyle DOĞRU dönüşmüyor
#: (`'İ'.lower()` tek bir `'i'` değil, `'i' + COMBINING DOT ABOVE`
#: üretiyor — ölçüldü), yani otomatik büyütme/küçültmeye güvenmek
#: yanlış-negatif üretebilirdi. `tests/test_login_dogrulanmamis_iddia.py`
#: (bu dosyanın öncülü, şimdi buraya taşındı) aynı gerekçeyle aynı deseni
#: kullanıyordu.
_CEVRIMDISI_VARYANTLARI = ("ÇEVRİMDIŞI", "çevrimdışı", "Çevrimdışı")

#: Yukarıdaki modül docstring'inin açıkladığı tek istisna: belirli bir
#: eylemi ("zaman damgasını çevrimdışı doğrular") nitelerken doğru ve
#: SECURITY.md §4.9 ile doğrulanmış. Fiil çekimleri elle listelendi —
#: burada da `.lower()` güvenilmez.
#: 2026-08-29: `çevrimdışı doğrulanamaz` eklendi — CORE/timestamp.py:672'nin
#: gerçek `raise TimestampError(...)` mesajı ("...bu damga sonradan
#: çevrimdışı doğrulanamaz.") bir SINIRLAMA bildiriyor (sertifika
#: gömülmemişse doğrulama YAPILAMAZ), bir mimari İDDİA değil — §4.9'un
#: doğruladığı yeteneğin negatif/uyarı biçimi, o yüzden meşru.
_CEVRIMDISI_IZIN_VERILEN_BAGLAM = (
    "çevrimdışı doğrular", "çevrimdışı doğrulanır", "çevrimdışı doğrulanıyor",
    "çevrimdışı doğrulanabilir", "çevrimdışı doğrulama", "çevrimdışı doğrulanamaz",
    "Çevrimdışı doğrular", "Çevrimdışı doğrulanır",
)


def _ui_dosyalari() -> list[Path]:
    """`rglob` — TÜM alt dizinler dahil (yalnızca doğrudan `UI/*.py` DEĞİL).
    Ölçüldü: `UI/` şu an alt dizin içermiyor (yalnızca `__pycache__`), ama
    `glob("*.py")` bir alt dizin eklendiğinde onu SESSİZCE atlardı — kanıt:
    `UI/_gecici_altdizin_kaniti/sahte.py`'ye enjekte edilen bir AIR-GAPPED
    terimi `glob("*.py")` ile 7/7 test yeşil kalarak yakalanamadı, `rglob`'a
    geçilince yakalandı (geçici dosya/dizin kanıttan sonra silindi)."""
    return sorted(
        p for p in _UI_DIZINI.rglob("*.py") if "__pycache__" not in p.parts
    )


def _core_db_dosyalari() -> list[Path]:
    """CORE/ ve DB/ — exception mesaj kaynakları (yukarıdaki not). Ölçüldü:
    ikisi de şu an alt dizin içermiyor, yine de `rglob` kullanılıyor (aynı
    UI/ dersini burada da baştan uygula, ayrı bir alt-dizin kanıtı tekrar
    yazmaya gerek kalmasın)."""
    dosyalar = [
        p
        for dizin in (_CORE_DIZINI, _DB_DIZINI)
        for p in dizin.rglob("*.py")
        if "__pycache__" not in p.parts
    ]
    return sorted(dosyalar)


def _taranacak_tum_dosyalar() -> list[Path]:
    return sorted(_ui_dosyalari() + _core_db_dosyalari())


def _string_sabitlerini_topla(kaynak: str, dosya_adi: str) -> list[tuple[str, int]]:
    """`(deger, satir)` çiftleri — dosyadaki HER string sabiti (f-string
    içindeki düz-metin parçaları dahil, `ast.walk` `JoinedStr`'ın içine
    de iniyor)."""
    agac = ast.parse(kaynak, filename=dosya_adi)
    return [
        (dugum.value, dugum.lineno)
        for dugum in ast.walk(agac)
        if isinstance(dugum, ast.Constant) and isinstance(dugum.value, str)
    ]


def _raise_mesaj_sabitlerini_topla(kaynak: str, dosya_adi: str) -> list[tuple[str, int]]:
    """CORE/DB için `_string_sabitlerini_topla`'nın DAR karşılığı: dosyadaki
    HER string sabiti değil, yalnızca `raise SinifAdi(...)` çağrılarının
    İÇİNDEKİ string sabitleri.

    Neden dar — ölçüldü, geniş tarama gerçek yanlış-pozitif üretti
    -----------------------------------------------------------------
    CORE/DB'nin tamamını (`_string_sabitlerini_topla` gibi) taramak
    denendi: `CORE/backup.py`, `CORE/rate_limit.py`'nin SALDIRGANIN
    "çevrimdışı kaba kuvvet" yapabileceğini anlatan modül docstring'leri,
    `CORE/timestamp.py`/`timestamp_verify.py`'nin "ÇEVRİMDIŞI DOĞRULANMASI"
    gibi isim-fiil biçimleriyle konuyu tanıtan docstring'leri YANLIŞ POZİTİF
    olarak yakalandı (8 ihlal, 7'si gerçek dışı) — hiçbiri kullanıcıya HİÇBİR
    yoldan gösterilmiyor (docstring/yorum, `str(exc)` ile UI'ye sızan tek
    kaynak değil, bkz. modülün üstündeki not). Kapsam bu yüzden yalnızca
    GERÇEKTEN sızabilecek metne — `raise` çağrısının argümanlarına —
    daraltıldı; bu hem tüm gerçek yanlış-pozitifleri ortadan kaldırdı hem de
    gerçek bir isabeti korudu (`CORE/timestamp.py:672`, bkz.
    `_CEVRIMDISI_IZIN_VERILEN_BAGLAM`)."""
    agac = ast.parse(kaynak, filename=dosya_adi)
    sonuc: list[tuple[str, int]] = []
    for dugum in ast.walk(agac):
        if isinstance(dugum, ast.Raise) and isinstance(dugum.exc, ast.Call):
            for alt in ast.walk(dugum.exc):
                if isinstance(alt, ast.Constant) and isinstance(alt.value, str):
                    sonuc.append((alt.value, alt.lineno))
    return sonuc


def _cevrimdisi_ihlali_mi(metin: str) -> bool:
    """İzin verilen bigram'ları metinden ÇIKARDIKTAN SONRA hâlâ bir
    "çevrimdışı" varyantı kalıyor mu? Kalıyorsa bağlam dışı kullanım."""
    kalan = metin
    for izinli in _CEVRIMDISI_IZIN_VERILEN_BAGLAM:
        kalan = kalan.replace(izinli, "")
    return any(v in kalan for v in _CEVRIMDISI_VARYANTLARI)


def _metindeki_ihlalleri_bul(metin: str) -> list[str]:
    """Bir tek string sabitindeki ihlalleri döndürür — terim adlarının
    listesi (rapor için)."""
    bulunanlar: list[str] = []
    for terim, varyantlar in _KOSULSUZ_YASAKLILAR.items():
        if any(v in metin for v in varyantlar):
            bulunanlar.append(terim)
    if _cevrimdisi_ihlali_mi(metin):
        bulunanlar.append("ÇEVRİMDIŞI (bağlam dışı)")
    return bulunanlar


def _core_db_dosyasi_mi(dosya: Path) -> bool:
    """`CORE/`/`DB/` altındaki GERÇEK dosyalar için True (kök dizinlere göre
    çözümlenmiş yol karşılaştırması — `tmp_path` altındaki geçici dosyalar
    hiçbir zaman bu iki kökün altında olmadığından doğal olarak False döner
    ve varsayılan (UI-tarzı, tam metin) taramayı kullanır)."""
    cozulmus = dosya.resolve()
    return cozulmus.is_relative_to(_CORE_DIZINI) or cozulmus.is_relative_to(_DB_DIZINI)


def _tum_ihlalleri_tara(dosyalar: list[Path]) -> list[str]:
    ihlaller: list[str] = []
    for dosya in dosyalar:
        try:
            bagil = dosya.relative_to(KOK).as_posix()
        except ValueError:
            bagil = dosya.name  # test amaçlı geçici dosya — depo dışında
        kaynak = dosya.read_text(encoding="utf-8")
        toplayici = (
            _raise_mesaj_sabitlerini_topla
            if _core_db_dosyasi_mi(dosya)
            else _string_sabitlerini_topla
        )
        for metin, satir in toplayici(kaynak, bagil):
            for terim in _metindeki_ihlalleri_bul(metin):
                ozet = metin if len(metin) <= 70 else metin[:67] + "..."
                ihlaller.append(f"{bagil}:{satir} — {terim} — {ozet!r}")
    return ihlaller


# ══════════════════════════════════════════════════════════════════════════════
# 1. Asıl tarama — UI/ + CORE/ + DB/, tek test
# ══════════════════════════════════════════════════════════════════════════════


def test_ui_stringlerinde_yasakli_mimari_iddia_YOK() -> None:
    """
    `UI/`, `CORE/`, `DB/` altındaki HER dosyadaki HER string sabiti
    taranıyor — yeni bir dosya eklendiğinde bu test onu otomatik kapsıyor,
    elle güncellenecek bir liste YOK (B-056'nın yapısal dersi). CORE/DB
    dahil çünkü buradaki exception mesajları `str(exc)` yoluyla HAM biçimde
    UI'ye sızıyor — ölçüldü, bkz. `_CORE_DIZINI`/`_DB_DIZINI` yorumu.
    """
    ihlaller = _tum_ihlalleri_tara(_taranacak_tum_dosyalar())
    assert not ihlaller, (
        "UI/CORE/DB string kaynaklarında yasaklı/doğrulanmamış mimari iddia "
        f"bulundu (SECURITY.md §6.8'deki terim listesi): {ihlaller}"
    )


def test_ui_dizini_taranacak_dosya_iceriyor() -> None:
    """Denetimin KENDİSİ çalışıyor mu: dizinler boş/bulunamaz olursa yukarıdaki
    test SESSİZCE boş kümeyi denetler ve hep geçer (bkz. test_tpm_sealing.py
    B-024 dersi — bu depoda tekrar eden bir ilke). Eşik 2026-08-29'da
    genişletildi: UI (~20+) + CORE (52) + DB (3) ≈ 75+."""
    assert len(_taranacak_tum_dosyalar()) >= 70, (
        "UI/CORE/DB dizinlerinde beklenenden az .py dosyası bulundu — "
        "tarama hedefi yanlış olabilir"
    )


def test_mevcut_UI_dosyalarindaki_mesru_kullanimlar_YANLIS_POZITIF_URETMIYOR() -> None:
    """
    `UI/GuvenlikView.py` ve `UI/main_window_files.py`, RFC 3161 zaman
    damgası doğrulamasını "çevrimdışı doğrular" diye tanımlıyor — GERÇEK,
    SECURITY.md §4.9 ile doğrulanmış bir yetenek. İzin verilen bağlam
    listesi bunları YANLIŞLIKLA yakalamamalı; yakalarsa tarayıcı fazla
    saldırgan demektir ve gerçek dosyalarda gürültü üretir.
    """
    ihlaller = _tum_ihlalleri_tara(_ui_dosyalari())
    yanlis_pozitif = [
        i for i in ihlaller
        if "GuvenlikView.py" in i or "main_window_files.py" in i
    ]
    assert yanlis_pozitif == [], (
        f"Meşru 'çevrimdışı doğrular' kullanımları yanlışlıkla yakalandı: "
        f"{yanlis_pozitif}"
    )


def test_mevcut_CORE_dosyalarindaki_docstring_mesru_kullanimlar_YANLIS_POZITIF_URETMIYOR() -> None:
    """
    2026-08-29'da ÖLÇÜLDÜ: CORE/DB'nin TAMAMINI (`_string_sabitlerini_topla`
    ile, UI'deki gibi) taramak `CORE/backup.py`, `CORE/hclx.py`,
    `CORE/rate_limit.py`, `CORE/timestamp.py`, `CORE/timestamp_verify.py`'nin
    modül/fonksiyon docstring'lerinde 7 YANLIŞ POZİTİF üretti — hiçbiri
    `raise` mesajı değil, hiçbiri kullanıcıya gösterilmiyor (ör. "çevrimdışı
    kaba kuvvet" saldırı senaryosu anlatımı, "ÇEVRİMDIŞI DOĞRULANMASI" gibi
    isim-fiil biçimiyle konu tanıtımı). Bu test o beş dosyanın gerçek
    içeriğinde ARTIK sıfır ihlal olduğunu kalıcı olarak doğruluyor — tarayıcı
    `raise`'e daraltıldıktan sonra (`_raise_mesaj_sabitlerini_topla`).
    """
    ihlaller = _tum_ihlalleri_tara(_core_db_dosyalari())
    beklenen_dosyalar = (
        "CORE/backup.py", "CORE/hclx.py", "CORE/rate_limit.py",
        "CORE/timestamp.py", "CORE/timestamp_verify.py",
    )
    yanlis_pozitif = [i for i in ihlaller if any(d in i for d in beklenen_dosyalar)]
    assert yanlis_pozitif == [], (
        f"CORE docstring'lerindeki meşru 'çevrimdışı' kullanımları "
        f"yanlışlıkla yakalandı: {yanlis_pozitif}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 2. Denetimin KENDİSİ çalışıyor mu — enjekte edilen bir terimi YAKALIYOR mu,
#    kaldırılınca YEŞİLE dönüyor mu (gerçek dosyalara HİÇ dokunmadan — tmp_path)
# ══════════════════════════════════════════════════════════════════════════════


def test_tarayici_enjekte_edilen_AIR_GAPPED_terimini_yakaliyor(tmp_path: Path) -> None:
    gecici = tmp_path / "sahte_dialog.py"
    gecici.write_text(
        'from PySide6.QtWidgets import QLabel\n'
        'etiket = QLabel("HYCLEUS v2.5 · AIR-GAPPED")\n',
        encoding="utf-8",
    )
    ihlaller = _tum_ihlalleri_tara([gecici])
    assert any("AIR-GAPPED" in i for i in ihlaller), (
        f"Enjekte edilen AIR-GAPPED terimi yakalanmadı: {ihlaller}"
    )


def test_tarayici_terim_kaldirilinca_YESILE_donuyor(tmp_path: Path) -> None:
    """Aynı geçici dosya, YASAKLI terim olmadan — sıfır ihlal beklenir."""
    gecici = tmp_path / "sahte_dialog.py"
    gecici.write_text(
        'from PySide6.QtWidgets import QLabel\n'
        'etiket = QLabel("HYCLEUS v2.3.0")\n',
        encoding="utf-8",
    )
    ihlaller = _tum_ihlalleri_tara([gecici])
    assert ihlaller == [], f"Temiz dosyada ihlal bulundu (yanlış pozitif): {ihlaller}"


def test_tarayici_enjekte_edilen_ZERO_TRUST_terimini_yakaliyor(tmp_path: Path) -> None:
    gecici = tmp_path / "sahte_dialog2.py"
    gecici.write_text('baslik = "Zero-Trust Mimari"\n', encoding="utf-8")
    ihlaller = _tum_ihlalleri_tara([gecici])
    assert any("ZERO-TRUST" in i for i in ihlaller), (
        f"Enjekte edilen ZERO-TRUST terimi yakalanmadı: {ihlaller}"
    )


def test_tarayici_ALT_DIZINDEKI_dosyayi_da_yakaliyor(tmp_path: Path) -> None:
    """Kalıcı regresyon — 2026-08-29'da `glob("*.py")`'nin (yalnızca `UI/`
    doğrudan altı) bir alt dizindeki (`UI/dialogs/` gibi, o an gerçekte var
    olmayan ama gelecekte eklenebilecek) dosyayı SESSİZCE atladığı kanıtlandı
    (gerçek `UI/_gecici_altdizin_kaniti/sahte.py` ile: enjekte edilen
    AIR-GAPPED 7/7 test yeşilken yakalanamadı). `rglob("*.py")`'ye geçildi;
    bu test o düzeltmenin kalıcı kanıtı — `_ui_dosyalari()`'nin gerçekte
    kullandığı fonksiyonu (tmp_path kökünü `_UI_DIZINI` yerine geçici olarak
    kullanmadan) doğrudan tarama fonksiyonuyla simüle ediyor."""
    alt_dizin = tmp_path / "dialogs"
    alt_dizin.mkdir()
    gecici = alt_dizin / "sahte_alt_dialog.py"
    gecici.write_text('baslik = "AIR-GAPPED"\n', encoding="utf-8")
    dosyalar = sorted(p for p in tmp_path.rglob("*.py") if "__pycache__" not in p.parts)
    assert dosyalar == [gecici], f"rglob alt dizindeki dosyayı bulamadı: {dosyalar}"
    ihlaller = _tum_ihlalleri_tara(dosyalar)
    assert any("AIR-GAPPED" in i for i in ihlaller), (
        f"Alt dizindeki enjekte edilen terim yakalanmadı: {ihlaller}"
    )


def test_tarayici_bagimsiz_CEVRIMDISI_rozetini_yakaliyor_ama_dogrulama_cumlesini_yakalamiyor(
    tmp_path: Path,
) -> None:
    """
    Tam olarak geçmişte sızan örüntü: bağımsız bir durum rozeti
    ("● ÇEVRİMDIŞI") YAKALANMALI, ama "çevrimdışı doğrular" içeren bir
    cümle YAKALANMAMALI — aynı dosyada ikisi birden test ediliyor.
    """
    gecici = tmp_path / "sahte_dialog3.py"
    gecici.write_text(
        'kotu = "● ÇEVRİMDIŞI"\n'
        'iyi = "Zaman damgasını çevrimdışı doğrular."\n',
        encoding="utf-8",
    )
    ihlaller = _tum_ihlalleri_tara([gecici])
    assert len(ihlaller) == 1, f"Beklenen tam olarak 1 ihlal (rozet), bulunan: {ihlaller}"
    assert ":1 —" in ihlaller[0], f"Yakalanan satır beklenmedik: {ihlaller[0]}"


# ══════════════════════════════════════════════════════════════════════════════
# 3. CORE/DB'ye özgü — `raise` mesajı YAKALANIYOR, docstring/yorum İÇERİĞİ
#    YAKALANMIYOR (dar kapsamın kendisi kanıtlanıyor, birim düzeyinde)
# ══════════════════════════════════════════════════════════════════════════════


def test_raise_icindeki_enjekte_edilen_terim_CORE_taramasinda_yakalaniyor() -> None:
    """`_raise_mesaj_sabitlerini_topla` — bir `raise X("...")` çağrısının
    İÇİNDEKİ yasaklı terimi yakalıyor mu?"""
    kaynak = (
        'class SahteHata(Exception):\n'
        '    pass\n\n\n'
        'def f():\n'
        '    raise SahteHata("HYCLEUS AIR-GAPPED modda çalışıyor")\n'
    )
    dizeler = _raise_mesaj_sabitlerini_topla(kaynak, "sahte.py")
    bulunanlar = [
        terim
        for metin, _ in dizeler
        for terim in _metindeki_ihlalleri_bul(metin)
    ]
    assert "AIR-GAPPED" in bulunanlar, f"raise içindeki terim yakalanmadı: {dizeler}"


def test_raise_DISINDAKI_docstring_CORE_taramasinda_YAKALANMIYOR() -> None:
    """`_raise_mesaj_sabitlerini_topla` — aynı yasaklı terim bir DOCSTRING'te
    (raise DIŞINDA) geçiyorsa YAKALANMAMALI; tam olarak CORE'un gerçek
    dosyalarında ölçülen yanlış-pozitif deseninin birim düzeyindeki kanıtı."""
    kaynak = (
        '"""Modül docstring: bu tasarım AIR-GAPPED bir senaryoyu ele almıyor,\n'
        'yalnızca saldırganın çevrimdışı kaba kuvvet yapabileceğini anlatıyor."""\n\n'
        'def f():\n'
        '    raise ValueError("meşru, terimsiz bir hata mesajı")\n'
    )
    dizeler = _raise_mesaj_sabitlerini_topla(kaynak, "sahte.py")
    bulunanlar = [
        terim
        for metin, _ in dizeler
        for terim in _metindeki_ihlalleri_bul(metin)
    ]
    assert bulunanlar == [], (
        f"Docstring'teki terim yanlışlıkla raise taramasına sızdı: {bulunanlar}"
    )
    # Docstring'in KENDİSİ de AIR-GAPPED içeriyor — ama tam metin taramasıyla
    # (`_string_sabitlerini_topla`, UI'nin kullandığı) hâlâ yakalanabildiğini
    # doğrula: dar tarama yalnızca CORE/DB YÖNLENDİRMESİNDE kullanılıyor,
    # fonksiyonun kendisi genel amaçlı kalıyor.
    tum_dizeler = _string_sabitlerini_topla(kaynak, "sahte.py")
    tum_bulunanlar = [
        terim for metin, _ in tum_dizeler for terim in _metindeki_ihlalleri_bul(metin)
    ]
    assert "AIR-GAPPED" in tum_bulunanlar


def test_core_db_dosyasi_mi_yol_ayrimi_dogru() -> None:
    """`_core_db_dosyasi_mi` — gerçek `CORE/`/`DB/` dosyaları için True,
    `UI/` ve `tmp_path` (depo dışı) dosyalar için False dönüyor mu?"""
    assert _core_db_dosyasi_mi(KOK / "CORE" / "timestamp.py") is True
    assert _core_db_dosyasi_mi(KOK / "DB" / "db_manager.py") is True
    assert _core_db_dosyasi_mi(KOK / "UI" / "login_dialog.py") is False


def test_gercek_CORE_timestamp_dosyasinin_raise_mesaji_UYGUN_ALLOWLIST_ile_GECIYOR(
) -> None:
    """`CORE/timestamp.py:672`'nin gerçek `raise TimestampError(...)` mesajı
    ("...bu damga sonradan çevrimdışı doğrulanamaz.") — ÖLÇÜLDÜ, dar
    taramaya geçilmeden önce bu YAKALANIYORDU (yanlış pozitif değildi, gerçek
    bir isabetti çünkü mesaj gerçekten kullanıcıya sızabilir); allowlist'e
    "çevrimdışı doğrulanamaz" eklenince (bir SINIRLAMA bildirimi, mimari
    İDDİA değil) geçmesi gerekiyor. Bu test o allowlist girdisinin gerçek
    dosyaya karşı hâlâ doğru çalıştığını kalıcı olarak doğruluyor."""
    dosya = KOK / "CORE" / "timestamp.py"
    kaynak = dosya.read_text(encoding="utf-8")
    dizeler = _raise_mesaj_sabitlerini_topla(kaynak, "CORE/timestamp.py")
    hedef = [m for m, ln in dizeler if ln == 672]
    assert hedef, "CORE/timestamp.py:672'deki raise mesajı bulunamadı — satır kaymış olabilir"
    assert _metindeki_ihlalleri_bul(hedef[0]) == [], (
        f"Meşru 'çevrimdışı doğrulanamaz' mesajı yanlışlıkla yakalandı: {hedef[0]!r}"
    )
