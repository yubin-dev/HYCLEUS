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
_CEVRIMDISI_IZIN_VERILEN_BAGLAM = (
    "çevrimdışı doğrular", "çevrimdışı doğrulanır", "çevrimdışı doğrulanıyor",
    "çevrimdışı doğrulanabilir", "çevrimdışı doğrulama",
    "Çevrimdışı doğrular", "Çevrimdışı doğrulanır",
)


def _ui_dosyalari() -> list[Path]:
    return sorted(_UI_DIZINI.glob("*.py"))


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


def _tum_ihlalleri_tara(dosyalar: list[Path]) -> list[str]:
    ihlaller: list[str] = []
    for dosya in dosyalar:
        try:
            bagil = dosya.relative_to(KOK).as_posix()
        except ValueError:
            bagil = dosya.name  # test amaçlı geçici dosya — depo dışında
        kaynak = dosya.read_text(encoding="utf-8")
        for metin, satir in _string_sabitlerini_topla(kaynak, bagil):
            for terim in _metindeki_ihlalleri_bul(metin):
                ozet = metin if len(metin) <= 70 else metin[:67] + "..."
                ihlaller.append(f"{bagil}:{satir} — {terim} — {ozet!r}")
    return ihlaller


# ══════════════════════════════════════════════════════════════════════════════
# 1. Asıl tarama — TÜM UI/ dizini, tek test
# ══════════════════════════════════════════════════════════════════════════════


def test_ui_stringlerinde_yasakli_mimari_iddia_YOK() -> None:
    """
    `UI/*.py` altındaki HER dosyadaki HER string sabiti taranıyor — yeni
    bir dosya eklendiğinde bu test onu otomatik kapsıyor, elle
    güncellenecek bir liste YOK (B-056'nın yapısal dersi).
    """
    ihlaller = _tum_ihlalleri_tara(_ui_dosyalari())
    assert not ihlaller, (
        "UI string kaynaklarında yasaklı/doğrulanmamış mimari iddia "
        f"bulundu (SECURITY.md §6.8'deki terim listesi): {ihlaller}"
    )


def test_ui_dizini_taranacak_dosya_iceriyor() -> None:
    """Denetimin KENDİSİ çalışıyor mu: `UI/` boş/bulunamaz olursa yukarıdaki
    test SESSİZCE boş kümeyi denetler ve hep geçer (bkz. test_tpm_sealing.py
    B-024 dersi — bu depoda tekrar eden bir ilke)."""
    assert len(_ui_dosyalari()) >= 20, (
        "UI/ dizininde beklenenden az .py dosyası bulundu — tarama hedefi "
        "yanlış olabilir"
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
