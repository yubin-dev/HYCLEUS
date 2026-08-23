"""
HYCLEUS — Yedek Doğrulama Diyaloğu

`verify_backup()` `backup_cli.py --verify`'dan beri çalışıyordu. Bu
diyalog aynı fonksiyonu arayüze bağlıyor — ikinci bir doğrulama
uygulaması DEĞİL.

GERİ YÜKLEME komut satırında KALIYOR ve bu bilinçli: geri yüklemenin
tipik senaryosu "disk gitti, yeni makine" ve o makinede grafik arayüz
zaten açılmıyor (`main.py` takılı ve kayıtlı bir USB ile bir vault
dosyası istiyor, ikisi de yok). Doğrulama ise rutin bir iş — çalışan bir
oturumda, "yedeğim hâlâ sağlam mı" sorusuna yanıt. Ayrıntılı gerekçe
`CORE/backup_cli.py` modül docstring'inde.


Arayüz neden DERİN doğrulama yapıyor
-------------------------------------
CLI'da derin mod (`--deep`) opsiyonel, çünkü orada anahtar USB + PIN
ister ve bunu her kontrol için istemek aracı kullanılmaz yapardı.

Arayüzde anahtar ZATEN elde: oturum açıkken `self._key` duruyor. Yani
derin doğrulamanın maliyeti yalnızca okuma süresi, ek bir kullanıcı
adımı yok. Sığ modu varsayılan yapmak, bedava olan bir kontrolü
kullanıcıdan saklamak olurdu.

Sığ mod yine de erişilebilir kalıyor (onay kutusu): çok büyük yedeklerde
"hızlı bir bakış" meşru bir istek ve iki mod arasındaki farkı rapor
kendisi söylüyor (`VerifyReport.deep`).


Ne GÖSTERİLİYOR
---------------
`VerifyReport`'un problem taşıyan ALTI alanının hepsi. Bu bir liste
değil bir sözleşme: `tests/test_backup_verify_ui.py` dataclass'ın
alanlarını sayıp her birinin ya gösterildiğini ya da bilerek
gösterilmediğini şart koşuyor. Yeni bir alan eklendiğinde test düşer.

Sebebi somut: `manifest_mismatch` sessizce atlanırsa kullanıcı
"değiştirilmiş manifesto" uyarısını hiç görmez ve yedeği sağlam sanır.
Bir doğrulama ekranının söylemediği şey, söylediği kadar önemli.
"""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from CORE.backup import VerifyReport
from UI.dialog_kit import (
    rapor_stili,
    varsayilan_gorunum,
    ayrac,
    kutu,
    sarmali,
)
from UI.main_window_palette import _DARK

#: En fazla kaç dosya adı listelenecek. Kalanı "… ve N tane daha".
#: CLI'daki sınırla aynı (`backup_cli.py::_cmd_verify`).
_LISTE_SINIRI = 20

#: Durum → (simge, renk). Dört ayrı durum, dört ayrı renk.
#:
#: `okunamadi` ile `kusurlu` AYRI: "manifestoyu açamadım" ile "üç dosya
#: bozuk" farklı şeyler ve ilkinde yedeğin bozuk OLDUĞU söylenemez.
#: `iptal` de ayrı — yarıda kesilmiş bir tarama ne sağlam ne kusurlu.
DURUM_SAGLAM = "saglam"
DURUM_KUSURLU = "kusurlu"
DURUM_OKUNAMADI = "okunamadi"
DURUM_IPTAL = "iptal"


def _durum_gorunum(T: dict[str, str]) -> dict[str, tuple[str, str]]:
    """Dört ayrı durum, dört ayrı renk (`test_dort_durum_dort_ayri_renk`).

    `iptal` bilerek `T['gray']` — "yarıda kesildi" bir uyarı değil, nötr
    bir durum (⏸ simgesi de bunu yansıtıyor); `okunamadi` gerçek bir
    uyarı olduğu için `T['yellow']`'da kalıyor.
    """
    return {
        DURUM_SAGLAM:    ("✔", T["green"]),
        DURUM_KUSURLU:   ("✖", T["red"]),
        DURUM_OKUNAMADI: ("⚠", T["yellow"]),
        DURUM_IPTAL:     ("⏸", T["gray"]),
    }

#: Problem listeleri: (`VerifyReport` alanı, başlık, ne anlama geldiği).
#:
#: Tek yerde tanımlı, çünkü hem ekrandaki kutular hem panoya kopyalanan
#: metin buradan üretiliyor. İkisini ayrı yazmak, birine eklenip
#: diğerine eklenmeyen bir liste üretirdi.
_PROBLEM_LISTELERI: tuple[tuple[str, str, str], ...] = (
    (
        "missing", "Eksik dosyalar",
        "Manifestoda yazılı ama yedekte YOK. Kopyalama yarıda kalmış ya "
        "da dosyalar sonradan silinmiş olabilir.",
    ),
    (
        "corrupt", "Bozuk dosyalar",
        "Dosya yerinde ama içeriği yedek alındığı andakinden farklı. "
        "Aktarım hatası ya da diskte bozulma.",
    ),
    (
        "auth_failed", "Doğrulanamayan dosyalar",
        "Dosyanın bütünlük mührü tutmuyor. Boyutu ve özeti doğru olsa "
        "bile içeriği güvenilir değil.",
    ),
)


class BackupVerifyDialog(QDialog):
    """Bir yedek doğrulamasının sonucunu gösterir."""

    def __init__(self, rapor: VerifyReport, yedek_dizini: Path, parent=None,
                 *, sade: bool = False, T: dict[str, str] | None = None) -> None:
        """
        Args:
            sade: `True` ise yalnızca simge, başlık ve tek cümlelik özet
                görünüyor; kapsam alanları, problem/bilgi kutuları ve
                teknik blok gizleniyor.

                `UI/TimestampDialog.py` ile AYNI kural: gizleniyor,
                silinmiyor — "Basit" ikinci bir metin kümesi değil, aynı
                içeriğin bir görünümü.
            T: Çağıranın aktif tema token sözlüğü (`HycleusWindow._T`).
                Verilmezse varsayılan "mavi" koyu palete düşer.
        """
        self._sade = sade
        self._T: dict[str, str] = T if T is not None else _DARK
        self._gelismis: list[QWidget] = []
        super().__init__(parent)
        self._rapor = rapor
        self._dizin = Path(yedek_dizini)
        self._durum = durum_of(rapor)

        self.setWindowTitle(f"HYCLEUS — Yedek Doğrulama · {self._dizin.name}")
        self.setMinimumWidth(560)
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setStyleSheet(rapor_stili(self._T))
        self._build_ui()

    # ── Kurulum ───────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        dis = QVBoxLayout(self)
        dis.setContentsMargins(0, 0, 0, 0)
        dis.setSpacing(0)

        kaydir = QScrollArea()
        kaydir.setWidgetResizable(True)
        govde = QWidget()
        govde.setObjectName("govde")
        kaydir.setWidget(govde)
        dis.addWidget(kaydir, 1)

        yerlesim = QVBoxLayout(govde)
        yerlesim.setContentsMargins(24, 20, 24, 16)
        yerlesim.setSpacing(10)

        yerlesim.addWidget(self._baslik_bloku())
        yerlesim.addWidget(sarmali(self._rapor.summary(), "ozet"))

        self._gelismis += [ayrac(), kutu(self._kapsam_alanlari())]
        self._gelismis += list(self._problem_kutulari())
        self._gelismis += list(self._bilgi_kutulari())
        self._gelismis += [ayrac(), self._teknik_bloku()]
        for parca in self._gelismis:
            yerlesim.addWidget(parca)
            if self._sade:
                parca.setHidden(True)
        yerlesim.addStretch(1)

        dis.addWidget(self._alt_cubuk())

    def _baslik_bloku(self) -> QWidget:
        simge_metni, renk = _durum_gorunum(self._T).get(
            self._durum, varsayilan_gorunum(self._T)
        )
        sarici = QWidget()
        satir = QHBoxLayout(sarici)
        satir.setContentsMargins(0, 0, 0, 0)
        satir.setSpacing(12)

        simge = QLabel(simge_metni)
        simge.setObjectName("simge")
        simge.setStyleSheet(f"color:{renk};")
        simge.setAlignment(Qt.AlignTop)
        satir.addWidget(simge)

        sutun = QVBoxLayout()
        sutun.setSpacing(2)
        baslik = sarmali(basligi(self._rapor), "baslik")
        baslik.setStyleSheet(f"color:{renk};")
        sutun.addWidget(baslik)
        sutun.addWidget(sarmali(str(self._dizin), "dosya"))
        satir.addLayout(sutun, 1)
        return sarici

    def _kapsam_alanlari(self) -> list[QWidget]:
        """Kontrolün NE KADARINI kapsadığı.

        Sonucun kendisi kadar önemli: "sağlam" cevabı, kaç dosyaya ve ne
        derinlikte bakıldığı bilinmeden okunamaz.
        """
        r = self._rapor
        satirlar = [
            ("Bakılan dosya", f"{r.checked} / {r.total}" if r.total else str(r.checked)),
            (
                "Kontrol derinliği",
                "Bütünlük mührü dahil (tam)" if r.deep
                else "Yalnızca boyut ve özet (hızlı)",
            ),
        ]
        cikti: list[QWidget] = []
        for ad, deger in satirlar:
            cikti.append(sarmali(ad, "alan_ad"))
            cikti.append(sarmali(deger, "alan_dgr"))
        return cikti

    def _problem_kutulari(self) -> list[QWidget]:
        kutular: list[QWidget] = []
        for alan, baslik, aciklama in _PROBLEM_LISTELERI:
            adlar: list[str] = getattr(self._rapor, alan)
            if not adlar:
                continue
            icerik = [
                self._renkli_baslik(f"✖  {baslik}  ({len(adlar)})", self._T["red"]),
                sarmali(aciklama, "not_gov"),
            ]
            icerik += [sarmali(f"   • {ad}", "not_gov") for ad in adlar[:_LISTE_SINIRI]]
            if len(adlar) > _LISTE_SINIRI:
                icerik.append(sarmali(
                    f"   … ve {len(adlar) - _LISTE_SINIRI} tane daha "
                    "(tam liste teknik ayrıntılarda)", "not_gov",
                ))
            kutular.append(kutu(icerik))

        if self._rapor.manifest_mismatch:
            kutular.append(kutu([
                self._renkli_baslik("✖  İçerik listesi uyuşmuyor", self._T["red"]),
                sarmali(
                    "Yedeğin düz metin içerik listesi, şifreli kopyasıyla "
                    "aynı şeyi söylemiyor. Liste yedek alındıktan sonra "
                    "değiştirilmiş olabilir — dosyalar sağlam görünse bile "
                    "yedeğin neyi içerdiği iddiası güvenilir değil.",
                    "not_gov",
                ),
            ]))

        if self._rapor.error:
            kutular.append(kutu([
                self._renkli_baslik("⚠  Yedek okunamadı", self._T["yellow"]),
                sarmali(
                    "Yedek dizini açılamadı, dolayısıyla sağlam olup "
                    "olmadığı SÖYLENEMEZ. Bu, yedeğin bozuk olduğu "
                    "anlamına gelmez.", "not_gov",
                ),
                sarmali(f"   {self._rapor.error}", "not_gov"),
            ]))

        if self._rapor.cancelled:
            kutular.append(kutu([
                self._renkli_baslik("⏸  Doğrulama yarıda kesildi", self._T["gray"]),
                sarmali(
                    "Bakılmayan dosyalar hakkında hiçbir şey bilinmiyor. "
                    "Sonuç, taranan kısım için bile 'sağlam' sayılmıyor — "
                    "eksik bir kontrol, yapılmamış bir kontroldür.",
                    "not_gov",
                ),
            ]))
        return kutular

    def _bilgi_kutulari(self) -> list[QWidget]:
        """Hata OLMAYAN ama söylenmesi gereken şeyler."""
        kutular: list[QWidget] = []

        if self._rapor.extra:
            # Adlar da yazılıyor, yalnızca sayı değil: "3 fazladan dosya
            # var" cümlesi kullanıcıya HANGİ dosyalar olduğunu sormaktan
            # başka bir şey bırakmaz. Renk mavi kalıyor — bilgi, hata değil.
            icerik: list[QWidget] = [
                self._renkli_baslik(
                    f"ℹ  Listede olmayan {len(self._rapor.extra)} fazladan dosya",
                    self._T["accent"],
                ),
                sarmali(
                    "Yedek dizininde, içerik listesinde yazmayan dosyalar "
                    "var. Bir hata değil — elle kopyalanmış ya da eski bir "
                    "yedekten kalmış olabilirler; doğrulamaya girmiyorlar.",
                    "not_gov",
                ),
            ]
            icerik += [
                sarmali(f"   • {ad}", "not_gov")
                for ad in self._rapor.extra[:_LISTE_SINIRI]
            ]
            if len(self._rapor.extra) > _LISTE_SINIRI:
                icerik.append(sarmali(
                    f"   … ve {len(self._rapor.extra) - _LISTE_SINIRI} tane daha",
                    "not_gov",
                ))
            kutular.append(kutu(icerik))

        if self._rapor.ok and not self._rapor.deep:
            kutular.append(kutu([
                self._renkli_baslik("ℹ  Bu hızlı bir kontroldü", self._T["accent"]),
                sarmali(
                    "Dosyaların boyutu ve özeti karşılaştırıldı; bütünlük "
                    "mühürleri açılmadı. Tam kontrol için doğrulamayı "
                    "derin modda tekrarlayın.", "not_gov",
                ),
            ]))
        return kutular

    def _renkli_baslik(self, metin: str, renk: str) -> QLabel:
        lbl = sarmali(metin, "not_bas")
        lbl.setStyleSheet(f"color:{renk};")
        return lbl

    def _teknik_bloku(self) -> QWidget:
        sarici = QWidget()
        sutun = QVBoxLayout(sarici)
        sutun.setContentsMargins(0, 0, 0, 0)
        sutun.setSpacing(8)

        self._teknik_alan = QTextEdit()
        self._teknik_alan.setObjectName("teknik")
        self._teknik_alan.setReadOnly(True)
        self._teknik_alan.setPlainText(self.teknik_metin())
        self._teknik_alan.setFixedHeight(170)
        self._teknik_alan.setVisible(False)

        dugmeler = QHBoxLayout()
        dugmeler.setSpacing(8)
        self._ac_kapa = QPushButton("▸  Tam liste ve teknik ayrıntılar")
        self._ac_kapa.setObjectName("flat_btn")
        self._ac_kapa.clicked.connect(self._teknik_degistir)
        dugmeler.addWidget(self._ac_kapa)

        kopyala = QPushButton("⧉  Kopyala")
        kopyala.setObjectName("flat_btn")
        kopyala.clicked.connect(self._kopyala)
        dugmeler.addWidget(kopyala)
        dugmeler.addStretch(1)

        sutun.addLayout(dugmeler)
        sutun.addWidget(self._teknik_alan)
        return sarici

    def _alt_cubuk(self) -> QWidget:
        sarici = QWidget()
        satir = QHBoxLayout(sarici)
        satir.setContentsMargins(24, 8, 24, 16)
        satir.addStretch(1)
        kapat = QPushButton("Kapat")
        kapat.setObjectName("primary_btn")
        kapat.setDefault(True)
        kapat.clicked.connect(self.accept)
        satir.addWidget(kapat)
        return sarici

    # ── Davranış ──────────────────────────────────────────────────────────────

    def teknik_metin(self) -> str:
        """Panoya kopyalanabilir tam rapor.

        Ekrandaki listeler `_LISTE_SINIRI` ile kısaltılıyor; burada
        KISALTMA YOK. Kullanıcı bunu yöneticisine iletecekse eksik bir
        liste işe yaramaz.
        """
        r = self._rapor
        satirlar = [
            f"HYCLEUS yedek doğrulama — {self._dizin}",
            "",
            r.summary(),
            f"Bakılan dosya: {r.checked} / {r.total}",
            f"Derinlik: {'tam (bütünlük mührü dahil)' if r.deep else 'hızlı (boyut + özet)'}",
        ]
        if r.error:
            satirlar += ["", f"Okuma hatası: {r.error}"]
        if r.cancelled:
            satirlar += ["", "Doğrulama kullanıcı tarafından yarıda kesildi."]
        for alan, baslik, _aciklama in _PROBLEM_LISTELERI:
            adlar: list[str] = getattr(r, alan)
            if adlar:
                satirlar += ["", f"{baslik} ({len(adlar)}):"]
                satirlar += [f"  - {ad}" for ad in adlar]
        if r.manifest_mismatch:
            satirlar += ["", "İçerik listesi şifreli kopyayla UYUŞMUYOR."]
        if r.extra:
            satirlar += ["", f"Listede olmayan fazladan dosyalar ({len(r.extra)}):"]
            satirlar += [f"  - {ad}" for ad in r.extra]
        return "\n".join(satirlar)

    def _teknik_degistir(self) -> None:
        acik = not self._teknik_alan.isVisible()
        self._teknik_alan.setVisible(acik)
        self._ac_kapa.setText(
            ("▾" if acik else "▸") + "  Tam liste ve teknik ayrıntılar"
        )
        self.adjustSize()

    def _kopyala(self) -> None:
        pano = QApplication.clipboard()
        if pano is not None:  # pragma: no branch — başsız ortamda None olabilir
            pano.setText(self.teknik_metin())


# ── Karar yardımcıları ────────────────────────────────────────────────────────
#
# Modül düzeyinde, çünkü hem diyalog hem testler soruyor ve bir Qt
# penceresinin içine gömülmüş karar test edilemez.


def durum_of(rapor: VerifyReport) -> str:
    """Raporun dört durumdan hangisi olduğu.

    Sıra önemli. `error` en başta: manifesto okunamadıysa diğer alanların
    hepsi boştur ve o boşluk "sorun yok" gibi okunurdu. `cancelled`
    ikinci: yarıda kesilmiş bir taramada bulunan hatalar gerçek ama
    LİSTE eksik, yani "kusurlu" demek bile eksik bilgi verir.
    """
    if rapor.error:
        return DURUM_OKUNAMADI
    if rapor.cancelled:
        return DURUM_IPTAL
    return DURUM_SAGLAM if rapor.ok else DURUM_KUSURLU


def basligi(rapor: VerifyReport) -> str:
    """Karar başlığı — tek satır, teknik terimsiz."""
    return {
        DURUM_OKUNAMADI: "Yedek okunamadı",
        DURUM_IPTAL:     "Doğrulama tamamlanmadı",
        DURUM_SAGLAM:    "Yedek sağlam",
        DURUM_KUSURLU:   "Yedekte sorun var",
    }[durum_of(rapor)]


__all__ = [
    "DURUM_IPTAL",
    "DURUM_KUSURLU",
    "DURUM_OKUNAMADI",
    "DURUM_SAGLAM",
    "BackupVerifyDialog",
    "basligi",
    "durum_of",
]
