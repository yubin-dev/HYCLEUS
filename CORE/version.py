"""
HYCLEUS — sürüm bilgisinin TEK kaynağı.

Neden bu dosya var (B-017)
--------------------------
Sürüm dizesi depoda beş ayrı yerde elle yazılıydı ve beşi farklı şeyler
söylüyordu:

    en son git etiketi        v2.1.2
    SECURITY.md başlığı       v2.1.0
    SECURITY.md §5            v2.1.0
    README rozeti             2.0
    Hakkında kutusu           v1.6
    İletişim kutusu           v1.5

Çalışma zamanında bir etkisi yoktu ama BİLDİRİM AKIŞINI kırıyordu:
SECURITY.md §6.3 bildirimciden "etkilenen sürüm"ü istiyor, kullanıcının
sürümü görebildiği tek yer Hakkında kutusu ve orası v1.6 diyordu. §5'in
"yalnızca en son sürüm düzeltme alır" kuralı böyle bir bildirimi kapsam
dışı gösterirdi — üstelik haksız yere.

Artık her şey buradan okunuyor; `tests/test_version.py` beşinin de bu
dosyayla uyuştuğunu her koşuda denetliyor.

İKİ sürüm var ve ikisi de gerekli
---------------------------------
`__version__` — çalıştırdığınız kod. Bugün etiketlenmemiş bir geliştirme
ağacı, o yüzden `.dev` eki taşıyor. SECURITY.md'nin "Applies to / Kapsam"
satırı buna bağlı, çünkü belge §4.9–§4.11'i (zaman damgası, şeffaf erişim,
yedekleme) anlatıyor ve o özellikler HİÇBİR yayınlanmış sürümde yok.

`SON_YAYIN` — en son git etiketi; güvenlik düzeltmesi alan sürüm.
SECURITY.md'nin "Supported version / Desteklenen sürüm" satırı buna bağlı.

İkisini tek sayıya indirmek yanlış olurdu: biri "ne çalıştırıyorsun",
diğeri "neyi düzeltiyoruz". Bugün farklılar ve bunu gizlemek, yukarıdaki
bildirim sorununun daha sinsi bir hâli olurdu.

Sürüm yükseltirken
------------------
1. `__version__` içindeki `.dev` ekini kaldır.
2. Etiketi at: `git tag v<sürüm>`.
3. `SON_YAYIN`'ı aynı değere çek.
4. Bir sonraki geliştirme turunda `__version__`'ı yükseltip `.dev` ekle.

Adım 3 unutulursa `tests/test_version.py::test_son_yayin_git_etiketiyle_
uyusuyor` uyarır (git varsa).
"""
from __future__ import annotations

#: Çalıştırılan kodun sürümü. `.dev` = etiketlenmemiş geliştirme ağacı.
__version__ = "2.2.0.dev"

#: En son yayınlanmış git etiketi — güvenlik düzeltmesi alan sürüm.
SON_YAYIN = "2.1.2"

#: Uygulama adı; arayüzdeki "HYCLEUS v..." dizelerinin ilk yarısı.
UYGULAMA_ADI = "HYCLEUS"


def surum_etiketi() -> str:
    """Arayüzde gösterilen biçim: `HYCLEUS v2.2.0.dev`."""
    return f"{UYGULAMA_ADI} v{__version__}"


def gelistirme_surumu_mu() -> bool:
    """Etiketlenmemiş bir ağaçta mıyız?"""
    return ".dev" in __version__
