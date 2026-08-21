"""
HYCLEUS — damga doğrulama sonucunun İNSAN DİLİNE çevrilmesi (adım 3.1)

`verify_timestamp()` bir `TimestampVerification` döndürüyor ve içindeki
`reason` alanı doğru ama TEKNİK: "İmzalı `message-digest` TSTInfo ile
eşleşmiyor", "`timeStamping` genişletilmiş anahtar kullanımı taşımıyor".
Bir denetçi ya da hukukçu için bu doğru registre — CLI onu olduğu gibi
yazıyor ve öyle kalmalı. Arayüzdeki kullanıcı için değil.

Bu modül `failed_check` kodunu üç şeye çeviriyor: NE OLDU, NE ANLAMA
GELİYOR, NE YAPMALI.


Neden AYRI bir modül, doğrudan diyaloğun içinde değil
------------------------------------------------------
Bu depoda beş kez aynı kusur çıktı: aynı iş için birden fazla bağımsız
uygulama (B-004/B-008 imha sayacı, B-007 mahrem filtresi, B-010 AAD
kontrolü, B-011 create_folder, share parser). Metni diyaloğun içine
yazmak altıncısını üretirdi: `failed_check` değerlerinin ne anlama
geldiği bilgisi ikinci bir yerde, `timestamp_verify.py`'den habersiz
yaşardı.

Asıl risk şu: `timestamp_verify.py`'ye YENİ bir `failed_check` eklendiği
gün CLI çalışmaya devam eder (o `reason`'ı olduğu gibi basıyor), arayüz
ise sessizce genel bir mesaja düşer. Kullanıcı "damga doğrulanamadı, sebep
bilinmiyor" görür — yani doğrulamanın en çok işe yarayacağı anda en az şey
söyler.

`tests/test_timestamp_report.py` bunu kapatıyor: `timestamp_verify.py`'yi
AST ile tarayıp ürettiği HER `failed_check` değerini buluyor ve her biri
için burada bir karşılık olmasını şart koşuyor. Yeni bir hata yolu
eklemek, karşılığını buraya yazmadan mümkün değil.

Metin denetimi yerine AST: bu depoda düz metin denetimi dört kez yanlış
yere takıldı, sonuncusu `assert "upx=True" in metin`'in dosyanın kendi
AÇIKLAMASINA eşleşmesiydi (B-024). Burada risk aynı — bu docstring'in
kendisi `failed_check` adlarını sayıyor.


CLI neden bu tablodan BESLENMİYOR
----------------------------------
Bilerek. İkisi aynı sonucu farklı KİTLEYE anlatıyor: CLI'ın çıktısı bir
denetim dosyasına yapıştırılmak için var ve teknik olması onun işi.
Ortaklaştırılan şey sunum değil, `failed_check` kümesinin kendisi — ve o
zaten tek yerde, `timestamp_verify.py`'de tanımlı. Denetim testi iki
yüzeyi de o tek kaynağa bağlıyor.


DOĞRULUK, SADELİKTEN ÖNCE GELİR
--------------------------------
Sadeleştirmenin en kolay hatası fazla söylemek. `verify_timestamp()`
AAD'deki `original_sha256`'nın damgalandığını doğruluyor; dosyanın
İÇERİĞİNİN gerçekten o özete sahip olduğunu DOĞRULAMIYOR — o kontrol
anahtar ister ve şifre çözmede yapılıyor (bkz. `CORE/timestamp_verify.py`
`verify_timestamp()` docstring'i).

Bu yüzden "damga geçerli" mesajı "dosya değiştirilmemiş" DEMİYOR.
`notlar()` bu sınırı ayrı bir madde olarak, her geçerli sonuçta
gösteriyor. Kullanıcıya olduğundan fazlasını vaat eden bir arayüz,
CLI'dan daha kötüdür.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from CORE.timestamp_verify import TimestampVerification

# ── Seviyeler ─────────────────────────────────────────────────────────────────
#
# Renk/simge kararını arayüz veriyor; burada yalnızca ANLAM var. Dördü de
# ayrı, çünkü kullanıcı için dört ayrı durum:

#: Damga doğrulandı.
SEVIYE_GECERLI = "gecerli"
#: Damga var ama hiçbir şey kanıtlamıyor. Kırmızı.
SEVIYE_GECERSIZ = "gecersiz"
#: Dosyada damga YOK. Bir hata değil — bir eksiklik. Nötr.
SEVIYE_DAMGASIZ = "damgasiz"
#: Kontrol tamamlanamadı; damga geçersiz olduğu SÖYLENEMEZ. Turuncu.
SEVIYE_OKUNAMADI = "okunamadi"
#: Damga kriptografik olarak geçerli AMA kökü doğrulanmadı.
#:
#: Ayrı bir seviye olması bilinçli ve kurumsal kullanımın asıl talebi:
#: "geçerli" ile "geçerli ve güvenilir kök" aynı yeşil onay işaretini
#: paylaşırsa, aradaki fark yalnızca alttaki bir nota kalır ve o notu
#: okumayan kullanıcı ikisini aynı sanır. Başlığın KENDİSİ farklı.
SEVIYE_UYARI = "uyari"
#: Geçerli sonuca eşlik eden bilgi notu.
SEVIYE_BILGI = "bilgi"


@dataclass(frozen=True)
class Aciklama:
    """Kullanıcıya gösterilecek tek bir mesaj.

    `oneri` ayrı bir alan, `ozet`'in içine gömülmüş bir cümle değil:
    arayüz onu farklı biçimlendirebilsin ve bir sonucun eyleme
    dönüştürülebilir bir tarafı olup olmadığı programla sorulabilsin diye.
    """

    seviye: str
    baslik: str
    ozet: str
    oneri: str | None = None


# ── Yinelenen öneriler ────────────────────────────────────────────────────────

_ONERI_KANIT = (
    "Bu dosyayı tarih kanıtı olarak KULLANMAYIN. Durumu yöneticinize "
    "bildirin ve varsa yedekteki kopyayla karşılaştırın."
)
_ONERI_YEDEK = (
    "Dosya aktarım ya da saklama sırasında zarar görmüş olabilir. Varsa "
    "yedekteki kopyayla karşılaştırın."
)
_ONERI_TSA = (
    "Sorun dosyanızda değil, damgayı atan kurumun sertifikasında görünüyor. "
    "Yöneticinize bildirin."
)
_ONERI_DAMGA_YOK = (
    "Bu dosya için tarih kanıtı gerekiyorsa yöneticinizden damga "
    "atılmasını isteyin."
)
_ONERI_SURUM = (
    "Bu, dosyada bir sorun olduğu anlamına gelmez — damgayı okuyan sürüm "
    "yetersiz. Yöneticinize bildirin."
)


# ── failed_check → açıklama ───────────────────────────────────────────────────
#
# Anahtarlar `CORE/timestamp_verify.py`'nin ürettiği `failed_check`
# değerleri. Kümenin eksiksizliğini `tests/test_timestamp_report.py` AST
# ile denetliyor — buraya elle bakıp "hepsi var" demek yetmez.

_ADIM: dict[str, Aciklama] = {
    # ── Damga yok ─────────────────────────────────────────────────────────
    "no_timestamp": Aciklama(
        seviye=SEVIYE_DAMGASIZ,
        baslik="Bu dosyada zaman damgası yok",
        ozet=(
            "Dosyaya hiç damga atılmamış ya da damgası sonradan silinmiş. "
            "İkisi birbirinden ayırt edilemiyor. Bu, dosyanın bozuk olduğu "
            "anlamına GELMEZ — yalnızca içeriğinin belli bir tarihte var "
            "olduğunu gösteren bir kanıt yok."
        ),
        oneri=_ONERI_DAMGA_YOK,
    ),
    # ── Okunamadı: kontrol tamamlanamadı ──────────────────────────────────
    "trailer": Aciklama(
        seviye=SEVIYE_OKUNAMADI,
        baslik="Damga bölümü okunamadı",
        ozet=(
            "Dosyanın sonundaki damga bölümü çözülemedi, bu yüzden damganın "
            "geçerli olup olmadığı söylenemiyor."
        ),
        oneri=_ONERI_YEDEK,
    ),
    "aad": Aciklama(
        seviye=SEVIYE_OKUNAMADI,
        baslik="Damganın hangi içeriğe ait olduğu belirlenemedi",
        ozet=(
            "Dosyanın başlık bilgisi eksik ya da okunamıyor. Damga bir "
            "içeriğe bağlanamadığı için kontrol tamamlanamadı."
        ),
        oneri=_ONERI_YEDEK,
    ),
    "parse": Aciklama(
        seviye=SEVIYE_OKUNAMADI,
        baslik="Damga çözülemedi",
        ozet=(
            "Damganın içeriği tanınan bir biçimde değil. Damga bozulmuş ya "
            "da eksik yazılmış olabilir."
        ),
        oneri=_ONERI_YEDEK,
    ),
    "hash_algorithm": Aciklama(
        seviye=SEVIYE_OKUNAMADI,
        baslik="Bu sürüm damgayı okuyamıyor",
        ozet=(
            "Damgada kullanılan hesaplama yöntemi bu HYCLEUS sürümü "
            "tarafından desteklenmiyor."
        ),
        oneri=_ONERI_SURUM,
    ),
    # ── Geçersiz: damga bu dosyaya ait değil ──────────────────────────────
    "trailer_aad_mismatch": Aciklama(
        seviye=SEVIYE_GECERSIZ,
        baslik="Damga bu dosyaya ait değil",
        ozet=(
            "Damganın işaret ettiği içerik ile dosyanın kendi içeriği "
            "uyuşmuyor. Başka bir dosyanın damgası buraya kopyalanmış "
            "olabilir."
        ),
        oneri=_ONERI_KANIT,
    ),
    "digest_match": Aciklama(
        seviye=SEVIYE_GECERSIZ,
        baslik="Damga başka bir içeriği koruyor",
        ozet=(
            "Damganın imzaladığı içerik bu dosyanın içeriği değil. Damga "
            "kendi içinde sağlam olabilir ama bu dosya hakkında hiçbir şey "
            "söylemiyor."
        ),
        oneri=_ONERI_KANIT,
    ),
    "merkle_path": Aciklama(
        seviye=SEVIYE_GECERSIZ,
        baslik="Damga bu dosyayı kapsamıyor",
        ozet=(
            "Bu dosya, tek seferde birçok dosyayı birlikte damgalayan bir "
            "kaydın parçası. Dosyayı o kayda bağlayan bağlantı kopuk — "
            "dosya ya kaydın içinde değil ya da bağlantı değiştirilmiş."
        ),
        oneri=_ONERI_KANIT,
    ),
    # ── Geçersiz: damganın içi kurcalanmış ────────────────────────────────
    "signature": Aciklama(
        seviye=SEVIYE_GECERSIZ,
        baslik="Damganın imzası tutmuyor",
        ozet=(
            "Damgayı atan kurumun imzası doğrulanamadı. Damga ya da "
            "sertifikası atıldıktan sonra değiştirilmiş."
        ),
        oneri=_ONERI_KANIT,
    ),
    "message_digest": Aciklama(
        seviye=SEVIYE_GECERSIZ,
        baslik="Damganın içeriği değiştirilmiş",
        ozet=(
            "Damganın imzaladığı bilgi ile damganın taşıdığı bilgi "
            "uyuşmuyor — damganın içi sonradan kurcalanmış."
        ),
        oneri=_ONERI_KANIT,
    ),
    "content_type": Aciklama(
        seviye=SEVIYE_GECERSIZ,
        baslik="Damga beklenen türde bir kayıt taşımıyor",
        ozet=(
            "Damganın içindeki kayıt bir zaman damgası kaydı değil. Damga "
            "geçerli sayılamaz."
        ),
        oneri=_ONERI_KANIT,
    ),
    "signed_attrs": Aciklama(
        seviye=SEVIYE_GECERSIZ,
        baslik="Damga eksik bilgi taşıyor",
        ozet=(
            "Damganın imzalanmış olması gereken bilgileri eksik. Bu hâliyle "
            "neyin imzalandığı belirlenemiyor."
        ),
        oneri=_ONERI_KANIT,
    ),
    "signer_info": Aciklama(
        seviye=SEVIYE_GECERSIZ,
        baslik="Damga beklenen yapıda değil",
        ozet=(
            "Bir zaman damgasında tam olarak bir imza bulunmalı; bu damgada "
            "farklı sayıda imza var."
        ),
        oneri=_ONERI_KANIT,
    ),
    # ── Geçersiz: sertifika tarafı ────────────────────────────────────────
    "signer_certificate": Aciklama(
        seviye=SEVIYE_GECERSIZ,
        baslik="Damgayı atan kurumun kimlik belgesi damgada yok",
        ozet=(
            "Damgayı imzalayan kurumun kimlik belgesi dosyanın içinde "
            "taşınmıyor. HYCLEUS damgayı internete çıkmadan doğruluyor, bu "
            "yüzden belgenin damgayla birlikte gelmesi gerekiyor."
        ),
        oneri=_ONERI_TSA,
    ),
    "eku": Aciklama(
        seviye=SEVIYE_GECERSIZ,
        baslik="Kimlik belgesi zaman damgası atmaya yetkili değil",
        ozet=(
            "Damgayı imzalayan kimlik belgesi, zaman damgası atma yetkisi "
            "taşımıyor. Yetkisiz bir belgeyle atılan damga kanıt değeri "
            "taşımaz."
        ),
        oneri=_ONERI_TSA,
    ),
    "validity": Aciklama(
        seviye=SEVIYE_GECERSIZ,
        baslik="Kimlik belgesi damga tarihinde geçerli değildi",
        ozet=(
            "Damganın atıldığı anda, imzalayan kurumun kimlik belgesi ya "
            "henüz yürürlükte değildi ya da süresi dolmuştu."
        ),
        oneri=_ONERI_TSA,
    ),
    "certificate_chain": Aciklama(
        seviye=SEVIYE_GECERSIZ,
        baslik="Kimlik belgeleri zinciri kopuk",
        ozet=(
            "Damgayı imzalayan belgeyi onaylaması gereken üst belgeler "
            "birbirini tutmuyor. Zincir tamamlanmadan damganın kime ait "
            "olduğu söylenemez."
        ),
        oneri=_ONERI_TSA,
    ),
    "trust_anchor": Aciklama(
        seviye=SEVIYE_GECERSIZ,
        baslik="Damga, güvendiğiniz kurumlardan birine çıkmıyor",
        ozet=(
            "Damga kendi içinde tutarlı, ama zinciri sizin güvenilir "
            "listenizdeki hiçbir kuruma ulaşmıyor. Tanımadığınız bir kurumun "
            "attığı damga, tarihi kendi belirlediği bir damgadır."
        ),
        oneri=_ONERI_TSA,
    ),
}


#: Tanınmayan bir `failed_check` geldiğinde gösterilen mesaj.
#:
#: Denetim testi bunun ERİŞİLEMEZ olmasını sağlıyor. Yine de var, çünkü
#: bir arayüzün boş kutu göstermesi ya da çökmesi, "bilmiyorum" demesinden
#: kötüdür — ve denetim testi ancak `timestamp_verify.py` içindeki
#: değerleri görebilir, dışarıdan gelen bir sonuç nesnesini değil.
BILINMEYEN = Aciklama(
    seviye=SEVIYE_OKUNAMADI,
    baslik="Damga doğrulanamadı",
    ozet=(
        "Doğrulama tamamlanamadı ve nedeni bu sürüm tarafından "
        "tanınmıyor. Damganın geçerli olduğu da geçersiz olduğu da "
        "söylenemez."
    ),
    oneri=(
        "Bu beklenen bir durum değil. Aşağıdaki teknik ayrıntıları "
        "kopyalayıp yöneticinize iletin."
    ),
)


#: Tam geçerli: imza tutuyor VE zincirin kökü kurumun güvenilir kök
#: listesinde bulundu (`CORE/trusted_roots.py`).
_GECERLI_GUVENILIR = Aciklama(
    seviye=SEVIYE_GECERLI,
    baslik="Damga geçerli ve damgayı atan kurum doğrulandı",
    ozet=(
        "Bu dosyanın parmak izi, aşağıda yazan tarihte bir zaman damgası "
        "kurumu tarafından imzalanmış. İmza internete çıkılmadan "
        "doğrulandı ve kurumun kimliği, DOSYADAN BAĞIMSIZ olarak tutulan "
        "güvenilir kurum listenizle karşılaştırıldı."
    ),
    oneri=None,
)

#: Kriptografik olarak geçerli ama güven kökü dosyanın kendisinden geldi.
#: Başlık `_GECERLI_GUVENILIR`'den AYRI ve seviyesi UYARI — gerekçe
#: `SEVIYE_UYARI`'nin yanında.
_GECERLI_KOK_DOGRULANMADI = Aciklama(
    seviye=SEVIYE_UYARI,
    baslik="Damga geçerli — ama damgayı atan kurum doğrulanmadı",
    ozet=(
        "Bu dosyanın parmak izi, aşağıda yazan tarihte imzalanmış ve imza "
        "matematiksel olarak tutuyor. Ancak imzalayan kurumun kimlik "
        "belgesi, doğrulanan dosyanın KENDİ İÇİNDEN geldi — yani bu ekran "
        "dosyanın kendi iddiasını kontrol etti, o iddianın doğru olduğunu "
        "değil."
    ),
    oneri=(
        "Kurumsal kullanımda yöneticiniz, kurumunuzun zaman damgası kökünü "
        "Yönetim Paneli → Ayarlar bölümünden bir kez ekler; sonraki her "
        "doğrulama onu kullanır."
    ),
)


# ── Genel arayüz ──────────────────────────────────────────────────────────────


def aciklama(sonuc: TimestampVerification) -> Aciklama:
    """Doğrulama sonucunun tek cümlelik insan dilindeki karşılığı.

    Sonucun BAŞLIK kararı burada veriliyor; eşlik eden uyarılar
    `notlar()`'da. İkisi ayrı, çünkü "geçerli ama kökü doğrulanmadı"
    tek bir başlığa sığmıyor ve sığdırmaya çalışmak ikisinden birini
    gizlerdi.
    """
    if sonuc.valid:
        # İKİ AYRI başlık. `anchor_trusted` bir ayrıntı değil, sonucun ne
        # kadarına güvenilebileceğini belirleyen alan — SECURITY.md §4.9.
        return (_GECERLI_GUVENILIR if sonuc.anchor_trusted
                else _GECERLI_KOK_DOGRULANMADI)
    if not sonuc.failed_check:
        return BILINMEYEN
    return _ADIM.get(sonuc.failed_check, BILINMEYEN)


def notlar(sonuc: TimestampVerification) -> list[Aciklama]:
    """Geçerli bir sonuca eşlik eden uyarı ve sınır notları.

    Geçersiz sonuçta boş: orada anlatılacak şey zaten `aciklama()`'da ve
    bir hata mesajının yanına "ayrıca şunu da bilin" eklemek asıl mesajı
    zayıflatırdı.

    Sıra önemli — güven uyarısı önce geliyor, çünkü ikisinden davranışı
    değiştirmesi muhtemel olan o.
    """
    if not sonuc.valid:
        return []

    cikti: list[Aciklama] = []

    if sonuc.anchor_trusted:
        cikti.append(Aciklama(
            seviye=SEVIYE_BILGI,
            baslik="Damgayı atan kurum doğrulandı",
            ozet=(
                "Zincirin ucundaki kurum, dosyadan bağımsız olarak tutulan "
                "güvenilir kurum listenizde bulundu."
            ),
        ))
    else:
        # Bu uyarı, güvenilir kök verilmediğinde HER geçerli sonuçta
        # görünür. "GEÇERLİ" demenin ne anlama GELMEDİĞİNİ söylemek, ne
        # anlama geldiğini söylemek kadar önemli — CLI'daki aynı gerekçe.
        cikti.append(Aciklama(
            seviye=SEVIYE_UYARI,
            baslik="Damgayı atan kurum doğrulanmadı",
            ozet=(
                "Kurumun kimlik belgesi, doğrulanan dosyanın KENDİ İÇİNDEN "
                "geldi. Dosyayı değiştirebilen biri, kendi uydurduğu bir "
                "kurumla kendi yazdığı tarihi taşıyan tutarlı bir damga "
                "üretebilir ve bu ekran ona da 'geçerli' der."
            ),
            oneri=(
                "Gerçek bir güven kararı için damga, dosyadan bağımsız bir "
                "güvenilir kurum listesiyle karşılaştırılmalı. Bu listeye "
                "Yönetim Paneli → Ayarlar bölümünden kök eklenir; komut "
                "satırındaki doğrulayıcı aynı işi --trusted-root seçeneğiyle "
                "yapıyor."
            ),
        ))

    cikti.append(Aciklama(
        seviye=SEVIYE_BILGI,
        baslik="Bu kontrol neyi kapsıyor",
        ozet=(
            "Doğrulanan şey damganın kendisi: parmak izinin gerçekten "
            "imzalandığı. Dosyanın İÇERİĞİNİN bu parmak iziyle eşleştiği "
            "burada kontrol edilmiyor — o kontrol anahtar gerektiriyor ve "
            "dosyayı her açtığınızda ya da indirdiğinizde otomatik "
            "yapılıyor. İkisi birlikte zinciri tamamlıyor."
        ),
    ))
    return cikti


def zaman_metni(an: datetime | None) -> str:
    """Damga zamanının okunur biçimi.

    UTC olarak gösteriliyor, yerel saate ÇEVRİLMİYOR: damganın hukuki
    değeri belirli bir evrensel ana bağlı ve yerel saate çevirmek, yaz
    saati ya da makinenin yanlış saat dilimi yüzünden kaydedilenden farklı
    bir tarih göstermeye açık olurdu. Tam ISO biçimi ayrıntılarda duruyor.
    """
    if an is None:
        return "—"
    return an.strftime("%d.%m.%Y %H:%M:%S UTC")


def detaylar(sonuc: TimestampVerification) -> list[tuple[str, str]]:
    """Teknik ayrıntılar — `(etiket, değer)` çiftleri.

    Ana mesajdan AYRI tutuluyor: seri numarası ve politika kodu bir
    kullanıcının kararını değiştirmiyor, ama bir yöneticiye ya da
    denetçiye iletildiğinde tam olarak bunlar gerekiyor. Boş alanlar
    listeye hiç girmiyor — "Politika: None" satırı bilgi değil gürültü.
    """
    alanlar: list[tuple[str, str | None]] = [
        ("Damga zamanı", sonuc.gen_time.isoformat() if sonuc.gen_time else None),
        ("Damgayı atan", sonuc.tsa_name),
        ("Adres", sonuc.tsa_url),
        ("Seri numarası", str(sonuc.serial_number) if sonuc.serial_number else None),
        ("Politika", sonuc.policy),
        ("Damgalanan parmak izi", sonuc.hashed_hex),
        ("Zincirin kökü", sonuc.anchor_subject),
        ("Sertifika zinciri", " → ".join(sonuc.chain_subjects) or None),
        ("Geçen kontroller", ", ".join(sonuc.checks) or None),
        ("Düşen kontrol", sonuc.failed_check),
        ("Teknik neden", sonuc.reason),
    ]
    return [(ad, deger) for ad, deger in alanlar if deger]


__all__ = [
    "Aciklama",
    "BILINMEYEN",
    "SEVIYE_BILGI",
    "SEVIYE_DAMGASIZ",
    "SEVIYE_GECERLI",
    "SEVIYE_GECERSIZ",
    "SEVIYE_OKUNAMADI",
    "SEVIYE_UYARI",
    "aciklama",
    "detaylar",
    "notlar",
    "zaman_metni",
]
