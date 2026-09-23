# HYCLEUS — Ne Yapmalıyım?

**Bir şeyler ters gittiğinde bu sayfayı açın.**

Bu rehber teknik bilgi varsaymıyor. Komut yazmanız gereken yerlerde
komutun tamamı hazır veriliyor — kopyalayıp yapıştırmanız yeterli.

Bu sayfaya üç yerden ulaşabilirsiniz: uygulamada sağ üstteki **☰** menüsünden
**📘 Kullanım Rehberi**, `docs/kullanici-rehberi.pdf` dosyasından, ya da size
gönderilen bir teslim paketinin (`.hclx`) içinden. Üçü de aynı metindir.

---

## ⛔ Her şeyden önce: asla yapmayacağınız tek şey

Aşağıdaki komutu **hiçbir koşulda** çalıştırmayın:

```
python CORE/setup_usb.py --role ... --reset
```

**Neden:** Bu komut sıfırdan yeni bir şifre anahtarı üretir. Eski anahtar
yok olur. Kasadaki bütün dosyalarınız **kalıcı olarak** açılamaz hâle
gelir — hiçbir uzman, hiçbir yazılım, hiçbir yedek onları geri getiremez.
Elinizdeki **basılı kurtarma kâğıdı da geçersizleşir.**

Program bunu bildiği için sizi durdurmaya çalışır:

```
  Veri kaybini kabul ediyorsaniz "SIFIRLA" yazin: _
```

**Bu satırı gördüyseniz pencereyi kapatın.** `SIFIRLA` yazmayın. Bu soru,
geri dönüşü olmayan bir işlemin son uyarısıdır.

`--reset` yalnızca **tamamen boş, içinde hiç dosyanız olmayan** bir
kurulumu baştan kurmak içindir. Kaybettiğiniz bir şeyi geri getirmek için
**değildir.**

---

## Başlamadan: komut penceresini açmak

Aşağıdaki bazı çözümler komut satırı gerektiriyor. Kurtarma aracı
paketin İÇİNDE, `HYCLEUS.exe` ile AYNI klasörde duran ayrı bir dosya:
**`HYCLEUS-Kurtarma.exe`**.

**1.** HYCLEUS'un kurulu olduğu klasörü bulun. İçinde `HYCLEUS.exe` VE
`HYCLEUS-Kurtarma.exe` adında iki dosya görüyorsanız doğru yerdesiniz.

**2.** Klasörün adres çubuğuna tıklayın, yazanı silin, `cmd` yazıp
Enter'a basın:

```
+------------------------------------------------------+
|  [klasör]  cmd                              v    X   |   <-- buraya cmd yazıp Enter
+------------------------------------------------------+
|   HYCLEUS.exe     HYCLEUS-Kurtarma.exe    data\       |
+------------------------------------------------------+
```

**3.** Siyah bir pencere açılır. Bu rehberdeki komutları buraya
yapıştırıp (sağ tık → Yapıştır) Enter'a basın — komutlar
`HYCLEUS-Kurtarma.exe` ile BAŞLIYOR, `HYCLEUS.exe` DEĞİL:
`HYCLEUS.exe` çift tıklayınca AÇILAN pencereli programdır, komut
girdisini okuyamaz — bu yüzden kurtarma aracı AYRI, ikinci bir dosya.

> **Linux'ta** (`.AppImage`): ikinci bir dosya YOK, aynı `.AppImage`'ı
> bir terminalden, başına `./` koyarak çalıştırın — ör.
> `./HYCLEUS-2.4.0-x86_64.AppImage --recover`.

> **Kaynak koddan çalıştırıyorsanız** (geliştirici/BT ortamı):
> `python CORE/recover_vault.py --recover` de hâlâ aynı şekilde
> çalışıyor — bu rehberdeki `HYCLEUS-Kurtarma.exe` yerine onu
> kullanabilirsiniz, ikisi AYNI aracı çalıştırıyor.

---

## 1. USB'mi kaybettim

### ⛔ Önce: yapmayacaklarınız

1. **`--reset` çalıştırmayın.** Yeni bir USB tanıtmanın tek yolu gibi
   görünür — ama bütün dosyalarınızı silmekle aynı şeydir.
2. **Yeni bir USB takıp kurulumu tekrarlamayın.** Program yeni USB'yi
   tanımaz; tanıtmaya çalışmak sizi 1. maddeye götürür.
3. **Panikle bir şeyler denemeyin.** Dosyalarınız şu anda **kayıp
   değil.** Diskte duruyorlar.

### Durumunuzu ayırt edin

**A) USB elinizde, ama başka bir şey bozuldu** — bilgisayar değişti,
Windows yeniden kuruldu, program dosyaları silindi:

Bu **çözülebilir bir durum.** Aşağıdaki **"2. PIN'imi unuttum"** ya da
**"4. Dosyalarım bozuk görünüyor"** bölümüne geçin — kurtarma aracı tam
olarak bu durumlar için yazıldı.

**B) USB fiziksel olarak kayboldu** — çalındı, kırıldı, bulunamıyor:

`--recover` size YARDIMCI OLAMAZ — o, **kayıtlı** (kaybettiğiniz) USB'nin
takılı olmasını istiyor, program kimliğinizi o USB'den okuyor. USB
olmadan şunu yazar:

```
Hata: USB tespit edilemedi.
  --recover icin share_2 anahtar kasasindan okunur; kasa kaydi
  HWID'e bagli oldugu icin kayitli USB takili olmalidir.
```

**Ama çaresiz değilsiniz.** Elinizde YENİ bir USB (herhangi biri, boş)
**ve basılı kurtarma kâğıdınız** varsa hesabınızı o yeni USB'ye
taşıyabilirsiniz — tam olarak bunun için ayrı bir komut var:

```
HYCLEUS-Kurtarma.exe --takeover
```

Kullanıcı adınızı, kurtarma kâğıdınızı ve yeni bir PIN isteyecek.
**Bu işlem GERİ ALINAMAZ:** eski USB (bulunsa/onarılsa bile) işlemden
sonra bir daha açılamaz — araç son bir onayla bunu size hatırlatıyor.

**Kurtarma kâğıdınız da yoksa** — yalnızca bu durumda gerçekten
çaresizsiniz:

1. Hiçbir komut çalıştırmayın.
2. Bilgisayarı olduğu gibi bırakın. HYCLEUS klasörünü ve içindeki `data`
   klasörünü **silmeyin, taşımayın, temizlemeyin.**
3. **Sistem yöneticinize durumu bildirin.**

> **Neden umut var:** Şifre anahtarınız üç parçaya bölünmüş ve herhangi
> **ikisi** yeterli. USB kaybolsa bile bilgisayardaki parça ve basılı
> kâğıt duruyor — `--takeover` tam olarak bu ikisini birleştirip
> hesabınızı yeni USB'ye bağlıyor. Kâğıt da yoksa geriye tek bir parça
> kalıyor, ki bu ikiden az demek — o zaman gerçekten yönetici
> müdahalesi gerekiyor.

---

## 2. PIN'imi unuttum

### ⛔ Önce: yapmayacaklarınız

1. **`--reset` çalıştırmayın.** PIN'i sıfırlamaz; dosyalarınızı siler.
2. **Tahmin etmeye devam etmeyin.** 5 yanlış denemeden sonra program
   kilitlenir ve süre her seferinde uzar: **30 saniye → 1 dakika →
   2 dakika → 5 dakika.** Beklemekle çözülmez.
3. **Programı silip yeniden kurmayın.** PIN programda değil, kasa
   dosyanızda saklı.

### ✅ Çözüm: kurtarma kâğıdıyla yeni PIN belirleyin

**Gerekenler:** kayıtlı USB (takılı olacak) + **basılı kurtarma kâğıdı**
(`HYCLEUS-R3-` ile başlayan uzun yazı).

**Adım 1.** USB'yi takın.

**Adım 2.** Komut penceresini açın ve şunu yapıştırın:

```
HYCLEUS-Kurtarma.exe --recover
```

**Adım 3.** Kurtarma kâğıdındaki yazıyı isteyecek. **Yazarken ekranda
hiçbir şey görünmez** — bu normaldir, güvenlik içindir. Boşluk ve
büyük/küçük harf farkı önemli değil.

```
Kurtarma parcasini girin (HYCLEUS-R3-... ile baslar).
Bosluk / satir sonu / kucuk harf farketmez.

  Kurtarma parcasi: _
```

**Adım 4.** Şu soru gelecek. **`2` yazın:**

```
Kalan pay hangisi?
  1) Vault dosyam duruyor, PIN'imi biliyorum  (share_2 kayip)
  2) Vault dosyam yok/bozuk                   (share_1 kayip)
  Secim [1/2]: 2         <-- PIN'i bilmediğiniz için 2
```

> **Neden 2?** Seçenek 1 sizden PIN ister — zaten onu unuttunuz.
> Seçenek 2, PIN yerine bilgisayarınızda saklı olan parçayı kullanır.
> Parantez içindeki açıklama teknik; sizin için anlamı
> **"PIN'siz devam et"**.

**Adım 5.** Anahtar kurtarıldığında şunu göreceksiniz:

```
====================================================================
MASTER KEY KURTARILDI
====================================================================

SIMDI VAULT'U YENIDEN KURABILIRIZ.

  · master_key KORUNUR   -> mevcut .hcl dosyalariniz acilmaya devam eder
  · polinom KORUNUR      -> elinizdeki BASILI KURTARMA PARCASI gecerli kalir
  · yeni PIN belirlenir ve share_2 bu cihazin kasasina yazilir

  Vault yeniden kurulsun mu? [e/H] e     <-- "e" yazıp Enter
```

**Adım 6.** Rol sorulacak; bilmiyorsanız doğrudan Enter'a basın. Sonra
**yeni PIN'inizi** iki kez yazın. **En az 6 hane olmalı.**

**Bitti.** Eski dosyalarınızın hepsi açılır. Basılı kâğıdınız hâlâ
geçerlidir — **atmayın.**

### Kurtarma kâğıdınız da yoksa

PIN de yok, kâğıt da yoksa **geri dönüş yolu yoktur.** Bu bir eksiklik
değil, tasarımın gereği: üç parçadan en az ikisi olmadan hiç kimse —
siz dahil — dosyaları açamaz. Yöneticinize bildirin.

---

## 3. Basılı kurtarma kâğıdımı kaybettim

### ⛔ Önce: yapmayacaklarınız

1. **`--reset` çalıştırmayın.** Kâğıdı geri getirmez; her şeyi siler.
2. **Acele etmeyin.** Kâğıdı kaybetmek erişiminizi kaybetmek **değildir**
   — normal şekilde giriş yapmaya devam edebilirsiniz.
3. **Yeni kâğıdı bilgisayarda saklamayın.** Fotoğrafını çekmek, parola
   yöneticisine yazmak veya buluta koymak korumayı etkisiz kılar.

### ✅ Çözüm: yenisini yazdırın

Kurtarma kâğıdı rastgele üretilmez; aynı değer her zaman yeniden
hesaplanabilir. Yani kaybettiğiniz kâğıdın **aynısını** tekrar
alabilirsiniz.

**Gerekenler:** kayıtlı USB + PIN'iniz.

**Adım 1.** Durumu kontrol edin:

```
HYCLEUS-Kurtarma.exe --status
```

**Adım 2.** Kâğıdı yeniden alın (PIN'inizi soracak):

```
HYCLEUS-Kurtarma.exe --export
```

**Adım 3.** Ekranda uzun bir yazı çıkacak (`HYCLEUS-R3-...` ile başlar).
**Bu bir daha gösterilmeyecek.** Hemen yazdırın veya dikkatlice elle
kopyalayın.

**Adım 4.** Kâğıdı **bilgisayarın olmadığı bir yerde** saklayın: kasa,
çelik dolap, başka bir bina. Bilgisayarın yanındaki çekmece korumayı
ortadan kaldırır.

> **Kaybolan kâğıdı bulan biri ne yapabilir?** Tek başına hiçbir şey —
> üç parçadan yalnızca biri o. Ama bilgisayarınıza da erişebilen biri
> için yeterlidir. Kâğıdın **kötü niyetli birinin eline geçmiş
> olabileceğinden şüpheleniyorsanız** yeni kâğıt yazdırmak yetmez:
> yöneticinize bildirin, anahtarın tümüyle yenilenmesi gerekir.

---

## 4. Dosyalarım bozuk görünüyor

HYCLEUS **haftada bir**, siz hiçbir şey yapmadan bütün dosyaları
kendiliğinden kontrol eder.

### ⛔ Önce: yapmayacaklarınız

1. **`--reset` çalıştırmayın.** Bozuk dosyayı onarmaz; sağlam olanları da
   açılamaz hâle getirir.
2. **Hemen yedekten geri yükleme yapmayın.** Önce sonucu okuyun —
   aşağıdaki bir durumda dosyalarınız aslında **sağlamdır** ve geri
   yükleme gereksiz yere eski bir sürüme dönmenize yol açar.
3. **Bozuk görünen dosyayı silmeyin.**

### ✅ Adım 1: sonucu okuyun

1. HYCLEUS'u açın.
2. Sağ üstteki menü düğmesine tıklayın.
3. **📋 Denetim Günlüğü**'nü seçin.
4. Açılan pencerede **İşlem** kutusundan `integrity_` ile başlayan
   kayıtları seçin.

```
+- HYCLEUS — Denetim Günlüğü ----------------------------+
|  İşlem: [ integrity_check_failed            v ]        |
+--------------------------------------------------------+
|  20.08.2026 03:14   integrity_sweep_finished           |
|  20.08.2026 03:14   integrity_check_failed   rapor.pdf |
+--------------------------------------------------------+
```

### Ne yazdığı ne demek

| Ekranda gördüğünüz | Sade anlamı | Ne yapmalı |
|---|---|---|
| `ok` | Dosya sağlam. | Bir şey yapmayın. |
| `missing` | Kayıt var ama dosya diskte yok — silinmiş ya da taşınmış. | Yedekten geri alın. |
| `unreadable` | Dosya duruyor, okunamıyor. Başka bir program açık tutuyor olabilir. | Bilgisayarı yeniden başlatıp tekrar bakın. |
| `malformed` | Dosyanın başı bozulmuş ya da dosya yarım kalmış. | Yedekten geri alın. |
| `tag_mismatch` | İçerik, kaydedildiği andakinden farklı. | Yedekten geri alın. |
| `hwid_mismatch` | Dosya **başka bir cihazda** şifrelenmiş. **Bozuk değil.** | Yöneticinize sorun. |

### ⚠️ Adım 2: bu satırı gördüyseniz durun

```
TÜM DOSYALAR TAG HATASI VERDİ — anahtar yanlış olabilir,
hiçbir kayıt bozuk olarak işaretlenmedi
```

**Bütün** dosyalar aynı anda bozulmaz. Bu mesaj neredeyse her zaman şu
anlama gelir: **dosyalar sağlam, yanlış anahtarla açılmaya çalışılıyor**
— çoğunlukla yanlış USB takılıdır.

- **Yapın:** Doğru USB'yi takın, programı kapatıp açın, tekrar bakın.
- **Yapmayın:** Geri yükleme. Sağlam dosyaların üzerine eski sürüm
  yazarsınız.

### ✅ Adım 3: yedeğinizin sağlam olduğunu doğrulayın

Geri yüklemeden **önce** yedeğin kendisi kontrol edilmeli.

1. HYCLEUS'ta menü → **🔍 Yedek Doğrula…**
2. Yedek klasörünü seçin.
3. Kontrol bitince sonucu okuyun:

```
+--------------------------------------------------------+
|  ✔  Yedek sağlam                                       |
|     D:\Yedekler\hycleus-2026-08-20                     |
|                                                        |
|  Bakılan dosya          142 / 142                      |
|  Kontrol derinliği      Bütünlük mührü dahil (tam)     |
+--------------------------------------------------------+
```

- **✔ Yedek sağlam** → geri yükleyebilirsiniz.
- **✖ Yedekte sorun var** → hangi dosyaların bozuk olduğu listelenir.
  **Bu yedeği kullanmayın**, daha eski bir yedek deneyin.
- **⚠ Yedek okunamadı** → muhtemelen yanlış klasörü seçtiniz. Yedek
  klasörünün içinde `files` adında bir klasör olmalı.
- **⏸ Doğrulama tamamlanmadı** → siz iptal ettiniz. Baştan çalıştırın;
  yarım kalan kontrol hiçbir şey kanıtlamaz.

### ✅ Adım 4: geri yükleme

Geri yükleme bilerek komut satırında bırakıldı: genellikle **program
açılmıyorken** gerekir, menüye koymak tam gerektiği anda ulaşılamaz
olurdu.

**Önce boş bir klasör oluşturun** (örneğin `D:\Kurtarma`), sonra:

```
python CORE/backup_cli.py --restore "D:\Yedekler\hycleus-2026-08-20" --dest "D:\Kurtarma"
```

> **Bu komut güvenlidir:** çalışan kasanıza **dokunmaz.** Dosyaları
> seçtiğiniz boş klasöre çıkarır; içeriği inceleyip yerine siz
> taşırsınız. Yanlış yedeği seçseniz bile bir kaybınız olmaz.

> **Not:** yukarıdaki `HYCLEUS-Kurtarma.exe` komutlarının aksine bu
> komut henüz pakete taşınmadı — yalnızca kaynak/geliştirici ortamından
> (`python` kurulu bir makineden) çalışıyor. Elinizde yalnızca paket
> varsa (yalnızca `HYCLEUS.exe`/`HYCLEUS-Kurtarma.exe`) sistem
> yöneticinize başvurun.

---

## Küçük sözlük

| Terim | Ne demek |
|---|---|
| **Kasa / vault** | Şifre anahtarınızın saklandığı küçük dosya. Bilgisayarda durur, USB'de değil. |
| **HWID** | USB'nizin seri numarası. Program sizi bununla tanır. |
| **`.hcl` dosyası** | Şifrelenmiş belgeniz. Doğrudan açılamaz, yalnızca HYCLEUS açar. |
| **Kurtarma parçası** | Yazdırdığınız `HYCLEUS-R3-...` yazısı. Anahtarın üç parçasından biri. |
| **Bütünlük taraması** | Dosyaların bozulup bozulmadığını haftalık kontrol eden otomatik iş. |
| **Bütünlük mührü** | Dosyanın içine gömülü, en ufak değişikliği yakalayan işaret. |

---

## Hâlâ çözülmediyse

Yöneticinize giderken şunları hazırlayın:

1. **Ne yaptığınızı** — hangi adıma kadar geldiniz.
2. **Ekranda ne yazdığını** — komut penceresindeki yazıyı fareyle seçip
   Enter'a basarak kopyalayın, ya da fotoğrafını çekin.
3. **Yedek doğrulama sonucunu** — o pencerede **⧉ Kopyala** düğmesi
   tam raporu panoya alır.

Ve son bir kez: **`--reset` yazmayın.** Bu rehberdeki hiçbir sorunun
çözümü o değil.
