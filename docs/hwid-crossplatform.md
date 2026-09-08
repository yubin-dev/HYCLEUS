# Çapraz platform USB kimliği — bulgular ve mimari öneri

**Durum:** 3.4 prototip raporu · Kod: `CORE/hwid_probe.py` — **2026-09-08'den
itibaren `read_linux()`/`read_macos()` üretime BAĞLI** (`CORE/usb_manager.py::
get_usb_hwid()` üzerinden, B-112/B-114 — aşağıdaki "2026-09-08 — Doğrulama ve
düzeltme" bölümüne bakın). Bu belgenin geri kalanındaki "bağlı değil" ifadeleri
o TARİHTEKİ durumu anlatıyor; okuyucu her ifadeyi tarihiyle birlikte
değerlendirmeli.

> ⛔ **Bu belgedeki öneri UYGULANMADI ve uygulanmayacak — eksik bacak
> 2026-08-16'da ölçüldü ve öneriyi zayıflattı.** Gerçek HYCLEUS token USB'si
> takılı halde yapılan ölçümde **aygıtın serisi çıktı** ve temiz okundu; UUID
> fallback'ine hiç düşülmüyor. Aşağıdaki §"Sınır" bloğu ve sonuçlar bu bulguya
> göre okunmalı. Ayrıntı ve güncel karar: **BACKLOG.md / B-016**.

---

## Kısa yanıt

Soru: *aynı USB çubuğu Windows, Linux ve macOS'ta aynı kimliği verir mi?*

**Hayır — güvenilir biçimde vermiyor.** İki bağımsız sebep var ve ikincisi
daha ağır:

1. Üç platform **farklı yığınlardan** okuyor; aynı alanı okudukları garanti
   değil.
2. Dayandığımız alan (`iSerialNumber`) **USB spec'inde opsiyonel** ve
   pratikte çoğu zaman yok.

Ve altını çizmek gerekiyor: **taşınabilirlik bugün tek platformda bile
kırık.** Çapraz platform bunu ortaya çıkarıyor, yaratmıyor.

---

## Ölçüm — varsayım değil

Geliştirme makinesinde (Windows 11) `Win32_PnPEntity` ile listelenen USB
aygıtları:

```
USB\VID_046D&PID_C52B&MI_01\9&2F9A62E0&0&0001
USB\VID_05E3&PID_0608\6&26C36CB0&0&1
USB\VID_0C45&PID_7672\7&1441131D&0&3
USB\VID_048D&PID_5702\8&F2CB6FA&0&16
… (toplam 12 aygıt)
```

Üçüncü segment normalde aygıtın `iSerialNumber` dizesidir. Serisi olan bir
aygıtta şöyle görünür:

```
USB\VID_0781&PID_5567\4C53XXXXXXXXXXXXXXXX
```

(Bu biçimin gerçekten böyle olduğu 2026-08-16'da doğrulandı — aşağıdaki
sınır bloğuna bakın. Seri maskeli, çünkü HWID kasa imza anahtarının HKDF
girdisi.)

**On iki aygıtın on ikisinde de üretilmiş kimlik var, gerçek seri yok.**
Üretilen kimlik `<hex>&<hex>&<port>` biçiminde ve **hub/port yoluna
bağlı** — aygıt başka bir porta takıldığında değişiyor.

Ayrıca depolama yığını serilerinin biçimlendirildiği de ölçüldü. Bu
makinedeki NVMe diski:

```
Win32_DiskDrive.SerialNumber = '6479_A7FF_F000_0285.'
```

Alt çizgiler ve sondaki nokta Windows'un eklediği biçim; Linux aynı aygıt
için biçimlendirmesiz dize verir. Ham metin karşılaştırması bu yüzden tek
başına yetmiyor (prototipte `normalize_serial()` bunu kapatıyor).

> **Sınır — yukarıdaki sayım HYCLEUS'un kendi USB'sini ÖLÇMEMİŞTİ.** O
> sırada fiziksel bir HYCLEUS kimlik doğrulama USB'si takılı değildi;
> sayılan aygıtlar dahili donanımdı: klavye, fare, kamera, Bluetooth, hub.
>
> **2026-08-16 — eksik ölçüm yapıldı, sonuç bu belgenin sonucunu daraltıyor.**
> Kayıtlı token (SanDisk Cruzer Blade, `VID_0781`/`PID_5567`) takılı halde:
>
> | Okuma | Sonuç |
> |---|---|
> | USB yığını düğümü `USB\VID_0781&PID_5567\<instance>` | **tanımlayıcı serisi VAR** — `<instance>` içinde `&` yok |
> | `Win32_DiskDrive.SerialNumber` | **aynı dize** — bu aygıtta alan belirsizliği yok |
> | `usb_manager.get_usb_hwid()` | seriyi döndürüyor; `_sanitize_hwid()` hiçbir karakteri düşürmüyor |
> | `data/usb_ids.json` | **dosya yok** — UUID fallback'i hiç kullanılmamış |
> | Aynı çubuk **başka bir portta** | **HWID birebir aynı** — ölçüldü, çıkarım değil |
>
> Son satır bu belgenin "üretilen kimlik port yoluna bağlı" uyarısını
> geçersiz kılmıyor: o uyarı **serisiz** aygıtlar için geçerli ve geçerli
> kalıyor. Serisi olan aygıtta instance ID zaten serinin kendisi, içinde
> port bilgisi yok — taşınacak bir bağımlılık da yok.
>
> Aynı makinedeki 14 USB düğümünden yalnızca bu 1'inde seri var. Yani
> "opsiyonel alan, çoğu aygıtta yok" gözlemi **doğru ama yanlış popülasyon
> için**: dahili çevre birimleri serisiz, USB *depolama* aygıtı serili.
> "HYCLEUS'un fiilen kullandığı USB'de seri yok" iddiası ise **yanlış
> çıktı**.
>
> Serinin değeri burada yazılmıyor: `hwid`, `_derive_signing_key()` içinde
> HKDF girdisi ve kasa AAD'ı, yani gizli-bitişik. Biçimi
> `4C53` + 16 onaltılık hane.
>
> Ölçüm ayrıca prototipin kendisinde bir hata ortaya çıkardı — bu aygıta
> "seri yok" dedi (**B-022**). Prototipin çıktısına değil, yukarıdaki ham
> WMI okumalarına güvenin.

---

## Üç platform hangi alanı okuyor

| Platform | API | Yığın | Kaynak alan |
|---|---|---|---|
| Windows | `Win32_DiskDrive.SerialNumber` | **Depolama** (USBSTOR/SCSI) | Genelde `iSerialNumber`, ama aygıt SCSI VPD 0x80 sunuyorsa **o** |
| Linux | `pyudev` → `ID_SERIAL_SHORT` | USB *veya* SCSI | `usb_id` → `iSerialNumber`; `scsi_id` → VPD 0x80 (kurala bağlı) |
| Linux (sysfs) | `/sys/.../serial` | **USB** | Doğrudan `iSerialNumber` |
| macOS | IOKit `"USB Serial Number"` | **USB** | Doğrudan `iSerialNumber` |

**Windows'un depolama yığınından okuması işin can alıcı yeri.** Diğer ikisi
USB tanımlayıcısına doğrudan bakarken Windows araya bir soyutlama koyuyor.
Aygıtın SCSI köprüsü kendi seri numarasını sunuyorsa Windows onu tercih
edebiliyor — o durumda aynı çubuk Windows'ta bir, Linux/macOS'ta başka
kimlik veriyor.

Teorik ortak payda **`iSerialNumber`** (USB 2.0 spec §9.6.1) ve üç platform
da ona ulaşabiliyor. Ama:

- Windows'ta ona ulaşmak için `Win32_DiskDrive` **yetmiyor**; `PNPDeviceID`
  ayrıştırmak gerekiyor (prototipte yapıldı).
- Linux'ta `ID_SERIAL_SHORT` belirsiz; kesin olan sysfs yolu.
- macOS en net olanı.

---

## HYCLEUS'ta bugünkü durum

`CORE/usb_manager.py` akışı:

```
Win32_DiskDrive.SerialNumber
   → boş / "0" / temizlenince boş kalıyorsa
        → _get_or_create_uuid(raw)
             → data_dir()/usb_ids.json     ← MAKİNEYE ÖZEL
```

Sonuç tablosu:

| Senaryo | HWID |
|---|---|
| Serili USB, aynı makine | Kararlı |
| Serili USB, başka makine (aynı OS) | Kararlı |
| Serili USB, başka OS | **Muhtemelen farklı** (alan + biçim) |
| **Serisiz USB, aynı makine** | Kararlı (JSON'dan) |
| **Serisiz USB, başka makine** | **FARKLI** — JSON o makinede yok |

Son satır, çapraz platformdan bağımsız bir sorun. Ve HYCLEUS'un
mimarisinde bu doğrudan erişimi kesiyor: `share_2` anahtar kasasında
`share_2:<hwid>` adıyla duruyor, vault dosyası `vaults/<hwid>.hclv`.
HWID değişirse kullanıcı **kendi kasasına giremiyor** — kurtarma parçası
(2.1) gerekiyor.

---

## Öneri: dosya tabanlı token'a geçiş

Donanım serisine dayanmayı bırakıp **USB'ye yazılan bir token dosyasına**
geçmek gerekiyor. Gerekçeler:

**1. Sorunu kaynağında çözüyor.** Token'ı biz üretiyoruz; opsiyonel bir
donanım alanının varlığına bağlı değil. Üç platformda da bir dosya
okumak aynı şey.

**2. Zaten yarı yarıya oradayız.** `usb_ids.json` fallback'i tam olarak
"seri güvenilmezse kendi kimliğimizi üret" diyor — yalnızca yanlış yere,
**makineye** yazıyor. Token'ı **USB'ye** yazmak aynı fikrin doğru hâli.

**3. Mevcut kripto mimarisine oturuyor.** Vault zaten USB'de duruyor
(`vaults/<hwid>.hclv`). Token'ı onun yanına koymak yeni bir güven varsayımı
eklemiyor.

### Ne DEĞİŞTİRMİYOR — dürüst olmak gerekirse

Donanım serisi bir **güvenlik** kontrolü değildi zaten; SECURITY.md §4.5 ve
§1'de yazılı: HWID kontrolü uygulama seviyesinde ve diski okuyabilen bir
saldırganı durdurmuyor. Seri numarası da kopyalanabilir bir dizeydi.

Dosya tabanlı token bunu **daha kötü yapmıyor** ama **daha iyi de
yapmıyor**: token dosyası da kopyalanabilir. Kazanç güvenlikte değil,
**taşınabilirlik ve öngörülebilirlikte**. Bu, geçişin gerekçesi olarak
yazılmalı — "daha güvenli" denirse yanlış olur.

Gerçek bir güçlendirme isteniyorsa yol donanım anahtarı (FIDO2/PIV,
challenge-response) — o ayrı ve çok daha büyük bir iş.

### Taslak geçiş yolu (uygulanmadı)

1. USB kökünde `.hycleus-token` — içinde rastgele 32 bayt kimlik + biçim
   sürümü. `CORE/audit_chain.py`'deki çıpa dosyasıyla aynı desen.
2. `get_usb_hwid()` önce token dosyasına baksın; yoksa **mevcut** seri
   yoluna düşsün (geriye uyumluluk).
3. Token yoksa ve seri okunabiliyorsa: token'ı yaz ve **mevcut HWID'yi
   içine göm** — böylece hâlihazırdaki kasalar açılmaya devam eder. Bu,
   göçün kritik adımı; atlanırsa tüm kullanıcılar kurtarma parçasına
   muhtaç kalır.
4. Token doğrulaması: dosyanın varlığı yetmemeli, içeriği `usb_tokens`
   tablosundaki kayıtla eşleşmeli.
5. Kaybolma senaryosu: token silinirse kurtarma parçası (2.1) yolu zaten
   var.

---

## Prototipin sınırları

**Gerçek donanımda çalıştırılmadı.** CI'da fiziksel USB yok, elimde Linux
ve macOS test cihazı da yok.

| Bölüm | Durum |
|---|---|
| Windows `PNPDeviceID` ayrıştırması | **Gerçek veriyle** doğrulandı (bu makine) |
| Windows `Win32_DiskDrive` USB yolu | Doğrulanamadı — makinede USB disk yok |
| Linux `pyudev` / sysfs | **Doğrulanmadı** — kod belgelenmiş alan adlarına göre yazıldı |
| macOS `ioreg` | **Doğrulanmadı** — ayrıştırıcı kaydedilmiş örnek çıktı üzerinde test edildi |
| Normalleştirme ve karşılaştırma | Testli (27 test) |

Testler ayrıştırma mantığını kapsıyor; araçların gerçekten bu biçimde çıktı
verdiğini **kapsamıyor**. "Testler geçiyor" ile "üç platformda çalışıyor"
bu modülde aynı şey değil.

### Sonraki adım için gereken

Kararı sağlamlaştırmak için tek bir ölçüm yeterli: **aynı USB çubuğu** üç
işletim sisteminde de takılıp `python -m CORE.hwid_probe` çalıştırılmalı ve
çıktılar karşılaştırılmalı. Bu, bir hafta sonu prototipinin ötesinde bir iş
değil ama fiziksel erişim gerektiriyor.

Önerinin kendisi o ölçüme **bağlı değil**: serisiz aygıtların makineler
arasında farklı HWID alması tek başına yeterli gerekçe ve o zaten ölçüldü.

---

## 2026-08-29 — yeniden doğrulama denendi, sonuç: fiziksel erişim hâlâ yok; onun yerine karşılaştırma bir araca dönüştürüldü

Görev "hwid_probe.py'nin sonucunu doğrula: üç platformda (veya elindeki
platformlarda) test et" idi. Dürüst sonuç: **bu oturumun ortamında elde
hiçbir platform yok** — takılı bir USB depolama aygıtı bulunmuyor
(`python -m CORE.hwid_probe` bugün burada çalıştırıldı, çıktı: `USB
depolama aygıtı bulunamadı.`) ve bu ortamdan yalnızca Windows'a
erişilebiliyor, Linux ya da macOS makinesi yok. Yani yukarıdaki "Sonraki
adım için gereken" bölümünün beklediği ölçüm — aynı çubuğun Linux'ta
`ID_SERIAL_SHORT` ile okunması — bugün de alınamadı. Bu, B-016'nın
Windows tarafında gerçek donanımla (2026-08-16, 2026-08-19) vardığı
sonucu ZAYIFLATMIYOR; yalnızca bu turun onu TEKRARLAYAMADIĞINI söylüyor.

Elde donanım olmadan yapılabilecek gerçek iş şuydu: yukarıdaki adımı
"aynı çubuğu üç OS'a takıp elle karşılaştır"dan çıkarıp **çalıştırılabilir
bir araca** çevirmek. `CORE/hwid_probe.py`'ye eklendi:

- `python -m CORE.hwid_probe --json > <platform>.json` — bu platformun
  okumasını (ham alanlar, `stable_id` HARİÇ — o türetilmiş, her yüklemede
  yeniden hesaplanıyor) dosyaya yazar.
- `python -m CORE.hwid_probe --compare A.json B.json` — iki dosyayı
  karşılaştırır, `CORE/backup_cli.py` ile aynı çıkış kodu deseniyle döner
  (0 eşleşti, 1 eşleşmedi, 2 kullanım hatası) — bir CI adımı ya da betik
  bunu okuyabilir.

`tests/test_hwid_probe.py`'ye bu iki bayrağı ve altındaki serileştirme
mantığını (`to_dict`/`from_dict`/`dump_json`/`load_json`/`compare_all`)
sınayan 15 yeni test eklendi (§7). Bunların hiçbiri donanım gerektirmiyor
— sınanan JSON round-trip'i ve karşılaştırma/çıkış-kodu mantığı, aşağıdaki
tablonun zaten söylediği sınırın DIŞINDA kalan bir katman. `--compare`'in
çıkış kodu canlı bir mutasyonla doğrulandı: satır geçici olarak her zaman
`0` dönecek şekilde bozuldu, `test_cli_compare_ESLESMEZSE_cikis_kodu_1`
beklendiği gibi kırıldı, sonra geri alındı.

**Değişmeyen şey — aşağıdaki tablo hâlâ doğru:** `pyudev`/sysfs ve
`ioreg`'in gerçek Linux/macOS makinelerinde belgelenmiş biçimde çıktı
verdiği bugün de doğrulanamadı. Kazanılan şey, o doğrulamanın günü
geldiğinde iki komuttan ibaret olması — elle karşılaştırma değil.

Ayrı bir mimari madde açılmadı: aşağıdaki "Öneri: dosya tabanlı token'a
geçiş" zaten var ve B-016'nın gerçek donanım ölçümüyle daralttığı
kapsamla (serili aygıtlar geçiş gerektirmiyor, serisiz aygıtlar asıl
kalan boşluk) hâlâ tutarlı — bu tur onu yeniden açmadı, yalnızca yeniden
doğruladı.

---

## 2026-09-08 — Asıl soru "donanım değişince HWID kırılır mı" değildi: ÜRETİM yolu Linux/macOS'ta hiç YOK

Bu turun görevi K2-24'ü temel alıp donanım DEĞİŞİKLİĞİ senaryolarına
(disk değişimi, RAM eklenmesi) karşı kırılganlığı ölçmekti. Doğrudan
yanıt önce:

**Disk değişimi ve RAM eklenmesi HWID'i HİÇ ETKİLEMİYOR — çünkü HYCLEUS'un
HWID'i ana makinenin donanımını hiçbir zaman ölçmüyor.** `CORE/usb_manager.
py::get_usb_hwid()` yalnızca TAKILI, HARİCİ bir USB depolama aygıtının
seri numarasını okuyor (yukarıdaki tablo); anakart, CPU, RAM ya da dahili
disk hiçbir yerde ölçüme girmiyor. Bir kullanıcı ana makinenin diskini
değiştirse, RAM eklese, hatta anakartı değiştirse — USB token aynı
kalınca HWID aynı kalır. "Sık değişebilir" kategorisindeki TEK bileşen,
tasarım gereği zaten USB token'ın kendisi (bkz. yukarıdaki "Öneri" bölümü,
kayıp/değişim senaryosu 2.1 kurtarma parçasına yönlendiriyor).

Bunu ölçerken çok daha büyük ve önceliği daha yüksek bir bulgu çıktı:

### `get_usb_hwid()`'in ÜRETİM kodu yalnızca Windows'ta çalışıyor — hwid_probe.py'nin üç platformu OKUMA prototipi buraya hiç BAĞLI DEĞİL

`CORE/usb_manager.py::get_usb_hwid()`'in ikisi de gerçek donanım okumaya
çalışan iki yöntemi var ve İKİSİ DE Windows'a özgü:

    Yöntem 1: `import wmi` → `wmi.WMI().Win32_DiskDrive()`
    Yöntem 2: `subprocess` ile `wmic diskdrive get ...`

İkisi de `except Exception: pass` ile sarılı (B-024'ün kendi gerekçesi:
eksik `wmi` bir hata değil "USB bulunamadı" olarak görünmeli). Linux'ta
`wmi` paketi zaten kurulamıyor (`import` anında `ImportError`) ve `wmic`
programı yok (`subprocess` `FileNotFoundError` fırlatır, aynı `except`e
düşer) — yani **bu fonksiyon Linux'ta HER ZAMAN, fiziksel bir USB takılı
olsa bile, `None` döner.** macOS için de üçüncü bir yöntem YOK. Bu
modülün kendi docstring'i "Windows'ta USB depolama kimliklerini
okur" diyor ama bunun tersi — "başka hiçbir platformda okumuyor" — hiçbir
yerde açıkça yazılmamış.

`CORE/hwid_probe.py`'nin üç platformu (Windows/Linux/macOS) okuyan
`read_linux()`/`read_macos()` fonksiyonları VAR ve çalışıyor (bu belgenin
geri kalanı onları anlatıyor) — ama bu modül, kendi docstring'inin ilk
satırında söylediği gibi, **uygulamaya BAĞLI DEĞİL**. `get_usb_hwid()`
`CORE/hwid_probe.py`'yi hiç import etmiyor, çağırmıyor. K2-24'ün "üç
platformda okuma nasıl yapılır" sorusuna verdiği yanıt, üretim koduna hiç
ULAŞMADI.

**Sonuç, `main.py`'nin kendi akışında ölçülebilir:** `main()` QApplication
kurulur kurulmaz, HERHANGİ bir giriş/kayıt ekranından ÖNCE,
`get_usb_hwid()`'i koşulsuz çağırıyor (main.py:322) ve `None` dönerse:

```python
if hwid is None:
    QMessageBox.critical(None, "USB Bulunamadı",
        "Yetkili USB cihazı takılı değil.\nUygulama başlatılamaz.")
    sys.exit(1)
```

Paketlenmiş (frozen) bir derlemede `DEV_MODE` yok sayılıyor ("EXE olarak
çalışırken DEV_MODE ne olursa olsun gerçek USB okunur" —
`get_usb_hwid()`'in kendi docstring'i). Yani **paketlenmiş Linux/macOS
derlemesinde uygulama, USB takılı olsun ya da olmasın, HER ZAMAN "USB
Bulunamadı" diyip kapanıyor** — bu bir donanım-değişikliği kırılganlığı
değil, sıfırdan hiç çalışmama durumu.

**Bu, projenin kendi araçlarında ZATEN üstü örtük biliniyor, ama hiçbir
yerde açıkça yazılmamış.** `packaging/linux/smoke-test.sh`'ın kendi
yorumu: *"main() USB bulamayınca modal bir QMessageBox açar ve başsız bir
koşucuda o kutu sonsuza kadar bekler. Bu yüzden test, uygulamanın
GUI'siz bayraklarını (--version / --selftest) kullanıyor."* — yani Linux
AppImage'ının duman testi GERÇEK GUI açılışını hiç denemiyor, bilerek
`--selftest`e (main.py'nin `_selftest()`'i, `get_usb_hwid()`'e hiç
dokunmuyor) yönleniyor. Sorunu çözmüyor, etrafından dolaşıyor — ve bu
dolaşma hiçbir yerde "Linux'ta giriş ekranı hiç açılmıyor" diye
yazılmamış, yalnızca "GUI'yi başsız test edemeyiz" diye gerekçelendirilmiş.

**Bunu doğrudan gözlemleyen bir test de yok.** `tests/` içinde
`sys.platform`'a göre atlanan tek HWID/USB testi
`test_static_analysis.py`'deki bir statik denetim (Windows'ta anlamlı);
`get_usb_hwid() is None` durumunda `main()`'in gerçekten çıktığını (ya da
Linux'ta HER ZAMAN `None` döndüğünü) doğrulayan hiçbir test yok — bu
turda **B-112** olarak açıldı (aşağıya bakın).

**Kod değişikliği önerisi buraya YAZILMADI, ayrı backlog maddesi olarak
açıldı — B-112, öncelik Yüksek.** Gerekçesi: bu bulgu bu belgenin asıl
konusundan (donanım-değişikliği kırılganlığı) daha büyük ve daha acil bir
sınıfta — "USB token değişince ne olur" sorusundan önce "Linux/macOS'ta
hiç açılıyor mu" sorusu var, ve bugünkü yanıt hayır.

### İkincil, daha dar bir kırılganlık: `usb_ids.json` MAKİNEYE bağlı, USB'ye değil

Yukarıdaki tablonun zaten söylediği "serisiz USB, başka makine → FARKLI"
satırının bir özel hâli donanım-değişikliği açısından ilgili: **ana
makinenin diskinin DEĞİŞTİRİLMESİ** (yeni disk + taze OS kurulumu, RAM
eklenmesinden FARKLI olarak `data_dir()`'i de götürür) `usb_ids.json`'u
kaybettirir. Etkisi yalnızca **serisiz** USB token'lar için gerçek: fiziksel
token DEĞİŞMEDİĞİ hâlde, ana makinenin diskini değiştiren bir kullanıcı
(yedekten geri yükleme, taze kurulum) o token için daha önce üretilmiş
UUID'yi kaybeder ve token "yeni" bir HWID alır — sessizce, uyarısız.
Serili token'lar (gerçek `iSerialNumber` taşıyanlar, B-016'nın ölçtüğü
HYCLEUS'un kendi token'ı dahil) bundan ETKİLENMİYOR: seri her okumada
donanımdan yeniden okunuyor, hiçbir dosyaya bağımlı değil.

Bu, yukarıdaki "Öneri: dosya tabanlı token'a geçiş" önerisinin (kimliği
MAKİNEYE değil USB'YE yazmak) zaten çözdüğü tam senaryo — ayrı bir
backlog maddesi açılmadı, mevcut öneri bunu kapsıyor.

---

## 2026-09-08 — Doğrulama ve düzeltme: B-112'nin iddiası bağımsız olarak KANITLANDI, kod düzeltildi (B-114)

Bir önceki tur B-112'yi (`get_usb_hwid()` yalnızca Windows'ta çalışıyor,
paketlenmiş Linux/macOS derlemesi hiç açılmıyor) açtıktan sonra, bu tur
o iddiayı düzeltmeye geçmeden ÖNCE bağımsız olarak yeniden doğruladı.

### Kanıt 1 — `get_usb_hwid()`'in Windows-özgü olduğu, GERÇEK ÇALIŞTIRMAYLA

`CORE/usb_manager.py::get_usb_hwid()`'in (düzeltmeden ÖNCEKİ hâli) iki
yöntemi vardı, ikisi de Windows'a özgü:

    Yöntem 1: `import wmi` → `wmi.WMI().Win32_DiskDrive()`
    Yöntem 2: `subprocess` ile tam yola çözülmüş `wmic.exe`

Bu makinede (Linux) DOĞRUDAN çalıştırılarak ölçüldü:

    >>> import wmi
    ImportError: No module named 'wmi'

    >>> yol = 'C:\Windows\System32\wbem\wmic.exe'  # _wmic_yolu()'nun hesapladığı
    >>> subprocess.check_output([yol, ...])
    FileNotFoundError: [Errno 2] No such file or directory: '...wmic.exe'

İkisi de fonksiyonun kendi `except Exception: pass`'ine düşüyor. Gerçek
fonksiyon (`from CORE.usb_manager import get_usb_hwid`) bu makinede
DOĞRUDAN çağrılarak ölçüldü: `DEV_MODE=False` iken **`None` döndü** —
iddia edilen davranışın ta kendisi, çıkarım değil.

### Kanıt 2 — `main()`'in koşulsuz açılış kapısı olduğu, ÇAĞRI GRAFİĞİYLE

`main.py::main()` (uygulamanın TEK giriş noktası, `if __name__ ==
"__main__": main()`) şu sırayı izliyor:

    1. `_erken_komut()` — yalnızca `--version`/`--selftest` bayrakları
       için erken çıkış; İKİSİ DE `QApplication` kurulmadan ÖNCE döner,
       giriş/kayıt akışına hiç dokunmaz.
    2. `QApplication(sys.argv)` kurulur.
    3. `hwid = get_usb_hwid()` — KOŞULSUZ, hiçbir try/except ya da
       özellik bayrağı YOK.
    4. `if hwid is None: ... sys.exit(1)` — giriş ekranından, kayıttan,
       vault'tan ÖNCE.

Paketlenmiş bir derlemede (`sys.frozen` True — `packaging/linux/
build-appimage.sh` gerçekten `pyinstaller ... HYCLEUS-linux.spec`
çalıştırıyor) `DEV_MODE` bayrağı da devre dışı ("sys.frozen → PyInstaller
EXE; ortam değişkeni miras alınsa bile DEV_MODE kapalı", main.py). Yani
kaçış yolu yok. Projenin kendi `packaging/linux/smoke-test.sh`'ı bunu
zaten biliyor ve etrafından dolaşıyor — kendi yorumu: *"main() USB
bulamayınca modal bir QMessageBox açar ve başsız bir koşucuda o kutu
sonsuza kadar bekler. Bu yüzden test, uygulamanın GUI'siz bayraklarını
(--version / --selftest) kullanıyor."*

**Sonuç: iki iddia da doğrulandı, yanlış alarm değildi.**

### Düzeltme (B-114) — `CORE/hwid_probe.py::read_linux()`/`read_macos()` üretime BAĞLANDI

İKİNCİ bir ayrıştırıcı YAZILMADI: `CORE/hwid_probe.py`'nin
`read_linux()` (pyudev/sysfs) ve `read_macos()` (ioreg) fonksiyonları
ZATEN vardı ve çalışıyordu, yalnızca üretime bağlı değillerdi.
`get_usb_hwid()`'e Yöntem 3/4 olarak eklendi: `descriptor_serial` dolu
olan ilk aygıtın serisi, Windows yollarıyla AYNI `_sanitize_hwid()`'den
geçiriliyor. `tests/test_hwid_probe.py`'nin eski "hiç bağlı değil" AST
denetimi, yeni bir "yalnızca `CORE/usb_manager.py`'den, yalnızca
`read_linux`/`read_macos` olarak bağlı" denetimine dönüştürüldü — ikinci
bir bağlanma yolu (ör. bir UI dosyasının doğrudan bağlanması) hâlâ
yakalanıyor.

**Gerçek donanımla doğrulandı — bu satırların yazıldığı makinede o an
takılı iki gerçek USB depolama aygıtı vardı:**

    >>> from CORE.usb_manager import get_usb_hwid
    >>> get_usb_hwid()
    '4C530301470118102554'

Bu, `hwid_probe.read_linux()`'un aynı anda bağımsız okuduğu gerçek
`iSerialNumber` ile (VID:PID `0781:5567`, B-016'nın ölçtüğü kayıtlı
SanDisk token'ıyla AYNI üretici/ürün kodu) BİREBİR eşleşiyor — sentetik
ya da sahte veri değil.

`tests/test_usb_manager.py` (yeni dosya, `get_usb_hwid()`'in daha önce
HİÇ doğrudan test edilmediği de bu turda fark edildi) sahte
`read_linux`/`read_macos` dönüşleriyle sekiz senaryoyu sınıyor —
en önemlisi, USB hiç takılı değilken (`read_linux` boş liste
döndürünce) fonksiyonun ÇÖKMEDEN, sessizce `None` döndüğü.

### Dürüst sınır — ne değişmedi

`hwid_probe.py`'nin kendi "gerçek donanımda hiç çalıştırılmadı" sınırı
`read_macos()` için hâlâ geçerli: bu turda yalnızca Linux tarafı gerçek
donanımla doğrulanabildi (elde macOS makinesi yok). `read_macos()`'un
üretime bağlanması aynı "tek karar noktası" gerekçesiyle yapıldı ama
`ioreg` çıktısının gerçek bir Mac'te belgelenen biçimde geldiği hâlâ
KANITLANMADI — yalnızca kaydedilmiş örnek çıktı üzerinde test edildi.
Çapraz platform taşınabilirlik sınırı (aynı USB'nin üç platformda aynı
kimliği vermemesi) de DEĞİŞMEDİ — bu düzeltme yalnızca "Linux/macOS'ta
HİÇ kimlik okunamıyor" sorununu kapattı, "üç platformda aynı kimlik"
sorununu değil.
