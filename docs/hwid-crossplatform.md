# Çapraz platform USB kimliği — bulgular ve mimari öneri

**Durum:** 3.4 prototip raporu · Kod: `CORE/hwid_probe.py` (uygulamaya bağlı DEĞİL)

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
