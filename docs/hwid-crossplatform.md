# Çapraz platform USB kimliği — bulgular ve mimari öneri

**Durum:** 3.4 prototip raporu · Kod: `CORE/hwid_probe.py` (uygulamaya bağlı DEĞİL)

> ⛔ **Bu belgedeki öneri UYGULANMADI ve şimdilik uygulanmayacak.** Dayandığı
> ölçümün bir bacağı eksik: sayım sırasında gerçek HYCLEUS token USB'si takılı
> değildi. Açık madde: **BACKLOG.md / B-016**.

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
USB\VID_0781&PID_5567\4C530001120523104381
```

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

> **Sınır — bu ölçüm HYCLEUS'un kendi USB'sini ÖLÇMEDİ.** Sayım sırasında
> fiziksel bir HYCLEUS kimlik doğrulama USB'si takılı değildi; yukarıdaki
> aygıtlar dahili donanım: klavye, fare, kamera, Bluetooth, hub. USB
> *depolama* çubuklarının serisi olma oranı bunlardan yüksek olabilir.
>
> "Opsiyonel alan, çoğu aygıtta yok" gözlemi geçerliliğini koruyor (spec'te
> yazılı) ve HYCLEUS'un kodunda zaten bir UUID fallback'i olması sahada da
> karşılaşıldığını gösteriyor — ama "HYCLEUS'un fiilen kullandığı USB'de
> seri yok" iddiası **doğrulanmadı**. Eksik ölçüm açık madde olarak
> BACKLOG.md / B-016'da duruyor; token geçişi o ölçüm yapılana kadar
> başlatılmayacak.

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
