"""
HYCLEUS — ikili dosyaya GÖMÜLÜ güvenilir TSA kökü (B-105)

Kapattığı boşluk
----------------
`CORE/trusted_roots.py` güven kökünü doğrulanan DOSYANIN dışına çıkardı
ama listeyi `settings` tablosunda tuttu — SECURITY.md §4.9'un yazdığı
gibi, veritabanına yazabilen biri (M3) kendi kökünü ekleyip sahte bir
damgayı "tam geçerli" gösterebilir (B-044). B-044 bunun çözümünü
`HYCLEUS_AUDIT_ANCHOR` deseninde ("dış güvenli depo": bir ortam
değişkeniyle listeyi USB'ye/ağ paylaşımına yönlendirmek) önermişti.

O yön DENENMEDİ — fazla karmaşık: ikinci bir ortam değişkeni, ikinci bir
"hangi kaynak kazanır" kararı, ikinci bir sızıntı yüzeyi (B-044'ün kendi
metninde de "iki kaynağı aynı anda kurmak tek karar noktası sınırını
bulanıklaştırırdı" diye yazıyordu). Bunun yerine her TLS yığınının
(OpenSSL'in `ca-certificates` paketi, tarayıcıların kök mağazası) yaptığı
şey yapıldı: güven köküNÜN KENDİSİ ikili dosyanın içine, DEĞİŞMEZ bir
sabit olarak gömüldü. `settings` tablosuna hiç uğramıyor — okuma da,
yazma da yok, yani M3'ün ERİŞEBİLECEĞİ bir yüzey değil.

Bu modülün ROLÜ dar: yalnızca HYCLEUS'un KENDİ varsayılan TSA'sının
(`CORE.timestamp.DEFAULT_TSA_URL`, freetsa.org) kökünü taşıyor. Kurumun
kendi/özel bir TSA kullanması hâlinde o kök hâlâ `CORE/trusted_roots.py`
üzerinden, Yönetim Paneli'nden eklenir — B-044'ün belgelediği sınır
(mutable DB, M3'e açık) o yol için AYNEN geçerliliğini koruyor.

**Genel dosya doğrulamasına (sağ tık menüsü) BİLEREK karıştırılmadı.**
`tsa_url` kurum başına ayarlanabilir bir ayar (`CORE/timestamp.py::
tsa_url`) ve `verify_timestamp(trusted_roots=...)` VERİLDİĞİNDE eşleşmeyen
her kök `anchor_trusted=False`'u değil doğrudan GEÇERSİZ'i
(`failed_check=trust_anchor`) üretiyor. Bu listeyi genel akışa karıştırmak,
kendi (freetsa OLMAYAN) TSA'sını kullanan her kurumun damgasını, o kurum
kendi kökünü Ayarlar'a eklemeden, YANLIŞLIKLA geçersiz gösterirdi — ölçüldü:
`tests/test_timestamp_ui.py`'nin `FakeTSA()` fixture'ı tam bu senaryoyu
üretti. Bkz. `tests/test_trusted_roots_builtin.py::
test_genel_dogrulama_akisi_BILEREK_karistirmiyor`.

Bugünkü tek KULLANICISI K4-20 (B-087, denetim raporuna RFC 3161 mührü) —
henüz yazılmadı, ama önkoşulu burada: dışa aktarılan bir denetim raporunun
mührü, raporu üreten makinenin veritabanından TAMAMEN bağımsız
doğrulanabilmeli — rapor başka bir makinede, hatta HYCLEUS hiç kurulu
olmayan bir ortamda (yalnızca bu modülün taşıdığı kökle) denetlenebilmeli.
Mutable bir DB satırına dayanan bir kök bunu veremezdi: raporla birlikte
"hangi kökle doğrulanmalı" bilgisini de ayrıca taşımak/paylaşmak gerekirdi.
O rapor mührü HER ZAMAN uygulamanın kendi varsayılan TSA'sıyla üretileceği
için, orada sert eşleşme (genel akıştan farklı olarak) yanlış pozitif
üretmez — bu modül o günü bekliyor, bugün yalnızca kendi başına test
ediliyor.

Sertifikanın kimliği
---------------------
Aşağıdaki DER, `tests/data/freetsa_response.der` fixture'ının GERÇEK
zincirinden çıkarılan, kendinden imzalı Free TSA Root CA sertifikası —
uydurma bir test kökü değil, uygulamanın varsayılan TSA'sının (freetsa.org)
bugün gerçekten kullandığı kök. `tests/test_trusted_roots_builtin.py`
parmak izini (SHA-256) sabit bir değerle karşılaştırıp yanlışlıkla farklı
bir sertifika yapıştırılmasına karşı kilitliyor.

    Konu:    CN=www.freetsa.org, O=Free TSA, OU=Root CA
    Geçerli: 2016-03-13 → 2041-03-07
    SHA-256: a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc

Neden veri dosyası DEĞİL, Python sabiti
-----------------------------------------
Bir `.pem`/`.der` dosyası paketlemeye (`HYCLEUS.spec`/`HYCLEUS-linux.spec`
→ `datas=[...]`) yeni bir giriş ister ve o giriş unutulursa (B-081'in
wmi/reportlab'da defalarca yakaladığı kusur sınıfı) EXE/AppImage kökü
SESSİZCE taşımaz. Bu modül SIRADAN bir `.py` dosyası — PyInstaller onu
zaten statik olarak görüyor, hiçbir `datas`/`collect_all` girişi
gerekmiyor. Basitlik burada bir seçim, B-044'ün reddettiği "dış depo"
fikrinin tam tersi yönünde.
"""
from __future__ import annotations

import base64

#: Free TSA (freetsa.org) kendinden imzalı Root CA sertifikası, DER, base64.
#: `tests/test_trusted_roots_builtin.py::test_gomulu_kok_freetsa_nin_GERCEK_koku`
#: bunun `tests/data/freetsa_response.der` fixture zincirindeki kökle BİREBİR
#: aynı bayt dizisi olduğunu doğruluyor.
_FREETSA_ROOT_DER_B64 = (
    "MIIH/zCCBeegAwIBAgIJAMHphhYNqOmAMA0GCSqGSIb3DQEBDQUAMIGVMREwDwYDVQQKEwhGcmVl"
    "IFRTQTEQMA4GA1UECxMHUm9vdCBDQTEYMBYGA1UEAxMPd3d3LmZyZWV0c2Eub3JnMSIwIAYJKoZI"
    "hvcNAQkBFhNidXNpbGV6YXNAZ21haWwuY29tMRIwEAYDVQQHEwlXdWVyemJ1cmcxDzANBgNVBAgT"
    "BkJheWVybjELMAkGA1UEBhMCREUwHhcNMTYwMzEzMDE1MjEzWhcNNDEwMzA3MDE1MjEzWjCBlTER"
    "MA8GA1UEChMIRnJlZSBUU0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNh"
    "Lm9yZzEiMCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJV3Vlcnpi"
    "dXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A"
    "MIICCgKCAgEAtgKODjAy8REQ2WTNqUudAnjhlCrpE6qlmQfNppeTmVvZrH4zutn+NwTaHAGpjSGv"
    "4/WRpZ1wZ3BRZ5mPUBZyLgq0YrIfQ5Fx0s/MRZPzc1r3lKWrMR9sAQx4mN4z11xFEO529L0dFJjP"
    "F9MD8Gpd2feWzGyptlelb+PqT+++fOa2oY0+NaMM7l/xcNHPOaMz0/2olk0i22hbKeVhvokPCqhF"
    "hzsuhKsmq4Of/o+t6dI7sx5h0nPMm4gGSRhfq+z6BTRgCrqQG2FOLoVFgt6iIm/BnNffUr7VDYd3"
    "zZmIwFOj/H3DKHoGik/xK3E82YA2ZulVOFRW/zj4ApjPa5OFbpIkd0pmzxzdEcL479hSA9dFiyVm"
    "SxPtY5ze1P+BE9bMU1PScpRzw8MHFXxyKqW13Qv7LWw4sbk3SciB7GACbQiVGzgkvXG6y85HOuvW"
    "NvC5GLSiyP9GlPB0V68tbxz4JVTRdw/Xn/XTFNzRBM3cq8lBOAVt/PAX5+uFcv1S9wFE8YjaBfWC"
    "P1jdBil+c4e+0tdywT2oJmYBBF/kEt1wmGwMmHunNEuQNzh1FtJY54hbUfiWi38mASE7xMtMhfj/"
    "C4SvapiDN837gYaPfs8x3KZxbX7C3YAsFnJinlwAUss1fdKar8Q/YVs7H/nU4c4Ixxxz4f67fcVq"
    "M2ITKentbCMCAwEAAaOCAk4wggJKMAwGA1UdEwQFMAMBAf8wDgYDVR0PAQH/BAQDAgHGMB0GA1Ud"
    "DgQWBBT6VQ2MNGZRQ0z357OnbJWveuaklzCBygYDVR0jBIHCMIG/gBT6VQ2MNGZRQ0z357OnbJWv"
    "euakl6GBm6SBmDCBlTERMA8GA1UEChMIRnJlZSBUU0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNV"
    "BAMTD3d3dy5mcmVldHNhLm9yZzEiMCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTES"
    "MBAGA1UEBxMJV3VlcnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFggkAwemGFg2o"
    "6YAwMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL3d3dy5mcmVldHNhLm9yZy9yb290X2NhLmNybDCB"
    "zwYDVR0gBIHHMIHEMIHBBgorBgEEAYHyJAEBMIGyMDMGCCsGAQUFBwIBFidodHRwOi8vd3d3LmZy"
    "ZWV0c2Eub3JnL2ZyZWV0c2FfY3BzLmh0bWwwMgYIKwYBBQUHAgEWJmh0dHA6Ly93d3cuZnJlZXRz"
    "YS5vcmcvZnJlZXRzYV9jcHMucGRmMEcGCCsGAQUFBwICMDsaOUZyZWVUU0EgdHJ1c3RlZCB0aW1l"
    "c3RhbXBpbmcgU29mdHdhcmUgYXMgYSBTZXJ2aWNlIChTYWFTKTA3BggrBgEFBQcBAQQrMCkwJwYI"
    "KwYBBQUHMAGGG2h0dHA6Ly93d3cuZnJlZXRzYS5vcmc6MjU2MDANBgkqhkiG9w0BAQ0FAAOCAgEA"
    "aK9+v5OFYu9M6ztYC+L69sw1omdyli89lZAfpWMMh9CRmJhM6KBqM/ipwoLtnxyxGsbCPhcQjuTv"
    "zm+ylN6VwTMmIlVyVSLKYZcdSjt/eCUN+41K7sD7GVmxZBAFILnBDmTGJmLkrU0KuuIpj8lI/E6Z"
    "6NnmuP2+RAQSHsfBQi6sssnXMo4HOW5gtPO7gDrUpVXID++1P4XndkoKn7Svw5n0zS9fv1hxBcYI"
    "HPPQUze2u30bAQt0n0iIyRLzaWuhtpAtd7ffwEbASgzB7E+NGF4tpV37e8KiA2xiGSRqT5ndu28f"
    "gpOY87gD3ArZDctZvvTCfHdAS5kEO3gnGGeZEVLDmfEsv8TGJa3AljVa5E40IQDsUXpQLi8G+UC4"
    "1DWZu8EVT4rnYaCw1VX7ShOR1PNCCvjb8S8tfdudd9zhU3gEB0rxdeTy1tVbNLXW99y90xcwr1ZI"
    "DUwM/xQ/noO8FRhm0LoPC73Ef+J4ZBdrvWwauF3zJe33d4ibxEcb8/pz5WzFkeixYM2nsHhqHsBK"
    "w7JPouKNXRnl5IAE1eFmqDyC7G/VT7OF669xM6hbUt5G21JE4cNK6NNucS+fzg1JPX0+3VhsYZjj"
    "7D5uljRvQXrJ8iHgr/M6j2oLHvTAI2MLdq2qjZFDOCXsxBxJpbmLGBx9ow6ZerlUxzws2AWv2pk="
)

#: `_FREETSA_ROOT_DER_B64`'ün SHA-256'sı — `tests/test_trusted_roots_builtin.py`
#: sabitleri, yanlış bir sertifika yapıştırılırsa testi düşürüyor.
FREETSA_ROOT_SHA256 = (
    "a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc"
)

#: Bugün tek kök taşıyor ama liste — ikinci bir varsayılan TSA (ör. ayrı
#: bir HYCLEUS sürümünün kendi TSA'sı) eklenirse `der_listesi()`'nin ve
#: çağıranların hiçbiri değişmeden büyüyebilsin diye.
_GOMULU_KOKLER_DER_B64: tuple[str, ...] = (_FREETSA_ROOT_DER_B64,)


def gomulu_kokler() -> list[bytes]:
    """
    İkili dosyaya gömülü, DEĞİŞMEZ güven köklerini döndürür.

    Kasıtlı olarak `db` PARAMETRESİ YOK — bu fonksiyonun bütün amacı
    veritabanından TAMAMEN bağımsız çalışmak. Ne okuma ne yazma: yalnızca
    bu modüldeki sabitlerin çözülmesi. `tests/test_trusted_roots_builtin.py`
    bunu, hiçbir DBManager/settings erişimi KURULMADAN çağırarak ölçüyor.
    """
    return [base64.b64decode(b64) for b64 in _GOMULU_KOKLER_DER_B64]


__all__ = [
    "FREETSA_ROOT_SHA256",
    "gomulu_kokler",
]
