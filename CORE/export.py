"""
HYCLEUS — Toplu dışa aktarma (çöz → yaz → logla)

İki akış var ve ikisi de `UI/main_window.py` içinde satır içi yazılıydı:

  · **Klasör indirme** — klasördeki her dosyayı çözüp tek bir ZIP'e koyar
  · **Toplu indirme**  — seçili dosyaları çözüp bir dizine tek tek yazar

Ortak iskelet aynı: her dosya için AAD'dan hwid'i oku, çöz, yaz, denetim
kaydı düş, hatayı listele ama DÖNGÜYÜ KIRMA. Farkları da vardı ve
aşağıda anlatıldığı gibi bilerek korundu.

TOTP doğrulaması, dosya seçim diyalogları ve ilerleme penceresi burada
DEĞİL — onlar arayüzün işi. Bu modül ilerlemeyi bir geri çağrımla bildiriyor
ve iptali bir geri çağrımla soruyor, böylece Qt'ye hiç dokunmuyor.

Düz metin diske yazılıyor — bilerek
-----------------------------------
Bu iki akış SafeZone kullanmıyor (CORE/safezone.py). Kullanmamalı da:
buradaki çıktı geçici bir çalışma kopyası değil, kullanıcının BİLEREK
istediği ve yerini kendi seçtiği kalıcı bir dışa aktarım. SafeZone'un işi
uygulamanın kendi ürettiği geçici kopyaları temizlemek; kullanıcının
masaüstüne kaydettiği dosyayı silmek değil.

Çözülmüş içerik yine de bellekte tam olarak bulunuyor. `export_to_directory()`
`decrypt_file(..., zeroizable=True)` kullanıyor — `bytes` yerine bir
`bytearray` alıyor ve yazdıktan HEMEN sonra `zero_bytearray()` ile
GERÇEKTEN sıfırlıyor (bkz. CORE/crypto.py::decrypt_file, "Bellek
güvenliği"). `export_to_zip()` henüz eski (varsayılan `bytes`) yolu
kullanıyor — ZIP akışı bugün yeniden giriş yapılabilir değil (aşağıya
bkz., "USB çekilince de durur" notu), zeroize edilebilir hâle getirmek
ayrı bir madde.

USB çekilince de durur — abort sinyali (2026-08-29, K1-15)
------------------------------------------------------------
`export_to_directory()`'nin çağrısı `QApplication.processEvents()`
çalıştıran bir `on_progress` geri çağrımı alıyor (bkz.
`UI/main_window_bulk.py`), yani bu döngü Qt olay döngüsüne yeniden giriş
yapabiliyor — USB çekilip `_lock()` tetiklenirse `should_continue()`
bunu görebilmeli. `should_continue()` bu yüzden döngüde İKİ KEZ kontrol
ediliyor: `on_progress`'TEN ÖNCE (aynen eskisi gibi) VE `on_progress`'TEN
SONRA, `decrypt_file()`'ı çağırmadan HEMEN önce — çünkü olay döngüsüne
yeniden giriş yalnızca `on_progress` içinde olabiliyor, ikinci kontrol
olmadan USB tam o sırada çekilirse bir dosya daha çözülüp yazılırdı. Bu
iki kontrol arasında `decrypt_file()`/`write_bytes()` senkron çalışıyor
— olay döngüsü hiç dönmüyor — yani kilit bir dosyanın YARISINI
yazdırabilecek bir noktada asla araya giremiyor: her dosya ya TAMAMEN
yazılıyor ya HİÇ başlamıyor.


GİDERİLEN FARK — hwid geri dönüşü (B-010)
-----------------------------------------
İki akış, DB'deki `aad_metadata` sütununda hwid bulunmadığında FARKLI
davranıyordu:

    ZIP     : hwid = aad_hwid or (DEV-HWID-1234 / oturum hwid'i)
    Dizine  : hwid = aad_hwid  (yoksa None — çağıran fallback vermiyordu)

Farkın nerede görünür olduğunu anlamak için `decrypt_file()`'ın kontrolüne
bakmak gerekiyor:

    if hwid is not None and meta.get("hwid") is not None and meta["hwid"] != hwid

`meta`, DOSYANIN kendi AAD'ından geliyor; `aad_hwid_of()` ise DB'nin
`aad_metadata` SÜTUNUNDAN okuyor. İkisi normalde aynı şeyi söylüyor ve o
zaman kontrol kendisiyle karşılaştırma yapıp her zaman geçiyor. Fark
yalnızca ikisi AYRIŞTIĞINDA ortaya çıkıyor: DB satırında hwid yok ama
dosyanın AAD'ında var. O durumda

    ZIP     → oturum hwid'iyle karşılaştırılır, uyuşmazsa dosya ATLANIR
    Dizine  → `hwid=None` geçildiği için kontrol HİÇ ÇALIŞMAZ

Aynı dosya, aynı anahtar, aynı kullanıcı — farklı sonuç.

Karar: **ZIP'in davranışı doğru olan.** Kontrolün amacı "bu dosya bu
cihazda mı şifrelendi" sorusunu yanıtlamak (SECURITY.md §4.5) ve DB
sütununun eksilmiş olması o soruyu geçersiz kılmıyor — dosya hâlâ
yanıtı taşıyor. `hwid=None` geçmek "kontrol etme" demek, yani gerçek bir
sinyali atmak. Toplu indirme artık `hwid_fallback` alıyor ve iki akış
aynı kararı veriyor.

RİSK — bilinçli kabul edildi: DB'si `aad_metadata`'sını kaybetmiş ve
BAŞKA bir cihazda şifrelenmiş dosyalar artık toplu indirmede de
"bütünlük hatası" verip atlanıyor. Bu yeni bir başarısızlık sınıfı
değil; aynı dosyalar ZIP akışında zaten atlanıyordu. Değişen, iki yolun
aynı şeyi söylemesi.
"""
from __future__ import annotations

import json
import logging
import zipfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from CORE.crypto import AuthenticationError, decrypt_file, zero_bytearray

_log = logging.getLogger("hycleus.export")


@dataclass(frozen=True)
class ExportResult:
    """Bir dışa aktarma turunun sonucu."""

    saved: int = 0
    #: Kullanıcıya gösterilecek hata satırları ("<ad> (sebep)").
    errors: list[str] = field(default_factory=list)
    #: Kullanıcı ilerleme penceresinden iptal etti.
    cancelled: bool = False

    @property
    def clean(self) -> bool:
        return not self.errors and not self.cancelled


def aad_hwid_of(aad_metadata: str | None) -> str | None:
    """
    AAD JSON'undan hwid alanını çıkarır; yoksa/bozuksa None.

    Bozuk JSON sessizce None'a düşüyor — mevcut davranış. Dosyanın kendisi
    zaten GCM ile doğrulanacak, buradaki okuma yalnızca hangi hwid'in
    bekleneceğini belirliyor.
    """
    if not aad_metadata:
        return None
    try:
        return json.loads(aad_metadata).get("hwid")
    except (ValueError, AttributeError):
        return None


#: Tek sorguda kaç `?` yer tutucu kullanılacağı. SQLite'ın eski
#: `SQLITE_MAX_VARIABLE_NUMBER` varsayılanı 999; yeni sürümler çok daha
#: yüksek ama derleme seçeneğine bağlı. 900, hangi sürümle karşılaşırsak
#: karşılaşalım güvenli — ve 500 dosyalık tipik bir turu zaten tek
#: sorguda bitiriyor.
_IN_CHUNK = 900


def aad_map(db: Any, file_ids: Sequence[int]) -> dict[int, str | None]:
    """
    Verilen dosya id'leri için `aad_metadata` değerlerini TEK turda okur.

    B-009: `export_to_directory()` bunu döngü içinde dosya başına bir
    sorguyla yapıyordu — 500 dosyalık bir indirme 500 ek sorgu demekti.
    Sorgular indeksliydi ve yerel SQLite'a gidiyordu, yani maliyet küçük;
    ama `export_to_zip()` aynı bilgiyi zaten tek sorguda alıyordu ve iki
    akışın aynı deseni kullanması bu modülün varlık sebebi.

    Bulunamayan id'ler sözlükte YER ALMAZ — çağıran `.get(id)` ile
    None'a düşüyor, tıpkı eski `fetchone()` None döndüğünde olduğu gibi.

    DAVRANIŞ NOTU: okuma artık döngüden ÖNCE, tek anda yapılıyor.
    Eşzamanlı bir yazma varsa eski kod ilk dosya için eski, son dosya
    için yeni değeri görebilirdi; yeni kod hepsi için tutarlı bir
    anlık görüntü kullanıyor. Tutarlı olan doğru olan, ama fark
    teknik olarak bir davranış değişikliği — 2.7'de bu yüzden
    ertelenmişti.
    """
    sonuc: dict[int, str | None] = {}
    benzersiz = list(dict.fromkeys(file_ids))
    for i in range(0, len(benzersiz), _IN_CHUNK):
        parca = benzersiz[i : i + _IN_CHUNK]
        yer_tutucu = ",".join("?" * len(parca))
        # nosemgrep: python.lang.security.audit.formatted-sql-query
        # Enterpolasyona giren tek şey `?` karakterleri; değerler bağlı.
        for row in db.fetchall(
            f"SELECT id, aad_metadata FROM files WHERE id IN ({yer_tutucu})",
            tuple(parca),
        ):
            sonuc[row["id"]] = row["aad_metadata"]
    return sonuc


def unique_path(directory: Path, filename: str) -> Path:
    """
    Dizinde çakışmayan bir hedef yol üretir: `ad.pdf` → `ad_1.pdf` → `ad_2.pdf`.

    Üzerine YAZMAZ — dışa aktarım kullanıcının kendi dizinine yazıyor ve
    oradaki bir dosyayı sessizce ezmek kabul edilemez.
    """
    hedef = directory / filename
    if not hedef.exists():
        return hedef
    stem, suffix, n = hedef.stem, hedef.suffix, 1
    while hedef.exists():
        hedef = directory / f"{stem}_{n}{suffix}"
        n += 1
    return hedef


def export_to_zip(
    db: Any,
    rows: Sequence[Any],
    key: bytes,
    zip_path: Path | str,
    *,
    hwid_fallback: str | None = None,
) -> ExportResult:
    """
    Verilen dosyaları çözüp tek bir ZIP arşivine yazar.

    Args:
        rows:          `id`, `filename`, `filepath`, `aad_metadata` alanlarına
                       sahip satırlar.
        hwid_fallback: AAD'da hwid yoksa kullanılacak değer (bkz. modül
                       docstring'i — "KORUNAN FARK").

    Tek bir dosyanın çözülememesi arşivi iptal ETMEZ: hata listeye eklenir
    ve kalanlar yazılmaya devam eder. Arşivin kendisi açılamazsa (disk dolu,
    izin yok) istisna yükselir — o durumda kısmi bir ZIP bırakmak yerine
    çağıranın haberi olması gerekir.
    """
    errors: list[str] = []
    saved = 0
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for row in rows:
            ad = row["filename"]
            try:
                hwid = aad_hwid_of(row["aad_metadata"]) or hwid_fallback
                content, meta = decrypt_file(row["filepath"], key, hwid=hwid)
                try:
                    zf.writestr(meta.get("filename", ad), content)
                finally:
                    del content
                saved += 1
            except AuthenticationError:
                errors.append(f"{ad} (bütünlük hatası)")
            except Exception as exc:
                errors.append(f"{ad} ({exc})")
    return ExportResult(saved=saved, errors=errors)


def export_to_directory(
    db: Any,
    items: Sequence[tuple[int, str | None]],
    key: bytes,
    dest_dir: Path | str,
    *,
    session_hwid: str | None = None,
    hwid_fallback: str | None = None,
    on_progress: Callable[[int, str], None] | None = None,
    should_continue: Callable[[], bool] | None = None,
) -> ExportResult:
    """
    Verilen dosyaları çözüp hedef dizine tek tek yazar.

    Args:
        items:           (file_id, filepath) çiftleri.
        session_hwid:    denetim kaydına yazılır.
        hwid_fallback:   DB'nin `aad_metadata` sütununda hwid yoksa
                         kullanılacak değer (B-010). `export_to_zip()`
                         ile aynı anlam; iki akış artık aynı kararı
                         veriyor.
        on_progress:     her dosyadan önce (sıra_no, kısa_ad) ile çağrılır.
                         `QApplication.processEvents()` çağırabilir —
                         bkz. modül docstring'i "USB çekilince de durur".
        should_continue: False dönerse döngü durur ve `cancelled=True`.
                         Yalnızca kullanıcının "İptal" düğmesi için değil
                         — çağıran USB/kilit durumunu da buraya
                         BAĞLAMALI (bkz. `UI/main_window_bulk.py`), aksi
                         hâlde kilitlenen bir oturum döngüyü durdurmaz.

    `aad_metadata` artık TEK sorguda önden okunuyor (B-009) — bkz.
    `aad_map()`.
    """
    hedef_dizin = Path(dest_dir)
    errors: list[str] = []
    saved = 0
    cancelled = False

    # B-009: döngüden ÖNCE tek sorgu. İptal edilse bile hepsi okunuyor —
    # tek bir indeksli sorgu, iptalin kazandıracağı şeyden ucuz.
    aadler = aad_map(db, [fid for fid, _yol in items])

    for index, (file_id, filepath) in enumerate(items):
        if should_continue is not None and not should_continue():
            cancelled = True
            break

        kisa = Path(filepath).name if filepath else "?"
        if on_progress is not None:
            on_progress(index, kisa)
            # `on_progress` Qt olay döngüsüne yeniden giriş yapmış olabilir
            # (`QApplication.processEvents()`) — USB tam O SIRADA çekilip
            # `_lock()` tetiklenmiş olabilir. Döngü başındaki kontrol bunu
            # KAÇIRIR (o zaman henüz kilitli değildik); bu yüzden
            # `decrypt_file()`'a girmeden HEMEN önce YENİDEN soruyoruz —
            # yalnızca `on_progress` VARSA: yeniden giriş fırsatı yalnızca
            # onun içinde var, yoksa ikinci kontrol `should_continue`'u
            # anlamsızca iki kez çağırır (bkz. test_directory_export_
            # can_be_cancelled — çağrı SAYISINA dayanıyor). Bu iki kontrol
            # arasında (ve decrypt_file()/write_bytes() sırasında) olay
            # döngüsü hiç dönmüyor, yani kilit bir dosyanın TAM ortasına
            # asla giremez — her dosya ya tamamen işlenir ya hiç başlamaz.
            if should_continue is not None and not should_continue():
                cancelled = True
                break

        if not filepath:
            errors.append(f"#{file_id} (dosya yolu yok)")
            continue

        try:
            hwid = aad_hwid_of(aadler.get(file_id)) or hwid_fallback

            content, meta = decrypt_file(filepath, key, hwid=hwid, zeroizable=True)
            try:
                hedef = unique_path(
                    hedef_dizin, meta.get("filename", Path(filepath).stem)
                )
                hedef.write_bytes(content)
            finally:
                # `zeroizable=True` sayesinde `content` gerçek bir
                # `bytearray` — `del` ile referansı kaldırmak yerine
                # (`bytes` sınırında olduğu gibi) burayı GERÇEKTEN
                # sıfırlayabiliyoruz. Hata olsa da (`write_bytes()`
                # patlarsa) çalışır — `finally`.
                zero_bytearray(content)
                del content

            db.log(
                "file_downloaded",
                target_type="file",
                target_id=file_id,
                detail=f"hwid={session_hwid} dest={hedef} bulk=True",
            )
            saved += 1
        except AuthenticationError:
            errors.append(f"{kisa} (bütünlük hatası)")
        except Exception as exc:
            errors.append(f"{kisa} ({exc})")

    return ExportResult(saved=saved, errors=errors, cancelled=cancelled)


def format_errors(errors: Sequence[str], *, limit: int = 10) -> str:
    """
    Hata listesini kullanıcıya gösterilecek metne çevirir.

    İlk `limit` tanesi listelenir, kalanı sayılır — yüzlerce dosyalık bir
    turda hata listesi ekranı taşırırdı.
    """
    if not errors:
        return ""
    gorunen = "\n".join(errors[:limit])
    if len(errors) > limit:
        gorunen += f"\n… ve {len(errors) - limit} daha"
    return gorunen
