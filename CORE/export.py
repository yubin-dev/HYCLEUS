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

Çözülmüş içerik yine de bellekte tam olarak bulunuyor (`decrypt_file`
`bytes` döndürüyor) ve yazıldıktan sonra referans kaldırılıyor. Sınır
SECURITY.md §3'te anlatılan sınırın aynısı: `bytes` değiştirilemez,
silinemez.


KORUNAN FARK — hwid geri dönüşü
-------------------------------
İki akış AAD'da hwid bulunmadığında FARKLI davranıyor:

    ZIP     : hwid = aad_hwid or (DEV-HWID-1234 / oturum hwid'i)
              → AAD'da yoksa oturum hwid'iyle doğrulama YAPILIR
    Dizine  : hwid = aad_hwid  (yoksa None)
              → AAD'da yoksa hwid doğrulaması HİÇ YAPILMAZ

Yani eski kayıtlarda (AAD'sız ya da hwid'siz) ZIP indirme
`AuthenticationError` verip dosyayı atlarken, toplu indirme aynı dosyayı
sorunsuz çözüyor. Hangisinin doğru olduğu ayrı bir tartışma —
`hwid_fallback` parametresi bu farkı görünür kılıyor ve iki çağıran da
bugünkü değerini geçiriyor. Davranış birebir korundu.
"""
from __future__ import annotations

import json
import logging
import zipfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from CORE.crypto import AuthenticationError, decrypt_file

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
        session_hwid:    denetim kaydına yazılır (dosya doğrulamasında
                         KULLANILMAZ — bkz. hwid_fallback).
        on_progress:     her dosyadan önce (sıra_no, kısa_ad) ile çağrılır.
        should_continue: False dönerse döngü durur ve `cancelled=True`.

    N+1 SORGU — bilerek korundu: her dosya için `aad_metadata` ayrı bir
    sorguyla okunuyor. Tek bir `WHERE id IN (...)` ile toplanabilirdi ve
    öyle olmalı, ama bu 2.7'de saf refactor kuralı gereği değiştirilmedi.
    Bkz. BACKLOG.md B-009.
    """
    hedef_dizin = Path(dest_dir)
    errors: list[str] = []
    saved = 0
    cancelled = False

    for index, (file_id, filepath) in enumerate(items):
        if should_continue is not None and not should_continue():
            cancelled = True
            break

        kisa = Path(filepath).name if filepath else "?"
        if on_progress is not None:
            on_progress(index, kisa)

        if not filepath:
            errors.append(f"#{file_id} (dosya yolu yok)")
            continue

        try:
            # B-009: döngü içi sorgu — mevcut davranış korunuyor.
            aad_row = db.fetchone(
                "SELECT aad_metadata FROM files WHERE id = ?", (file_id,)
            )
            hwid = aad_hwid_of(aad_row["aad_metadata"] if aad_row else None)
            hwid = hwid or hwid_fallback

            content, meta = decrypt_file(filepath, key, hwid=hwid)
            try:
                hedef = unique_path(
                    hedef_dizin, meta.get("filename", Path(filepath).stem)
                )
                hedef.write_bytes(content)
            finally:
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
