"""
HYCLEUS — Sırların eski konumundan güvenli biçimde silinmesi

Migration sırasında sır yeni yerine (anahtar kasası) taşındıktan sonra eski
kopyanın DELETE/unlink ile kaldırılması YETMEZ:

  · SQLite'ta silinen satırın byte'ları serbest sayfada kalır; ayrıca WAL
    modunda eski sayfa checkpoint'e kadar -wal dosyasında durur.
  · Dosya sisteminde unlink yalnızca dizin girdisini kaldırır; içerik
    üzerine yazılana kadar diskte okunabilir durumdadır.

Bu yüzden sıra şudur: ÖNCE üzerine rastgele yaz, SONRA sil, EN SON kalıntıyı
temizle (WAL checkpoint + VACUUM / fsync + truncate).

Dürüst uyarı — sınırlar
-----------------------
Üzerine yazma, verinin fiziksel olarak aynı sektöre gittiğini varsayar. SSD'de
wear leveling, kopyala-yaz dosya sistemleri (btrfs, ReFS), snapshot'lar ve
VM disk imajları bu varsayımı bozar. Buradaki işlemler "mantıksal katmanda
elimizden gelenin en iyisi"dir, donanım seviyesinde silme garantisi değildir.
Gerçek garanti için tam disk şifrelemesi gerekir.
"""
from __future__ import annotations

import os
import secrets
import sqlite3
from pathlib import Path

# Üzerine yazma tur sayısı — tek tur mantıksal katmanda yeterli,
# üç tur dosya sistemi önbelleğinin araya girme ihtimaline karşı ucuz sigorta.
_PASSES = 3


def random_text(length: int) -> str:
    """Verilen uzunlukta rastgele hex metin üretir (TEXT sütunu üzerine yazmak için)."""
    if length <= 0:
        return ""
    return secrets.token_hex((length // 2) + 1)[:length]


def overwrite_text_column(
    conn: sqlite3.Connection,
    *,
    table: str,
    column: str,
    where_column: str,
    where_value: str,
    passes: int = _PASSES,
) -> None:
    """
    Bir TEXT sütununun değerini rastgele veriyle üzerine yazar, sonra boşaltır.

    Satır SİLİNMEZ — yalnızca sütun temizlenir. HYCLEUS'ta usb_tokens satırı
    HWID kaydı, token_id ve blacklisted bayrağı için gereklidir; satırın
    tamamını silmek USB kimlik doğrulamasını bozar.

    Tablo ve sütun adları parametreleştirilemediği için (SQL sözdizimi) çağıran
    taraf bunları sabit literal olarak geçmelidir — kullanıcı girdisi ASLA.
    """
    row = conn.execute(
        f"SELECT length({column}) AS n FROM {table} WHERE {where_column} = ?",  # noqa: S608
        (where_value,),
    ).fetchone()
    if row is None or row["n"] is None:
        return

    original_len = int(row["n"])

    # 1) Aynı uzunlukta rastgele veriyle üzerine yaz — her tur ayrı commit,
    #    böylece her tur gerçekten diske iner
    for _ in range(passes):
        conn.execute(
            f"UPDATE {table} SET {column} = ? WHERE {where_column} = ?",  # noqa: S608
            (random_text(original_len), where_value),
        )
        conn.commit()

    # 2) Sütunu boşalt (NOT NULL kısıtı nedeniyle NULL değil, boş string)
    conn.execute(
        f"UPDATE {table} SET {column} = '' WHERE {where_column} = ?",  # noqa: S608
        (where_value,),
    )
    conn.commit()


def purge_sqlite_residue(conn: sqlite3.Connection) -> None:
    """
    WAL'ı ana dosyaya işleyip kısaltır ve VACUUM ile dosyayı baştan yazar.

    Sıralama önemli:
      1. wal_checkpoint(TRUNCATE) — -wal dosyasındaki eski sayfalar ana dosyaya
         işlenir ve WAL sıfırlanır; aksi halde düz metin -wal'da kalır
      2. VACUUM — veritabanı dosyası canlı sayfalardan yeniden inşa edilir,
         serbest sayfalardaki (silinmiş/üzerine yazılmış) kalıntı düşer

    VACUUM açık transaction içinde çalışmaz; çağırmadan önce commit edilmiş olmalı.
    """
    conn.commit()
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.OperationalError:
        # WAL modunda değilse checkpoint anlamsız — VACUUM yine de çalışır
        pass
    conn.execute("VACUUM")
    conn.commit()


def shred_file(path: Path, passes: int = _PASSES) -> bool:
    """
    Dosyanın içeriğini rastgele byte'larla üzerine yazar, kısaltır ve siler.

    Returns:
        True  — dosya vardı ve silindi
        False — dosya zaten yoktu

    Sıra: üzerine yaz → fsync (önbellekten diske zorla) → truncate → unlink.
    fsync olmadan üzerine yazma yalnızca sayfa önbelleğinde kalabilir ve
    unlink sonrası diske hiç inmeyebilir — yani orijinal içerik diskte kalır.
    """
    if not path.exists():
        return False

    size = path.stat().st_size
    if size > 0:
        with open(path, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
            f.seek(0)
            f.truncate(0)
            f.flush()
            os.fsync(f.fileno())

    path.unlink()
    return True
