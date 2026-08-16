"""
HYCLEUS — Klasör işlemleri

Klasör oluşturma, silme, içeriğini İmha Odası'na taşıma ve dosya atama.
Bu mantık `UI/main_window.py` içinde satır içi yazılıydı ve Qt olmadan
çalıştırılamadığı için test edilmemişti.

Onay diyalogları ve gezinme kararları (silinen klasör açıksa "Genel"e dön)
UI'da KALDI — bunlar arayüz kararları. Burada yalnızca veritabanına ne
yazıldığı var.


KORUNAN DAVRANIŞ — silinen klasörün dosyaları SİLİNMEZ
------------------------------------------------------
`delete_folder()` yalnızca klasörü kaldırıyor; içindeki dosyalar
`folder_id = NULL` alıp kök seviyesine çıkıyor. Kullanıcıya gösterilen
onay metni de bunu söylüyor ("Dosyalar klasörden çıkarılır ama silinmez").

Şema `folders.parent_id` üzerinde `ON DELETE CASCADE` taşıyor, yani ALT
KLASÖRLER siliniyor — ama alt klasörlerdeki dosyalar için `folder_id`
temizliği YAPILMIYOR: `files.folder_id` yabancı anahtarı
`ON DELETE SET NULL` olduğu için veritabanı onları da NULL'a çekiyor.
Sonuç doğru ama iki farklı mekanizmadan geliyor; biri açık SQL, diğeri
şema kısıtı.


KALDIRILAN KAÇAMAK — artık kullanıcı satırı UYDURULMUYOR (B-011)
----------------------------------------------------------------
`create_folder()` eskiden, `owner_id` `users` tablosunda yoksa onu
uyduruyordu ("yonetici", boş parola hash'i, `admin` rolü). Sebep
`folders.owner_id` yabancı anahtarıydı: `users` satırı yazılmamış bir
oturumda klasör oluşturma FK hatasıyla düşerdi.

Kök neden burada değildi. `main.py` `HycleusWindow`'a `user_id` hiç
geçmiyordu, yani oturum kim olursa olsun sahip **1** numaralı kullanıcı
oluyordu; o satır da çoğu zaman yoktu. Kaçamak, eksik bir giriş adımını
yanlış katmanda örtüyordu.

Artık giriş akışı `CORE.session_user.sync_session_user()` ile oturumu
gerçek bir `users.id`'ye bağlıyor ve o id buraya geliyor. Dolayısıyla
`create_folder()` FK hatasını **bastırmıyor**: sahip yoksa bu bir
programlama hatasıdır ve görünmesi gerekir.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from CORE.expiry import expiry_from_now

_log = logging.getLogger("hycleus.folders")


@dataclass(frozen=True)
class FolderInfo:
    """Kenar çubuğunda gösterilen klasör satırı."""

    id: int
    name: str
    file_count: int


def list_folders(db: Any) -> list[FolderInfo]:
    """Tüm klasörler, içerdikleri dosya sayısıyla birlikte (ada göre sıralı)."""
    rows = db.fetchall(
        "SELECT fo.id, fo.name,"
        "       (SELECT COUNT(*) FROM files f WHERE f.folder_id = fo.id) AS n"
        " FROM folders fo ORDER BY fo.name"
    )
    return [FolderInfo(id=r["id"], name=r["name"], file_count=r["n"]) for r in rows]


def create_folder(
    db: Any,
    name: str,
    *,
    owner_id: int,
    hwid: str | None = None,
    audit_extra: str | None = None,
) -> int:
    """
    Klasör oluşturur ve id'sini döndürür.

    Ad kırpılıyor (`strip`) — mevcut davranış. BOŞ ad kontrolü burada
    DEĞİL: arayüz zaten boş girişte diyaloğu kapatıyor ve o bir arayüz
    doğrulaması.

    Args:
        audit_extra: Denetim kaydı detayının SONUNA eklenecek ek alanlar
            (ör. `"via=drag_drop files=12"`). Sürükle-bırak akışı kendi
            INSERT'ünü yaparken bu bilgiyi yazıyordu; tek uygulamada
            birleşirken kaybolmasın diye parametreye alındı. Alan sırası
            mevcut kayıtlarla birebir aynı kalıyor.

    Raises:
        sqlite3.IntegrityError: `owner_id` `users` tablosunda yoksa.
            Bu hata artık BASTIRILMIYOR (B-011): oturum kullanıcısı
            giriş anında `CORE.session_user.sync_session_user()` ile
            yazılıyor, dolayısıyla eksik sahip bir programlama hatasıdır.
    """
    temiz = name.strip()
    cur = db.execute(
        "INSERT INTO folders (name, owner_id) VALUES (?, ?)", (temiz, owner_id)
    )
    detay = f"name={temiz} hwid={hwid}"
    if audit_extra:
        detay = f"{detay} {audit_extra}"
    db.log("folder_created", detail=detay)
    return int(cur.lastrowid)


def delete_folder(db: Any, folder_id: int, folder_name: str) -> int:
    """
    Klasörü siler; içindeki dosyalar KALIR, yalnızca klasörden çıkar.

    Returns:
        Klasörden çıkarılan dosya sayısı.
    """
    rows = db.fetchall("SELECT id FROM files WHERE folder_id = ?", (folder_id,))
    db.execute("UPDATE files SET folder_id = NULL WHERE folder_id = ?", (folder_id,))
    db.execute("DELETE FROM folders WHERE id = ?", (folder_id,))
    db.log(
        "folder_deleted", target_type="folder", target_id=folder_id,
        detail=f"name={folder_name}",
    )
    return len(rows)


def move_folder_to_imha(
    db: Any, folder_id: int, *, hwid: str | None = None
) -> int:
    """
    Klasördeki tüm dosyaları İmha Odası'na taşır ve sayacı kurar.

    Returns:
        Taşınan dosya sayısı.

    Her dosya için AYRI denetim kaydı yazılıyor — mevcut davranış. Tek bir
    özet kayıt daha derli toplu olurdu ama dosya bazlı sorgulanabilirliği
    kaybederdi (`target_id` ile hangi dosyanın ne zaman imhaya gittiği).
    """
    expires_at = expiry_from_now(db)
    rows = db.fetchall("SELECT id FROM files WHERE folder_id = ?", (folder_id,))
    for row in rows:
        db.execute(
            "UPDATE files SET label = 'Imha', expires_at = ? WHERE id = ?",
            (expires_at, row["id"]),
        )
        db.log(
            "file_moved_to_imha", target_type="file", target_id=row["id"],
            detail=(
                f"hwid={hwid} via=folder folder_id={folder_id}"
                f" expires_at={expires_at}"
            ),
        )
    return len(rows)


def assign_file_to_folder(
    db: Any, file_id: int, folder_id: int | None, *, hwid: str | None = None
) -> None:
    """
    Dosyayı bir klasöre atar; `folder_id=None` klasörden çıkarır.
    """
    db.execute("UPDATE files SET folder_id = ? WHERE id = ?", (folder_id, file_id))
    # Alan sırası (folder_id önce, hwid sonra) mevcut kayıtlarla aynı kalsın
    # diye korunuyor — denetim kaydı geriye dönük ayrıştırılabilir olmalı.
    db.log(
        "file_moved_to_folder", target_type="file", target_id=file_id,
        detail=f"folder_id={folder_id} hwid={hwid}",
    )
