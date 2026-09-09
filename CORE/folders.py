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
    parent_id: int | None = None


def list_folders(db: Any) -> list[FolderInfo]:
    """Tüm klasörler, içerdikleri dosya sayısı VE üst klasörüyle (ada göre sıralı).

    `parent_id` B-123'te eklendi — kenar çubuğu bunu ağaç olarak
    (derinlik/girinti) render etmek için kullanıyor. Sıralama hâlâ ada
    göre, düz liste; hiyerarşiyi kuran (ebeveyn→çocuk eşlemesi) çağıran
    taraf (`UI/main_window_tree.py::_refresh_folder_sidebar()`).
    """
    rows = db.fetchall(
        "SELECT fo.id, fo.name, fo.parent_id,"
        "       (SELECT COUNT(*) FROM files f WHERE f.folder_id = fo.id) AS n"
        " FROM folders fo ORDER BY fo.name"
    )
    return [
        FolderInfo(id=r["id"], name=r["name"], file_count=r["n"], parent_id=r["parent_id"])
        for r in rows
    ]


def create_folder(
    db: Any,
    name: str,
    *,
    owner_id: int,
    hwid: str | None = None,
    parent_id: int | None = None,
    audit_extra: str | None = None,
) -> int:
    """
    Klasör oluşturur ve id'sini döndürür.

    Ad kırpılıyor (`strip`) — mevcut davranış. BOŞ ad kontrolü burada
    DEĞİL: arayüz zaten boş girişte diyaloğu kapatıyor ve o bir arayüz
    doğrulaması.

    Args:
        parent_id: Verilirse yeni klasör onun ALTINA oluşturulur (B-123).
            `None` (varsayılan) kök seviyede oluşturur — eski davranış
            AYNEN korunuyor, mevcut TÜM çağıranlar hiç değişmeden kök
            klasör üretmeye devam ediyor.
        audit_extra: Denetim kaydı detayının SONUNA eklenecek ek alanlar
            (ör. `"via=drag_drop files=12"`). Sürükle-bırak akışı kendi
            INSERT'ünü yaparken bu bilgiyi yazıyordu; tek uygulamada
            birleşirken kaybolmasın diye parametreye alındı. Alan sırası
            mevcut kayıtlarla birebir aynı kalıyor.

    Raises:
        sqlite3.IntegrityError: `owner_id` `users` tablosunda yoksa, ya da
            `parent_id` `folders` tablosunda yoksa.
            Eksik sahip artık BASTIRILMIYOR (B-011): oturum kullanıcısı
            giriş anında `CORE.session_user.sync_session_user()` ile
            yazılıyor, dolayısıyla eksik sahip bir programlama hatasıdır.
    """
    temiz = name.strip()
    cur = db.execute(
        "INSERT INTO folders (name, owner_id, parent_id) VALUES (?, ?, ?)",
        (temiz, owner_id, parent_id),
    )
    detay = f"name={temiz} hwid={hwid}"
    if parent_id is not None:
        detay = f"{detay} parent_id={parent_id}"
    if audit_extra:
        detay = f"{detay} {audit_extra}"
    db.log("folder_created", detail=detay)
    return int(cur.lastrowid)


def is_descendant(db: Any, hedef_id: int, tasinan_id: int) -> bool:
    """
    `hedef_id`, `tasinan_id`'nin KENDİSİ mi ya da ALT AĞACINDA mı (B-123)?

    `move_folder()`'ın döngü koruması burada: bir klasörü kendi alt
    ağacının içine (ya da kendisine) taşımak `parent_id` zincirinde
    sonsuz döngü yaratırdı — DB seviyesinde bunu engelleyen bir kısıt
    YOK (`parent_id` düz bir FK, döngü kontrolü taşımıyor).

    `hedef_id`'den başlayıp `parent_id` zincirinde KÖKE doğru yürüyor;
    yolda `tasinan_id`'ye rastlarsa `hedef_id` onun alt ağacındadır —
    yani bu taşıma YASAK. `gorulen` kümesi yalnızca savunma amaçlı:
    zaten bozulmuş (elle DB düzenlemesiyle oluşmuş) bir döngüye
    rastlarsa sonsuz döngüye GİRMEDEN `False` döner.
    """
    if hedef_id == tasinan_id:
        return True
    simdi = hedef_id
    gorulen = {simdi}
    while True:
        row = db.fetchone("SELECT parent_id FROM folders WHERE id = ?", (simdi,))
        if row is None or row["parent_id"] is None:
            return False
        simdi = row["parent_id"]
        if simdi == tasinan_id:
            return True
        if simdi in gorulen:
            return False
        gorulen.add(simdi)


def move_folder(
    db: Any, folder_id: int, new_parent_id: int | None, *, hwid: str | None = None
) -> None:
    """
    Klasörü başka bir üst klasörün altına (ya da köke) taşır (B-123).

    Raises:
        ValueError: `new_parent_id`, `folder_id`'nin kendisi ya da alt
            ağacındaki bir klasörse — döngü oluştururdu.
    """
    if new_parent_id is not None and is_descendant(db, new_parent_id, folder_id):
        raise ValueError(
            "Bir klasör kendisinin ya da alt klasörünün içine taşınamaz."
        )
    db.execute(
        "UPDATE folders SET parent_id = ? WHERE id = ?", (new_parent_id, folder_id)
    )
    db.log(
        "folder_moved", target_type="folder", target_id=folder_id,
        detail=f"yeni_parent_id={new_parent_id} hwid={hwid}",
    )


def folder_subtree_summary(db: Any, folder_id: int) -> tuple[list[int], int]:
    """
    `folder_id` VE tüm alt ağacındaki klasör id'leri + bu klasörlerdeki
    TOPLAM dosya sayısı (B-123) — silme onay diyaloğu için.

    Silme `ON DELETE CASCADE` ile ÇOK SEVİYELİ kademelenir (canlı
    doğrulandı: torun/torun-torun fark etmeksizin TÜM alt ağaç gider,
    tek seviye değil) — bu fonksiyon o gerçek kapsamı SİLMEDEN ÖNCE
    kullanıcıya göstermek için hesaplıyor.
    """
    tum_id = [folder_id]
    kuyruk = [folder_id]
    while kuyruk:
        simdi = kuyruk.pop()
        for cocuk in db.fetchall("SELECT id FROM folders WHERE parent_id = ?", (simdi,)):
            tum_id.append(cocuk["id"])
            kuyruk.append(cocuk["id"])

    yer_tutucular = ",".join("?" * len(tum_id))
    row = db.fetchone(
        f"SELECT COUNT(*) AS n FROM files WHERE folder_id IN ({yer_tutucular})",
        tum_id,
    )
    return tum_id, (int(row["n"]) if row else 0)


def delete_folder(db: Any, folder_id: int, folder_name: str) -> int:
    """
    Klasörü VE TÜM ALT AĞACINI siler; içindeki (ve alt klasörlerindeki)
    dosyalar KALIR, yalnızca klasörden çıkar (B-123 — eskiden yalnızca
    TEK klasör siliniyordu, alt klasör kavramı yoktu).

    Dosyaların `folder_id`'sini `NULL`'a çekme işi artık ELLE
    yapılmıyor: `files.folder_id` üzerindeki `ON DELETE SET NULL` FK
    eylemi, silinen HER klasör (kök + tüm alt ağaç) için bunu OTOMATİK
    yapıyor — canlı doğrulandı (bkz. modül üstü not / BACKLOG B-123).

    Returns:
        Klasörden çıkarılan (kök + tüm alt ağaçtaki) TOPLAM dosya sayısı.
    """
    _, dosya_sayisi = folder_subtree_summary(db, folder_id)
    db.execute("DELETE FROM folders WHERE id = ?", (folder_id,))
    db.log(
        "folder_deleted", target_type="folder", target_id=folder_id,
        detail=f"name={folder_name}",
    )
    return dosya_sayisi


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
