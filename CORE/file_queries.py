"""
HYCLEUS — Dosya listeleme sorguları

`UI/main_window.py` içindeki dört liste görünümünün SQL'i burada. Daha önce
dördü de satır içi yazılıydı ve aynı dokuz sütunluk SELECT dört kez
kopyalanmıştı; biri değişince diğerlerinin ayrışmaması hiçbir şeyle
garanti değildi.

Taşınmasının nedeni yalnızca tekrar değil: satır içi SQL Qt olmadan
çalıştırılamıyordu, dolayısıyla test edilemiyordu. Bu dersin bedeli bir kez
ödendi — `files.added_by` kolonu tam da bu yüzden INSERT listesinden düşmüş
ve kimse fark etmemişti (bkz. CORE/file_records.py docstring'i).

Sözleşme
--------
Fonksiyonlar `sqlite3.Row` listesi döndürür ve HATA GÖSTERMEZ — istisnayı
çağırana bırakır. Kullanıcıya ne söyleneceği arayüzün kararı; CORE bir
diyalog açamaz (bkz. tests/test_layering.py).

Dönen sütun kümesi dördünde de aynı: `_FILE_COLUMNS`. Arayüzün
`_populate_table()` metodu bu sütunlara ada göre eriştiği için küme
sabittir — sütun eklemek serbest, ÇIKARMAK arayüzü kırar.


KORUNAN TUTARSIZLIK — mahrem etiket filtresi
--------------------------------------------
Mahrem etiket (`tags.is_private = 1`) taşıyan dosyalar yönetici olmayan
kullanıcılardan gizleniyor. Ama bu filtre dört görünümün yalnızca İKİSİNDE
uygulanıyor:

    files_by_label()   → filtre VAR      (include_private parametresi)
    search_files()     → filtre VAR      (include_private parametresi)
    files_by_tag()     → filtre YOK
    files_by_folder()  → filtre YOK  ← asıl boşluk

Etiket görünümü pratikte kapalı: mahrem etiketler yönetici olmayana
kenar çubuğunda hiç gösterilmiyor ve tıklanması ayrıca engelleniyor
(UI/main_window.py, `_refresh_tag_sidebar` ve `_on_tag_click`). Yani oraya
ulaşmanın yolu yok.

**Klasör görünümünde böyle bir engel yok.** Yönetici olmayan bir kullanıcı
bir klasöre girdiğinde, o klasördeki mahrem etiketli dosyaları GÖRÜR —
aynı dosyalar etiket görünümünde gizlenirken.

Bu davranış BİLEREK olduğu gibi taşındı. 2.7 saf bir yeniden düzenleme:
buradaki iş, mevcut davranışı test edilebilir hâle getirmek, düzeltmek
değil. Filtreyi dört görünüme birden uygulamak refactor'ü davranış
değişikliğine çevirirdi ve gerçek bir düzeltme olsaydı bile bu commit'te
gizlenmiş olurdu. Bulgu BACKLOG.md'ye yazıldı ve mevcut hâli
tests/test_file_queries.py içinde sabitlendi — yani düzeltildiğinde o test
bilinçli olarak güncellenecek.
"""
from __future__ import annotations

import sqlite3
from typing import Any

#: Dört görünümün de döndürdüğü sütunlar. `scan_reason` ilişkili alt
#: sorgudur: dosyanın EN SON karantina kaydının gerekçesi (JSON).
_FILE_COLUMNS = """
    f.id, f.filename, f.label, f.size_bytes, f.added_at,
    f.filepath, f.original_sha256, f.expires_at,
    (SELECT q.reason FROM quarantine q
     WHERE q.file_id = f.id
     ORDER BY q.quarantined_at DESC LIMIT 1) AS scan_reason
"""

#: Mahrem etiketli dosyaları dışarıda bırakan koşul. Alt sorgu takma adları
#: (`ft`, `t`) çağıran sorgudakilerle çakışmasın diye parametreli.
_EXCLUDE_PRIVATE = """
    AND f.id NOT IN (
            SELECT ft_p.file_id FROM file_tags ft_p
            INNER JOIN tags t_p ON t_p.id = ft_p.tag_id
            WHERE t_p.is_private = 1
        )
"""

#: Dört görünümün de sıralaması — en yeni önce.
_ORDER = "ORDER BY f.added_at DESC"

#: Etiket ADINA göre eşleşen dosya id'leri — aramanın üçüncü ayağı.
_FILES_MATCHING_TAG_NAME = """
    SELECT ft_s.file_id FROM file_tags ft_s
    INNER JOIN tags t_s ON t_s.id = ft_s.tag_id
    WHERE t_s.name LIKE ?
"""


def files_by_label(
    db: Any, label: str, *, include_private: bool = True
) -> list[sqlite3.Row]:
    """
    Bir etikete (`Genel` / `Kritik` / `Karantina` / `Imha`) ait dosyalar.

    Args:
        include_private: False ise mahrem etiket taşıyan dosyalar
                         listelenmez. Arayüz bunu role göre veriyor;
                         rol adlarını CORE bilmiyor.
    """
    gizle = "" if include_private else _EXCLUDE_PRIVATE
    return db.fetchall(
        f"SELECT {_FILE_COLUMNS} FROM files f WHERE f.label = ? {gizle} {_ORDER}",
        (label,),
    )


def files_by_tag(db: Any, tag_id: int) -> list[sqlite3.Row]:
    """
    Bir etikete atanmış dosyalar.

    Mahrem filtresi UYGULANMAZ — mevcut davranış birebir korunuyor. Pratikte
    kapalı olmasının nedeni arayüzün mahrem etiketleri yönetici olmayana hiç
    göstermemesi; sorgunun kendisi bir engel içermiyor. Bkz. modül
    docstring'i, "KORUNAN TUTARSIZLIK".
    """
    return db.fetchall(
        f"SELECT {_FILE_COLUMNS} FROM files f"
        f" INNER JOIN file_tags ft ON ft.file_id = f.id"
        f" WHERE ft.tag_id = ? {_ORDER}",
        (tag_id,),
    )


def files_by_folder(db: Any, folder_id: int) -> list[sqlite3.Row]:
    """
    Bir klasördeki dosyalar.

    Mahrem filtresi UYGULANMAZ ve burada arayüz tarafında da bir engel yok —
    yönetici olmayan bir kullanıcı klasöre girip mahrem etiketli dosyaları
    görebiliyor. Bilinen boşluk, bilerek olduğu gibi taşındı; bkz. modül
    docstring'i ve BACKLOG.md.
    """
    return db.fetchall(
        f"SELECT {_FILE_COLUMNS} FROM files f WHERE f.folder_id = ? {_ORDER}",
        (folder_id,),
    )


def search_files(
    db: Any, term: str, *, include_private: bool = True
) -> list[sqlite3.Row]:
    """
    Dosya adı, SHA-256 özeti ve etiket adı üzerinden arama.

    Üç alanda da LIKE `%term%` — yani parçalı eşleşme, büyük/küçük harf
    duyarsız (SQLite'ın ASCII LIKE davranışı; Türkçe karakterlerde harf
    katlaması YAPILMAZ, mevcut davranış budur).

    Boş terim burada ele alınmıyor: çağıran taraf boş aramada önceki
    görünüme dönüyor ve bu bir gezinme kararı, sorgu kararı değil.
    """
    gizle = "" if include_private else _EXCLUDE_PRIVATE
    like = f"%{term}%"
    return db.fetchall(
        f"SELECT {_FILE_COLUMNS} FROM files f"
        f" WHERE (f.filename LIKE ?"
        f"     OR f.original_sha256 LIKE ?"
        f"     OR f.id IN ({_FILES_MATCHING_TAG_NAME}))"
        f" {gizle} {_ORDER}",
        (like, like, like),
    )
