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


GİDERİLEN TUTARSIZLIK — mahrem etiket filtresi (B-007)
------------------------------------------------------
Mahrem etiket (`tags.is_private = 1`) taşıyan dosyalar yönetici olmayan
kullanıcılardan gizleniyor. Bu filtre artık **dört görünümde de** var:

    files_by_label()   → include_private
    search_files()     → include_private
    files_by_tag()     → include_private   ← B-007'de eklendi
    files_by_folder()  → include_private   ← B-007'de eklendi, asıl boşluk

Eskiden yalnızca ilk ikisinde vardı. Etiket görünümü pratikte kapalıydı
(mahrem etiketler yönetici olmayana kenar çubuğunda hiç çizilmiyor ve
tıklanması ayrıca engelleniyor), ama **klasör görünümünde hiçbir engel
yoktu**: yönetici olmayan bir kullanıcı klasöre girdiğinde o klasördeki
mahrem dosyaları görüyordu — aynı dosyalar aramada gizlenirken.

Arayüz engelleri KALDIRILMADI. İki katman birlikte duruyor: kenar
çubuğu mahrem etiketi çizmiyor, sorgu da satırı döndürmüyor. Kenar
çubuğu mantığı bir gün değişirse sorgu artık ikinci bir engel sunuyor —
eskiden sunmuyordu.

Varsayılan `include_private=True` olarak KALDI. Ters çevirmek daha
"güvenli" görünürdü ama sessiz bir davranış değişikliği olurdu: parametre
geçmeyen her çağrı aniden veri gizlemeye başlardı ve bunun fark edilme
yolu, kullanıcının dosyasını kaybetmesi olurdu. Çağrı yerlerinin dördü de
parametreyi açıkça veriyor; bunu `tests/test_file_queries.py` içindeki
AST denetimi koruyor.


Rol adı katman sınırında kalıyor
--------------------------------
`include_private` bilerek bir bool: `"Yönetici"` bir arayüz sabiti ve
CORE onu bilmiyor (bkz. tests/test_layering.py). Rol → yetki eşlemesini
CORE'a taşımak ayrı bir iş; vault rolü ile `users.role` sütunu farklı
şeyler.
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


def files_by_tag(
    db: Any, tag_id: int, *, include_private: bool = True
) -> list[sqlite3.Row]:
    """
    Bir etikete atanmış dosyalar.

    Args:
        include_private: False ise mahrem etiket taşıyan dosyalar
                         listelenmez (B-007).

    NOT: `include_private=False` iken MAHREM ETİKETİN KENDİSİ sorgulansa
    bile sonuç boş döner — dosya, sorgulanan etiket yüzünden mahrem
    sayılıyor. Bu doğru davranış: filtre "bu dosya mahrem mi", "hangi
    etiketten geldi" değil.
    """
    gizle = "" if include_private else _EXCLUDE_PRIVATE
    return db.fetchall(
        f"SELECT {_FILE_COLUMNS} FROM files f"
        f" INNER JOIN file_tags ft ON ft.file_id = f.id"
        f" WHERE ft.tag_id = ? {gizle} {_ORDER}",
        (tag_id,),
    )


def files_by_folder(
    db: Any, folder_id: int, *, include_private: bool = True
) -> list[sqlite3.Row]:
    """
    Bir klasördeki dosyalar.

    Args:
        include_private: False ise mahrem etiket taşıyan dosyalar
                         listelenmez (B-007).

    B-007'nin asıl boşluğu buradaydı: bu görünümde arayüz tarafında da
    hiçbir engel yoktu, yani mahrem dosyalar yönetici olmayana gerçekten
    görünüyordu.
    """
    gizle = "" if include_private else _EXCLUDE_PRIVATE
    return db.fetchall(
        f"SELECT {_FILE_COLUMNS} FROM files f"
        f" WHERE f.folder_id = ? {gizle} {_ORDER}",
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
