"""
HYCLEUS — Şifrelenmiş dosya kaydının veritabanına yazılması

Tek iş yapar: `files` tablosuna upsert. Kendi modülünde olmasının nedeni,
bu SQL'in daha önce `UI/main_window.py` içinde satır içi durması ve tam da
bu yüzden test edilememesiydi — Qt olmadan çalıştırılamayan bir kod yolu
gözden kaçan bir kolon barındırıyordu (bkz. `added_by`, BACKLOG B-005).

added_by — kim yükledi
----------------------
Kolon şemada ilk günden beri vardı ama INSERT listesinde YOKTU; yani her
dosyanın sahibi NULL kalıyordu. Değer zaten elde duruyordu: worker
`self._user_id` taşıyor ve `encrypt_file(..., user_id=...)` çağrısında
kullanıyordu — yalnızca veritabanına yazılmıyordu.

ON CONFLICT dalında added_by KORUNUR — ezilmez
----------------------------------------------
Aynı `filepath` yeniden yazıldığında (aynı dosyanın tekrar eklenmesi)
`DO UPDATE` içeriği tazeler: ad, etiket, boyut, özet, AAD, klasör. İki kolon
bilerek dışarıda:

  · `added_at` — zaten güncellenmiyordu. Anlamı "İLK kayıt tarihi".
  · `added_by` — bu yüzden o da güncellenmiyor. Anlamı "İLK kaydeden".

İkisi bir çifttir. Biri korunup diğeri güncellenseydi kayıt kendi içinde
tutarsız olurdu: 2020 tarihli bir kaydın sahibi 2026'da dosyaya dokunan
kişi görünürdü.

`COALESCE(files.added_by, excluded.added_by)` de KULLANILMIYOR — yani eski
NULL kayıtlar yeniden yükleme sırasında doldurulmuyor. Bu kasıtlı: o dosyayı
gerçekte kimin yüklediğini bilmiyoruz, sonradan dokunan kişiyi sahip yazmak
veriyi tahmin etmek olurdu. Eski kayıtlar NULL kalır ve envanter raporunda
dürüstçe "bilinmiyor" görünür.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from DB.db_manager import DBManager

_UPSERT = """
INSERT INTO files
    (filename, filepath, label, size_bytes, expires_at,
     original_sha256, aad_metadata, folder_id, added_by)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(filepath) DO UPDATE SET
    filename        = excluded.filename,
    label           = excluded.label,
    size_bytes      = excluded.size_bytes,
    expires_at      = excluded.expires_at,
    original_sha256 = excluded.original_sha256,
    aad_metadata    = excluded.aad_metadata,
    folder_id       = excluded.folder_id
    -- added_at ve added_by bilerek yok: ilk kayıt bilgisi korunur (docstring)
"""


def record_encrypted_file(
    db: DBManager,
    *,
    filename: str,
    filepath: str,
    label: str,
    size_bytes: int | None = None,
    expires_at: str | None = None,
    original_sha256: str | None = None,
    aad_metadata: str | None = None,
    folder_id: int | None = None,
    added_by: int | None = None,
) -> int:
    """
    Şifrelenmiş dosyanın kaydını yazar (yoksa ekler, varsa tazeler).

    Args:
        added_by: dosyayı ekleyen kullanıcının id'si. Yalnızca İLK kayıtta
                  yazılır; mevcut bir satır tazelenirken dokunulmaz.

    Returns:
        `files.id`.

    Raises:
        RuntimeError: kayıt yazıldıktan sonra geri okunamazsa.
    """
    db.execute(
        _UPSERT,
        (
            filename,
            filepath,
            label,
            size_bytes,
            expires_at,
            original_sha256,
            aad_metadata,
            folder_id,
            added_by,
        ),
    )
    row = db.fetchone("SELECT id FROM files WHERE filepath = ?", (filepath,))
    if row is None:
        raise RuntimeError(f"files kaydı bulunamadı: {filepath}")
    return int(row["id"])
