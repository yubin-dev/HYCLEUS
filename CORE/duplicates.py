"""
HYCLEUS — Tekrar tespiti (aynı içerikli belgeler)

Bir dosya kasaya eklenmeden ÖNCE, aynı içeriğin zaten kayıtlı olup
olmadığını söyler. Kullanıcıya bir uyarı üretmek için var; bir engel değil.

Neden `original_sha256`
-----------------------
`files` tablosunda iki özet sütunu duruyor ve yalnızca biri canlı:

  · `original_sha256` — DÜZ METNİN özeti. `encrypt_file()` şifrelemeden önce
    hesaplayıp hem AAD'ye hem bu sütuna yazıyor. Tekrar tespitinin
    dayanabileceği tek alan bu.
  · `hash_sha256` — şemada var, HİÇBİR KOD YAZMIYOR. Ölü sütun; adı
    yüzünden bu iş için doğru yer sanılabilir. Bkz. BACKLOG B-014.

Ciphertext özeti bu iş için KULLANILAMAZDI: her şifreleme yeni bir nonce
kullanıyor, yani aynı belge iki kez eklendiğinde şifreli çıktıları
tamamen farklı oluyor. Aynılığı yalnızca düz metin özeti görebiliyor.

Çarpışma: SHA-256'da aynı özete sahip iki farklı belge pratikte
üretilemiyor. Yine de bu bir UYARI mekanizması, bir eşitlik ispatı değil —
karar kullanıcıda kalıyor ve yanlış bir eşleşmenin bedeli gereksiz bir
soru sormaktan ibaret.


Kapsam kararları — hangi dosyalar "zaten var" sayılıyor
--------------------------------------------------------
**İmha Odası HARİÇ.** `label = 'Imha'` taşıyan bir dosya silinmek üzere
sayaç bekliyor. "Bu belge zaten kayıtlı" demek yanıltıcı olurdu: kullanıcı
belgeyi bilerek imhaya göndermiş ve şimdi yeniden ekliyor olabilir — yani
tam olarak yapmak İSTEDİĞİ şeyi yapıyor. Uyarı, doğru eylemi sorgulatırdı.

**Karantina DAHİL.** Karantinadaki bir dosya hâlâ kasada duruyor ve
oradaki uyarı en değerli uyarı: "bu içerik zaten karantinada" bilgisi,
kullanıcının Defender'ın işaretlediği bir belgeyi farkında olmadan
yeniden yüklemesini engelliyor.

**Fiziksel olarak silinmiş dosyalar** zaten `files` tablosundan kalkıyor
(imha akışı satırı siliyor), dolayısıyla ayrı bir filtre gerekmiyor.


MAHREM ETİKET — tekrar tespiti bir SORGULAMA ARACINA dönüşmemeli
-----------------------------------------------------------------
Bu modülün en önemli kararı.

Mahrem etiketli (`tags.is_private = 1`) dosyalar yönetici olmayan
kullanıcılardan gizleniyor. Tekrar tespiti bu filtreyi UYGULAMASAYDI,
kendisi bir bilgi sızdırma kanalı olurdu:

    Yönetici olmayan biri eline geçirdiği bir belgeyi kasaya sürükler.
    "Bu belge zaten 'Yönetim Kurulu' klasöründe kayıtlı" uyarısını görür.
    Belgeyi eklemekten vazgeçer. Öğrendiği şey: o belge kasada VAR ve
    şurada duruyor — hiçbirini görme yetkisi olmadığı hâlde.

Bu bir tahmin oyunu değil, kesin bir yanıt: saldırgan elindeki her
adayı tek tek deneyerek kasanın içeriğini haritalayabilirdi. Listeleme
ekranlarında saklanan bilgi, yükleme ekranından sızardı.

Bu yüzden `include_private` parametresi var ve VARSAYILANI False.
Yönetici olmayan bir kullanıcı için mahrem bir eşleşme HİÇ DÖNMÜYOR:
uyarı çıkmıyor, dosya ikinci kez ekleniyor. Takas bilinçli — gereksiz bir
kopya, yetkisiz bir ifşadan iyidir.

Parametre bir rol ADI değil bir bool; `CORE/file_queries.py` ile aynı
sözleşme, aynı gerekçe: rolü yorumlamak arayüzün işi.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_log = logging.getLogger("hycleus.duplicates")

#: Okuma blok boyu — CORE/crypto.py ile aynı.
_CHUNK = 64 * 1024

#: Tekrar sayılmayan etiket; gerekçe modül docstring'inde.
EXCLUDED_LABEL = "Imha"

#: Mahrem etiketli dosyaları dışarıda bırakan koşul. Takma adlar
#: (`ft_p`, `t_p`) çağıran sorgudakilerle çakışmasın diye ayrı.
_EXCLUDE_PRIVATE = """
    AND f.id NOT IN (
            SELECT ft_p.file_id FROM file_tags ft_p
            INNER JOIN tags t_p ON t_p.id = ft_p.tag_id
            WHERE t_p.is_private = 1
        )
"""

_QUERY = """
SELECT f.id, f.filename, f.label, f.added_at,
       fo.name AS folder_name,
       (SELECT group_concat(t.name, ', ')
          FROM file_tags ft
          INNER JOIN tags t ON t.id = ft.tag_id
         WHERE ft.file_id = f.id
         ORDER BY t.name) AS tag_names
  FROM files f
  LEFT JOIN folders fo ON fo.id = f.folder_id
 WHERE f.original_sha256 = ?
   AND f.label <> ?
"""

_ORDER = " ORDER BY f.added_at DESC, f.id DESC"


@dataclass(frozen=True)
class DuplicateMatch:
    """Aynı içeriğe sahip, kasada zaten kayıtlı bir dosya."""

    file_id: int
    filename: str
    label: str
    folder_name: str | None
    tags: tuple[str, ...]
    added_at: str

    def location(self) -> str:
        """
        Dosyanın NEREDE olduğunu tek satırda anlatır.

        Kullanıcının sorusu "bu belge nerede duruyor" — cevabı klasör ve
        etiket. İkisi de yoksa geriye etiket (`label`) kalıyor; o her
        dosyada var.
        """
        parcalar: list[str] = []
        if self.folder_name:
            parcalar.append(f"'{self.folder_name}' klasöründe")
        if self.tags:
            parcalar.append(f"etiket: {', '.join(self.tags)}")
        if not parcalar:
            parcalar.append(f"'{self.label}' sekmesinde")
        return ", ".join(parcalar)

    def describe(self) -> str:
        return f"{self.filename} — {self.location()} (eklenme: {self.added_at})"


def sha256_of_file(path: Path | str) -> str:
    """
    Bir dosyanın düz metin SHA-256 özeti (hex).

    `crypto.encrypt_file()`'ın AAD'ye yazdığı `original_sha256` ile AYNI
    değeri üretiyor — aynı algoritma, aynı blok okuma.

    Neden `encrypt_file()`'a hazır özet GEÇİRİLMİYOR
    ------------------------------------------------
    Tekrar kontrolü şifrelemeden önce yapılıyor, yani dosya iki kez
    okunuyor: bir kez burada, bir kez `encrypt_file()` içinde. Bu tekrarı
    `encrypt_file(original_sha256=...)` gibi bir parametreyle silmek
    mümkündü ama BİLEREK yapılmadı.

    AAD'deki özetin değeri, onu şifrelenen baytlardan `encrypt_file()`'ın
    KENDİSİNİN hesaplamasından geliyor. Dışarıdan enjekte edilebilir
    olsaydı, yanlış bir değer AAD'ye girer ve GCM tag'i o yalanı
    doğrulanmış gibi gösterirdi. 3.1b'den beri o özet ayrıca RFC 3161
    zaman damgasına imzalatılıyor — yani hatalı bir özet, bir TSA
    tarafından imzalanmış bir yalana dönüşürdü.

    Bir dosya okumasının bedeli bu değil. Ölçüm: 150 küçük belge 0,61 s,
    500 MB'lık tek dosya 0,27 s.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(_CHUNK):
            h.update(chunk)
    return h.hexdigest()


def find_duplicates_by_hash(
    db: Any, sha256: str, *, include_private: bool = False
) -> list[DuplicateMatch]:
    """
    Verilen özete sahip, kasada kayıtlı dosyaları döndürür.

    Args:
        sha256: Düz metin SHA-256 (hex). Boşsa boş liste döner.
        include_private: True ise mahrem etiketli dosyalar da dâhil.
            Yalnızca yönetici için True geçilmeli — gerekçe modül
            docstring'inde ("tekrar tespiti bir sorgulama aracına
            dönüşmemeli").

    Returns:
        En yeni önce sıralı eşleşmeler. Boş liste = tekrar yok.

    Adı ÇOĞUL: aynı belge birden fazla klasörde kayıtlı olabiliyor ve
    kullanıcıya hepsini göstermek gerekiyor. Tek bir eşleşme döndürmek,
    "başka nerede var" sorusunu yanıtsız bırakırdı.

    CORE sözleşmesi gereği hata GÖSTERMEZ, istisnayı çağırana bırakır.
    """
    if not sha256:
        return []

    sql = _QUERY + ("" if include_private else _EXCLUDE_PRIVATE) + _ORDER
    rows = db.fetchall(sql, (sha256, EXCLUDED_LABEL))
    return [
        DuplicateMatch(
            file_id=r["id"],
            filename=r["filename"],
            label=r["label"],
            folder_name=r["folder_name"],
            tags=tuple(
                t.strip() for t in (r["tag_names"] or "").split(",") if t.strip()
            ),
            added_at=r["added_at"],
        )
        for r in rows
    ]


def find_duplicates_for_file(
    db: Any, path: Path | str, *, include_private: bool = False
) -> tuple[str, list[DuplicateMatch]]:
    """
    Bir dosyayı hash'leyip tekrarlarını arar.

    Returns:
        (sha256_hex, eşleşmeler) — özet de dönüyor çünkü çağıran onu
        günlüğe yazmak isteyebiliyor.
    """
    digest = sha256_of_file(path)
    return digest, find_duplicates_by_hash(db, digest, include_private=include_private)


def format_duplicate_warning(filename: str, matches: list[DuplicateMatch]) -> str:
    """
    Kullanıcıya gösterilecek uyarı metni.

    Metin CORE'da çünkü biçimlendirme mantığı Qt gerektirmiyor ve testi
    arayüzsüz yazılabiliyor — `CORE/expiry.format_countdown()` ve
    `CORE/export.format_errors()` ile aynı desen. Diyaloğu AÇMAK yine
    arayüzün işi.
    """
    if not matches:
        return ""
    if len(matches) == 1:
        bas = f"'{filename}' ile aynı içerikli bir belge zaten kayıtlı:"
    else:
        bas = (
            f"'{filename}' ile aynı içerikli {len(matches)} belge zaten kayıtlı:"
        )
    satirlar = "\n".join(f"  • {m.describe()}" for m in matches)
    return f"{bas}\n\n{satirlar}"


def log_duplicate_decision(
    db: Any,
    *,
    filename: str,
    sha256: str,
    matches: list[DuplicateMatch],
    added_anyway: bool,
    user_id: int | None = None,
) -> None:
    """
    Tekrar kararını denetim kaydına yazar.

    Neden kaydediliyor: "bu belge neden iki kez var" sorusu sonradan
    sorulduğunda yanıtı bir yerde durmalı. Kayıt, kullanıcının uyarıyı
    GÖRDÜĞÜNÜ ve bilerek devam ettiğini gösteriyor — mükerrer kayıt bir
    kaza değil, bir karar.
    """
    eylem = "duplicate_added_anyway" if added_anyway else "duplicate_skipped"
    db.log(
        eylem,
        user_id=user_id,
        detail=(
            f"filename={filename} sha256={sha256[:16]}… "
            f"matches={len(matches)} ids={[m.file_id for m in matches]}"
        ),
    )


__all__ = [
    "EXCLUDED_LABEL",
    "DuplicateMatch",
    "find_duplicates_by_hash",
    "find_duplicates_for_file",
    "format_duplicate_warning",
    "log_duplicate_decision",
    "sha256_of_file",
]
