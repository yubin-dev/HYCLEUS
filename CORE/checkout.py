"""
HYCLEUS — Şeffaf erişim (çöz → düzenle → geri şifrele)

Kullanıcı belgeyi açıyor, düzenliyor, kapatıyor. Şifre çözmeyi, geri
şifrelemeyi ve geçici kopyayı silmeyi HYCLEUS yapıyor. Kapatılan boşluk
şuydu: indirilen bir belge diskte düz metin olarak kalıyordu ve kullanıcı
onu geri şifrelemeyi hatırlamak zorundaydı.

Bu modül Qt İÇERMEZ. Dosya izleyici ve uygulama başlatma arayüz
katmanında (`UI/main_window_open.py`); burada olan her şey — kayıt
defteri, değişiklik tespiti, atomik geri yazma, güvenli silme — başsız
test edilebiliyor.

Tam sanal sürücü (Dokan/WinFsp) kapsam dışı; bu bir ara çözüm.


"KAPANDI" DİYE BİR OLAY YOK — bu yüzden model check-out/check-in
-----------------------------------------------------------------
İlk tasarım refleksi "varsayılan uygulama kapanınca geri şifrele" oluyor.
Bu tespit edilemez:

  · `os.startfile()` hemen dönüyor ve bir tutamaç vermiyor.
  · `subprocess.Popen` ile açılsa bile Windows'ta çoğu uygulama bir
    başlatıcı süreç çalıştırıyor; o süreç dosyayı ZATEN AÇIK olan asıl
    uygulamaya devredip anında çıkıyor. "Süreç bitti" = "belge kapandı"
    DEĞİL.
  · Dosya kilidini yoklamak da güvenilmez: bazı uygulamalar dosyayı açık
    tutmuyor, kaydedip bırakıyor.

Bu yüzden model sürüm kontrolündeki gibi: belge **çıkış kaydı**
(check-out) ile açılıyor, açık olduğu SÜRECE kayıtta duruyor ve şu dört
olaydan biriyle **giriş kaydı** (check-in) yapılıyor:

  1. Değişiklik algılandı ve dosya durulmuş (arayüzdeki izleyici)
  2. Kullanıcı "Bitir" dedi
  3. Uygulama kapanıyor
  4. Oturum kilitlendi (USB çıktı / hareketsizlik)

Sonuç, "kapanışta yaz"dan DAHA İYİ: değişiklik algılandıkça geri
yazıldığı için oturum ortasında bir çökme, yapılan düzenlemeyi
kaybetmiyor.


DOĞRULUK İZLEYİCİDE DEĞİL, ÖZET KARŞILAŞTIRMASINDA
---------------------------------------------------
Bazı uygulamalar (Word, Excel) kaydederken dosyanın üzerine YAZMIYOR:
yeni bir dosya oluşturup adını eskisinin üzerine taşıyor. Bu, dosya yolu
izleyicisini düşürüyor — izlenen düğüm siliniyor ve olay hiç gelmiyor,
ya da "silindi" olarak geliyor.

Bu yüzden izleyici bir OPTİMİZASYON olarak tasarlandı, doğruluk
mekanizması olarak değil. Geri yazma kararı HER ZAMAN düz metin
SHA-256'sının karşılaştırılmasıyla veriliyor (`has_changed`). İzleyici
hiçbir olay üretmese bile check-in anında değişiklik yakalanıyor;
izleyicinin tek katkısı bunun daha ERKEN olması.

`mtime` de tek başına yeterli değildi: bazı uygulamalar zaman damgasını
koruyarak yazıyor, bazı araçlar içerik değişmeden `touch`luyor. Boyut
ucuz bir ön eleme ama son söz özette.


Geri yazma ATOMİK
-----------------
Yeniden şifreleme doğrudan `.hcl` üzerine yazmıyor: önce geçici bir yola
şifreleniyor, sonra `os.replace()` ile yerine konuyor. Yarıda kesilen bir
yazma (elektrik, çökme) orijinali BOZMUYOR — geriye yalnızca artık bir
geçici dosya kalıyor. Aynı desen `CORE/timestamp.attach_trailer()` içinde
de kullanılıyor ve aynı gerekçeyle: yarım yazılmış bir `.hcl`, GCM
doğrulamasında "bozuk" görünür ve haftalık bütünlük taraması sağlam
sanılan bir dosyayı kaybettiğimizi söylerdi.


Aynı belge iki kez açılırsa
---------------------------
Kayıt defteri `file_id` ile anahtarlı. İkinci açma YENİ bir kopya
üretmiyor, mevcut çıkış kaydını döndürüyor. İki kopya olsaydı:

  · kullanıcı ikisini de düzenler, son geri yazan diğerinin işini silerdi
  · SafeZone'da iki düz metin kopyası dururdu
  · biri check-in edilip silinince diğeri artık dosya olarak kalırdı

`reopened` bayrağı arayüze "yeni açmadım, olanı gösteriyorum" diyor.


Aynı belge BAŞKA BİR UYGULAMA ÖRNEĞİNDE açıksa — `file_locks`
----------------------------------------------------------------
Yukarıdaki "iki kez açılırsa" bölümü tek bir SÜREÇ içindir: `registry`
bellekte, süreç kapanınca (ya da çökünce) kaybolur. İKİ AYRI HYCLEUS
süreci (aynı makinede çift tıklama, ya da aynı `data/` dizinini paylaşan
iki kurulum) aynı `file_id`'yi aynı anda çıkışa alırsa, hiçbiri diğerinin
bellek içi kaydını GÖREMEZ — sonuç modülün en üstteki "iki kopya olsaydı"
uyarısıyla AYNI sınıf sorun, yalnızca ikinci kopya başka bir SÜREÇTE:
iki düz metin kopyası, iki bağımsız düzenleme, son geri yazan diğerininkini
SESSİZCE SİLER.

Çözüm `disposal_queue` (B-079) ile AYNI desen — DB/migrations.py::
_m26_file_locks: niyet (kimin, hangi makineden, hangi süreçten açtığı)
FİİLİ çözmeden ÖNCE `file_locks` tablosuna kalıcı yazılır. `file_id`
PRIMARY KEY olduğu için ikinci bir yazma denemesi `IntegrityError` ile
anında reddedilir — SELECT'le önce kontrol edip sonra INSERT etmenin
açacağı yarış penceresi yok, SQLite'ın kendi tekillik garantisi kilidi
veriyor.

PID canlılığı — SAHİPSİZ KALAN kilit
-------------------------------------
Bir süreç dosyayı açıkken çökerse (`check_in`/`discard` hiç çağrılmaz),
kilit satırı SÜRESİZ orada kalır — tıpkı `disposal_queue`'nun yarım kalan
bir silmeyi kalıcı kaydetmesi gibi. `release_stale_locks()` açılışta
(`main.py`, `resume_pending_disposals()`/`purge_orphans()` ile AYNI
bölümde) her satırı gözden geçirir:

  · `hostname` BU makineyle eşleşmiyorsa DOKUNULMAZ — başka bir makinenin
    süreç tablosu buradan sorgulanamaz, "canlı mı" sorusu YANITLANAMAZ ve
    yanıtlanamayan bir soruya "ölü" demek YANLIŞ tarafta hata yapmak olur.
  · Eşleşiyorsa `pid` işletim sisteminden sorgulanır (`_pid_alive`):
    Windows'ta `OpenProcess` (ctypes, `os.kill(pid, 0)` KULLANILMIYOR —
    Windows'ta 0 sinyali `TerminateProcess`'e düşüyor ve GERÇEKTEN
    öldürüyor, bu yüzden POSIX'teki "sinyal gönderme, yalnızca var mı
    bak" anlamını TAŞIMIYOR), POSIX'te `os.kill(pid, 0)`. Ölüyse kilit
    SAHİPSİZ sayılır ve kaldırılır — dosya bir sonraki `check_out()`
    çağrısında normal şekilde devralınabilir.

BİLİNÇLİ ASİMETRİ: `pid` YENİDEN KULLANILMIŞSA (süreç çıkmış, işletim
sistemi aynı numarayı BAŞKA bir programa vermiş) canlılık kontrolü
YANLIŞ POZİTİF verir — kilit "hâlâ tutuluyor" sanılıp SERBEST
BIRAKILMAZ. Bu KASITLI: yanlış tarafta hata yapmak (ölü bir kilidi biraz
daha uzun tutmak) diğer yönden (canlı bir kilidi erken serbest bırakıp
iki sürecin aynı dosyayı aynı anda düzenlemesine izin vermek) kesinlikle
daha güvenli — ikincisi bu modülün var olma sebebini bizzat ihlal
ederdi.
"""
from __future__ import annotations

import hashlib
import logging
import os
import socket
import sqlite3
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from CORE.crypto import decrypt_file, encrypt_file
from CORE.safezone import allocate, safezone_dir
from CORE.secure_erase import shred_file

_log = logging.getLogger("hycleus.checkout")

_CHUNK = 64 * 1024

#: Geri yazmadan önce dosyanın "durulmuş" sayılması için geçmesi gereken
#: süre. Bir uygulama kaydederken dosyayı birkaç adımda yazabiliyor;
#: yarısı yazılmışken şifrelemek bozuk bir belge kaydederdi.
SETTLE_SECONDS = 2.0

#: Geri yazma sırasında kullanılan geçici uzantı.
_TMP_SUFFIX = ".hcl-rewrite-tmp"

#: Bu SÜRECİN kilit sahipliği kimliği — süreç başına BİR KEZ, ithal
#: edilirken üretilir (modül tekil, bkz. DBManager singleton deseni).
#: `file_locks.session_id`'ye yazılır; `release_lock()` yalnızca KENDİ
#: session_id'sine ait satırı kaldırır. Testler iki AYRI "uygulama
#: örneğini" aynı süreçte simüle etmek için `check_out()`'a açıkça farklı
#: bir `session_id` geçebilir.
SESSION_ID = uuid.uuid4().hex


class CheckoutError(Exception):
    """Çıkış/giriş akışının bir adımı başarısız olduğunda fırlar."""


class FileLockedError(CheckoutError):
    """
    Dosya BAŞKA bir uygulama örneğinde zaten açık.

    `CheckoutError`'ın alt sınıfı: mevcut `except CheckoutError` çağrı
    yerleri (ör. `UI/main_window_open.py::_on_ctx_open`) hiçbir değişiklik
    gerekmeden bunu da yakalıyor — yalnızca mesaj daha bilgilendirici.
    """

    def __init__(
        self,
        message: str,
        *,
        holder_user_id: int | None,
        holder_hostname: str,
        locked_at: str,
    ) -> None:
        super().__init__(message)
        self.holder_user_id = holder_user_id
        self.holder_hostname = holder_hostname
        self.locked_at = locked_at


@dataclass
class CheckedOutFile:
    """Şu anda açık (çıkışta) olan bir belge."""

    file_id: int
    hcl_path: Path
    safe_path: Path
    original_name: str
    aad_hwid: str | None
    #: En son ŞİFRELENMİŞ hâlin düz metin özeti. Değişiklik buna göre
    #: ölçülüyor; her başarılı geri yazmada tazeleniyor.
    baseline_sha256: str
    opened_at: float = field(default_factory=time.monotonic)
    writebacks: int = 0
    reopened: bool = False

    def exists(self) -> bool:
        return self.safe_path.is_file()


@dataclass(frozen=True)
class CheckinResult:
    """Bir giriş kaydının (check-in) sonucu."""

    file_id: int
    rewritten: bool
    shredded: bool
    reason: str
    new_sha256: str | None = None
    size_bytes: int | None = None
    aad_metadata: str | None = None

    def summary(self) -> str:
        if self.rewritten:
            return f"{self.file_id}: değişiklik geri şifrelendi ({self.reason})"
        return f"{self.file_id}: değişiklik yok, geri yazılmadı ({self.reason})"


def sha256_of(path: Path | str) -> str:
    """Dosyanın düz metin SHA-256 özeti (hex)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(_CHUNK):
            h.update(chunk)
    return h.hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
# Kayıt defteri
# ══════════════════════════════════════════════════════════════════════════════


class CheckoutRegistry:
    """
    Açık belgelerin kaydı — `file_id` ile anahtarlı.

    Neden bir sınıf: "hangi belgeler şu anda düz metin olarak diskte"
    sorusunun tek bir yanıtı olmalı. Arayüz bu listeyi kullanıcıya
    gösterebiliyor ve kapanışta üzerinden geçebiliyor.
    """

    def __init__(self) -> None:
        self._acik: dict[int, CheckedOutFile] = {}

    def __len__(self) -> int:
        return len(self._acik)

    def __contains__(self, file_id: object) -> bool:
        return file_id in self._acik

    def get(self, file_id: int) -> CheckedOutFile | None:
        return self._acik.get(file_id)

    def all(self) -> list[CheckedOutFile]:
        return list(self._acik.values())

    def add(self, entry: CheckedOutFile) -> None:
        self._acik[entry.file_id] = entry

    def remove(self, file_id: int) -> CheckedOutFile | None:
        return self._acik.pop(file_id, None)

    def by_safe_path(self, path: Path | str) -> CheckedOutFile | None:
        """İzleyiciden gelen yol ile kaydı bulur."""
        hedef = str(Path(path))
        for entry in self._acik.values():
            if str(entry.safe_path) == hedef:
                return entry
        return None


# ══════════════════════════════════════════════════════════════════════════════
# Kilit — `file_locks` (modül docstring'i, "BAŞKA BİR UYGULAMA ÖRNEĞİNDE")
# ══════════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class LockSweepReport:
    """`release_stale_locks()`'ın sonucu — `CORE/disposal.py::DisposalResumeReport` ile aynı biçim."""

    released: int = 0
    #: (file_id, eski sahibin hostname'i) çiftleri — denetim/UI için.
    released_ids: list[tuple[int, str]] = field(default_factory=list)

    @property
    def had_stale(self) -> bool:
        return self.released > 0

    def summary(self) -> str:
        if not self.had_stale:
            return "Dosya kilitleri temiz — sahipsiz kalan yok."
        return f"{self.released} sahipsiz kalan dosya kilidi temizlendi."


def _pid_alive(pid: int) -> bool:
    """
    `pid`'in BU makinede hâlâ çalışan bir sürece ait olup olmadığı.

    `os.kill(pid, 0)` Windows'ta KULLANILMIYOR: POSIX'te sinyal 0 "sinyal
    gönderme, yalnızca izin/varlığı sına" anlamına gelir ama Windows'un
    `os.kill()` uygulaması sinyal değerini `TerminateProcess`'e geçiriyor
    — yani `0` GERÇEKTEN süreci öldürür (ölçülmedi, CPython kaynağından:
    `Modules/posixmodule.c` Windows dalı `TerminateProcess(handle, sig)`
    çağırıyor). Bunun yerine `OpenProcess` ile bir tutamaç açılabiliyor mu
    diye bakılıyor — yalnızca sorgulama, yan etkisi yok.
    """
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(  # type: ignore[attr-defined]
            PROCESS_QUERY_LIMITED_INFORMATION, False, pid
        )
        if not handle:
            return False
        ctypes.windll.kernel32.CloseHandle(handle)  # type: ignore[attr-defined]
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # var ama başka kullanıcıya ait — yine de ÇALIŞIYOR
    except OSError:
        return False
    return True


def acquire_lock(
    db: Any,
    *,
    file_id: int,
    user_id: int | None = None,
    session_id: str | None = None,
    pid: int | None = None,
    hostname: str | None = None,
) -> None:
    """
    `file_id` için kalıcı bir kilit satırı yazar — FİİLİ çözmeden ÖNCE.

    `file_id` PRIMARY KEY olduğu için ikinci bir çağrı `IntegrityError`
    ile reddedilir; bu satır o zaman kimin elinde olduğuna bakar:
    KENDİ `session_id`'mize aitse (aynı süreç yeniden açıyor) sessizce
    başarılı sayılır — `check_out()`'un "aynı belge iki kez açılırsa"
    yolunun bu tabloda karşılığı budur. Başkasına aitse `FileLockedError`.

    `pid`/`hostname` yalnızca TESTLER için dışarıdan verilebiliyor
    (sahte/ölü bir süreç simüle etmek); üretim çağrıları hep gerçek
    `os.getpid()`/`socket.gethostname()` kullanır.

    Raises:
        FileLockedError — dosya BAŞKA bir session_id tarafından tutuluyor.
    """
    sid = session_id or SESSION_ID
    gercek_pid = pid if pid is not None else os.getpid()
    gercek_host = hostname or socket.gethostname()
    try:
        db.execute(
            "INSERT INTO file_locks (file_id, session_id, user_id, hostname, pid)"
            " VALUES (?, ?, ?, ?, ?)",
            (file_id, sid, user_id, gercek_host, gercek_pid),
        )
    except sqlite3.IntegrityError:
        row = db.fetchone("SELECT * FROM file_locks WHERE file_id = ?", (file_id,))
        if row is not None and row["session_id"] == sid:
            _log.info("lock_reused  file_id=%s session=%s", file_id, sid)
            return
        sahip = row["hostname"] if row is not None else "?"
        kilit_zamani = row["locked_at"] if row is not None else "?"
        sahip_kullanici = row["user_id"] if row is not None else None
        raise FileLockedError(
            f"Bu dosya başka bir uygulama örneğinde zaten açık "
            f"(makine={sahip}, kullanıcı={sahip_kullanici}, "
            f"açılma={kilit_zamani}). Bu dosyayı düzenlemek için önce "
            "orada kapatılması gerekiyor.",
            holder_user_id=sahip_kullanici,
            holder_hostname=sahip,
            locked_at=kilit_zamani,
        ) from None


def release_lock(db: Any, file_id: int, *, session_id: str | None = None) -> bool:
    """
    `file_id`'nin kilidini kaldırır — yalnızca KENDİ `session_id`'mize aitse.

    Başka bir session_id'ye ait bir satırı SESSİZCE atlar (silmez): bu
    süreç o dosyayı hiç açmamıştır, bir başkasının kilidine dokunmak
    `check_out()`'un verdiği tekillik garantisini bozardı.

    Returns:
        True  — kilit KALDIRILDI (bizimdi)
        False — satır yoktu ya da bize ait değildi
    """
    sid = session_id or SESSION_ID
    row = db.fetchone("SELECT session_id FROM file_locks WHERE file_id = ?", (file_id,))
    if row is None or row["session_id"] != sid:
        return False
    db.execute("DELETE FROM file_locks WHERE file_id = ? AND session_id = ?", (file_id, sid))
    return True


def release_stale_locks(db: Any) -> LockSweepReport:
    """
    Açılış kurtarması — SAHİPSİZ KALAN kilitleri temizler.

    `main.py`'de `resume_pending_disposals()`/`purge_orphans()` ile AYNI
    açılış bölümünde çağrılmalı. Modül docstring'indeki "PID canlılığı"
    bölümüne bakın: yalnızca BU makineye ait (`hostname` eşleşen) VE
    `pid`'i artık yaşamayan satırlar kaldırılır; başka bir makineye ait
    ya da hâlâ yaşayan bir sürece ait satırlara DOKUNULMAZ.

    Temizlenen bir dosya bir SONRAKİ `check_out()` çağrısında normal
    şekilde (yeniden `acquire_lock()` ile) devralınabilir — bu fonksiyon
    kendiliğinden yeniden açmaz, yalnızca yolu temizler.
    """
    kendi_host = socket.gethostname()
    rows = db.fetchall("SELECT * FROM file_locks")
    released = 0
    released_ids: list[tuple[int, str]] = []

    for row in rows:
        if row["hostname"] != kendi_host:
            continue  # başka makine — canlılık buradan doğrulanamaz, dokunma
        if _pid_alive(row["pid"]):
            continue  # hâlâ çalışıyor — meşru kilit

        db.execute("DELETE FROM file_locks WHERE file_id = ?", (row["file_id"],))
        db.log(
            "file_lock_released_stale",
            target_type="file",
            target_id=row["file_id"],
            detail=(
                f"eski_session={row['session_id']} pid={row['pid']} "
                f"hostname={row['hostname']} locked_at={row['locked_at']} "
                "— önceki oturum dosya açıkken çökmüş olabilir"
            ),
        )
        released += 1
        released_ids.append((row["file_id"], row["hostname"]))

    if released:
        _log.warning(
            "Açılışta %d sahipsiz kalan dosya kilidi temizlendi — "
            "önceki oturum bir belge açıkken çökmüş olabilir.",
            released,
        )
    return LockSweepReport(released=released, released_ids=released_ids)


# ══════════════════════════════════════════════════════════════════════════════
# Çıkış (check-out)
# ══════════════════════════════════════════════════════════════════════════════


def check_out(
    registry: CheckoutRegistry,
    *,
    db: Any,
    file_id: int,
    hcl_path: Path | str,
    key: bytes,
    aad_hwid: str | None = None,
    user_id: int | None = None,
    session_id: str | None = None,
) -> CheckedOutFile:
    """
    Belgeyi SafeZone'a çözer ve kayıt defterine ekler.

    Aynı belge AYNI süreçte zaten açıksa YENİ kopya üretmez; mevcut kaydı
    `reopened=True` ile döndürür (gerekçe modül docstring'inde, "iki kez
    açılırsa"). BAŞKA bir uygulama örneğinde açıksa `FileLockedError`
    (modül docstring'i, "BAŞKA BİR UYGULAMA ÖRNEĞİNDE") — dosyaya HİÇ
    dokunulmaz.

    `db`'ye ne kadar erken sırada gerekli — kilit çözmeden ÖNCE alınır:
    kilit alınamazsa (başka bir örnek tutuyor) şifre çözme hiç
    denenmemeli.

    Raises:
        FileLockedError — dosya başka bir örnekte açık.
        CheckoutError    — şifre çözme ya da yazma başarısız olursa.
    """
    mevcut = registry.get(file_id)
    if mevcut is not None and mevcut.exists():
        mevcut.reopened = True
        _log.info("checkout_reused  file_id=%s", file_id)
        return mevcut
    if mevcut is not None:
        # Kayıt var ama dosya yok: kullanıcı SafeZone'dan silmiş ya da
        # bir temizlik geçmiş. Kaydı düşürüp yeniden çözüyoruz.
        _log.warning("checkout_stale  file_id=%s path=%s", file_id, mevcut.safe_path)
        registry.remove(file_id)

    sid = session_id or SESSION_ID
    acquire_lock(db, file_id=file_id, user_id=user_id, session_id=sid)

    hcl_path = Path(hcl_path)
    try:
        content, meta = decrypt_file(hcl_path, key, hwid=aad_hwid)
    except Exception as exc:
        release_lock(db, file_id, session_id=sid)
        raise CheckoutError(f"Dosya çözülemedi: {exc}") from exc

    original_name = str(meta.get("filename") or hcl_path.stem)
    # Uzantı korunuyor: varsayılan uygulamayı seçen şey o.
    safe_path = allocate(suffix=Path(original_name).suffix or "")

    try:
        safe_path.write_bytes(content)
    except Exception as exc:
        release_lock(db, file_id, session_id=sid)
        raise CheckoutError(f"SafeZone'a yazılamadı: {exc}") from exc
    finally:
        del content

    entry = CheckedOutFile(
        file_id=file_id,
        hcl_path=hcl_path,
        safe_path=safe_path,
        original_name=original_name,
        aad_hwid=aad_hwid,
        baseline_sha256=str(meta.get("original_sha256") or sha256_of(safe_path)),
    )
    registry.add(entry)
    _log.info("checkout  file_id=%s name=%s", file_id, original_name)
    return entry


# ══════════════════════════════════════════════════════════════════════════════
# Değişiklik tespiti
# ══════════════════════════════════════════════════════════════════════════════


def has_changed(entry: CheckedOutFile) -> bool:
    """
    Geçici kopya, en son şifrelenen hâlden farklı mı.

    Özete bakıyor — `mtime`'a değil. Gerekçe modül docstring'inde
    ("DOĞRULUK İZLEYİCİDE DEĞİL").

    Dosya YOKSA False: "silinmiş" ile "değişmiş" aynı şey değil ve
    olmayan bir dosyadan şifrelenecek içerik yok.
    """
    if not entry.exists():
        return False
    try:
        return sha256_of(entry.safe_path) != entry.baseline_sha256
    except OSError as exc:
        # Kaydetme sırasında dosya kilitli olabiliyor; okunamıyorsa
        # "değişmedi" demek yanlış olurdu ama şu an geri de yazamayız.
        _log.debug("has_changed_unreadable  path=%s exc=%s", entry.safe_path, exc)
        return False


def is_settled(entry: CheckedOutFile, *, now: float | None = None,
               settle_seconds: float = SETTLE_SECONDS) -> bool:
    """
    Dosyaya yazma işlemi bitmiş görünüyor mu.

    Son değişiklikten bu yana `settle_seconds` geçtiyse True. Bir
    uygulama kaydederken dosyayı birkaç adımda yazabiliyor; yarısı
    yazılmışken şifrelemek BOZUK bir belge kaydederdi ve o bozukluk
    orijinalin üzerine yazılırdı.

    Zaman DIŞARIDAN verilebiliyor — testler beklemek zorunda kalmasın.
    """
    if not entry.exists():
        return False
    try:
        mtime = entry.safe_path.stat().st_mtime
    except OSError:
        return False
    return ((now if now is not None else time.time()) - mtime) >= settle_seconds


# ══════════════════════════════════════════════════════════════════════════════
# Giriş (check-in)
# ══════════════════════════════════════════════════════════════════════════════


def rewrite_encrypted(
    entry: CheckedOutFile,
    key: bytes,
    *,
    user_id: int,
    hwid: str | None = None,
) -> tuple[str, int, str]:
    """
    Düzenlenmiş kopyayı yeni bir nonce ile şifreler ve `.hcl`'in üzerine
    ATOMİK olarak koyar.

    Returns:
        (yeni_sha256, boyut, aad_json)

    Nonce her `encrypt_file()` çağrısında yeniden üretiliyor, yani
    ayrıca bir şey yapmaya gerek yok — aynı anahtarla aynı nonce'un
    tekrar kullanılması GCM'i kırardı ve buradaki akış tam da aynı
    anahtarla aynı dosyayı defalarca şifreliyor.

    AAD'de `filename` KORUNUYOR: kaynak, SafeZone'daki rastgele adlı
    kopya ve o ad belgenin gerçek adı değil.

    Raises:
        CheckoutError — şifreleme ya da yer değiştirme başarısız olursa.
    """
    tmp = entry.hcl_path.with_suffix(entry.hcl_path.suffix + _TMP_SUFFIX)
    try:
        _yol, sha256_hex, aad_json = encrypt_file(
            entry.safe_path,
            key,
            user_id=user_id,
            hwid=hwid,
            dst=tmp,
            filename=entry.original_name,
        )
        boyut = entry.safe_path.stat().st_size
        # Atomik: aynı dizin, dolayısıyla aynı dosya sistemi. Yarıda
        # kesilirse orijinal .hcl'e hiç dokunulmamış olur.
        os.replace(tmp, entry.hcl_path)
    except Exception as exc:
        tmp.unlink(missing_ok=True)
        raise CheckoutError(f"Yeniden şifreleme başarısız: {exc}") from exc

    entry.baseline_sha256 = sha256_hex
    entry.writebacks += 1
    _log.info(
        "writeback  file_id=%s name=%s sha=%s",
        entry.file_id, entry.original_name, sha256_hex[:12],
    )
    return sha256_hex, boyut, aad_json


def check_in(
    registry: CheckoutRegistry,
    file_id: int,
    key: bytes,
    *,
    db: Any,
    user_id: int,
    hwid: str | None = None,
    reason: str = "manual",
    shred: bool = True,
    session_id: str | None = None,
) -> CheckinResult:
    """
    Belgeyi kapatır: değiştiyse geri şifreler, geçici kopyayı güvenli siler.

    `shred=False` yalnızca ara geri yazmalar için (belge açık kalmaya
    devam ediyor) — bu durumda `file_locks` kilidi de KORUNUR, belge
    hâlâ bu süreçte açık.

    Geri yazma BAŞARISIZ olursa geçici kopya SİLİNMEZ ve kayıt defterinde
    kalır: kullanıcının düzenlemesi tek nüsha hâlinde orada duruyor,
    onu silmek veri kaybı olurdu — kilit de aynı gerekçeyle KORUNUR.
    """
    entry = registry.get(file_id)
    if entry is None:
        raise CheckoutError(f"Açık kayıt yok: file_id={file_id}")

    degisti = has_changed(entry)
    yeni_sha = boyut = aad = None

    if degisti:
        yeni_sha, boyut, aad = rewrite_encrypted(
            entry, key, user_id=user_id, hwid=hwid
        )
    elif not entry.exists():
        _log.warning(
            "checkin_missing  file_id=%s path=%s — geçici kopya yok, "
            "orijinal olduğu gibi bırakılıyor", file_id, entry.safe_path,
        )

    silindi = False
    if shred:
        silindi = _shred(entry)
        registry.remove(file_id)
        release_lock(db, file_id, session_id=session_id)

    return CheckinResult(
        file_id=file_id, rewritten=degisti, shredded=silindi,
        reason=reason, new_sha256=yeni_sha, size_bytes=boyut,
        aad_metadata=aad,
    )


def discard(registry: CheckoutRegistry, file_id: int, *, db: Any, session_id: str | None = None) -> bool:
    """
    Değişiklikleri ATARAK kapatır — geri yazma YOK, yalnızca güvenli silme.

    "Kaydetmeden çık" karşılığı. Ayrı bir fonksiyon olması bilinçli:
    `check_in(shred=True)` içine bir bayrak koymak, yanlış bayrakla
    çağrıldığında sessizce veri kaybettirirdi.
    """
    entry = registry.remove(file_id)
    if entry is None:
        return False
    _log.info("discard  file_id=%s", file_id)
    release_lock(db, file_id, session_id=session_id)
    return _shred(entry)


def _shred(entry: CheckedOutFile) -> bool:
    """Geçici kopyayı güvenli siler; başarısızlık akışı durdurmaz."""
    try:
        return shred_file(entry.safe_path)
    except OSError as exc:
        # Dosya hâlâ açık uygulamada kilitli olabilir. SafeZone'un
        # açılışta yaptığı artık temizliği (purge_orphans) bunu
        # yakalayacak — yani düz metin diskte kalıcı olmuyor.
        _log.warning(
            "shred_failed  path=%s exc=%s — açılışta temizlenecek",
            entry.safe_path, exc,
        )
        return False


def check_in_all(
    registry: CheckoutRegistry,
    key: bytes,
    *,
    db: Any,
    user_id: int,
    hwid: str | None = None,
    reason: str = "shutdown",
    session_id: str | None = None,
) -> list[CheckinResult]:
    """
    Açık BÜTÜN belgeleri kapatır — kapanışta ve oturum kilidinde çağrılıyor.

    Bir belgenin başarısız olması diğerlerini DURDURMUYOR: kapanışta
    yarıda kalmak, geri kalan belgelerin düz metin kopyalarını diskte
    bırakmak demek olurdu.
    """
    sonuclar: list[CheckinResult] = []
    for entry in registry.all():
        try:
            sonuclar.append(
                check_in(registry, entry.file_id, key, db=db,
                         user_id=user_id, hwid=hwid, reason=reason,
                         session_id=session_id)
            )
        except CheckoutError as exc:
            _log.error("checkin_failed  file_id=%s exc=%s", entry.file_id, exc)
            sonuclar.append(
                CheckinResult(file_id=entry.file_id, rewritten=False,
                              shredded=False, reason=f"{reason}:hata")
            )
    return sonuclar


# ══════════════════════════════════════════════════════════════════════════════
# Veritabanı ve denetim kaydı
# ══════════════════════════════════════════════════════════════════════════════


def apply_checkin(db: Any, result: CheckinResult, *, user_id: int | None = None,
                  hwid: str | None = None) -> None:
    """
    Geri yazma sonucunu `files` satırına ve denetim kaydına işler.

    Şifreli içerik değişti; `original_sha256`, `aad_metadata` ve
    `size_bytes` de değişmeli. Güncellenmezlerse tekrar tespiti
    (`CORE/duplicates.py`) ve zaman damgası doğrulaması (3.1b) ESKİ özete
    bakmaya devam eder — ikincisi damgayı geçersiz gösterirdi.
    """
    if result.rewritten:
        db.execute(
            "UPDATE files SET original_sha256 = ?, aad_metadata = ?, size_bytes = ?"
            " WHERE id = ?",
            (result.new_sha256, result.aad_metadata, result.size_bytes,
             result.file_id),
        )
    db.log(
        "file_checked_in" if result.rewritten else "file_closed_unchanged",
        user_id=user_id,
        target_type="file",
        target_id=result.file_id,
        detail=(
            f"reason={result.reason} rewritten={result.rewritten} "
            f"shredded={result.shredded} hwid={hwid}"
        ),
    )


def log_checkout(db: Any, entry: CheckedOutFile, *, user_id: int | None = None,
                 hwid: str | None = None) -> None:
    """
    Açma olayını denetim kaydına yazar.

    Bu kayıt önemli: düz metin bir kopyanın diske indiği AN burası.
    "Bu belge ne zaman açıldı" sorusunun yanıtı zincirde durmalı.
    """
    db.log(
        "file_opened" if not entry.reopened else "file_reopened",
        user_id=user_id,
        target_type="file",
        target_id=entry.file_id,
        detail=f"name={entry.original_name} hwid={hwid}",
    )


def stale_safezone_files(registry: CheckoutRegistry) -> list[Path]:
    """
    SafeZone'da duran ama HİÇBİR açık kayda ait olmayan dosyalar.

    Bir önceki oturumdan kalmış olabilirler (çökme) ya da bir check-in
    silme aşamasında düşmüş olabilir. Arayüz bunları kullanıcıya
    gösterebiliyor; `safezone.purge_orphans()` zaten açılışta temizliyor.
    """
    bilinen = {str(e.safe_path) for e in registry.all()}
    kok = safezone_dir(create=False)
    if not kok.exists():
        return []
    return [p for p in sorted(kok.rglob("*"))
            if p.is_file() and str(p) not in bilinen]


__all__ = [
    "SESSION_ID",
    "SETTLE_SECONDS",
    "CheckedOutFile",
    "CheckinResult",
    "CheckoutError",
    "CheckoutRegistry",
    "FileLockedError",
    "LockSweepReport",
    "acquire_lock",
    "apply_checkin",
    "check_in",
    "check_in_all",
    "check_out",
    "discard",
    "has_changed",
    "is_settled",
    "log_checkout",
    "release_lock",
    "release_stale_locks",
    "rewrite_encrypted",
    "sha256_of",
    "stale_safezone_files",
]
