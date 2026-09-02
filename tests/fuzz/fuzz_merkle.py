#!/usr/bin/env python3
"""
Fuzz hedefi — Merkle ağacı: `build_leaves`/`build_tree`, `verify_proof`.

Neden bu hedef, NOT-WIRED olmasına rağmen
------------------------------------------
K0-4 kararınca (b) `CORE/merkle.py`'nin YAZMA tarafı (`build_tree`)
üretime hiç bağlanmadı ve bu haftanın kapsamında bağlanmayacak (BACKLOG
B-035, `tests/test_deneysel_bagli_degil.py`). Ama modülün kendi
docstring'inin de dediği gibi OKUMA tarafı (`verify_proof`) `UI/
main_window_files.py`'nin "Damgayı Doğrula" eylemine GERÇEKTEN bağlı —
bugün anlamlı bir ağaç görmediği için sessiz kalması GÜVENLİ olduğu
anlamına gelmiyor. `build_leaves`/`build_tree`/`verify_proof` dışarıdan
veri ayrıştırıyor; bağlı olmasalar bile kendi başlarına fuzz edilebilirler
— bu harness onu yapıyor. Fuzzing yapmak üretime bağlama kararını
DEĞİŞTİRMİYOR: modül hâlâ NOT-WIRED (bkz. SECURITY.md §4.9, BACKLOG
B-109).

Aranan sözleşmeler
------------------
    build_tree(leaves)        → MerkleError (boş liste, yanlış boy yaprak)
    MerkleTree.proof(index)   → MerkleError (aralık dışı indis)
    compute_root(leaf, proof) → MerkleError (yanlış boy yaprak)
    node_hash(left, right)    → MerkleError (yanlış boy çocuk)
    MerkleProof(...)          → MerkleError (kardeş/yön sayısı uyuşmuyor,
                                 kardeş yanlış boyda — `__post_init__`)
    verify_proof(leaf, proof, root)
                               → HİÇBİR ŞEY. Docstring'i "sabit zamanlı
                                 karşılaştırma kullanılmıyor" derken bunu
                                 örtük vaat ediyor: her girdi için bir
                                 `bool` dönmeli, asla patlamamalı — çağıran
                                 (UI doğrulama akışı) onu try/except'siz
                                 çağırıyor.

Ayrıca bir DEĞİŞMEZ sınanıyor: `build_tree` + `MerkleTree.proof()` ile
kurulan gerçek bir yol, `verify_proof()`'a verildiğinde HER ZAMAN
doğrulanmalı — üretim (yazma) ile tüketim (okuma) aynı ağacı
anlamıyorsa, bu K0-4'ün gün birinde bağlanacağı an sessizce patlayacak bir
uyuşmazlık demektir. Ve sahte bir kökle AYNI yol REDDEDİLMELİ — yoksa
`verify_proof` her zaman `True` döndüren bir işlevden ayırt edilemez.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import BilinenIhlal, Tuketici, cagir, enstrumante, main  # noqa: E402

# Enstrümantasyon bloğu — bkz. fuzz_crypto.py'deki aynı yorum ve
# harness.enstrumante docstring'i. Bu olmadan kapsam güdümlü değil.
with enstrumante():  # noqa: E402
    from CORE.merkle import (
        HASH_SIZE,
        MerkleError,
        MerkleProof,
        build_leaves,
        build_tree,
        compute_root,
        node_hash,
        verify_proof,
    )

IZINLI: tuple[type[BaseException], ...] = (MerkleError,)

#: `verify_proof` için: BOŞ küme — hiçbir istisnaya izin yok, kendi
#: docstring'inin vaadi bu.
IZINLI_DOGRULAMA: tuple[type[BaseException], ...] = ()

#: Bilinen ve düzeltilmemiş ihlal YOK.
BILINEN: tuple[BilinenIhlal, ...] = ()

#: Hedefe özel tohum korpusu.
TOHUMLAR: tuple[bytes, ...] = (
    b"\x00",                                # boş yaprak listesi (kip 0)
    b"\x01" + b"\x00" * 31,                 # tek "yaprak", 32 bayttan 1 eksik
    b"\x01" + b"\x00" * 33,                 # tek "yaprak", 32 bayttan 1 fazla
    b"\x04" + b"\x00" * 32 * 3,             # tam boy 3 yaprak — çift/tek karışık
    b"\x04" + b"\x00" * 32 * 8,             # tam boy 8 yaprak — güç-of-2 kenarı
)


def _yapraklar(t: Tuketici, *, dogru_boy: bool) -> list[bytes]:
    """
    `dogru_boy=True`: her biri tam `HASH_SIZE` — `build_tree` başarmalı.
    `dogru_boy=False`: fuzzer'ın verdiği ham parçalar — çoğu YANLIŞ boyda,
    `build_tree`'nin boy kontrolünü hedefliyor.
    """
    adet = t.tamsayi(12)
    boy = HASH_SIZE if dogru_boy else 1 + t.tamsayi(40)
    return [t.bayt(boy) for _ in range(adet)]


def one_input(data: bytes) -> None:
    t = Tuketici(data)
    kip = t.tamsayi(6)

    if kip == 0:
        # Boş liste — sözleşme: MerkleError, sessizce bir kök UYDURULMUYOR.
        cagir("build_tree(bos)", IZINLI, data, lambda: build_tree([]))
        return

    if kip == 1:
        # Yanlış boy yapraklar — genelde en az biri 32 bayt değil.
        yapraklar = _yapraklar(t, dogru_boy=False)
        if not yapraklar:
            return
        cagir("build_tree(yanlis_boy)", IZINLI, data,
              lambda: build_tree(yapraklar))
        return

    if kip == 2:
        # node_hash / MerkleProof doğrudan — boy ve sayı kontrolleri.
        sol = t.bayt(1 + t.tamsayi(40))
        sag = t.bayt(1 + t.tamsayi(40))
        cagir("node_hash", IZINLI, data, lambda: node_hash(sol, sag))

        n = t.tamsayi(6)
        kardesler = tuple(t.bayt(1 + t.tamsayi(40)) for _ in range(n))
        # Yön sayısı BİLEREK bazen kardeş sayısıyla uyuşmuyor.
        m = n if t.bayt(1)[0] & 1 else t.tamsayi(6)
        yonler = tuple(bool(t.bayt(1)[0] & 1) for _ in range(m))
        cagir("MerkleProof", IZINLI, data,
              lambda: MerkleProof(leaf_index=0, siblings=kardesler,
                                   right_flags=yonler))
        return

    if kip == 3:
        # compute_root / verify_proof — biçimi GEÇERLİ (kardeşler tam 32
        # bayt, sayılar eşit) ama içeriği rastgele bir yol; yaprak boyu
        # bilerek keyfi. verify_proof HİÇBİR ZAMAN patlamamalı.
        yaprak = t.bayt(1 + t.tamsayi(40))
        derinlik = t.tamsayi(8)
        kardesler = tuple(t.bayt(HASH_SIZE) for _ in range(derinlik))
        yonler = tuple(bool(t.bayt(1)[0] & 1) for _ in range(derinlik))
        yol = MerkleProof(leaf_index=0, siblings=kardesler, right_flags=yonler)
        kok = t.bayt(HASH_SIZE)

        cagir("compute_root", IZINLI, data,
              lambda: compute_root(yaprak, yol))

        sonuc = cagir("verify_proof", IZINLI_DOGRULAMA, data,
                       lambda: verify_proof(yaprak, yol, kok))
        if sonuc is not None:
            assert isinstance(sonuc, bool), type(sonuc)
        return

    if kip == 4:
        # MerkleTree.proof(index) — aralık dışı (negatif ve taşan) indis.
        yukler = [t.bayt(1 + t.tamsayi(64)) for _ in range(1 + t.tamsayi(12))]
        agac = build_tree(build_leaves(yukler))
        indis = t.tamsayi(agac.leaf_count * 3 + 1) - agac.leaf_count
        cagir("MerkleTree.proof", IZINLI, data, lambda: agac.proof(indis))
        return

    # kip == 5: DEĞİŞMEZ — yazma tarafının ürettiği yol, okuma tarafında
    # HER ZAMAN doğrulanmalı; sahte bir kökle AYNI yol REDDEDİLMELİ. K0-4
    # bir gün bu ağacı bağladığında üretim ve tüketimin aynı ağacı
    # anladığını garanti eden test bu.
    yukler = [t.bayt(1 + t.tamsayi(64)) for _ in range(1 + t.tamsayi(30))]
    yapraklar = build_leaves(yukler)
    agac = build_tree(yapraklar)
    indis = t.tamsayi(agac.leaf_count)
    yol = agac.proof(indis)
    assert verify_proof(yapraklar[indis], yol, agac.root), (
        f"gerçek bir yol doğrulanmadı: {len(yukler)} yaprak, indis={indis}"
    )
    sahte_kok = bytes((agac.root[0] ^ 1,)) + agac.root[1:]
    assert not verify_proof(yapraklar[indis], yol, sahte_kok), (
        "sahte kök yanlışlıkla doğrulandı"
    )


def _kendi_kendini_sina() -> None:
    """
    Harness'ın GERÇEKTEN bir şey ürettiğini gösteren küçük duman testi.

    `python tests/fuzz/fuzz_merkle.py --yerel` çalıştırıldığında bu
    fonksiyon çağrılmıyor; yalnızca elle kontrol için duruyor.
    """
    one_input(b"")
    one_input(b"\x05" + bytes(range(64)))


if __name__ == "__main__":
    raise SystemExit(
        main(one_input, ad="merkle", bilinen=BILINEN, tohumlar=TOHUMLAR)
    )
