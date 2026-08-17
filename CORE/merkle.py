"""
HYCLEUS — Merkle ağacı (toplu zaman damgası için)

Neden var
---------
RFC 3161 damgalaması bugün DOSYA BAŞINA bir TSA çağrısı yapıyor. Yüz
dosyayı damgalamak yüz ağ turu, yüz token (~5 KB × 100 ≈ 500 KB) ve TSA
tarafında yüz istek demek. Oysa damganın kanıtladığı şey tek bir cümle:
"bu özet, o tarihte zaten vardı."

Merkle ağacı bu cümleyi çoğaltmadan paylaştırıyor: N özet bir ağaca
diziliyor, YALNIZCA KÖK damgalanıyor, her dosya kendi yaprağından köke
giden yolu (birkaç yüz byte) saklıyor. Bir dosyanın o tarihte var olduğu,
kökün imzalı olması + yolun köke çıkması ile kanıtlanıyor.

    100 dosya:  100 TSA çağrısı, ~500 KB token
              →   1 TSA çağrısı, ~5 KB token + 100 × ~224 B yol

Yol uzunluğu log₂(N): 100 yaprakta 7 kardeş × 32 byte = 224 byte.


GÜVENLİK — iki bilinen tuzak ve neden kaçınıldıkları
----------------------------------------------------
**1. İkinci öngörüntü (second preimage).** Yaprak ile iç düğüm aynı
biçimde özetlenirse, bir saldırgan bir İÇ DÜĞÜMÜ yaprakmış gibi sunabilir:
`H(a‖b)` değerini "yaprak" diye gösterip ona ait sahte bir yol kurar.
Çözüm ALAN AYRIMI (domain separation) — yaprak ve düğüm farklı ön eklerle
özetleniyor:

    yaprak = SHA256(0x00 ‖ veri)
    düğüm  = SHA256(0x01 ‖ sol ‖ sağ)

Böylece hiçbir iç düğüm değeri geçerli bir yaprak değeri olamaz. Bu,
RFC 6962'nin (Certificate Transparency) kullandığı yaklaşımın aynısı.

Hangi ön ek YÜK TAŞIYOR — ölçüldü: HYCLEUS'un yaprak yükleri her zaman
32 baytlık özetler (dosya `original_sha256`'sı ya da etiketli çıpa
özeti). Bu sabit boyutta yaprak ön görüntüsü 33, düğüm ön görüntüsü 64
byte oluyor; yani `LEAF_PREFIX` tek başına iki uzayı zaten ayırıyor ve
`NODE_PREFIX`'i kaldıran bir değişiklik hiçbir testi bozmuyor.
`NODE_PREFIX` yine de duruyor: değişken uzunluklu bir yaprak yükü
eklenirse (bugün yok) ayrımı ayakta tutan tek şey o olur.

**2. Tek sayıda düğüm — KOPYALAMA DEĞİL YÜKSELTME.** Bitcoin'in ağacı
tek kalan düğümü kendisiyle eşleştiriyor (`H(x‖x)`) ve bu CVE-2012-2459'a
yol açtı: farklı yaprak listeleri AYNI kökü üretebiliyor, yani kök artık
içeriği tekil olarak belirlemiyor. Burada tek kalan düğüm olduğu gibi bir
üst seviyeye YÜKSELTİLİYOR. Sonuç: yaprak listesi → kök eşlemesi
birebir.


Sözleşme
--------
· Yaprak sırası ANLAMLIDIR. Aynı küme farklı sırayla farklı kök verir.
  Toplu damgalama çağıranın verdiği sırayı koruyor ve her dosyaya kendi
  yaprak indisini yazıyor — doğrulama ağacı yeniden kurmuyor, yalnızca
  yolu yürüyor.
· Boş liste REDDEDİLİYOR. Boş bir ağacın "kökü" tanımsız; sessizce bir
  sabit döndürmek, hiçbir şey içermeyen bir damgayı geçerli gösterirdi.
· Tek yapraklı ağacın kökü o yaprağın kendisidir ve yolu boştur. Bu,
  tek dosyalık toplu damgalamayı özel durum yapmadan çalıştırıyor.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

#: Yaprak özetinin alan ayrımı ön eki.
LEAF_PREFIX = b"\x00"

#: İç düğüm özetinin alan ayrımı ön eki.
NODE_PREFIX = b"\x01"

#: SHA-256 çıktısı — yaprak ve kardeş hash'lerinin sabit uzunluğu.
HASH_SIZE = 32


class MerkleError(Exception):
    """Ağaç kurulamadı ya da yol geçersiz."""


def leaf_hash(data: bytes) -> bytes:
    """
    Bir yaprağın özeti: `SHA256(0x00 ‖ veri)`.

    `veri` burada dosyanın DÜZ METİN SHA-256'sı (32 ham byte) — yani
    özetin özeti alınıyor. Bu bilinçli: yaprak girdisinin sabit uzunlukta
    olması, uzunluk-uzatma benzeri sürprizleri baştan kaldırıyor.
    """
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """İki çocuğun birleşimi: `SHA256(0x01 ‖ sol ‖ sağ)`."""
    if len(left) != HASH_SIZE or len(right) != HASH_SIZE:
        raise MerkleError(
            f"Düğüm çocukları {HASH_SIZE} byte olmalı; "
            f"{len(left)}/{len(right)} verildi."
        )
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


@dataclass(frozen=True)
class MerkleProof:
    """
    Bir yaprağı köke bağlayan yol.

    `siblings` aşağıdan yukarıya sıralı. `right_flags[i]`, i'inci kardeşin
    o seviyede SAĞDA durduğunu söylüyor — yani birleştirme sırası
    `node_hash(yürüyen, kardeş)`. False ise kardeş solda:
    `node_hash(kardeş, yürüyen)`.

    Yön bilgisi ZORUNLU: `node_hash` sırayla ilgileniyor (`H(a‖b) ≠
    H(b‖a)`) ve yön olmadan yol tek anlamlı değil. İndisten türetmek de
    mümkündü ama yükseltme (odd promotion) indis–seviye ilişkisini
    bozuyor; yönü açıkça taşımak hem daha ucuz hem hatasız.
    """

    leaf_index: int
    siblings: tuple[bytes, ...]
    right_flags: tuple[bool, ...]

    def __post_init__(self) -> None:
        if len(self.siblings) != len(self.right_flags):
            raise MerkleError(
                "Kardeş sayısı ile yön sayısı eşleşmiyor: "
                f"{len(self.siblings)} / {len(self.right_flags)}"
            )
        for h in self.siblings:
            if len(h) != HASH_SIZE:
                raise MerkleError(
                    f"Kardeş hash'i {HASH_SIZE} byte olmalı, {len(h)} verildi."
                )

    @property
    def depth(self) -> int:
        return len(self.siblings)


@dataclass(frozen=True)
class MerkleTree:
    """Kurulmuş ağaç. `levels[0]` yapraklar, `levels[-1]` tek elemanlı kök."""

    levels: tuple[tuple[bytes, ...], ...]

    @property
    def root(self) -> bytes:
        return self.levels[-1][0]

    @property
    def leaf_count(self) -> int:
        return len(self.levels[0])

    def proof(self, index: int) -> MerkleProof:
        """
        `index` numaralı yaprağın köke giden yolu.

        Raises:
            MerkleError — indis aralık dışıysa.
        """
        if not 0 <= index < self.leaf_count:
            raise MerkleError(
                f"Yaprak indisi aralık dışı: {index} "
                f"(ağaçta {self.leaf_count} yaprak var)"
            )

        siblings: list[bytes] = []
        flags: list[bool] = []
        konum = index
        for seviye in self.levels[:-1]:
            es = konum ^ 1
            if es < len(seviye):
                siblings.append(seviye[es])
                # Çift indis solda durur → kardeşi sağdadır.
                flags.append(konum % 2 == 0)
            # `es >= len(seviye)`: bu düğüm tek kalmış ve YÜKSELTİLİYOR.
            # Kardeşi yok, dolayısıyla yola bir şey eklenmiyor — yol
            # uzunluğu yaprağa göre değişebilir, bu normaldir.
            #
            # `konum //= 2` yükseltmede de DOĞRU, ve bu ilk bakışta
            # şaşırtıcı: yükseltilen düğüm bir üst seviyede sona ekleniyor,
            # yani indisi `len(seviye) // 2` oluyor. Ama yükseltilen düğüm
            # her zaman TEK UZUNLUKLU bir seviyenin SON elemanıdır, yani
            # `konum == len(seviye) - 1` ve `len(seviye)` tek. Bu durumda
            # `konum // 2 == (len - 1) // 2 == len // 2` — iki hesap
            # çakışıyor. 1..40 yaprak için tüm indisler ölçülerek
            # doğrulandı (tests/test_merkle.py).
            konum //= 2
        return MerkleProof(
            leaf_index=index,
            siblings=tuple(siblings),
            right_flags=tuple(flags),
        )


def build_tree(leaves: list[bytes]) -> MerkleTree:
    """
    Yaprak ÖZETLERİNDEN ağacı kurar.

    Args:
        leaves: `leaf_hash()` çıktıları (32 byte). Ham veri DEĞİL —
            alan ayrımının uygulanmış olması çağıranın sorumluluğu ve
            `build_leaves()` bunu yapıyor.

    Raises:
        MerkleError — liste boşsa ya da bir yaprak 32 byte değilse.
    """
    if not leaves:
        raise MerkleError(
            "Boş yaprak listesinden ağaç kurulamaz — kökü tanımsız olurdu."
        )
    for i, h in enumerate(leaves):
        if len(h) != HASH_SIZE:
            raise MerkleError(
                f"{i}. yaprak {HASH_SIZE} byte olmalı, {len(h)} verildi."
            )

    seviyeler: list[tuple[bytes, ...]] = [tuple(leaves)]
    while len(seviyeler[-1]) > 1:
        onceki = seviyeler[-1]
        ust: list[bytes] = []
        for i in range(0, len(onceki) - 1, 2):
            ust.append(node_hash(onceki[i], onceki[i + 1]))
        if len(onceki) % 2:
            # Tek kalan düğüm YÜKSELTİLİYOR (kopyalanmıyor) — modül
            # docstring'indeki CVE-2012-2459 gerekçesi.
            ust.append(onceki[-1])
        seviyeler.append(tuple(ust))
    return MerkleTree(levels=tuple(seviyeler))


def build_leaves(payloads: list[bytes]) -> list[bytes]:
    """Ham yükleri yaprak özetlerine çevirir."""
    return [leaf_hash(p) for p in payloads]


def compute_root(leaf: bytes, proof: MerkleProof) -> bytes:
    """
    Yaprak + yol → kök. Doğrulamanın çekirdeği.

    Yalnızca yürüyor; hiçbir şeyi karşılaştırmıyor. Karşılaştırmayı
    `verify_proof()` yapıyor — ayrı durmaları, "hangi kökü ürettin"
    sorusunu hata ayıklarken sorabilmek için.
    """
    if len(leaf) != HASH_SIZE:
        raise MerkleError(f"Yaprak {HASH_SIZE} byte olmalı, {len(leaf)} verildi.")
    yuruyen = leaf
    for kardes, sagda in zip(proof.siblings, proof.right_flags):
        yuruyen = node_hash(yuruyen, kardes) if sagda else node_hash(kardes, yuruyen)
    return yuruyen


def verify_proof(leaf: bytes, proof: MerkleProof, root: bytes) -> bool:
    """
    Yaprağın verilen köke çıkıp çıkmadığı.

    Sabit zamanlı karşılaştırma KULLANILMIYOR ve gerekmiyor: iki taraf da
    zaten dosyada açıkta duran, gizli olmayan değerler. Sabit zaman
    kullanmak burada güvenlik değil, yanlış bir güven işareti olurdu.
    """
    try:
        return compute_root(leaf, proof) == root
    except MerkleError:
        return False


__all__ = [
    "HASH_SIZE",
    "LEAF_PREFIX",
    "NODE_PREFIX",
    "MerkleError",
    "MerkleProof",
    "MerkleTree",
    "build_leaves",
    "build_tree",
    "compute_root",
    "leaf_hash",
    "node_hash",
    "verify_proof",
]
