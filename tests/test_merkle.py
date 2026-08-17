"""
HYCLEUS — Merkle ağacı testleri

Ağaç, toplu zaman damgasının taşıyıcısı: bir dosyanın "o tarihte vardı"
kanıtı, yaprağının köke çıkmasına dayanıyor. Yol yanlış yürürse damga
yanlış dosyayı kanıtlar.

Buradaki testlerin çoğu ÖZELLİK (property) testi: 1..40 yaprak için TÜM
indisler sınanıyor. Tek tek örnek seçmek, `konum //= 2`'nin yükseltmeyle
etkileşimi gibi ince hataları kaçırırdı — o hata yalnızca belirli yaprak
sayılarında ortaya çıkar.
"""
from __future__ import annotations

import hashlib

import pytest

from CORE.merkle import (
    HASH_SIZE,
    LEAF_PREFIX,
    NODE_PREFIX,
    MerkleError,
    MerkleProof,
    build_leaves,
    build_tree,
    compute_root,
    leaf_hash,
    node_hash,
    verify_proof,
)


def _yukler(n: int) -> list[bytes]:
    """n adet ayırt edilebilir 32 baytlık yük."""
    return [hashlib.sha256(f"belge-{i}".encode()).digest() for i in range(n)]


# ══════════════════════════════════════════════════════════════════════════════
# 1. Ağaç kuruluyor mu
# ══════════════════════════════════════════════════════════════════════════════


def test_tek_yaprakta_kok_yapragin_kendisi() -> None:
    """
    Tek dosyalık toplu damga ÖZEL DURUM OLMADAN çalışmalı.

    Kök yaprağa eşit ve yol boş. Bu sayede `timestamp_batch()` tek
    dosyada da aynı kod yolunu kullanıyor.
    """
    (yaprak,) = build_leaves(_yukler(1))
    agac = build_tree([yaprak])
    assert agac.root == yaprak
    assert agac.proof(0).depth == 0
    assert verify_proof(yaprak, agac.proof(0), agac.root)


def test_iki_yaprak_elle_hesapla_uyusuyor() -> None:
    """Ağacın ürettiği kök, elle hesaplananla aynı olmalı."""
    a, b = build_leaves(_yukler(2))
    agac = build_tree([a, b])
    assert agac.root == node_hash(a, b)


def test_uc_yaprakta_tek_dugum_YUKSELTILIYOR() -> None:
    """
    Tek kalan düğüm KOPYALANMIYOR (`H(c‖c)`), yükseltiliyor.

    Kopyalama Bitcoin'in CVE-2012-2459'una yol açan seçim: farklı yaprak
    listeleri aynı kökü üretebiliyor. Bu test o seçimin yapılmadığını
    sabitliyor.
    """
    a, b, c = build_leaves(_yukler(3))
    agac = build_tree([a, b, c])

    assert agac.root == node_hash(node_hash(a, b), c)
    assert agac.root != node_hash(node_hash(a, b), node_hash(c, c))


def test_bos_liste_reddediliyor() -> None:
    """Boş ağacın kökü tanımsız — sessiz bir sabit döndürmek yanlış olurdu."""
    with pytest.raises(MerkleError, match="Boş yaprak"):
        build_tree([])


@pytest.mark.parametrize("boyut", [0, 1, 31, 33, 64])
def test_yanlis_boyutlu_yaprak_reddediliyor(boyut: int) -> None:
    with pytest.raises(MerkleError, match="byte olmalı"):
        build_tree([b"\x00" * boyut])


# ══════════════════════════════════════════════════════════════════════════════
# 2. Yol doğrulaması — TÜM indisler, 1..40 yaprak
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("n", list(range(1, 41)))
def test_her_yapragin_yolu_koke_cikiyor(n: int) -> None:
    """
    ASIL ÖZELLİK. Tek örnekle sınamak yetmez: yükseltme yalnızca tek
    sayıda düğüm kalan seviyelerde devreye giriyor ve o da yaprak
    sayısına bağlı.
    """
    yapraklar = build_leaves(_yukler(n))
    agac = build_tree(yapraklar)
    for i in range(n):
        assert verify_proof(yapraklar[i], agac.proof(i), agac.root), (
            f"n={n}, indis={i} köke çıkmadı"
        )


@pytest.mark.parametrize("n", [2, 3, 5, 8, 17])
def test_yanlis_yaprak_ayni_yolla_koke_cikmiyor(n: int) -> None:
    """Yol doğru olsa bile başka bir yaprakla kök tutmamalı."""
    yapraklar = build_leaves(_yukler(n))
    agac = build_tree(yapraklar)
    sahte = leaf_hash(b"\xff" * 32)
    for i in range(n):
        assert not verify_proof(sahte, agac.proof(i), agac.root)


def test_yol_derinligi_logaritmik() -> None:
    """
    Yol boyutu iddiası ölçülüyor: 100 yaprak → en fazla 7 kardeş = 224 B.

    Docstring'lerde geçen "birkaç yüz byte" sayısı buradan geliyor;
    ölçmeden yazılmış olsaydı ilk büyük turda yanlış çıkardı.
    """
    yapraklar = build_leaves(_yukler(100))
    agac = build_tree(yapraklar)
    derinlikler = [agac.proof(i).depth for i in range(100)]
    assert max(derinlikler) == 7
    assert max(derinlikler) * HASH_SIZE == 224


def test_aralik_disi_indis_reddediliyor() -> None:
    agac = build_tree(build_leaves(_yukler(4)))
    for kotu in (-1, 4, 99):
        with pytest.raises(MerkleError, match="aralık dışı"):
            agac.proof(kotu)


# ══════════════════════════════════════════════════════════════════════════════
# 3. Bir yaprak değişince — diğerleri BOZULMAMALI
# ══════════════════════════════════════════════════════════════════════════════


def test_bir_dosya_degisince_diger_yollar_ESKI_KOKTE_gecerli_kaliyor() -> None:
    """
    KULLANICININ SORDUĞU GARANTİ.

    Bir dosya değişirse yalnızca ONUN kanıtı geçersizleşmeli. Diğer
    dosyaların damgası, damgalandıkları ANDAKİ köke göre hâlâ geçerli
    olmalı — çünkü onların içeriği değişmedi ve TSA o kökü imzaladı.

    Ayrım önemli: yeni ağacın kökü elbette farklı (ağacın işi bu). Ama
    dosyalardaki fragmanlar ESKİ kökü ve eski yolları taşıyor ve o damga
    hâlâ doğru bir şey söylüyor.
    """
    yukler = _yukler(6)
    yapraklar = build_leaves(yukler)
    agac = build_tree(yapraklar)
    eski_kok = agac.root
    eski_yollar = [agac.proof(i) for i in range(6)]

    # 2 numaralı dosya değişti.
    yukler[2] = hashlib.sha256(b"DEGISTIRILDI").digest()
    yeni_yapraklar = build_leaves(yukler)
    yeni_kok = build_tree(yeni_yapraklar).root

    assert yeni_kok != eski_kok, "içerik değişti ama kök aynı kaldı"

    # Değişmeyen dosyalar eski kökte hâlâ geçerli.
    for i in (0, 1, 3, 4, 5):
        assert verify_proof(yapraklar[i], eski_yollar[i], eski_kok)

    # Değişen dosyanın YENİ içeriği eski köke çıkmıyor — kanıt tam olarak
    # bu dosya için bozuldu.
    assert not verify_proof(yeni_yapraklar[2], eski_yollar[2], eski_kok)


def test_tek_bit_degisimi_koku_degistiriyor() -> None:
    yukler = _yukler(8)
    kok1 = build_tree(build_leaves(yukler)).root
    bozuk = bytearray(yukler[5])
    bozuk[0] ^= 0x01
    yukler[5] = bytes(bozuk)
    assert build_tree(build_leaves(yukler)).root != kok1


def test_sira_degisince_kok_degisiyor() -> None:
    """Yaprak sırası ANLAMLI — sözleşmede yazılı, burada sabitleniyor."""
    yukler = _yukler(5)
    kok1 = build_tree(build_leaves(yukler)).root
    kok2 = build_tree(build_leaves(list(reversed(yukler)))).root
    assert kok1 != kok2


# ══════════════════════════════════════════════════════════════════════════════
# 4. İkinci öngörüntü — alan ayrımı
# ══════════════════════════════════════════════════════════════════════════════


def test_yaprak_ve_dugum_farkli_alanlarda() -> None:
    """
    `leaf_hash(x)` ile `node_hash` çıktıları KARIŞMAMALI.

    Ön ekler olmasaydı bir iç düğüm değeri geçerli bir yaprak değeri
    olabilir ve saldırgan onu "dosya özeti" diye sunabilirdi.
    """
    a = b"\x11" * 32
    b = b"\x22" * 32
    assert leaf_hash(a + b) != node_hash(a, b)
    assert LEAF_PREFIX != NODE_PREFIX


def test_ic_dugum_degeri_YAPRAK_YUKU_olarak_uretilemiyor() -> None:
    """
    ASIL İKİNCİ ÖNGÖRÜNTÜ TESTİ — `LEAF_PREFIX`'i kaldıran mutasyonu
    öldüren tek test.

    Saldırganın istediği şey: bir iç düğümün DEĞERİNİ, bir yaprağın
    özeti olarak ürettirmek. İç düğüm `SHA256(0x01‖sol‖sağ)` olduğuna
    göre, yaprak yükü olarak `0x01‖sol‖sağ` (65 byte) verirse ve yaprak
    özetlemesi ön eksiz olsaydı ikisi AYNI değeri üretirdi.

    `LEAF_PREFIX` bunu yapısal olarak imkânsız kılıyor: yaprak
    `SHA256(0x00‖…)`, düğüm `SHA256(0x01‖…)` — ön ekler farklı olduğu
    sürece iki uzay kesişemez.

    İlk yazdığım test bunu ÖLÇMÜYORDU: `leaf_hash(a+b) != node_hash(a,b)`
    diyordu ve `LEAF_PREFIX` kaldırılsa bile `NODE_PREFIX` durduğu için
    geçiyordu. Mutasyon testi hayatta kaldı ve açığı gösterdi.
    """
    sol = b"\x11" * 32
    sag = b"\x22" * 32
    ic_dugum = node_hash(sol, sag)

    kotu_yuk = NODE_PREFIX + sol + sag       # düğümün ön görüntüsü
    assert leaf_hash(kotu_yuk) != ic_dugum

    # Aynı iddianın doğrudan hâli: yaprak özetlemesi ham SHA-256 DEĞİL.
    assert leaf_hash(kotu_yuk) == hashlib.sha256(
        LEAF_PREFIX + kotu_yuk
    ).digest()
    assert leaf_hash(kotu_yuk) != hashlib.sha256(kotu_yuk).digest()


def test_dugum_ozetlemesi_de_on_ekli() -> None:
    """
    `NODE_PREFIX` gerçekten uygulanıyor mu.

    DÜRÜST NOT: bu ön ek, HYCLEUS'un kullandığı SABİT 32 baytlık
    yüklerde tek başına GEREKLİ DEĞİL — `LEAF_PREFIX` varken yaprak
    ön görüntüsü 33, düğüm ön görüntüsü 64 byte ve iki uzay zaten
    kesişemiyor. Mutasyon testi bunu gösterdi: yalnızca `NODE_PREFIX`'i
    kaldıran değişiklik hiçbir davranışı bozmuyor.

    Yine de duruyor ve sınanıyor: değişken uzunluklu bir yaprak yükü
    eklenirse (bugün yok) tek koruma o olurdu. Ön ekin varlığını teste
    bağlamak, "gereksiz" diye sessizce silinmesini engelliyor.
    """
    sol = b"\x33" * 32
    sag = b"\x44" * 32
    assert node_hash(sol, sag) == hashlib.sha256(
        NODE_PREFIX + sol + sag
    ).digest()
    assert node_hash(sol, sag) != hashlib.sha256(sol + sag).digest()


def test_ic_dugum_yaprak_gibi_sunulamiyor() -> None:
    """
    İKİNCİ ÖNGÖRÜNTÜ SALDIRISI — somut senaryo.

    4 yapraklı ağaçta `H(l0‖l1)` bir iç düğüm. Saldırgan onu "yaprak"
    diye sunup kısaltılmış bir yolla köke çıkarmaya çalışıyor. Alan
    ayrımı sayesinde iç düğümün değeri hiçbir yaprağın değeri olamaz,
    dolayısıyla `leaf_hash(ic_dugum)` ≠ `ic_dugum` ve yol tutmuyor.
    """
    yapraklar = build_leaves(_yukler(4))
    agac = build_tree(yapraklar)
    ic_dugum = agac.levels[1][0]          # H(l0‖l1)
    sag_dal = agac.levels[1][1]           # H(l2‖l3)

    # İç düğümü "yaprak" sayıp tek adımlık bir yol kuruyoruz.
    sahte_yol = MerkleProof(
        leaf_index=0, siblings=(sag_dal,), right_flags=(True,)
    )
    # Ham iç düğüm değeri köke çıkar (matematik böyle) —
    assert compute_root(ic_dugum, sahte_yol) == agac.root
    # — ama YAPRAK OLARAK sunulduğunda çıkmaz: yaprak olmak 0x00 ön eki
    # gerektiriyor ve hiçbir iç düğüm o biçimde üretilmiyor.
    assert not verify_proof(leaf_hash(ic_dugum), sahte_yol, agac.root)


# ══════════════════════════════════════════════════════════════════════════════
# 5. MerkleProof sözleşmesi
# ══════════════════════════════════════════════════════════════════════════════


def test_kardes_ve_yon_sayisi_esit_olmali() -> None:
    with pytest.raises(MerkleError, match="eşleşmiyor"):
        MerkleProof(leaf_index=0, siblings=(b"\x00" * 32,), right_flags=())


def test_kardes_hashi_32_byte_olmali() -> None:
    with pytest.raises(MerkleError, match="32 byte olmalı"):
        MerkleProof(leaf_index=0, siblings=(b"kisa",), right_flags=(True,))


def test_yon_yanlis_olursa_kok_tutmuyor() -> None:
    """
    `node_hash(a,b) ≠ node_hash(b,a)` — yön bilgisi gerçekten gerekli.

    Yön indisten türetilseydi yükseltme onu bozardı; bu test yönün
    taşınmasının boşuna olmadığını gösteriyor.
    """
    yapraklar = build_leaves(_yukler(4))
    agac = build_tree(yapraklar)
    dogru = agac.proof(1)
    ters = MerkleProof(
        leaf_index=1,
        siblings=dogru.siblings,
        right_flags=tuple(not f for f in dogru.right_flags),
    )
    assert verify_proof(yapraklar[1], dogru, agac.root)
    assert not verify_proof(yapraklar[1], ters, agac.root)


def test_verify_proof_bozuk_yaprakta_patlamiyor() -> None:
    """Doğrulama girdi hatasında False dönmeli, istisna değil."""
    agac = build_tree(build_leaves(_yukler(2)))
    assert verify_proof(b"kisa", agac.proof(0), agac.root) is False


def test_node_hash_yanlis_boyutu_reddediyor() -> None:
    with pytest.raises(MerkleError, match="32 byte olmalı"):
        node_hash(b"kisa", b"\x00" * 32)
