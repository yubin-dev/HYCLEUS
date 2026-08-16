# Semgrep kanaryaları

Bu dizindeki dosyalar **bilerek güvensizdir** ve HYCLEUS'un hiçbir yerinden
import edilmez. Tek işleri `.semgrep/hycleus.yml` içindeki kuralların
gerçekten tetiklendiğini kanıtlamak.

Neden gerekli: bir semgrep kuralı sözdizimi hatası, yanlış `paths` filtresi
ya da eşleşmeyen bir desen yüzünden **hiçbir şey bulamaz hâle gelebilir** ve
tarama yine yeşil çıkar. Yeşil tarama iki şeyin ikisine de benziyor:
"kod temiz" ve "kural ölü". Kanarya ikisini ayırıyor.

`tests/test_static_analysis.py` her kural için burada en az bir eşleşme
olduğunu doğruluyor. Yeni bir kural eklerken kanaryasını da ekleyin —
test aksi hâlde kırılır.

Dosya adları `canary_` ile başlıyor ki `pytest` bunları test modülü sanmasın
(`pytest.ini` içindeki `python_files` deseni `test_*.py`).
