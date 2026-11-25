import sys
from pathlib import Path

# Memastikan direktori 'des' ditemukan setiap skrip dijalankan
for candidate in [
    Path(__file__).resolve().parent,
    Path(__file__).resolve().parent / "Kriptografi-DES",
    Path.cwd(),
    Path.cwd() / "Kriptografi-DES",
]:
    if (candidate / "des" / "__init__.py").exists():
        if str(candidate) not in sys.path:
            sys.path.insert(0, str(candidate))
        break

from des.core import encrypt_block, decrypt_block
from des.modes import encrypt, decrypt
from des.utils import bytes_to_hex, hex_to_bytes


def main():
    print("=" * 60)
    print("DEMO PENGUJIAN IMPLEMENTASI DES")
    print("=" * 60)

    # -------------------------------------------------------------
    # 1. UJI BLOK TUNGGAL (64-BIT / 8 BYTE) SESUAI STANDAR FIPS 46-3
    # -------------------------------------------------------------
    print("\n[1] Uji Blok Tunggal DES (FIPS 46-3 Test Vector)")
    key_hex = "133457799BBCDFF1"
    plain_hex = "0123456789ABCDEF"
    expected_cipher_hex = "85E813540F0AB405"

    key = hex_to_bytes(key_hex)
    block = hex_to_bytes(plain_hex)

    # Enkripsi & Dekripsi blok tunggal
    cipher_block = encrypt_block(block, key)
    decrypted_block = decrypt_block(cipher_block, key)

    print(f"Kunci (Hex)        : {key_hex}")
    print(f"Plaintext (Hex)    : {plain_hex}")
    print(f"Ciphertext (Hex)   : {bytes_to_hex(cipher_block)}")
    print(f"Expected (FIPS)    : {expected_cipher_hex}")
    print(f"Hasil Dekripsi     : {bytes_to_hex(decrypted_block)}")
    assert bytes_to_hex(cipher_block) == expected_cipher_hex, "Ciphertext tidak cocok!"
    assert decrypted_block == block, "Dekripsi gagal!"
    print("Status: LULUS (Sesuai spesifikasi FIPS 46-3)")

    # -------------------------------------------------------------
    # 2. UJI MODE CBC (TEKS BEBAS + PKCS#7 PADDING + RANDOM IV)
    # -------------------------------------------------------------
    print("\n" + "-" * 60)
    print("[2] Uji Enkripsi Teks dengan Mode CBC")
    pesan_asli = "Halo, kami dari Kelompok 2 Algoritma DES"
    pesan_bytes = pesan_asli.encode("utf-8")

    # Enkripsi mode CBC (otomatis generate IV 8 byte dan padding PKCS#7)
    ciphertext_cbc = encrypt(pesan_bytes, key, mode="CBC")
    # Dekripsi mode CBC (membaca IV dari 8 byte pertama dan unpad)
    decrypted_cbc = decrypt(ciphertext_cbc, key, mode="CBC")

    print(f"Pesan Asli         : {pesan_asli}")
    print(f"Panjang Plaintext  : {len(pesan_bytes)} byte")
    print(f"Ciphertext CBC     : {bytes_to_hex(ciphertext_cbc)}")
    print(f"Panjang Ciphertext : {len(ciphertext_cbc)} byte (termasuk 8 byte IV)")
    print(f"Hasil Dekripsi     : {decrypted_cbc.decode('utf-8')}")
    assert decrypted_cbc == pesan_bytes, "Dekripsi CBC gagal!"
    print("Status: LULUS (Round-trip CBC sukses)")

    # -------------------------------------------------------------
    # 3. UJI MODE ECB (ELECTRONIC CODEBOOK)
    # -------------------------------------------------------------
    print("\n" + "-" * 60)
    print("[3] Uji Enkripsi Teks dengan Mode ECB")
    ciphertext_ecb = encrypt(pesan_bytes, key, mode="ECB")
    decrypted_ecb = decrypt(ciphertext_ecb, key, mode="ECB")

    print(f"Ciphertext ECB     : {bytes_to_hex(ciphertext_ecb)}")
    print(f"Hasil Dekripsi     : {decrypted_ecb.decode('utf-8')}")
    assert decrypted_ecb == pesan_bytes, "Dekripsi ECB gagal!"
    print("Status: LULUS (Round-trip ECB sukses)")

    print("\n" + "=" * 60)
    print("SEMUA PENGUJIAN BERHASIL DENGAN BENAR!")
    print("=" * 60)


if __name__ == "__main__":
    main()
