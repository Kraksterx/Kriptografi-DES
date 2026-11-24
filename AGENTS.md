# AGENTS.md - Proyek Kriptografi: DES

## Tujuan
Implementasi DES from scratch dengan Python, dilengkapi UI Tkinter dan modul analisis (avalanche effect, brute force kunci kecil, weak key). Tugas kelompok 5 orang, mata kuliah Kriptografi. Semua logika DES harus bisa dijelaskan saat presentasi.

## Aturan Wajib
1. Logika DES (permutasi, S-box, Feistel, key schedule, padding, mode operasi) TIDAK boleh memakai library kripto atau library pihak ketiga. Hanya standard library Python.
2. Library hanya boleh untuk hal non-inti: `tkinter` (UI), `os.urandom` (IV), `unittest` (test), `time`/`csv`/`argparse` jika perlu. Jika butuh library lain, tulis alasannya di README sebelum dipakai.
3. Komentar seminimal mungkin: satu docstring satu baris per fungsi yang menjelaskan kegunaannya. Tanpa komentar inline kecuali benar-benar tidak jelas.
4. Jangan ubah signature fungsi di bagian "Antarmuka" tanpa memperbarui file ini dan memberi tahu seluruh tim.
5. Satu tahap selesai hanya jika semua test tahap itu lolos. Jangan lanjut ke tahap berikutnya sebelum itu.
6. Jangan menulis ulang file yang sudah selesai kecuali diminta. Perubahan dilakukan seminimal mungkin.
7. Nama fungsi/variabel dalam bahasa Inggris, snake_case. Tipe data ditulis dengan type hint.

## Struktur Repo
    des/
      __init__.py
      tables.py       # IP, FP, E, P, PC1, PC2, SHIFTS, SBOXES
      core.py         # inti DES (blok 64 bit)
      padding.py      # PKCS#7
      modes.py        # ECB dan CBC
      utils.py        # konversi hex/bytes/bits, parsing kunci
    analysis/
      avalanche.py
      bruteforce.py
      weak_keys.py
    ui/
      app.py          # Tkinter
    tests/
      test_core.py
      test_padding.py
      test_modes.py
      test_analysis.py
    README.md
    AGENTS.md

## Representasi Data
- Blok, kunci, IV, plaintext, ciphertext: `bytes`.
- Kunci DES: 8 byte (64 bit, bit paritas diabaikan). Input kunci dari user berupa 16 karakter hex.
- Di dalam `core.py`, data diproses sebagai `list[int]` berisi 0/1 agar mudah dijelaskan dan di-trace.
- Semua tabel memakai indeks 1-based sesuai standar FIPS 46-3; `permute` yang mengurangi 1 saat mengakses.

## Antarmuka (jangan diubah sepihak)
`des/utils.py`
- `bytes_to_bits(data: bytes) -> list[int]`
- `bits_to_bytes(bits: list[int]) -> bytes`
- `hex_to_bytes(hex_str: str) -> bytes` (validasi panjang dan karakter, raise `ValueError`)
- `bytes_to_hex(data: bytes) -> str` (huruf besar)
- `xor_bits(a: list[int], b: list[int]) -> list[int]`

`des/core.py`
- `permute(bits: list[int], table: list[int]) -> list[int]`
- `generate_subkeys(key: bytes) -> list[list[int]]` (16 subkey, masing-masing 48 bit)
- `feistel(right: list[int], subkey: list[int]) -> list[int]` (ekspansi E, XOR, 8 S-box, permutasi P; output 32 bit)
- `encrypt_block(block: bytes, key: bytes) -> bytes` (blok 8 byte)
- `decrypt_block(block: bytes, key: bytes) -> bytes`
- `encrypt_block_trace(block: bytes, key: bytes) -> list[list[int]]` (state 64 bit setelah IP dan setelah tiap ronde; untuk analisis dan penjelasan)

`des/padding.py`
- `pad(data: bytes, block_size: int = 8) -> bytes`
- `unpad(data: bytes, block_size: int = 8) -> bytes` (raise `ValueError` jika padding tidak valid)

`des/modes.py`
- `encrypt(data: bytes, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes`
- `decrypt(data: bytes, key: bytes, mode: str = "CBC") -> bytes`
- `mode` bernilai `"ECB"` atau `"CBC"`. Pada CBC, jika `iv` None maka dibuat acak 8 byte dengan `os.urandom`, dan IV ditaruh di 8 byte pertama ciphertext. `decrypt` membaca IV dari 8 byte pertama.
- Padding PKCS#7 diterapkan otomatis di `encrypt` dan dilepas di `decrypt`.

`analysis/avalanche.py`
- `avalanche_plaintext(plaintext: bytes, key: bytes, bit_index: int) -> list[int]` (jumlah bit berbeda per ronde setelah 1 bit plaintext diubah)
- `avalanche_key(plaintext: bytes, key: bytes, bit_index: int) -> list[int]` (sama, untuk 1 bit kunci)
- `average_avalanche(plaintext: bytes, key: bytes, mode: str) -> list[float]` (rata-rata semua posisi bit; `mode` = `"plaintext"` atau `"key"`)

`analysis/bruteforce.py`
- `bruteforce_reduced_key(plaintext: bytes, ciphertext: bytes, known_key_prefix: bytes, unknown_bits: int) -> tuple[bytes | None, int, float]`
  `unknown_bits` dibatasi maksimal 24, default demo 16-20. Bit yang tidak diketahui hanya
  boleh menempati 7 bit non-paritas (bit 1-7 dari kiri) pada byte-byte terakhir kunci,
  bukan bit paritas. Hasil ditutup dengan estimasi waktu 2^56 dari kecepatan terukur.
- `estimate_full_bruteforce(trials_per_second: float) -> float` (estimasi waktu 2^56 kunci dalam tahun)

`analysis/weak_keys.py`
- `WEAK_KEYS: list[bytes]` (4 weak key)
- `SEMI_WEAK_KEYS: list[bytes]` (12 semi-weak key)
- `is_weak_key(key: bytes) -> bool`
- `check_complementation(plaintext: bytes, key: bytes) -> bool` (memverifikasi E(~K, ~P) == ~E(K, P))

## Test Wajib
- Test vector utama: key `133457799BBCDFF1`, plaintext `0123456789ABCDEF`, ciphertext `85E813540F0AB405`.
- Test vector kedua: key `0123456789ABCDEF`, plaintext `4E6F772069732074` ("Now is t"), ciphertext `3FA40E8A984D4815`. Jika hasil berbeda, jangan langsung mengubah test; laporkan agar diverifikasi manual.
- `decrypt_block(encrypt_block(x, k), k) == x` untuk banyak blok acak.
- Pada weak key, `encrypt_block(encrypt_block(x, k), k) == x`.
- Properti komplementasi lolos untuk beberapa pasangan acak.
- Padding: round-trip untuk panjang 0 sampai 17 byte; `unpad` menolak padding rusak.
- Mode: round-trip ECB dan CBC untuk data kosong, 1 byte, 8 byte, dan 1000 byte. Pada CBC, enkripsi dua kali memberi ciphertext berbeda (IV acak).
- Perbandingan dengan library kripto hanya boleh di skrip terpisah `dev_check.py` yang tidak di-import oleh kode proyek dan tidak masuk ke repo final.

## Fitur UI (Tkinter)
Tab Enkripsi/Dekripsi teks dan file (input kunci hex, pilih mode ECB/CBC, tampilkan hasil hex). Tab Analisis berisi avalanche (tabel/grafik sederhana per ronde), demo brute force kunci kecil, dan pengecekan weak key. UI hanya memanggil fungsi di `des/` dan `analysis/`, tanpa logika kripto di dalam UI.

## Roadmap
- [ ] Tahap 1: `tables.py`, `utils.py`, `core.py` + `test_core.py` (test vector lolos)
- [ ] Tahap 2: `padding.py`, `modes.py` + test
- [ ] Tahap 3: `analysis/` (avalanche, brute force, weak keys) + test
- [ ] Tahap 4: `ui/app.py` (enkripsi/dekripsi teks dan file)
- [ ] Tahap 5: UI tab analisis
- [ ] Tahap 6: README (cara menjalankan, ringkasan algoritma), bahan laporan dan presentasi

Pembagian tugas: bebas dipilih anggota. Tulis nama di samping tahap yang diambil dan pastikan tidak ada dua orang mengerjakan file yang sama.