"""Pengujian mode ECB dan CBC Tahap 2."""

import unittest

from des.core import encrypt_block
from des.modes import decrypt, encrypt
from des.padding import pad


class ModeTests(unittest.TestCase):
    """Periksa format ciphertext, chaining, round-trip, dan input rusak."""

    key: bytes = bytes.fromhex("133457799BBCDFF1")

    def test_round_trips(self) -> None:
        """Periksa ECB dan CBC untuk data kosong, satu, delapan, dan seribu byte."""
        for mode in ("ECB", "CBC"):
            for size in (0, 1, 8, 1000):
                with self.subTest(mode=mode, size=size):
                    data = bytes(index % 256 for index in range(size))
                    ciphertext = encrypt(data, self.key, mode)
                    self.assertEqual(len(ciphertext), (size // 8 + 1) * 8 + (8 if mode == "CBC" else 0))
                    self.assertEqual(decrypt(ciphertext, self.key, mode), data)

    def test_random_iv(self) -> None:
        """Periksa CBC default menghasilkan IV dan ciphertext berbeda."""
        first = encrypt(b"same plaintext", self.key)
        second = encrypt(b"same plaintext", self.key)
        self.assertNotEqual(first[:8], second[:8])
        self.assertNotEqual(first, second)

    def test_explicit_iv_and_chaining(self) -> None:
        """Periksa awalan IV dan rantai CBC langsung terhadap inti DES."""
        iv = bytes.fromhex("0123456789ABCDEF")
        data = b"abcdefgh"
        first = encrypt_block(bytes(a ^ b for a, b in zip(data, iv)), self.key)
        second = encrypt_block(bytes(a ^ b for a, b in zip(pad(b""), first)), self.key)
        ciphertext = encrypt(data, self.key, "CBC", iv)
        self.assertEqual(ciphertext, iv + first + second)
        self.assertEqual(decrypt(ciphertext, self.key), data)

    def test_ecb_identical_blocks(self) -> None:
        """Periksa dua blok plaintext identik menghasilkan blok ECB identik."""
        block = b"abcdefgh"
        ciphertext = encrypt(block * 2, self.key, "ECB")
        self.assertEqual(ciphertext[:8], ciphertext[8:16])
        self.assertEqual(ciphertext[:8], encrypt_block(block, self.key))

    def test_wrong_key(self) -> None:
        """Pastikan kunci salah tidak mengembalikan plaintext asli pada kedua mode."""
        data = b"wrong key test plaintext"
        wrong_key = bytes.fromhex("0123456789ABCDEF")
        for mode in ("ECB", "CBC"):
            ciphertext = encrypt(data, self.key, mode)
            try:
                recovered = decrypt(ciphertext, wrong_key, mode)
            except ValueError:
                continue
            self.assertNotEqual(recovered, data)

    def test_invalid_inputs(self) -> None:
        """Tolak mode, IV, panjang ciphertext, dan panjang kunci tidak sah."""
        for mode in ("", "cbc", "CFB"):
            with self.assertRaises(ValueError):
                encrypt(b"", self.key, mode)
            with self.assertRaises(ValueError):
                decrypt(bytes(16), self.key, mode)
        for size in (0, 1, 7, 9, 16):
            with self.assertRaises(ValueError):
                encrypt(b"", self.key, "CBC", bytes(size))
        with self.assertRaises(ValueError):
            encrypt(b"", self.key, "ECB", bytes(8))
        for mode in ("ECB", "CBC"):
            for size in (0, 1, 7, 9, 15, 17):
                with self.assertRaises(ValueError):
                    decrypt(bytes(size), self.key, mode)
            for size in (0, 7, 9):
                with self.assertRaises(ValueError):
                    encrypt(b"", bytes(size), mode)
                with self.assertRaises(ValueError):
                    decrypt(bytes(16), bytes(size), mode)
        with self.assertRaises(ValueError):
            decrypt(bytes(8), self.key, "CBC")

    def test_invalid_decrypted_padding(self) -> None:
        """Pastikan dekripsi meneruskan penolakan padding rusak di kedua mode."""
        invalid = b"A" * 7 + b"\x00"
        ciphertext = encrypt_block(invalid, self.key)
        for mode, data in (("ECB", ciphertext), ("CBC", bytes(8) + ciphertext)):
            with self.assertRaises(ValueError):
                decrypt(data, self.key, mode)
