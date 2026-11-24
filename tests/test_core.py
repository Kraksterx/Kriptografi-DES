"""Test vector dan properti inti DES Tahap 1."""

import os
import unittest

from des.core import decrypt_block, encrypt_block, encrypt_block_trace, feistel, generate_subkeys, permute
from des.tables import FP, IP
from des.utils import bits_to_bytes, bytes_to_bits, bytes_to_hex, hex_to_bytes, xor_bits


class CoreTests(unittest.TestCase):
    """Periksa hasil standar, trace, properti, dan validasi input."""

    def test_vectors(self) -> None:
        """Periksa enkripsi dan dekripsi kedua vector wajib tanpa mengubah expected."""
        for key, plaintext, ciphertext in [
            ("133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"),
            ("0123456789ABCDEF", "4E6F772069732074", "3FA40E8A984D4815"),
        ]:
            with self.subTest(key=key):
                key, plaintext, ciphertext = map(hex_to_bytes, (key, plaintext, ciphertext))
                self.assertEqual(encrypt_block(plaintext, key), ciphertext)
                self.assertEqual(decrypt_block(ciphertext, key), plaintext)

    def test_random_round_trips(self) -> None:
        """Periksa round-trip seratus pasangan blok dan kunci acak."""
        for _ in range(100):
            block, key = os.urandom(8), os.urandom(8)
            self.assertEqual(decrypt_block(encrypt_block(block, key), key), block)

    def test_weak_keys(self) -> None:
        """Periksa enkripsi dua kali dengan masing-masing empat weak key."""
        for key in ("0101010101010101", "FEFEFEFEFEFEFEFE", "E0E0E0E0F1F1F1F1", "1F1F1F1F0E0E0E0E"):
            for _ in range(5):
                block = os.urandom(8)
                key_bytes = hex_to_bytes(key)
                self.assertEqual(encrypt_block(encrypt_block(block, key_bytes), key_bytes), block)

    def test_complementation(self) -> None:
        """Periksa properti komplementasi pada dua puluh pasangan acak."""
        for _ in range(20):
            block, key = os.urandom(8), os.urandom(8)
            complemented_block = bytes(value ^ 255 for value in block)
            complemented_key = bytes(value ^ 255 for value in key)
            expected = bytes(value ^ 255 for value in encrypt_block(block, key))
            self.assertEqual(encrypt_block(complemented_block, complemented_key), expected)

    def test_schedule_and_trace(self) -> None:
        """Periksa subkey serta state antara vector utama."""
        key = hex_to_bytes("133457799BBCDFF1")
        block = hex_to_bytes("0123456789ABCDEF")
        subkeys = generate_subkeys(key)
        self.assertEqual(len(subkeys), 16)
        self.assertTrue(all(len(subkey) == 48 for subkey in subkeys))
        self.assertEqual(bytes_to_hex(bits_to_bytes(subkeys[0])), "1B02EFFC7072")
        self.assertEqual(bytes_to_hex(bits_to_bytes(subkeys[-1])), "CB3D8B0E17F5")
        self.assertEqual(generate_subkeys(bytes(value ^ 1 for value in key)), subkeys)
        states = encrypt_block_trace(block, key)
        self.assertEqual(len(states), 17)
        self.assertTrue(all(len(state) == 64 for state in states))
        self.assertEqual(bytes_to_hex(bits_to_bytes(states[0])), "CC00CCFFF0AAF0AA")
        self.assertEqual(bytes_to_hex(bits_to_bytes(states[1])), "F0AAF0AAEF4A6544")
        self.assertEqual(bytes_to_hex(bits_to_bytes(states[-1])), "434232340A4CD995")
        self.assertEqual(bits_to_bytes(permute(permute(bytes_to_bits(block), IP), FP)), block)

    def test_utils(self) -> None:
        """Periksa konversi MSB-first, hex, dan XOR termasuk data kosong."""
        data = bytes(range(256))
        self.assertEqual(bytes_to_bits(b"\x81"), [1, 0, 0, 0, 0, 0, 0, 1])
        self.assertEqual(bits_to_bytes(bytes_to_bits(data)), data)
        self.assertEqual(hex_to_bytes(bytes_to_hex(data)), data)
        self.assertEqual(bytes_to_hex(b"\xab\xcd"), "ABCD")
        self.assertEqual(hex_to_bytes("aBcD"), b"\xab\xcd")
        self.assertEqual(bits_to_bytes([]), b"")
        self.assertEqual(hex_to_bytes(""), b"")
        self.assertEqual(xor_bits([1, 0], [1, 1]), [0, 1])

    def test_invalid_inputs(self) -> None:
        """Pastikan panjang blok, kunci, bit, dan karakter hex tidak valid ditolak."""
        for size in (0, 1, 7, 9, 16):
            for operation in (encrypt_block, decrypt_block, encrypt_block_trace):
                with self.assertRaises(ValueError):
                    operation(bytes(size), bytes(8))
                with self.assertRaises(ValueError):
                    operation(bytes(8), bytes(size))
            with self.assertRaises(ValueError):
                generate_subkeys(bytes(size))
        for value in ("0", "GG", "00 0", " 00 ", "\t0", "１２"):
            with self.assertRaises(ValueError):
                hex_to_bytes(value)
        for bits in ([1], [2] * 8):
            with self.assertRaises(ValueError):
                bits_to_bytes(bits)
        for left, right in (([0], []), ([2], [0])):
            with self.assertRaises(ValueError):
                xor_bits(left, right)
        for right, subkey in (([0] * 31, [0] * 48), ([0] * 32, [0] * 47)):
            with self.assertRaises(ValueError):
                feistel(right, subkey)
        for table in ([0], [2]):
            with self.assertRaises(ValueError):
                permute([0], table)


if __name__ == "__main__":
    unittest.main()
