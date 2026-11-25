import os
import unittest

from analysis.avalanche import avalanche_key, avalanche_plaintext, average_avalanche
from analysis.bruteforce import bruteforce_reduced_key, estimate_full_bruteforce
from analysis.weak_keys import SEMI_WEAK_KEYS, WEAK_KEYS, check_complementation, is_weak_key
from des.core import encrypt_block
from des.utils import hex_to_bytes


class AnalysisTests(unittest.TestCase):
    """Pengujian avalanche effect, weak keys, komplementasi, dan brute force."""

    def test_avalanche_length_and_range(self) -> None:
        """Pastikan avalanche effect menghasilkan 16 ronde dalam rentang 0-64 bit."""
        plaintext = hex_to_bytes("0123456789ABCDEF")
        key = hex_to_bytes("133457799BBCDFF1")
        diffs_pt = avalanche_plaintext(plaintext, key, 0)
        diffs_key = avalanche_key(plaintext, key, 0)
        self.assertEqual(len(diffs_pt), 16)
        self.assertEqual(len(diffs_key), 16)
        self.assertTrue(all(0 <= count <= 64 for count in diffs_pt))
        self.assertTrue(all(0 <= count <= 64 for count in diffs_key))

    def test_average_avalanche(self) -> None:
        """Pastikan rata-rata avalanche effect menghasilkan nilai float sekitar 32 bit."""
        plaintext = hex_to_bytes("0123456789ABCDEF")
        key = hex_to_bytes("133457799BBCDFF1")
        avg_pt = average_avalanche(plaintext, key, "plaintext")
        avg_key = average_avalanche(plaintext, key, "key")
        self.assertEqual(len(avg_pt), 16)
        self.assertEqual(len(avg_key), 16)
        self.assertGreater(avg_pt[-1], 20.0)
        self.assertGreater(avg_key[-1], 20.0)

    def test_weak_and_semi_weak_keys(self) -> None:
        """Pastikan 4 weak keys dan 12 semi-weak keys terdeteksi dengan tepat."""
        self.assertEqual(len(WEAK_KEYS), 4)
        self.assertEqual(len(SEMI_WEAK_KEYS), 12)
        for key in WEAK_KEYS:
            self.assertTrue(is_weak_key(key))
        for key in SEMI_WEAK_KEYS:
            self.assertTrue(is_weak_key(key))
        normal_key = hex_to_bytes("133457799BBCDFF1")
        self.assertFalse(is_weak_key(normal_key))

    def test_complementation_property(self) -> None:
        """Verifikasi properti komplementasi DES untuk sampel acak."""
        for _ in range(5):
            plaintext = os.urandom(8)
            key = os.urandom(8)
            self.assertTrue(check_complementation(plaintext, key))

    def test_bruteforce_reduced_key(self) -> None:
        """Uji pencarian kunci 8-bit tereduksi dan verifikasi hasil kecocokan."""
        plaintext = hex_to_bytes("0123456789ABCDEF")
        base_key = bytearray(hex_to_bytes("133457799BBCDF00"))
        # Set 8 bit non-paritas terakhir untuk kunci target
        target_key = bytes(base_key)
        ciphertext = encrypt_block(plaintext, target_key)
        found_key, trials, elapsed = bruteforce_reduced_key(plaintext, ciphertext, target_key[:7], 8)
        self.assertIsNotNone(found_key)
        self.assertEqual(encrypt_block(plaintext, found_key), ciphertext)
        self.assertGreater(trials, 0)
        self.assertGreater(elapsed, 0.0)

    def test_estimate_full_bruteforce(self) -> None:
        """Pastikan kalkulasi estimasi waktu 2^56 menghasilkan nilai tahun positif."""
        years = estimate_full_bruteforce(1_000_000.0)
        self.assertGreater(years, 0.0)
