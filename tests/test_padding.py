"""Pengujian padding PKCS#7 Tahap 2."""

import unittest

from des.padding import pad, unpad


class PaddingTests(unittest.TestCase):
    """Periksa round-trip dan penolakan padding tidak valid."""

    def test_round_trips(self) -> None:
        """Periksa panjang nol sampai tujuh belas dan isi padding tepat."""
        for size in range(18):
            with self.subTest(size=size):
                data = bytes(range(size))
                padded = pad(data)
                count = 8 - size % 8
                self.assertEqual(padded, data + bytes([count]) * count)
                self.assertEqual(unpad(padded), data)

    def test_invalid_padding(self) -> None:
        """Tolak data kosong, blok terpotong, dan byte padding tidak sah."""
        for data in (b"", b"a", b"A" * 9, b"A" * 7 + b"\x00",
                     b"A" * 7 + b"\x09", b"A" * 6 + b"\x01\x02",
                     b"\x07" + b"\x08" * 7):
            with self.subTest(data=data), self.assertRaises(ValueError):
                unpad(data)

    def test_custom_block_sizes(self) -> None:
        """Periksa ukuran blok sah termasuk batas satu dan 255."""
        for block_size in (1, 16, 255):
            for data in (b"", b"abc", bytes(block_size)):
                self.assertEqual(unpad(pad(data, block_size), block_size), data)

    def test_invalid_block_sizes(self) -> None:
        """Tolak ukuran blok di luar rentang PKCS#7."""
        for block_size in (-1, 0, 256):
            for operation in (pad, unpad):
                with self.assertRaises(ValueError):
                    operation(b"", block_size)
