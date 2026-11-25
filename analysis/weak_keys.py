"""Pendeteksian weak key, semi-weak key, dan properti komplementasi DES."""

from des.core import encrypt_block
from des.utils import hex_to_bytes

WEAK_KEYS: list[bytes] = [
    hex_to_bytes("0101010101010101"),
    hex_to_bytes("FEFEFEFEFEFEFEFE"),
    hex_to_bytes("E0E0E0E0F1F1F1F1"),
    hex_to_bytes("1F1F1F1F0E0E0E0E"),
]

SEMI_WEAK_KEYS: list[bytes] = [
    hex_to_bytes("01FE01FE01FE01FE"),
    hex_to_bytes("FE01FE01FE01FE01"),
    hex_to_bytes("1FE01FE00EF10EF1"),
    hex_to_bytes("E01FE01FF10EF10E"),
    hex_to_bytes("01E001E001F101F1"),
    hex_to_bytes("E001E001F101F101"),
    hex_to_bytes("1FFE1FFE0EFE0EFE"),
    hex_to_bytes("FE1FFE1FFE0EFE0E"),
    hex_to_bytes("011F011F010E010E"),
    hex_to_bytes("1F011F010E010E01"),
    hex_to_bytes("E0FEE0FEF1FEF1FE"),
    hex_to_bytes("FEE0FEE0FEF1FEF1"),
]


def is_weak_key(key: bytes) -> bool:
    """Periksa apakah kunci merupakan weak key atau semi-weak key DES."""
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes")
    return key in WEAK_KEYS or key in SEMI_WEAK_KEYS


def check_complementation(plaintext: bytes, key: bytes) -> bool:
    """Verifikasi apakah E(~K, ~P) menghasilkan komplemen dari E(K, P)."""
    if len(plaintext) != 8 or len(key) != 8:
        raise ValueError("Plaintext and key must be exactly 8 bytes")
    complemented_plaintext = bytes(byte ^ 0xFF for byte in plaintext)
    complemented_key = bytes(byte ^ 0xFF for byte in key)
    original_ciphertext = encrypt_block(plaintext, key)
    complemented_ciphertext = encrypt_block(complemented_plaintext, complemented_key)
    return complemented_ciphertext == bytes(byte ^ 0xFF for byte in original_ciphertext)
