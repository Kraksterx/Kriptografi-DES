"""Analisis avalanche effect pada setiap ronde DES."""

from des.core import encrypt_block_trace
from des.utils import bits_to_bytes, bytes_to_bits


def avalanche_plaintext(plaintext: bytes, key: bytes, bit_index: int) -> list[int]:
    """Hitung perbedaan bit per ronde setelah satu bit plaintext diubah."""
    if len(plaintext) != 8 or len(key) != 8:
        raise ValueError("Plaintext and key must be exactly 8 bytes")
    if bit_index < 0 or bit_index >= 64:
        raise ValueError("Bit index must be between 0 and 63")
    original_bits = bytes_to_bits(plaintext)
    flipped_bits = list(original_bits)
    flipped_bits[bit_index] ^= 1
    flipped_plaintext = bits_to_bytes(flipped_bits)
    trace_orig = encrypt_block_trace(plaintext, key)
    trace_flip = encrypt_block_trace(flipped_plaintext, key)
    return [sum(b1 ^ b2 for b1, b2 in zip(s1, s2)) for s1, s2 in zip(trace_orig[1:], trace_flip[1:])]


def avalanche_key(plaintext: bytes, key: bytes, bit_index: int) -> list[int]:
    """Hitung perbedaan bit per ronde setelah satu bit kunci diubah."""
    if len(plaintext) != 8 or len(key) != 8:
        raise ValueError("Plaintext and key must be exactly 8 bytes")
    if bit_index < 0 or bit_index >= 64:
        raise ValueError("Bit index must be between 0 and 63")
    original_bits = bytes_to_bits(key)
    flipped_bits = list(original_bits)
    flipped_bits[bit_index] ^= 1
    flipped_key = bits_to_bytes(flipped_bits)
    trace_orig = encrypt_block_trace(plaintext, key)
    trace_flip = encrypt_block_trace(plaintext, flipped_key)
    return [sum(b1 ^ b2 for b1, b2 in zip(s1, s2)) for s1, s2 in zip(trace_orig[1:], trace_flip[1:])]


def average_avalanche(plaintext: bytes, key: bytes, mode: str) -> list[float]:
    """Hitung rata-rata avalanche effect per ronde untuk seluruh posisi bit."""
    if mode not in ("plaintext", "key"):
        raise ValueError("Mode must be 'plaintext' or 'key'")
    fn = avalanche_plaintext if mode == "plaintext" else avalanche_key
    round_totals = [0.0] * 16
    for bit_index in range(64):
        diffs = fn(plaintext, key, bit_index)
        for round_idx in range(16):
            round_totals[round_idx] += diffs[round_idx]
    return [total / 64.0 for total in round_totals]
