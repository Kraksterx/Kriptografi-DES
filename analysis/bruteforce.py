"""Simulasi brute force dengan ruang kunci tereduksi dan estimasi waktu."""

import time

from des.core import encrypt_block
from des.utils import bits_to_bytes, bytes_to_bits

NON_PARITY_INDICES = [idx for idx in range(64) if (idx % 8) != 7]


def bruteforce_reduced_key(
    plaintext: bytes, ciphertext: bytes, known_key_prefix: bytes, unknown_bits: int
) -> tuple[bytes | None, int, float]:
    """Cari kunci dengan brute force pada sejumlah bit non-paritas terakhir."""
    if len(plaintext) != 8 or len(ciphertext) != 8:
        raise ValueError("Plaintext and ciphertext must be exactly 8 bytes")
    if unknown_bits < 1 or unknown_bits > 24:
        raise ValueError("Unknown bits must be between 1 and 24")
    padded_prefix = known_key_prefix.ljust(8, b"\x00")[:8]
    base_bits = bytes_to_bits(padded_prefix)
    target_indices = NON_PARITY_INDICES[-unknown_bits:]
    trials = 0
    start_time = time.perf_counter()
    for value in range(1 << unknown_bits):
        trials += 1
        candidate_bits = list(base_bits)
        for offset, bit_pos in enumerate(target_indices):
            candidate_bits[bit_pos] = (value >> (unknown_bits - 1 - offset)) & 1
        candidate_key = bits_to_bytes(candidate_bits)
        if encrypt_block(plaintext, candidate_key) == ciphertext:
            elapsed = time.perf_counter() - start_time
            return candidate_key, trials, elapsed
    elapsed = time.perf_counter() - start_time
    return None, trials, elapsed


def estimate_full_bruteforce(trials_per_second: float) -> float:
    """Hitung estimasi waktu untuk memecahkan ruang 2^56 kunci dalam tahun."""
    if trials_per_second <= 0:
        return float("inf")
    total_seconds = (2 ** 56) / trials_per_second
    return total_seconds / (365.25 * 24 * 3600)
