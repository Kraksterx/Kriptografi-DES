"""Inti DES berbasis list bit tanpa library kripto."""

from .tables import E, FP, IP, P, PC1, PC2, SBOXES, SHIFTS
from .utils import bits_to_bytes, bytes_to_bits, xor_bits


def permute(bits: list[int], table: list[int]) -> list[int]:
    """Pilih bit menggunakan posisi tabel berbasis satu."""
    if any(position < 1 or position > len(bits) for position in table):
        raise ValueError("Permutation position is outside the input")
    return [bits[position - 1] for position in table]


def generate_subkeys(key: bytes) -> list[list[int]]:
    """Hasilkan enam belas subkey 48 bit dari kunci delapan byte."""
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes")
    selected = permute(bytes_to_bits(key), PC1)
    left, right = selected[:28], selected[28:]
    subkeys = []
    for shift in SHIFTS:
        left = left[shift:] + left[:shift]
        right = right[shift:] + right[:shift]
        subkeys.append(permute(left + right, PC2))
    return subkeys


def feistel(right: list[int], subkey: list[int]) -> list[int]:
    """Terapkan ekspansi, XOR subkey, delapan S-box, dan permutasi P."""
    if len(right) != 32 or len(subkey) != 48:
        raise ValueError("Feistel requires 32 right bits and 48 subkey bits")
    mixed = xor_bits(permute(right, E), subkey)
    substituted = []
    for index, sbox in enumerate(SBOXES):
        chunk = mixed[index * 6:(index + 1) * 6]
        row = (chunk[0] << 1) | chunk[5]
        column = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        value = sbox[row][column]
        substituted.extend((value >> shift) & 1 for shift in range(3, -1, -1))
    return permute(substituted, P)


def _round_states(block: bytes, subkeys: list[list[int]]) -> list[list[int]]:
    """Catat L dan R setelah IP dan setiap ronde sebelum pertukaran akhir."""
    if len(block) != 8:
        raise ValueError("DES block must be exactly 8 bytes")
    state = permute(bytes_to_bits(block), IP)
    states = [state]
    left, right = state[:32], state[32:]
    for subkey in subkeys:
        left, right = right, xor_bits(left, feistel(right, subkey))
        states.append(left + right)
    return states


def encrypt_block(block: bytes, key: bytes) -> bytes:
    """Enkripsi satu blok delapan byte menggunakan DES."""
    state = encrypt_block_trace(block, key)[-1]
    return bits_to_bytes(permute(state[32:] + state[:32], FP))


def decrypt_block(block: bytes, key: bytes) -> bytes:
    """Dekripsi satu blok menggunakan subkey berurutan terbalik."""
    state = _round_states(block, generate_subkeys(key)[::-1])[-1]
    return bits_to_bytes(permute(state[32:] + state[:32], FP))


def encrypt_block_trace(block: bytes, key: bytes) -> list[list[int]]:
    """Kembalikan 17 state L||R sesudah IP dan setiap ronde enkripsi."""
    return _round_states(block, generate_subkeys(key))
