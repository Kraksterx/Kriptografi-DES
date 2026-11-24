"""Konversi data dan operasi bit DES."""


def bytes_to_bits(data: bytes) -> list[int]:
    """Ubah byte menjadi bit dengan bit paling signifikan lebih dahulu."""
    return [(value >> shift) & 1 for value in data for shift in range(7, -1, -1)]


def bits_to_bytes(bits: list[int]) -> bytes:
    """Ubah bit biner dengan panjang kelipatan delapan menjadi byte."""
    if len(bits) % 8 or any(bit not in (0, 1) for bit in bits):
        raise ValueError("Bits must be binary and have a length divisible by 8")
    return bytes(sum(bits[start + i] << (7 - i) for i in range(8))
                 for start in range(0, len(bits), 8))


def hex_to_bytes(hex_str: str) -> bytes:
    """Ubah hex berpanjang genap tanpa spasi menjadi byte."""
    if len(hex_str) % 2 or any(char not in "0123456789abcdefABCDEF" for char in hex_str):
        raise ValueError("Hex must contain an even number of hexadecimal characters")
    return bytes.fromhex(hex_str)


def bytes_to_hex(data: bytes) -> str:
    """Ubah byte menjadi hex huruf besar."""
    return data.hex().upper()


def xor_bits(a: list[int], b: list[int]) -> list[int]:
    """Hitung XOR dua deret bit biner dengan panjang sama."""
    if len(a) != len(b) or any(bit not in (0, 1) for bit in a + b):
        raise ValueError("XOR requires binary lists of equal length")
    return [left ^ right for left, right in zip(a, b)]
