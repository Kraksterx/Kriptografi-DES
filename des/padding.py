"""Padding PKCS#7 dengan validasi ukuran blok dan isi padding."""


def pad(data: bytes, block_size: int = 8) -> bytes:
    """Tambahkan padding PKCS#7 termasuk satu blok penuh pada data sejajar."""
    if not 1 <= block_size <= 255:
        raise ValueError("Block size must be between 1 and 255")
    padding_size = block_size - len(data) % block_size
    return data + bytes([padding_size]) * padding_size


def unpad(data: bytes, block_size: int = 8) -> bytes:
    """Lepaskan padding PKCS#7 atau tolak panjang dan byte padding yang rusak."""
    if not 1 <= block_size <= 255:
        raise ValueError("Block size must be between 1 and 255")
    if not data or len(data) % block_size:
        raise ValueError("Padded data must contain complete blocks")
    padding_size = data[-1]
    if not 1 <= padding_size <= block_size:
        raise ValueError("Invalid padding size")
    if data[-padding_size:] != bytes([padding_size]) * padding_size:
        raise ValueError("Invalid padding bytes")
    return data[:-padding_size]
