"""Mode ECB dan CBC DES dengan padding PKCS#7 otomatis."""

import os

from .core import decrypt_block, encrypt_block
from .padding import pad, unpad


def encrypt(data: bytes, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    """Enkripsi data dengan padding dan awalan IV untuk mode CBC."""
    if mode not in ("ECB", "CBC"):
        raise ValueError("Mode must be ECB or CBC")
    if mode == "ECB" and iv is not None:
        raise ValueError("ECB does not use an IV")
    if mode == "CBC" and iv is not None and len(iv) != 8:
        raise ValueError("DES IV must be exactly 8 bytes")
    previous = (os.urandom(8) if iv is None else iv) if mode == "CBC" else b""
    result = bytearray(previous)
    padded = pad(data)
    for start in range(0, len(padded), 8):
        block = padded[start:start + 8]
        if mode == "CBC":
            block = bytes(left ^ right for left, right in zip(block, previous))
        encrypted = encrypt_block(block, key)
        result.extend(encrypted)
        previous = encrypted
    return bytes(result)


def decrypt(data: bytes, key: bytes, mode: str = "CBC") -> bytes:
    """Dekripsi data ECB atau CBC berawalan IV lalu validasi padding."""
    if mode not in ("ECB", "CBC"):
        raise ValueError("Mode must be ECB or CBC")
    if len(data) % 8 or len(data) < (16 if mode == "CBC" else 8):
        raise ValueError("Ciphertext must contain complete blocks and any required IV")
    previous = data[:8] if mode == "CBC" else b""
    result = bytearray()
    for start in range(8 if mode == "CBC" else 0, len(data), 8):
        block = data[start:start + 8]
        decrypted = decrypt_block(block, key)
        if mode == "CBC":
            decrypted = bytes(left ^ right for left, right in zip(decrypted, previous))
        result.extend(decrypted)
        previous = block
    return unpad(bytes(result))
