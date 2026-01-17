from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac
import os

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

def aes_decrypt(key: bytes, data: bytes) -> bytes:
    nonce, ciphertext = data[:12], data[12:]
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, None)

def hmac_digest(key: bytes, data: bytes, hash_algo=hashes.SHA256()) -> bytes:
    h = hmac.HMAC(key, hash_algo)
    h.update(data)
    return h.finalize()

def xor_bytes(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))