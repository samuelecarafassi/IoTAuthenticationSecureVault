import random
import struct

def random_challenge(n_keys: int, p: int) -> list[int]:
    return random.sample(range(n_keys), p)

def pack_challenge(challenge: list[int], r: bytes) -> bytes:
    return struct.pack(f"!{len(challenge)}B", *challenge) + r

def unpack_challenge(data: bytes, p: int, r_len: int):
    challenge = list(data[:p])
    r = data[p:p+r_len]
    return challenge, r
