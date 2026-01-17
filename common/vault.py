import os
import json
from functools import reduce
from operator import xor

class SecureVault:
    def __init__(self, keys: list[bytes]):
        self.keys = keys

    @classmethod
    def generate(cls, num_keys: int, key_size: int):
        return cls([os.urandom(key_size) for _ in range(num_keys)])

    def derive_key(self, indices: list[int]) -> bytes:
        return reduce(
            lambda a, b: bytes(x ^ y for x, y in zip(a, b)),
            (self.keys[i] for i in indices)
        )

    def update(self, hmac_value: bytes):
        new_keys = []
        for i, key in enumerate(self.keys):
            chunk = hmac_value[i % len(hmac_value)]
            new_keys.append(bytes(b ^ chunk for b in key))
        self.keys = new_keys
