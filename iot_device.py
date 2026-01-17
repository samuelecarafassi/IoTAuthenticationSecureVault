from common.crypto import aes_encrypt, aes_decrypt, xor_bytes
from common.protocol_messages import random_challenge
import numpy as np
import os

class IoTDevice:
    def __init__(self, device_id, vault, config):
        self.device_id = device_id
        self.vault = vault
        self.cfg = config

    def create_m1(self):
        self.session ={}
        self.session["session_id"] =os.urandom(8)
        return {"device_id":self.device_id,"session_id":self.session["session_id"]}

    def receive_m2(self, C1, r1):
        k1 = self.vault.derive_key(C1)

        # generate challenge for the server
        C2 = C1.copy()
        # C1 and C2 must be different
        while (np.all(np.asarray(C2) == np.asarray(C1))):
            C2 = random_challenge(
                self.cfg["vault"]["num_keys"],
                self.cfg["challenge"]["p"]
            )
        t1 = os.urandom(self.cfg["crypto"]["session_key_size"])
        r2 = os.urandom(self.cfg["crypto"]["random_size_bytes"])

        # store session data
        self.session["t1"] = t1
        self.session["C2"] = C2
        self.session["r2"] = r2

        # prepare message
        payload = r1 + t1 + bytes(C2) + r2
        encrypted = aes_encrypt(k1, payload)
        return {"device_id":self.device_id,"session_id":self.session["session_id"],"message":encrypted}

    def receive_m4(self, m4):
        # decrypt message
        k2 = self.vault.derive_key(self.session["C2"])
        received_r2 = aes_decrypt(xor_bytes(k2,self.session["t1"]), m4)

        # verify challenge
        assert received_r2[:self.cfg["crypto"]["random_size_bytes"]] == self.session["r2"]
        
        # compute session key
        t2 = received_r2[-self.cfg["crypto"]["session_key_size"]:]

        session_key = xor_bytes(self.session["t1"],t2)
        print("Device session key:",session_key)
