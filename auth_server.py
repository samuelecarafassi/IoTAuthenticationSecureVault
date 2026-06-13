from common.crypto import aes_decrypt, aes_encrypt, xor_bytes, hmac_digest
from common.protocol_messages import random_challenge
import os

class IoTServer:
    def __init__(self, device_ids, vault, config, print_session_key = True):
        self.device_ids = device_ids
        self.vault = vault
        self.cfg = config
        self.sessions_data = {}
        self._print_session_key = print_session_key

        for device in device_ids:
            self.sessions_data[device] = {}

    def receive_m1(self, device_id, session_id):
        # only allowed devices can communicate
        assert device_id in self.device_ids

        # avoid resetting an already existing connection
        assert session_id not in self.sessions_data[device_id]


        # generate challenge for the iot device
        C1 = random_challenge(
            self.cfg["vault"]["num_keys"],
            self.cfg["challenge"]["p"]
        )
        r1 = os.urandom(self.cfg["crypto"]["random_size_bytes"])

        # store connection data
        self.sessions_data[device_id][session_id] = {}
        self.sessions_data[device_id][session_id]["C1"] = C1
        self.sessions_data[device_id][session_id]["r1"] = r1

        return {"C1": C1, "r1": r1}

    def receive_m3(self, m3):

        # decrypt message
        k1 = self.vault.derive_key(self.sessions_data[m3["device_id"]][m3["session_id"]]["C1"])
        plaintext = aes_decrypt(k1, m3["message"])

        # verify challenge
        r1 = self.sessions_data[m3["device_id"]][m3["session_id"]]["r1"]
        assert plaintext.startswith(r1)

        # compute challenge
        C2_index = len(r1) + self.cfg["crypto"]["session_key_size"]
        C2 = list(plaintext[C2_index:C2_index+self.cfg["challenge"]["p"]])
        t1 = plaintext[len(r1):len(r1)+self.cfg["crypto"]["session_key_size"]]
        r2 = plaintext[-self.cfg["crypto"]["random_size_bytes"]:]
        t2 = os.urandom(self.cfg["crypto"]["session_key_size"])

        session_data = self.sessions_data[m3["device_id"]][m3["session_id"]]
        session_data["t1"] = t1
        session_data["r2"] = r2
        session_data["t2"] = t2

        k2 = self.vault.derive_key(C2)

        session_key = xor_bytes(t1, t2)
        if self._print_session_key:
            print(f"Server session key for device {m3['device_id']}: {session_key}")

        return aes_encrypt(xor_bytes(k2, t1), r2 + t2), session_key

    def finalize_session(self, device_id, session_id, application_data=b""):
        session = self.sessions_data[device_id][session_id]
        payload = session["r1"] + session["t1"] + session["r2"] + session["t2"] + application_data
        vault_key = b"".join(self.vault.keys)
        hmac_value = hmac_digest(vault_key, payload)
        self.vault.update(hmac_value)

