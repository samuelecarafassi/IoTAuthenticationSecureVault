# IoTAuthenticationSecureVault
IoTAuthenticationSecureVault is a project for a Cyber-Physical Systems and IoT Security university course; it tries to implement the IoT mutual authentication protocol _(device <-> server)_ proposed by Shah and Venkatesan in [Authentication of IoT Device and IoT Server Using Secure Vaults (2018)](https://ieeexplore.ieee.org/document/8455985).

## Assumptions
> Since the reference document omits several low-level communication specifics, we adopted the following assumptions to establish a predictable engineering baseline.

1. **Single active connection per device:** Each IoT device is assumed to establish only one active connection to the server at any given time. This simplifies the implementation of the iot device without affecting the correctness or the security properties of the authentication protocol.
2. **Fixed-size protocol fields:** The protocol description does not clearly specify the sizes of challenges. In our implementation, all protocol fields have fixed sizes (e.g., nonces are strictly 8 bytes). This choice simplifies parsing and is consistent with common practices in embedded network protocol design to avoid buffer ambiguities.
3. **Cryptographic parameter selection:** The protocol does not define the exact size or number of keys stored in the vault. These parameters are treated as variable inputs for our performance scaling experiments, chosen to reflect modern IoT constraints (e.g., AES-128 equivalents).
4. **Secure Vault Update Payload:** The protocol documentation does not explicitly define the contents of the vault update message. We assume that the HMAC input for the vault update includes both the session-specific nonces and the complete application data payload transmitted during the session. This assumption is necessary to evaluate the scalability of the protocol under variable data loads, as a vault update strictly dependent only on fixed-size nonces would result in constant-time complexity, rendering the ”secure vault” evolution independent of the volume of data exchanged.

## Implementation limitations
1. **Absence of authentication timeouts:** No authentication timeout mechanism was implemented in the simulation to allow for uninterrupted performance benchmarking. In a real-world deployment, timeouts and rate-limiting are strictly required to mitigate connection flooding.
2. **Hardware Abstraction:** Unlike the original Arduino-based implementation, this simulation does not measure physical energy consumption or execution time under strict embedded hardware constraints. Performance metrics are relative to algorithmic complexity.
3. **Cryptographic Ambiguity in Vault Updates:** The original paper states that the secure vault is updated via an HMAC where the key is the “data exchanged between the server and the IoT device”. However, the authors fail to specify the exact composition of this data stream (e.g., whether it includes protocol headers, plaintext nonces, ciphertexts, or concatenated payloads). Due to this lack of cryptographic reproducibility, our simulation must explicitly define the HMAC payload as a strict concatenation of the session’s handshake entropy (r1||t1||r2||t2) combined with any appended application data.

## How to use
To run the full data-gathering.
> This will create two files in the current directory (crypto_scaling.csv and payload_scaling.csv).
> It will overwrite any possible file with the same name in the directory.
```python
python3 secureVault.py sweep
```

To display the help message.
```python
python3 secureVault.py
```
