# IoTAuthenticationSecureVault
IoTAuthenticationSecureVault is a project for a Cyber-Physical Systems and IoT Security university course; it tries to implement the IoT mutual authentication protocol _(device <-> server)_ proposed by Shah and Venkatesan in [Authentication of IoT Device and IoT Server Using Secure Vaults (2018)](https://ieeexplore.ieee.org/document/8455985).

## Assumptions
> Since the reference document omits several low-level communication specifics, we adopted the following assumptions to establish a predictable engineering baseline.

1. **Single active connection per device:** Each IoT device is assumed to establish only one active connection to the server at any given time. This simplifies the implementation of the iot device without affecting the correctness or the security properties of the authentication protocol.
2. **Device identification at the server:** The server identifies and tracks IoT devices using the cleartext pair _(device_id, session_id)_. While an alternative approach could rely on transport-layer information such as source IP address and TCP port, the reference paper does not specify how the server associates incoming messages with a specific device or authentication session. We therefore adopted an explicit identifier-based mechanism. This choice does not impact the security of the protocol, since both identifiers are transmitted in clear text at the beginning of the protocol and are inherently bound to the ongoing authentication attempt.
3. **Fixed-size protocol fields:** The protocol description does not clearly specify the sizes of challenges. In our implementation, all protocol fields have fixed sizes (e.g., nonces are strictly 8 bytes). This choice simplifies parsing and is consistent with common practices in embedded network protocol design to avoid buffer ambiguities.
4. **Cryptographic parameter selection:** The protocol does not define the exact size or number of keys stored in the vault. These parameters are treated as variable inputs for our performance scaling experiments, chosen to reflect modern IoT constraints (e.g., AES-128 equivalents).

## Implementation limitations
1. **Absence of authentication timeouts:** No authentication timeout mechanism was implemented in the simulation to allow for uninterrupted performance benchmarking. In a real-world deployment, timeouts and rate-limiting are strictly required to mitigate connection flooding.
2. **Hardware Abstraction:** Unlike the original Arduino-based implementation, this simulation does not measure physical energy consumption or execution time under strict embedded hardware constraints. Performance metrics are relative to algorithmic complexity.
3. **Faked network delays:** Being this simulation hosted on a single device, to measure the protocol's overhead what we thought made sense the most was to add some delays in between the message exchange, so we emulated the real-like delays due to the packets Round Trip Time (RTT) on the network.

## How to use
```python
python3 secureVault.py
```
