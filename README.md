# IoTAuthenticationSecureVault
IoTAuthenticationSecureVault is a project for a Cyber-Physical Systems and IoT Security university project that tries to implement an IoT mutual authentication protocol (device <-> server) proposed by Shah and Venkatesan in [Authentication of IoT Device and IoT Server Using Secure Vaults (2018)](https://ieeexplore.ieee.org/document/8455985).

## Assumptions
> Why we needed assumptions
1. The device makes only one connection at the time towards to the server (easier to implement)
2. The server recognize the iot device by device_id and session_id at each message. We could have been used IP + TCP port too, but the paper doesn't specify how the server recognizes whose message is.
Hence we chose this way which doesn't have any impact on the security of the protocol since the information are sent in clear at the beginning of the protocol and are anyway tied to the authentication attempt.
3. The protocol is not very clear about the sizes of challenges. So we assumed that every value has fixed size (e.g. every random number must be 8 bytes)
4. The protocol does not specify the size of keys, number of keys, nonces length. Hence we decided them based on what we think it might be considered safe nowadays considering the limited computation of the devices. 

## Implementation limitations
1. We didn't implement any authentication timeout, but in a real world scenario would make sense to implement iot to limit connection flooding.

## Examples

