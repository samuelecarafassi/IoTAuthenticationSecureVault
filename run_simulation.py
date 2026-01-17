import json
from common.vault import SecureVault
from auth_server import IoTServer
from iot_device import IoTDevice

config = json.load(open("config.json"))

vault = SecureVault.generate(
    config["vault"]["num_keys"],
    config["vault"]["key_size_bytes"]
)

server = IoTServer(["device-001"], vault, config)
device = IoTDevice("device-001", vault, config)

# M1
m1 = device.create_m1()

# M2
m2 = server.receive_m1(m1["device_id"],m1["session_id"])

# M3
m3 = device.receive_m2(m2["C1"], m2["r1"])

# M4
m4 = server.receive_m3(m3)

# Verify
device.receive_m4(m4)
