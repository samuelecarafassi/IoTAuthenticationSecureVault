import os
import json
import time
import sys
import random

from common.vault import SecureVault
from auth_server import IoTServer
from iot_device import IoTDevice


def get_plausible_delay_ms():
    """
    Simulates a regional internet connection to major CDNs.
    Average: 75ms, Floor: 12ms, Rare spikes up to ~180ms-200ms.
    """
    mean = 75.0
    std_dev = 35.0
    min_floor = 12.0
    delay_ms = max(random.gauss(mean, std_dev), min_floor)
    return delay_ms / 1000.0


def setup_nodes(num_keys: int = None, key_size: int = None, print_session_key: bool = False) -> tuple[IoTServer, IoTDevice]:
    config = json.load(open("config.json"))

    if num_keys:
        config["vault"]["num_keys"] = num_keys
    if key_size:
        config["vault"]["key_size_bytes"] = key_size
        config["crypto"]["random_size_bytes"] = key_size
        config["crypto"]["session_key_size"] = key_size

    vault = SecureVault.generate(
       config["vault"]["num_keys"],
       config["vault"]["key_size_bytes"]
    )

    server = IoTServer(["device-001"], vault, config, print_session_key)
    device = IoTDevice("device-001", vault, config, print_session_key)

    return server, device


def run_cryptographic_sweep():
    """Experiment A: Scales m and n. Application payload is 0."""
    m_values = [4, 8, 16, 32, 64, 128, 256]
    n_values = [16, 24, 32]  # 128-bit, 192-bit and 256-bit
    sweep_rounds = 5000
    filename = "crypto_scaling.csv"

    print("\n[*] --- EXPERIMENT A: CRYPTOGRAPHIC SCALING ---")
    print(f"[*] Writing results to {filename}...")
    
    with open(filename, "w") as f:
        header = "m_keys,n_bits,avg_handshake_ms,avg_hmac_ms"
        print(header)
        f.write(header + "\n")

        for n in n_values:
            for m in m_values:
                server, device = setup_nodes(num_keys=m, key_size=n, print_session_key=False)
                total_handshake = 0.0
                total_hmac = 0.0

                for _ in range(sweep_rounds):
                    # Phase 1: AES Handshake
                    t0 = time.perf_counter()
                    m1 = device.create_m1()
                    m2 = server.receive_m1(m1["device_id"], m1["session_id"])
                    m3 = device.receive_m2(m2["C1"], m2["r1"])
                    m4, server_sk = server.receive_m3(m3)
                    device_sk = device.receive_m4(m4)
                    t1 = time.perf_counter()
                    
                    assert server_sk == device_sk, "Desync during handshake!"
                    total_handshake += (t1 - t0)

                    # Phase 2: HMAC Update (Zero application data)
                    t2 = time.perf_counter()
                    server.finalize_session(m1["device_id"], m1["session_id"], b"")
                    device.finalize_session(b"")
                    t3 = time.perf_counter()
                    
                    # Divide by 2 to average the 1-sided computational cost
                    total_hmac += ((t3 - t2) / 2) 

                avg_hand_ms = (total_handshake / sweep_rounds) * 1000
                avg_hmac_ms = (total_hmac / sweep_rounds) * 1000
                
                row = f"{m},{n * 8},{avg_hand_ms:.6f},{avg_hmac_ms:.6f}"
                print(row)
                f.write(row + "\n")


def run_payload_sweep():
    """Experiment B: Fixes m and n. Scales session application data."""
    fixed_m = 16
    fixed_n = 16  # 128-bit keys
    payload_sizes_bytes = [0, 128, 1024, 10240, 51200, 102400]  # Up to 100KB
    sweep_rounds = 1000
    filename = "payload_scaling.csv"

    print("\n[*] --- EXPERIMENT B: PAYLOAD SCALING ---")
    print(f"[*] Writing results to {filename}...")

    with open(filename, "w") as f:
        header = "payload_bytes,avg_hmac_ms"
        print(header)
        f.write(header + "\n")

        for size in payload_sizes_bytes:
            server, device = setup_nodes(num_keys=fixed_m, key_size=fixed_n, print_session_key=False)
            total_hmac = 0.0
            
            # Generate dummy data outside the timing loop to avoid OS entropy bottlenecks
            dummy_data = os.urandom(size) 

            for _ in range(sweep_rounds):
                # Execute handshake (untimed for this experiment)
                m1 = device.create_m1()
                m2 = server.receive_m1(m1["device_id"], m1["session_id"])
                m3 = device.receive_m2(m2["C1"], m2["r1"])
                m4, server_sk = server.receive_m3(m3)
                device_sk = device.receive_m4(m4)

                assert server_sk == device_sk, "Desync during handshake!"

                # Time only the vault update with the appended application data
                t0 = time.perf_counter()
                server.finalize_session(m1["device_id"], m1["session_id"], dummy_data)
                device.finalize_session(dummy_data)
                t1 = time.perf_counter()
                
                total_hmac += ((t1 - t0) / 2)

            avg_hmac_ms = (total_hmac / sweep_rounds) * 1000
            
            row = f"{size},{avg_hmac_ms:.6f}"
            print(row)
            f.write(row + "\n")


def run_general_auth(server: IoTServer, device: IoTDevice, num_rounds: int):
    """Original network latency simulation for a static configuration."""
    if not num_rounds:
        num_rounds = 10_000

    rand_delay = [get_plausible_delay_ms() for _ in range(num_rounds * 4)]

    starting_time = time.perf_counter()
    for i in range(num_rounds):
        j = i * 4
        m1 = device.create_m1()
        time.sleep(rand_delay[j])

        m2 = server.receive_m1(m1["device_id"], m1["session_id"])
        time.sleep(rand_delay[j + 1])

        m3 = device.receive_m2(m2["C1"], m2["r1"])
        time.sleep(rand_delay[j + 2])

        m4, server_session_key = server.receive_m3(m3)
        time.sleep(rand_delay[j + 3])

        device_session_key = device.receive_m4(m4)
        assert server_session_key == device_session_key, "Session keys do not coincide"

        # Finalize the session with zero application data to maintain state
        server.finalize_session(m1["device_id"], m1["session_id"], b"")
        device.finalize_session(b"")

    elapsed_time = time.perf_counter() - starting_time
    total_delay = sum(rand_delay)
    
    print("\n[+] Test Results:")
    print(f"    - Total execution time for {num_rounds} rounds  : {elapsed_time:.4f} seconds")
    print(f"    - Total network delay                : {total_delay:.4f} seconds")
    print(f"    - Avg Handshake time for 1 round     : {(elapsed_time / num_rounds) * 1000:.4f} ms")
    print(f"    - Avg network delay for 1 round      : {(total_delay / num_rounds) * 1000:.4f} ms")


def default_run(num_keys: int, key_size: int, num_rounds: int):
    server, device = setup_nodes(num_keys, key_size, print_session_key=False)
    if not num_rounds:
        num_rounds = 1
    
    print(f"[*] Starting Single Benchmark Test...")
    print(f"    - Vault Size (m) : {server.cfg['vault']['num_keys']} keys")
    print(f"    - Key Length (n) : {server.cfg['vault']['key_size_bytes'] * 8} bits")
    print(f"    - Total Rounds   : {num_rounds}")

    return run_general_auth(server, device, num_rounds)


def print_help():
    print("\n  Master Execution Script for Secure Vault IoT Project")
    print("  Handles performance benchmarking and desynchronization attack simulations.\n")
    print("Usage:")
    print(f"  python3 {sys.argv[0]} [command] [flags]\n")
    print("Available commands:")
    print("  auth [flags]  Execute the original latency-simulated authentication mechanism.")
    print("  sweep         Run strictly isolated cryptographic benchmarks and generate CSV files.")
    print("  help          Show this help message.\n")
    print("Flags (for 'auth' command):")
    print("  -m, --num-keys     Number of keys in the secure vault (m). Default: 16")
    print("  -n, --key-len      Size of each key in bytes. Default: 16 (128 bits)")
    print("  -r, --rounds       Total number of authentication handshakes to simulate. Default: 10000")


def parse_auth():
    flags = ["-m", "--num-keys", "-n", "--key-len", "-r", "--rounds"]
    m = n = r = None
    
    # Process arguments in pairs (flag, value)
    for i in range(2, len(sys.argv), 2):
        arg = sys.argv[i]
        if arg not in flags:
            print(f"Flag {arg} not recognized.")
            return
        try:
            flag_param = int(sys.argv[i + 1])
        except IndexError:
            print(f"Flag {arg} expects a number.")
            return
        except ValueError:
            print(f"Flag {arg} expects a whole number.")
            return

        if arg in ("-m", "--num-keys"):
            m = flag_param
        elif arg in ("-n", "--key-len"):
            n = flag_param
        elif arg in ("-r", "--rounds"):
            r = flag_param

    return default_run(m, n, r)


def main():
    if len(sys.argv) == 1:
        return print_help()
    
    command = sys.argv[1]
    
    if command == "auth":
        return parse_auth()
    elif command == "sweep":
        if len(sys.argv) > 2:
            print("The 'sweep' command does not accept additional flags.")
            return
        run_cryptographic_sweep()
        run_payload_sweep()
        print("\n[+] Both sweeps complete. Data saved to CSV files.")
    elif command == "help":
        print_help()
    else:
        print(f"Command '{command}' does not exist.")
        print_help()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Execution aborted by user.")
        sys.exit(0)
