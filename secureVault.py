from common.vault import SecureVault
from auth_server import IoTServer
from iot_device import IoTDevice
import json
import time
import sys


def setup_nodes(num_keys: int = None, key_size: int = None) -> IoTServer, IoTDevice:
    config = json.load(open("config.json"))

    if m:
        config["vault"]["num_keys"] = m
    if n:
        config["vault"]["key_size_bytes"] = n

    vault = SecureVault.generate(
       config["vault"]["num_keys"],
        config["vault"]["key_size_bytes"]
    )

    server = IoTServer(["device-001"], vault, config)
    device = IoTDevice("device-001", vault, config)

    return server, device


# TODO: Delete
def run_single_test(num_keys, key_len, rounds):
    """Runs a targeted simulation to benchmark symmetric vs. HMAC overhead."""
    print(f"[*] Starting Single Benchmark Test...")
    print(f"    - Vault Size (m) : {num_keys} keys")
    print(f"    - Key Length (n) : {key_len} bits")
    print(f"    - Total Rounds   : {rounds}")

    assert False, "Not implemented; to be deleted"

    total_handshake_time = 0.0

    # TODO: Initialize your IoT Device and Server instances here

    for current_round in range(1, rounds + 1):
        # --- 1. TIME THE ENCRYPTION HANDSHAKE ---
        start_time = time.perf_counter()

        # TODO: Execute Messages 1 through 4 (XOR key derivation & AES encryption)

        end_time = time.perf_counter()
        total_handshake_time += (end_time - start_time)


    # Print Results
    print("\n[+] Test Results:")
    print(f"    - Total execution time   : {total_handshake_time + total_vault_update_time:.4f} seconds")
    print(f"    - Avg Handshake Latency  : {(total_handshake_time / rounds) * 1000:.4f} ms")
    if vault_update_count > 0:
        print(f"    - Avg HMAC Update Latency: {(total_vault_update_time / vault_update_count) * 1000:.4f} ms")
    else:
        print(f"    - Avg HMAC Update Latency: N/A (Session length > Total rounds)")
    print("\n")


def run_general_auth(server: IoTServer, device: IoTDevice, num_rounds: int):
    if not num_rounds:
        num_rounds = 10_000

    m1 = device.create_m1()
    m2 = server.receive_m1(m1["device_id"],m1["session_id"])
    m3 = device.receive_m2(m2["C1"], m2["r1"])
    m4 = server.receive_m3(m3)
    device.receive_m4(m4)


def default_run(num_keys: int, key_size: int, num_rounds: int):
    server, device = setup_nodes(num_keys, key_size)

    if not num_rounds:
        num_rounds = 10_000
    return run_general_auth(server, device, num_rounds)


def run_sweep():
    """Runs the full parameter matrix to generate CSV data for LaTeX plotting."""
    assert False, "Not yet implemented"

    print(f"[*] Starting Full Performance Sweep (m: [...], n: [...], rounds: ...)")

    # Testing matrix based on modern IoT constraints
    m_values = [8, 16, 32, 64, 128]
    n_values = [128, 256, 512]
    sweep_rounds = 10000

    # Print CSV Header
    print("\n--- BEGIN CSV DATA ---")
    print("m_keys,n_bits,avg_handshake_ms,avg_hmac_ms")

    for n in n_values:
        for m in m_values:
            # TODO: Initialize Device/Server with parameters 'm' and 'n'
            # TODO: Run the timing loop (similar to run_single_test)

            # Placeholder variables for your actual timed results
            avg_handshake_ms = 0.0
            avg_hmac_ms = 0.0

            # Print comma-separated values for easy copy-pasting into plotting tools
            print(f"{m},{n},{avg_handshake_ms:.4f},{avg_hmac_ms:.4f}")

    print("--- END CSV DATA ---\n")
    print("[+] Full sweep complete. Data is ready for plotting.\n")


def print_help():
    print("\n  Master Execution Script for Secure Vault IoT Project\n"
          "  Handles performance benchmarking and desynchronization attack simulations.")
    print("\nUsage:")
    print("  python3", sys.argv[0], "[command] [flags]")
    print("\nAvailable commands:")
    print("  auth [flags]  Execute the single run authentication mechanism.")
    print("  sweep         TODO: explanation")
    print("  help          Show this help message.")
    print("\nFlags:")
    print("  -m, --num-keys     Number of keys in the secure vault (m). Default: 16")
    print("  -n, --key-len      Size of each key in bits (n). Default: 128")
    print("  -r, --rounds       Total number of authentication handshakes to simulate. Default: 10000")


def parse_auth():
    flags = ["-m", "--num-keys", "-n", "--key-len", "-r", "--rounds"]
    m = n = r = None
    for i, arg in enumerate(sys.argv[2:]):
        flag_param = None

        if i % 2:
            continue
        if arg not in flags:
            print("Flag", arg, "not recognized.")
            return
        try:
            flag_param = int(sys.argv[i + 3])
        except IndexError:
            print("Flag", arg, "expects a number.")
            return
        except ValueError:
            print("Flag", arg, "expects a whole number.")
            return

        if arg == "-m" or arg == "--num-keys":
            m = flag_param
        if arg == "-n" or arg == "--key-len":
            n = flag_param
        if arg == "-r" or arg == "--rounds":
            r = flag_param

    return default_run(m, n, r)


def main():
    if len(sys.argv) == 1:
        return print_help()
    if sys.argv[1] == "auth":
        return parse_auth()
    if sys.argv[1] == "sweep":
        if len(sys.argv) > 2:
            print("sweep command does not expect any flag")
            return
        return run_sweep()
    if sys.argv[1] != "help":
        print(f"Command \"{sys.argv[1]}\" does not exit")
    print_help()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Execution aborted by user.")
        sys.exit(0)

