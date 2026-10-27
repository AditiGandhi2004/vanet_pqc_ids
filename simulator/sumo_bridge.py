"""SUMO -> Vehicle -> ML-DSA-65 -> ML-KEM-768/AES-GCM -> RSU UDP bridge.

Start simulator/rsu_server.py first so it can publish its ML-KEM public key.
"""
import json
import os
import shutil
import socket
import sys
import time

import traci

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from security.pseudonym import PseudonymManager
from security.secure_channel import encrypt_for_rsu
from simulator.vehicle import Vehicle

SUMO_HOME = os.environ.get("SUMO_HOME", r"C:\Program Files (x86)\SUMO")
DEFAULT_GUI = os.path.join(SUMO_HOME, "bin", "sumo-gui.exe")
SUMO_BINARY = os.environ.get("SUMO_BINARY") or shutil.which("sumo-gui") or DEFAULT_GUI
SUMO_CONFIG = os.path.join(PROJECT_ROOT, "sumo", "vanet.sumocfg")
RSU_PUBLIC_KEY_PATH = os.path.join(PROJECT_ROOT, "results", "rsu_mlkem_public_key.bin")
RSU_HOST = os.environ.get("VANET_RSU_HOST", "127.0.0.1")
RSU_PORT = int(os.environ.get("VANET_RSU_PORT", "5002"))
STEP_LENGTH = 0.1
SIMULATION_END = 60
MESSAGE_INTERVAL = 1.0  # seconds of simulation time per vehicle
PUBLIC_KEY_WAIT_SECONDS = 30


def wait_for_rsu_public_key():
    deadline = time.time() + PUBLIC_KEY_WAIT_SECONDS
    while time.time() < deadline:
        if os.path.isfile(RSU_PUBLIC_KEY_PATH):
            with open(RSU_PUBLIC_KEY_PATH, "rb") as handle:
                key = handle.read()
            if key:
                return key
        time.sleep(0.25)
    raise FileNotFoundError(
        "RSU ML-KEM public key not found. Start simulator/rsu_server.py first. "
        f"Expected: {RSU_PUBLIC_KEY_PATH}"
    )


def run_simulation():
    if not os.path.isfile(SUMO_CONFIG):
        raise FileNotFoundError(f"SUMO configuration not found: {SUMO_CONFIG}")
    if not os.path.isfile(SUMO_BINARY):
        raise FileNotFoundError(
            f"SUMO GUI executable not found: {SUMO_BINARY}. Set SUMO_BINARY or SUMO_HOME."
        )

    print("Waiting for RSU ML-KEM public key...")
    rsu_public_key = wait_for_rsu_public_key()
    print(f"[OK] Loaded RSU ML-KEM public key ({len(rsu_public_key)} bytes)")

    pseudonym_manager = PseudonymManager()
    vehicles = {}
    next_publish = {}
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sumo_started = False
    sent_count = 0

    try:
        print("=" * 64)
        print("SUMO + VANET POST-QUANTUM SECURE BRIDGE")
        print(f"SUMO binary : {SUMO_BINARY}")
        print(f"SUMO config : {SUMO_CONFIG}")
        print(f"RSU endpoint: {RSU_HOST}:{RSU_PORT}")
        print("Authentication: ML-DSA-65 | KEM: ML-KEM-768 | AEAD: AES-256-GCM")
        print("=" * 64)


        print("[DEBUG] Launching SUMO and connecting through TraCI...", flush=True)

        traci.start(
            [
                SUMO_BINARY.replace("sumo-gui.exe", "sumo.exe"),
                "-c", SUMO_CONFIG,
                "--step-length", str(STEP_LENGTH),
                "--end", str(SIMULATION_END),
            ],
            label="vanet_sim",
            numRetries=3
        )

        sumo_started = True
        print("[OK] TraCI connected to SUMO.", flush=True)
        print(
            f"[DEBUG] Expected vehicles: "
            f"{traci.simulation.getMinExpectedNumber()}",
            flush=True
        )



        while traci.simulation.getMinExpectedNumber() > 0:
            traci.simulationStep()
            sim_time = traci.simulation.getTime()

            for vehicle_id in traci.vehicle.getIDList():
                x, y = traci.vehicle.getPosition(vehicle_id)
                speed_kmh = traci.vehicle.getSpeed(vehicle_id) * 3.6
                heading = traci.vehicle.getAngle(vehicle_id)

                if vehicle_id not in vehicles:
                    vehicle = Vehicle(vehicle_id, x, y, speed_kmh, heading)
                    pseudonym = pseudonym_manager.generate_pseudonym(vehicle_id)
                    vehicle.set_pseudonym(pseudonym)
                    vehicles[vehicle_id] = vehicle
                    next_publish[vehicle_id] = 0.0
                    print(f"[REGISTERED] {vehicle_id} -> {pseudonym}")

                vehicle = vehicles[vehicle_id]
                # SUMO is the only movement source; don't call vehicle.move().
                vehicle.x, vehicle.y = x, y
                vehicle.speed, vehicle.direction = speed_kmh, heading

                if sim_time + 1e-9 < next_publish[vehicle_id]:
                    continue
                next_publish[vehicle_id] = sim_time + MESSAGE_INTERVAL

                message = vehicle.create_status_message()
                vehicle.sign_message(message)
                payload = {"message": message.to_dict()}
                envelope = encrypt_for_rsu(payload, rsu_public_key)
                wire_bytes = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
                udp_sock.sendto(wire_bytes, (RSU_HOST, RSU_PORT))
                sent_count += 1
                print(
                    f"[SENT] CAM #{sent_count} | vehicle={vehicle_id} | "
                    f"pseudonym={vehicle.pseudonym} | x={x:.1f}m y={y:.1f}m | "
                    f"speed={speed_kmh:.1f}km/h | seq={vehicle.sequence_number} | "
                    f"encrypted_bytes={len(wire_bytes)}"
                )

        print(f"[DONE] SUMO completed. Vehicles={len(vehicles)}, messages_sent={sent_count}")
    except KeyboardInterrupt:
        print("\n[STOP] Interrupted by user.")
    finally:
        if sumo_started:
            try:
                traci.close()
            except Exception as exc:
                print(f"[WARNING] SUMO close: {exc}")
        udp_sock.close()
        print("[CLOSED] SUMO secure bridge stopped.")


if __name__ == "__main__":
    run_simulation()
