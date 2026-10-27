"""Compatibility entry point for the integrated RSU receiver.

The former per-vehicle plaintext receiver did not match the encrypted SUMO
bridge's UDP port/protocol. Use this entry point or simulator/rsu_server.py
for the integrated ML-KEM/AES-GCM + ML-DSA + IDS workflow.
"""
from simulator.rsu_server import main


if __name__ == "__main__":
    main()
