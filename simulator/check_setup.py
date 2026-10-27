"""Check project paths and Python dependencies without starting SUMO or sockets."""
import importlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
checks = {
    "traci": "traci",
    "oqs": "oqs",
    "cryptography AESGCM": "cryptography.hazmat.primitives.ciphers.aead",
    "pandas": "pandas",
    "sklearn": "sklearn",
    "joblib": "joblib",
}
failed = False
print(f"Python: {sys.version.split()[0]} ({sys.executable})")
for label, module_name in checks.items():
    try:
        module = importlib.import_module(module_name)
        print(f"[OK] {label}: {getattr(module, '__file__', 'available')}")
    except Exception as exc:
        failed = True
        print(f"[MISSING/ERROR] {label}: {type(exc).__name__}: {exc}")
for rel in ["sumo/vanet.net.xml", "sumo/vanet.rou.xml", "sumo/vanet.sumocfg", "results/vanet_ids_model.pkl"]:
    path = os.path.join(ROOT, rel)
    status = os.path.isfile(path)
    print(f"{'[OK]' if status else '[MISSING]'} {rel}")
    failed |= not status
if not failed:
    try:
        import oqs
        algorithms = set(oqs.get_enabled_kem_mechanisms())
        signatures = set(oqs.get_enabled_sig_mechanisms())
        for name in ["ML-KEM-768"]:
            print(f"{'[OK]' if name in algorithms else '[UNAVAILABLE]'} KEM algorithm {name}")
            failed |= name not in algorithms
        for name in ["ML-DSA-65"]:
            print(f"{'[OK]' if name in signatures else '[UNAVAILABLE]'} signature algorithm {name}")
            failed |= name not in signatures
    except Exception as exc:
        failed = True
        print(f"[ERROR] Algorithm enumeration: {type(exc).__name__}: {exc}")
print("Setup check FAILED." if failed else "Setup check passed.")
sys.exit(1 if failed else 0)
