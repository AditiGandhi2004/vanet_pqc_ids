# VANET PQC IDS — SUMO + ML-DSA + ML-KEM + RSU + AI IDS

This project integrates a SUMO traffic simulation with post-quantum message authentication, key encapsulation, authenticated encryption, RSU processing, geographic forwarding, and the existing Random Forest intrusion detector.

## Implemented workflow

1. SUMO/TraCI supplies simulated vehicle positions, speeds, and headings.
2. Each simulated vehicle gets a local pseudonym and creates a CAM-like status message.
3. The vehicle signs the canonical message with ML-DSA-65.
4. The bridge encapsulates a fresh ML-KEM-768 shared secret to the RSU public key, derives a 256-bit key using HKDF-SHA256, and encrypts the signed payload with AES-256-GCM.
5. The encrypted envelope is sent by UDP to the RSU on port 5002.
6. The RSU decapsulates the secret, authenticates/decrypts the envelope, verifies the ML-DSA signature, and runs replay, Sybil heuristic, DoS, and AI IDS checks.
7. Messages within the configured RSU geographic range are emitted as geographic forwarding packets on UDP port 5200. The packet contains the accepted message and a list of known nearby pseudonyms; this is a simulation-level forwarding bus, not a real wireless/radio network.

## Requirements

- Windows 10/11
- Python 3.11 (recommended; use the same interpreter for every command)
- Eclipse SUMO 1.28.0 (the included `sumo/` files were generated for SUMO)
- `liboqs` native library and the `liboqs-python` wrapper with `ML-DSA-65` and `ML-KEM-768` enabled
- Python packages in `requirements.txt`

`liboqs-python` is a wrapper around the native liboqs library; installing the Python package alone may not install a compatible native library on every Windows machine. If `import oqs` fails, follow the official liboqs-python/liboqs Windows installation instructions and verify that `ML-DSA-65` and `ML-KEM-768` appear in the supported algorithm list. Do not ignore native library version/API errors.

## Installation

From the project root in PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If you already have a working Python 3.11 environment with `oqs`, `traci`, and `cryptography`, you can use that environment instead of creating a new one.

SUMO environment (adjust path if installed elsewhere):

```powershell
$env:SUMO_HOME = "C:\Program Files (x86)\SUMO"
$env:Path = "$env:Path;$env:SUMO_HOME\bin"
```

## Run the integrated simulation

Open three PowerShell terminals in the project root.

### Terminal 1 — RSU, crypto receiver, IDS and forwarding logic

```powershell
py -3.11 .\simulator\rsu_server.py
```

The RSU creates `results/rsu_mlkem_public_key.bin` and listens on UDP `127.0.0.1:5002`.

### Terminal 2 — Optional forwarding monitor

```powershell
py -3.11 .\simulator\forwarding_monitor.py
```

This listens on UDP port 5200 and displays geographic forwarding packets. It is optional; the RSU can send forwarding packets without a monitor running.

### Terminal 3 — SUMO vehicle sender

```powershell
py -3.11 .\simulator\sumo_bridge.py
```

The bridge waits for the RSU public key, launches SUMO GUI, signs and encrypts one status message per active vehicle per simulated second, and sends it to the RSU.

## Configuration

Environment variables can override defaults:

- `SUMO_HOME`: SUMO installation root
- `SUMO_BINARY`: explicit `sumo-gui.exe` path
- `VANET_RSU_HOST` (default `127.0.0.1`)
- `VANET_RSU_PORT` (default `5002`)
- `VANET_RSU_X` (default `500.0` metres)
- `VANET_RSU_Y` (default `500.0` metres)
- `VANET_RSU_RANGE_M` (default `500` metres)
- `VANET_FORWARD_HOST` (default `127.0.0.1`)
- `VANET_FORWARD_PORT` (default `5200`)

The RSU coordinates are in the SUMO network's coordinate system. Change them if your network geometry changes.

## Tests and existing components

Existing project tests and attack examples remain in `security/`, `attacks/`, and `ids/`. Run from the project root, using the same Python environment:

```powershell
py -3.11 -m unittest discover -s tests -v
```

Some pre-existing files are interactive/standalone test scripts rather than unittest test cases. Run those individually as their docstrings or prompts specify. The integrated path additionally requires the native liboqs algorithms and a working SUMO installation.

## Security and research limitations

- ML-KEM-768 is a key-encapsulation mechanism; it establishes a shared secret and does not encrypt messages by itself. HKDF-SHA256 derives the AES key, and AES-256-GCM provides authenticated encryption.
- The sender creates a fresh KEM encapsulation and AES-GCM nonce per message. Do not reuse a nonce with the same AES key; this implementation derives a fresh key per envelope.
- ML-DSA verification checks that the message matches the public key included in that message. A production VANET must also validate that the key/pseudonym is authorized by a trusted credential or certificate authority; this demo does not implement PKI/certificate issuance or revocation.
- The RSU geographic forwarding output is a local UDP simulation bus with a recipient list based on recently observed vehicle positions. It is not a real radio channel, packet-delivery simulation, or SUMO/Veins wireless integration.
- The Sybil detector is a heuristic based on different pseudonyms at the same rounded location; it is not a definitive Sybil proof.
- The included IDS dataset/model is synthetic. Its metrics do not establish real-world detection performance. Re-train/evaluate on a documented dataset before drawing empirical conclusions.
- This code has not been validated as a safety-critical vehicular deployment. Measure latency, packet delivery, overhead, and attack detection in the target environment before reporting those results.

## One-command launch and visible security tests (Windows PowerShell)

After installing and verifying Python 3.11, native liboqs, the required OQS algorithms, and SUMO, open PowerShell in the project root and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\run_all.ps1
```

This preflights dependencies and opens separate consoles for the RSU receiver, forwarding monitor, and SUMO bridge. Keep all three consoles open. The SUMO bridge ends when its configured simulation finishes; the RSU and forwarding monitor continue until Ctrl+C.

To send controlled security test packets through the same ML-KEM/AES-GCM/ML-DSA receiver pipeline, open a fourth PowerShell window in the project root while the RSU is running:

```powershell
py -3.11 .\simulator\security_demo.py
```

The script sends a normal message, repeats the same protected envelope for replay testing, modifies a signed field for signature-failure testing, sends two pseudonyms at the same coordinates for the Sybil heuristic, and sends a short message burst for the DoS rate rule. Watch the RSU console for the outcome of each packet. The test cases are controlled demonstrations; a detector may not flag a case if the corresponding rule's state or thresholds differ from the assumptions. The Sybil detector is a location-based heuristic, not proof of a real Sybil attack.

The launcher intentionally stops if dependencies or expected files are missing. Do not bypass the protocol, signature, or AES-GCM checks to make a test appear to pass.

## Browser demo (added frontend)

The browser demo adds a local dashboard while reusing the project's existing vehicle, ML-DSA-65, ML-KEM-768/AES-256-GCM, RSU, replay/Sybil/DoS checks, Random Forest IDS, risk response, and forwarding logic. The RSU now sends a local acknowledgement only for dashboard-originated packets so the UI can show the stages actually reported by the RSU. Normal SUMO packets do not request acknowledgements.

1. Stop any old RSU process listening on port 5002.
2. From this project directory, run in PowerShell:

   ```powershell
   .\run_frontend.ps1
   ```

3. The browser opens at `http://127.0.0.1:8765`.
4. Select Vehicle A, B, or C, choose a scenario, set position/speed if desired, and click **Run selected scenario**.
5. Follow the twelve stages in the dashboard and the corresponding messages in the RSU terminal. If an earlier security check rejects the message, later stages are marked as skipped rather than being presented as completed.

This browser demo uses manually selected vehicle coordinates and does not start SUMO. Continue using `run_all.ps1` for the existing SUMO simulation. The frontend binds to localhost only and is intended for a research demonstration, not production deployment.


## Browser demo (scenario-based)

Run `run_frontend.ps1` on Windows. Choose one of six scenarios:
- **Normal driving:** a valid CAM is processed; no safety alert should be raised.
- **Vehicle accident:** a valid ML-DSA-signed DENM is encrypted, verified, passed through the IDS/rule checks, and forwarded as a safety notification to the local geographic forwarding channel.
- **Compromised vehicle:** signed message data is changed after signing; the RSU must reject it at ML-DSA verification and stop later processing.
- **Replay attack:** the exact same signed/encrypted envelope is sent twice; the second packet should fail replay detection.
- **Sybil attack:** two distinct pseudonyms send valid signed messages claiming the same run-specific location; the second should trigger the location-based Sybil heuristic.
- **DoS attack:** six signed/encrypted CAMs are sent rapidly from one sender; the configured rule flags more than five messages within two seconds.

The browser shows the actual RSU acknowledgement stage-by-stage. The forwarding monitor is a local demonstration receiver; this prototype does not connect to real vehicles or emergency services.
