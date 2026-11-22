from __future__ import annotations

import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import time
from datetime import datetime
from pathlib import Path
from werkzeug.utils import secure_filename
from flask import Flask, jsonify, render_template, request, send_from_directory

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
LOG_DIR = BASE_DIR / "logs"
UPLOAD_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "activity.jsonl"
MAX_FILE_BYTES = 5 * 1024 * 1024
MESSAGES = []
SIM_MESSAGES = []
SIM_FILES = []
DEFAULT_PORT = int(os.environ.get("CYBERSHIELD_PORT", "5000"))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_BYTES + 1024 * 1024
app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)


def log_event(event: str, detail: str, status: str = "info") -> None:
    record = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "date": datetime.now().strftime("%Y-%m-%d"),
        "event": event[:80],
        "detail": detail[:240],
        "status": status,
    }
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def get_local_ipv4() -> str:
    """Best-effort local IPv4 discovery without sending application data."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 80))  # TEST-NET address; UDP connect sends no packet.
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def firewall_status() -> tuple[str, str]:
    """Read Windows Defender Firewall profile state without disabling protection."""
    if platform.system() != "Windows":
        return "Not checked", "Windows Firewall status is only available on Windows."
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles"],
            capture_output=True, text=True, timeout=10, check=False
        )
        if result.returncode != 0:
            return "Unknown", "Windows Firewall status could not be queried."
        states = [line.strip().lower() for line in result.stdout.splitlines()
                  if line.strip().lower().startswith("state")]
        if states and all(line.endswith("on") for line in states):
            return "Enabled", "Windows Firewall is enabled. CyberShield does not disable or bypass it."
        if states and any(line.endswith("off") for line in states):
            return "Warning", "One or more Windows Firewall profiles are disabled."
        return "Unknown", "Windows Firewall profile state could not be interpreted."
    except (OSError, subprocess.TimeoutExpired):
        return "Unknown", "Windows Firewall status query was unavailable or timed out."


def tcp_probe(host: str, port: int, timeout: float = 3.0) -> tuple[bool, str, float]:
    """Perform a blocking TCP connect with a bounded timeout."""
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = (time.perf_counter() - started) * 1000
            return True, "TCP port is accepting connections", elapsed
    except socket.timeout:
        elapsed = (time.perf_counter() - started) * 1000
        return False, "Connection attempt timed out", elapsed
    except OSError as exc:
        elapsed = (time.perf_counter() - started) * 1000
        return False, f"TCP connection failed: {exc}", elapsed


@app.get("/")
def home():
    return render_template("index.html", local_ip=get_local_ipv4(), port=DEFAULT_PORT)


@app.get("/api/status")
def api_status():
    return jsonify({"online": True, "host_ip": get_local_ipv4(), "port": DEFAULT_PORT,
                    "platform": platform.system(), "max_file_mb": 5})


@app.post("/api/simulate")
def api_simulate():
    data = request.get_json(silent=True) or {}
    ip_a = str(data.get("ip_a", "192.168.1.10")).strip()
    ip_b = str(data.get("ip_b", "192.168.1.20")).strip()
    results = []
    try:
        a, b = ipaddress.ip_address(ip_a), ipaddress.ip_address(ip_b)
        results.append(("IP validation", a.version == 4 and b.version == 4, "Both virtual device addresses are valid IPv4 addresses."))
        results.append(("Port availability", True, "Simulation: virtual service port is available."))
        results.append(("Firewall check", True, "Simulation: virtual firewall policy allows the demo connection."))
        results.append(("Suspicious indicators", not (a.is_multicast or b.is_multicast), "Simulation uses private demo addresses; this is not a malware scan."))
        results.append(("Network configuration", a.version == b.version, "Both virtual devices use a compatible address family."))
        results.append(("Timeout detection", True, "Simulation response completed within the virtual timeout."))
    except ValueError:
        results.append(("IP validation", False, "Enter valid IP addresses for both virtual devices."))
    response = [{"name": n, "passed": bool(p), "detail": d} for n, p, d in results]
    log_event("Simulation check", f"Virtual assessment completed for {ip_a} and {ip_b}.", "success")
    return jsonify({"mode": "simulation", "results": response, "warning_count": sum(not r["passed"] for r in results)})


@app.post("/api/simulate/message")
def api_simulate_message():
    """Store a message in the virtual Device A <-> Device B simulation inbox."""
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip()
    sender = str(data.get("sender", "Device A")).strip()
    if sender not in ("Device A", "Device B"):
        sender = "Device A"
    if not message:
        return jsonify({"error": "Please enter a message."}), 400
    if len(message) > 2000:
        return jsonify({"error": "Messages are limited to 2,000 characters."}), 400
    entry = {
        "id": len(SIM_MESSAGES) + 1,
        "message": message,
        "time": datetime.now().strftime("%H:%M:%S"),
        "sender": sender,
        "recipient": "Device B" if sender == "Device A" else "Device A",
        "mode": "simulation",
    }
    SIM_MESSAGES.append(entry)
    del SIM_MESSAGES[:-100]
    log_event("Simulated message", f"{sender} -> {entry['recipient']}: {message[:100]}", "success")
    return jsonify({"sent": True, **entry})


@app.get("/api/simulate/messages")
def api_simulate_messages():
    return jsonify(SIM_MESSAGES[-50:])


@app.post("/api/simulate/upload")
def api_simulate_upload():
    """Demonstrate a virtual file transfer without writing a file to disk."""
    file = request.files.get("file")
    if not file or not file.filename:
        return jsonify({"error": "Choose a file first."}), 400
    safe_name = secure_filename(file.filename)
    if not safe_name:
        return jsonify({"error": "That filename is not supported."}), 400
    content = file.read(MAX_FILE_BYTES + 1)
    if len(content) > MAX_FILE_BYTES:
        return jsonify({"error": "File exceeds the 5 MB limit."}), 413
    entry = {
        "name": safe_name,
        "size": len(content),
        "time": datetime.now().strftime("%H:%M:%S"),
        "sender": "Device A",
        "recipient": "Device B",
        "mode": "simulation",
    }
    SIM_FILES.append(entry)
    del SIM_FILES[:-30]
    log_event("Simulated file transfer", f"{safe_name} ({len(content)} bytes) Device A -> Device B", "success")
    return jsonify({"uploaded": True, **entry})


@app.get("/api/simulate/files")
def api_simulate_files():
    return jsonify(SIM_FILES[-30:])


@app.get("/api/client-info")
def api_client_info():
    """Return the address Flask actually sees for this browser session."""
    client_ip = request.remote_addr or "127.0.0.1"
    try:
        address = ipaddress.ip_address(client_ip)
        is_lan_client = address.version == 4 and address.is_private and not address.is_loopback
    except ValueError:
        is_lan_client = False
    return jsonify({
        "client_ip": client_ip,
        "host_ip": get_local_ipv4(),
        "host_port": DEFAULT_PORT,
        "is_lan_client": is_lan_client,
        "is_host_browser": not is_lan_client,
    })


@app.post("/api/lan-check")
def api_lan_check():
    """Assess an entered client IPv4 address against this CyberShield host."""
    data = request.get_json(silent=True) or {}
    target_ip = str(data.get("target_ip", "")).strip()
    port = data.get("target_port", DEFAULT_PORT)

    try:
        client_address = ipaddress.ip_address(target_ip)
        if client_address.version != 4:
            raise ValueError
    except ValueError:
        return jsonify({"error": "Enter a valid IPv4 address for the other laptop, for example 192.168.1.17."}), 400

    if client_address.is_loopback or client_address.is_unspecified or client_address.is_multicast or client_address.is_link_local:
        return jsonify({"error": "Enter the other laptop's Wi-Fi IPv4 address, not 127.0.0.1, 0.0.0.0, or a link-local address."}), 400

    try:
        port = int(port)
        if not 1 <= port <= 65535:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({"error": "Port must be a number from 1 to 65535."}), 400

    host_ip = get_local_ipv4()
    results = []
    is_private = client_address.is_private
    results.append({"name": "IP address validation", "passed": is_private,
                    "detail": f"Entered address {target_ip} is a valid {'private' if is_private else 'public'} IPv4 address."})

    # The host port is checked locally on the machine running CyberShield.
    reachable, probe_detail, elapsed = tcp_probe("127.0.0.1", port, 3.0)
    results.append({"name": "Port availability", "passed": reachable,
                    "detail": f"{probe_detail} on this CyberShield host at {host_ip}:{port}. This confirms the host service is listening; it does not test a service on the client laptop."})

    fw, fw_detail = firewall_status()
    fw_passed = fw == "Enabled"
    results.append({"name": "Firewall rule check", "passed": fw_passed,
                    "detail": fw_detail})

    suspicious = (not is_private or client_address.is_multicast or client_address.is_unspecified or client_address.is_loopback or client_address.is_link_local)
    results.append({"name": "Suspicious connection indicators", "passed": not suspicious,
                    "detail": "No basic IP-range red flags detected. This is not a malware or threat-intelligence scan." if not suspicious else "The entered address is outside the expected private LAN range."})

    same_subnet = False
    try:
        host_address = ipaddress.ip_address(host_ip)
        same_subnet = host_address.version == 4 and client_address.version == 4 and host_address in ipaddress.ip_network(f"{client_address}/24", strict=False)
    except ValueError:
        pass
    results.append({"name": "Network configuration", "passed": same_subnet,
                    "detail": f"Host address: {host_ip}. Other laptop: {target_ip}. Basic /24 comparison: {'same subnet' if same_subnet else 'not confirmed on the same /24 subnet'}."})
    results.append({"name": "Connection timeout detection", "passed": reachable and elapsed < 3000,
                    "detail": f"Host port probe took {elapsed:.0f} ms (3-second timeout)."})

    log_event("LAN security assessment", f"Assessed entered client address {target_ip} against host {host_ip}:{port}.",
              "warning" if any(not item["passed"] for item in results) else "success")
    return jsonify({"mode": "lan", "host_ip": host_ip, "target_ip": target_ip, "target_port": port,
                    "results": results, "warning_count": sum(not item["passed"] for item in results)})


@app.post("/api/message")
def api_message():
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip()
    if not message:
        return jsonify({"error": "Please enter a message."}), 400
    if len(message) > 2000:
        return jsonify({"error": "Messages are limited to 2,000 characters."}), 400
    entry = {"id": len(MESSAGES) + 1, "message": message, "time": datetime.now().strftime("%H:%M:%S"), "sender": request.remote_addr or "LAN device"}
    MESSAGES.append(entry)
    del MESSAGES[:-100]
    log_event("Message received", message[:120], "success")
    return jsonify({"sent": True, **entry})


@app.get("/api/messages")
def api_messages():
    return jsonify(MESSAGES[-50:])


@app.post("/api/upload")
def api_upload():
    file = request.files.get("file")
    if not file or not file.filename:
        return jsonify({"error": "Choose a file first."}), 400
    safe_name = secure_filename(file.filename)
    if not safe_name:
        return jsonify({"error": "That filename is not supported."}), 400
    content = file.read(MAX_FILE_BYTES + 1)
    if len(content) > MAX_FILE_BYTES:
        return jsonify({"error": "File exceeds the 5 MB limit."}), 413
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    stored_name = f"{stamp}_{safe_name}"
    (UPLOAD_DIR / stored_name).write_bytes(content)
    log_event("File received", f"{safe_name} ({len(content)} bytes)", "success")
    return jsonify({"uploaded": True, "name": safe_name, "size": len(content), "stored_name": stored_name})


@app.get("/api/files")
def api_files():
    files = []
    for path in sorted(UPLOAD_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        if path.is_file():
            files.append({"name": path.name.split("_", 2)[-1], "stored_name": path.name, "size": path.stat().st_size})
    return jsonify(files[:30])


@app.get("/api/files/<path:filename>")
def download_file(filename: str):
    return send_from_directory(UPLOAD_DIR, filename, as_attachment=True)


@app.get("/api/logs")
def api_logs():
    if not LOG_FILE.exists():
        return jsonify([])
    lines = LOG_FILE.read_text(encoding="utf-8").splitlines()[-30:]
    entries = []
    for line in reversed(lines):
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return jsonify(entries)


@app.errorhandler(413)
def too_large(_error):
    return jsonify({"error": "File exceeds the 5 MB limit."}), 413


if __name__ == "__main__":
    print("\nCyberShield host is starting...")
    print(f"Open on this computer: http://127.0.0.1:{DEFAULT_PORT}")
    print(f"Computer 2 can use: http://{get_local_ipv4()}:{DEFAULT_PORT}\n")
    app.run(host="0.0.0.0", port=DEFAULT_PORT, debug=False, threaded=True)
