#!/usr/bin/env python3

import collections
import hashlib
import hmac
import base64
import ipaddress
import json
import os
import re
import secrets
import select
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import uuid

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote
from urllib.request import urlopen


def load_public_config():
    path = Path(os.environ.get(
        "BTICINO_SNIFFER_CONFIG", "/opt/bticino-sniffer/config.json"
    ))
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


CONFIG = load_public_config()


def resolve_executable(config_key, environment_key, command, candidates):
    configured = CONFIG.get(config_key) or os.environ.get(environment_key)
    if configured:
        return configured
    discovered = shutil.which(command)
    if discovered:
        return discovered
    for candidate in candidates:
        if Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    return command

# ============================================================
# HOMETOUCH SIP passive diagnostic listener
# ============================================================

BASE = Path(CONFIG.get("base_dir", "/opt/bticino-sniffer"))
LOGDIR = BASE / "logs"
SNAPSHOT_DIR = BASE / "snapshots"
RUNTIME_DIR = BASE / "runtime"
DIAGNOSTIC_KEY_FILE = RUNTIME_DIR / "diagnostic-hmac.key"
FFMPEG = resolve_executable(
    "ffmpeg", "BTICINO_FFMPEG", "ffmpeg",
    ("/opt/homebrew/bin/ffmpeg", "/usr/local/bin/ffmpeg", "/usr/bin/ffmpeg"),
)
OPENSSL = resolve_executable(
    "openssl", "BTICINO_OPENSSL", "openssl",
    ("/opt/homebrew/bin/openssl", "/usr/local/bin/openssl", "/usr/bin/openssl"),
)

CREDS_FILE = Path(CONFIG.get("credentials_file", "/opt/bticino-gateway/config/sip_credentials.json"))
CERT_FILE = Path(CONFIG.get("certificate_file", "/opt/bticino-gateway/certs/client.cert.pem"))
KEY_FILE = Path(CONFIG.get("private_key_file", "/opt/bticino-gateway/private/client.key"))
CA_FILE = Path(CONFIG.get("ca_file", "/opt/bticino-gateway/certs/ca-chain.cert.pem"))

SERVER_IP = CONFIG.get("sip_server") or os.environ.get("BTICINO_SIP_SERVER", "")
SERVER_PORT = int(CONFIG.get("sip_port", 5061))
DOMAIN = CONFIG.get("sip_domain") or os.environ.get("BTICINO_SIP_DOMAIN", "")

REGISTER_EXPIRES = 300
REFRESH_MARGIN = 90
KEEPALIVE_INTERVAL = 25.0
SIP_INSTANCE_FILE = RUNTIME_DIR / "sip-instance.uuid"
RECONNECT_INITIAL_DELAY = float(CONFIG.get("reconnect_initial_delay", 0.25))
RECONNECT_MAX_DELAY = float(CONFIG.get("reconnect_max_delay", 10.0))
RECONNECT_STABLE_AFTER = float(CONFIG.get("reconnect_stable_after", 30.0))

USER_AGENT = "HOMETOUCH-Diagnostic-Listener/1.0"
MEDIA_IP_OVERRIDE = str(CONFIG.get("media_ip", "") or "").strip() or None
MEDIA_TIMEOUT = 30


def parse_media_ports(value):
    """Accetta '2202-2213' (default) e restituisce (start, end) validati."""
    text = str(value if value is not None else "").strip() or "2202-2213"
    match = re.fullmatch(r"(\d{1,5})\s*-\s*(\d{1,5})", text)
    if not match:
        raise ValueError("media_ports deve essere 'START-END' (es. 2202-2203)")
    start, end = int(match.group(1)), int(match.group(2))
    if not 1 <= start <= 65535 or not 1 <= end <= 65535:
        raise ValueError("media_ports fuori range 1-65535")
    if start % 2 != 0:
        raise ValueError("media_ports deve iniziare su porta pari (RTP)")
    if end <= start:
        raise ValueError("media_ports: END deve essere maggiore di START")
    return start, end


MEDIA_PORT_START, MEDIA_PORT_END = parse_media_ports(CONFIG.get("media_ports"))
INTERNAL_MEDIA_PORT_START = 22202
INTERNAL_MEDIA_PORT_END = 22213
LIVE_VIDEO_HOST = "127.0.0.1"
LIVE_VIDEO_PORT = 22300
SNAPSHOT_HTTP_HOST = str(CONFIG.get("http_bind", "127.0.0.1")).strip() or "127.0.0.1"
SNAPSHOT_HTTP_PORT = 8766
OPENER_RAW = CONFIG.get("opener", {})
OPENER_OPTS = OPENER_RAW if isinstance(OPENER_RAW, dict) else {}
OPENER_TOKEN = str(OPENER_OPTS.get("token", "") or "")
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
HOMEBRIDGE_HTTP_PORT = 8767
HOMEBRIDGE_DOORBELL_NAME = CONFIG.get("homekit_doorbell_name", "Videocitofono")
DOORBELL_SNAPSHOT_TIMEOUT = float(CONFIG.get("doorbell_snapshot_timeout", 0.0))
ANSWER_CALLS = bool(CONFIG.get("answer_calls", False))
MQTT_RAW = CONFIG.get("mqtt", {})
MQTT = MQTT_RAW if isinstance(MQTT_RAW, dict) else {}
MQTT_ENABLED = bool(MQTT.get("enabled", False))
MQTT_HOST = str(MQTT.get("host", "")).strip()
MQTT_PORT = int(MQTT.get("port", 1883))
MQTT_TOPIC = str(MQTT.get("topic", "bticino/citofono/ring")).strip() or "bticino/citofono/ring"
MQTT_CLIENT_ID = str(MQTT.get("client_id", "bticino-hometouch")).strip() or "bticino-hometouch"
MQTT_USERNAME = str(MQTT.get("username", "") or "").strip() or None
MQTT_PASSWORD_FILE = str(MQTT.get("password_file", "") or "").strip() or None
MQTT_USE_TLS = bool(MQTT.get("use_tls", False))
MQTT_RETAIN = bool(MQTT.get("retain", False))
MQTT_QOS = 0
MQTT_TIMEOUT = float(MQTT.get("timeout", 5.0))
PLACEHOLDER_SNAPSHOT = RUNTIME_DIR / "snapshot-pending.jpg"
SAVE_RAW_SIP = bool(CONFIG.get("save_raw_sip", False))
POST_CALL_FALLBACK_SECONDS = int(CONFIG.get("post_call_fallback_seconds", -1))
ENTRANCE_CLASSIFICATION = CONFIG.get("entrance_classification", {})
ENTRANCE_CLASSIFICATION_ENABLED = bool(ENTRANCE_CLASSIFICATION.get("enabled", False))
ENTRANCE_CLASSIFICATION_FRAME = max(0, int(ENTRANCE_CLASSIFICATION.get("frame_index", 2)))
ENTRANCE_CLASSIFICATION_THRESHOLD = float(ENTRANCE_CLASSIFICATION.get("max_distance", 0.35))
ENTRANCE_CLASSIFICATION_MARGIN = float(ENTRANCE_CLASSIFICATION.get("min_margin", 0.08))
ENTRANCE_SIGNATURE_WIDTH = 32
ENTRANCE_SIGNATURE_HEIGHT = 24
ENTRANCE_SIGNATURE_SIZE = ENTRANCE_SIGNATURE_WIDTH * ENTRANCE_SIGNATURE_HEIGHT

RUNNING = True
PENDING_CALLS = set()
PENDING_LOCK = threading.Lock()
DIAGNOSTIC_KEY = None
DIAGNOSTIC_KEY_LOCK = threading.Lock()
ENTRANCE_PROFILES = {}
FALLBACK_PROCESS = None
FALLBACK_LOCK = threading.Lock()


def normalized_luma_signature(data):
    """Return a contrast-normalized vector from a small grayscale frame."""
    if len(data) != ENTRANCE_SIGNATURE_SIZE:
        raise ValueError(f"frame diagnostico incompleto: {len(data)} byte, attesi {ENTRANCE_SIGNATURE_SIZE}")
    values = [float(value) for value in data]
    mean = sum(values) / len(values)
    centered = [value - mean for value in values]
    norm = sum(value * value for value in centered) ** 0.5
    if norm <= 1e-9:
        raise ValueError("frame diagnostico privo di contrasto")
    return tuple(value / norm for value in centered)


def gradient_signature(data):
    """Describe fixed scene geometry while suppressing global light changes."""
    if len(data) != ENTRANCE_SIGNATURE_SIZE:
        raise ValueError(
            f"frame diagnostico incompleto: {len(data)} byte, "
            f"attesi {ENTRANCE_SIGNATURE_SIZE}"
        )
    horizontal = []
    vertical = []
    width = ENTRANCE_SIGNATURE_WIDTH
    height = ENTRANCE_SIGNATURE_HEIGHT
    for y in range(height - 1):
        for x in range(width - 1):
            offset = y * width + x
            horizontal.append(float(data[offset + 1]) - data[offset])
            vertical.append(float(data[offset + width]) - data[offset])
    values = horizontal + vertical
    norm = sum(value * value for value in values) ** 0.5
    if norm <= 1e-9:
        raise ValueError("frame diagnostico privo di bordi")
    return tuple(value / norm for value in values)


def signature_distance(left, right):
    """Cosine distance for already normalized signatures."""
    if len(left) != len(right) or not left:
        raise ValueError("impronte visive incompatibili")
    similarity = sum(a * b for a, b in zip(left, right))
    return max(0.0, min(2.0, 1.0 - similarity))


def classify_entrance(signature, profiles, max_distance=0.35, min_margin=0.08):
    """Classify a frame, rejecting weak or ambiguous matches."""
    scores = []
    for name, references in profiles.items():
        if references:
            scores.append((min(signature_distance(signature, ref) for ref in references), name))
    scores.sort()
    if not scores:
        return None, None, "no-profiles"
    best_distance, best_name = scores[0]
    if best_distance > max_distance:
        return None, best_distance, "distance"
    if len(scores) > 1 and scores[1][0] - best_distance < min_margin:
        return None, best_distance, "ambiguous"
    return best_name, best_distance, "matched"


def image_signature(path):
    """Decode a reference image locally without adding image dependencies."""
    result = subprocess.run([
        FFMPEG, "-hide_banner", "-loglevel", "error", "-nostdin", "-i", str(path),
        "-vf", f"scale={ENTRANCE_SIGNATURE_WIDTH}:{ENTRANCE_SIGNATURE_HEIGHT}:flags=area,format=gray",
        "-frames:v", "1", "-f", "rawvideo", "-pix_fmt", "gray", "-",
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace")[-500:].strip()
        raise RuntimeError(detail or "FFmpeg non ha decodificato l'immagine")
    return gradient_signature(result.stdout)


def load_entrance_profiles():
    """Load installation-private reference images named in config.json."""
    profiles = {}
    configured = ENTRANCE_CLASSIFICATION.get("profiles", {})
    if not isinstance(configured, dict):
        raise RuntimeError("entrance_classification.profiles deve essere un oggetto")
    for name, paths in configured.items():
        if not isinstance(name, str) or not name.strip():
            raise RuntimeError("nome profilo ingresso non valido")
        if isinstance(paths, str):
            paths = [paths]
        if not isinstance(paths, list) or not paths:
            raise RuntimeError(f"profilo {name!r} privo di immagini")
        profiles[name] = [image_signature(Path(path).expanduser()) for path in paths]
    return profiles


def post_call_fallback_command(snapshot, duration=None):
    """Build a low-bandwidth, periodically keyed still-video fallback."""
    seconds = POST_CALL_FALLBACK_SECONDS if duration is None else int(duration)
    command = [
        FFMPEG, "-hide_banner", "-loglevel", "warning", "-nostdin",
        "-re", "-loop", "1", "-framerate", "2", "-i", str(snapshot),
        "-an", "-c:v", "libx264", "-preset", "ultrafast",
        "-tune", "stillimage,zerolatency", "-pix_fmt", "yuv420p",
        "-r", "2", "-g", "4", "-keyint_min", "4", "-sc_threshold", "0",
        "-b:v", "120k", "-maxrate", "180k", "-bufsize", "240k",
    ]
    if seconds > 0:
        command.extend(["-t", str(seconds)])
    command.extend([
        "-mpegts_flags", "+resend_headers",
        "-f", "mpegts", f"udp://{LIVE_VIDEO_HOST}:{LIVE_VIDEO_PORT}?pkt_size=1316",
    ])
    return command


def stop_post_call_fallback(reason=None):
    global FALLBACK_PROCESS
    with FALLBACK_LOCK:
        process = FALLBACK_PROCESS
        FALLBACK_PROCESS = None
        if not process or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)
    if reason:
        log(f"POST-CALL FALLBACK: arrestato ({reason})")


def start_post_call_fallback(snapshot):
    """Serve the latest private snapshot briefly when live early media ends."""
    global FALLBACK_PROCESS
    if POST_CALL_FALLBACK_SECONDS == 0 or not snapshot or not Path(snapshot).is_file():
        return
    stop_post_call_fallback()
    command = post_call_fallback_command(snapshot)
    with FALLBACK_LOCK:
        FALLBACK_PROCESS = subprocess.Popen(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True,
        )
    lifetime = (
        "continuo" if POST_CALL_FALLBACK_SECONDS < 0
        else f"per {POST_CALL_FALLBACK_SECONDS}s"
    )
    log(f"POST-CALL FALLBACK: attivo ({lifetime})")


def classify_entrance_image(path):
    signature = image_signature(path)
    return classify_entrance(
        signature, ENTRANCE_PROFILES,
        ENTRANCE_CLASSIFICATION_THRESHOLD,
        ENTRANCE_CLASSIFICATION_MARGIN,
    )


def next_reconnect_delay(previous_delay, connected_for):
    """Return a short delay after stable sessions and back off rapid failures."""
    initial = max(0.0, RECONNECT_INITIAL_DELAY)
    maximum = max(initial, RECONNECT_MAX_DELAY)
    if connected_for >= max(0.0, RECONNECT_STABLE_AFTER):
        return initial
    return min(maximum, max(initial, previous_delay * 2))


def validate_runtime_settings():
    """Reject incomplete configuration before entering the reconnect loop."""
    missing = []
    if not SERVER_IP:
        missing.append("sip_server")
    if not DOMAIN:
        missing.append("sip_domain")
    if missing:
        raise RuntimeError(
            "configurazione SIP incompleta: " + ", ".join(missing)
        )


def sip_instance_uuid():
    """Stable SIP instance id across restarts (RFC 5626 replacement)."""
    try:
        value = SIP_INSTANCE_FILE.read_text(encoding="utf-8").strip()
        uuid.UUID(value)
        return value
    except (FileNotFoundError, ValueError, OSError):
        pass
    value = str(uuid.uuid4())
    try:
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        try:
            SIP_INSTANCE_FILE.unlink()
        except FileNotFoundError:
            pass
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        try:
            descriptor = os.open(SIP_INSTANCE_FILE, flags, 0o600)
        except FileExistsError:
            return value
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(value + "\n")
    except OSError:
        pass
    return value


def diagnostic_key():
    """Return a private, installation-local key for stable log fingerprints."""
    global DIAGNOSTIC_KEY
    with DIAGNOSTIC_KEY_LOCK:
        if DIAGNOSTIC_KEY is not None:
            return DIAGNOSTIC_KEY
        try:
            DIAGNOSTIC_KEY = DIAGNOSTIC_KEY_FILE.read_bytes()
        except FileNotFoundError:
            key = secrets.token_bytes(32)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            try:
                descriptor = os.open(DIAGNOSTIC_KEY_FILE, flags, 0o600)
            except FileExistsError:
                DIAGNOSTIC_KEY = DIAGNOSTIC_KEY_FILE.read_bytes()
            else:
                with os.fdopen(descriptor, "wb") as output:
                    output.write(key)
                DIAGNOSTIC_KEY = key
        if len(DIAGNOSTIC_KEY) < 16:
            raise RuntimeError("chiave diagnostica locale non valida")
        return DIAGNOSTIC_KEY


def privacy_token(value, key=None):
    if value is None or not str(value).strip():
        return "-"
    digest = hmac.new(
        key or diagnostic_key(), str(value).strip().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest[:12]


def sip_uri(value):
    match = re.search(r"(?i)sips?:([^>;,\s]+)", value or "")
    return match.group(1) if match else ""


def entrance_fingerprints(raw, key=None):
    """Extract comparable call metadata while returning only keyed hashes."""
    headers, _ = sip_headers(raw)
    body = sip_body(raw)
    first = sip_first_line(raw).split()
    request_uri = first[1] if len(first) > 1 else ""
    lines = body.replace("\r", "").split("\n")
    origin = next((line[2:].split() for line in lines if line.startswith("o=")), [])
    connections = sorted({
        line.split()[-1] for line in lines
        if line.startswith("c=") and line.split()
    })
    session_name = next((line[2:] for line in lines if line.startswith("s=")), "")
    whole = raw.decode("utf-8", errors="replace")
    devaddr = sorted(set(re.findall(
        r"(?im)DEVADDR\s*[:=]\s*([^;\s\r\n]+)", whole
    )))
    selected_headers = {}
    for name, value in headers.items():
        if name.startswith(("x-", "p-")) or name in {
            "alert-info", "diversion", "remote-party-id", "subject"
        }:
            selected_headers[name] = privacy_token(value, key)
    return {
        "request": privacy_token(request_uri, key),
        "from": privacy_token(sip_uri(headers.get("from", "")), key),
        "contact": privacy_token(sip_uri(headers.get("contact", "")), key),
        "user_agent": privacy_token(headers.get("user-agent", ""), key),
        "devaddr": [privacy_token(value, key) for value in devaddr],
        "origin_user": privacy_token(origin[0] if origin else "", key),
        "origin_address": privacy_token(origin[-1] if len(origin) >= 6 else "", key),
        "connections": [privacy_token(value, key) for value in connections],
        "session": privacy_token(session_name, key),
        "headers": selected_headers,
    }


def call_reference(call_id):
    return privacy_token(call_id)


# ------------------------------------------------------------
# utilities
# ------------------------------------------------------------

def now():
    return datetime.now().isoformat(timespec="seconds")


def stamp():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def log(message):
    line = f"[{now()}] {message}"
    print(line, flush=True)

    BASE.mkdir(parents=True, exist_ok=True)

    with open(BASE / "listener.log", "a", encoding="utf-8") as f:
        f.write(line + "\n")


def latest_snapshot():
    snapshots = [p for p in SNAPSHOT_DIR.glob("*.jpg") if p.is_file()]
    return max(snapshots, key=lambda p: p.stat().st_mtime, default=None)


def set_snapshot_pending(call_id, pending):
    with PENDING_LOCK:
        if pending:
            PENDING_CALLS.add(call_id)
        else:
            PENDING_CALLS.discard(call_id)


def snapshot_pending():
    with PENDING_LOCK:
        return bool(PENDING_CALLS)


def ensure_placeholder_snapshot():
    cmd = [
        FFMPEG, "-hide_banner", "-loglevel", "error", "-nostdin",
        "-f", "lavfi", "-i", "color=c=0x252a33:s=400x288",
        "-frames:v", "1", "-q:v", "2", "-y",
        str(PLACEHOLDER_SNAPSHOT),
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)
    os.chmod(PLACEHOLDER_SNAPSHOT, 0o600)


class SnapshotHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.split("?", 1)[0] != "/snapshot.jpg":
            self.send_error(404)
            return
        path = (PLACEHOLDER_SNAPSHOT if snapshot_pending() else latest_snapshot())
        if not path:
            self.send_error(503, "Snapshot non ancora disponibile")
            return
        try:
            data = path.read_bytes()
        except OSError:
            self.send_error(503, "Snapshot temporaneamente non disponibile")
            return
        self.send_response(200)
        self.send_header("Content-Type", "image/jpeg")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path.split("?", 1)[0] != "/open":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length > 0:
            self.rfile.read(min(length, 4096))
        try:
            from bticino_opener import opener_settings
            enabled = opener_settings().get("enabled", False)
        except Exception:
            enabled = False
        if not enabled:
            self._open_reply(503, {"status": "disabled"})
            return
        if not self._open_authorized():
            self._open_reply(403, {"status": "forbidden"})
            log("OPENER: token mancante/errato")
            return
        threading.Thread(target=trigger_gate_open, daemon=True).start()
        self._open_reply(202, {"status": "triggered"})

    def _open_authorized(self):
        """Token obbligatorio se l'ascolto non è solo loopback."""
        if SNAPSHOT_HTTP_HOST in LOOPBACK_HOSTS and not OPENER_TOKEN:
            return True
        if not OPENER_TOKEN:
            return False
        from urllib.parse import parse_qs, urlsplit
        query = parse_qs(urlsplit(self.path).query)
        provided = query.get("token", [""])[0] or self.headers.get("X-Opener-Token", "")
        return hmac.compare_digest(provided, OPENER_TOKEN)

    def _open_reply(self, code, payload):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        return


def trigger_gate_open():
    """Esegue l'apertura cancellino su connessione TLS dedicata."""
    try:
        from bticino_opener import open_gate
        ok, detail = open_gate()
        log(f"OPENER: {'OK' if ok else 'FAIL'} {detail}")
    except Exception as exc:
        log(f"OPENER: errore {type(exc).__name__}: {exc}")


def start_snapshot_server():
    server = ThreadingHTTPServer(
        (SNAPSHOT_HTTP_HOST, SNAPSHOT_HTTP_PORT), SnapshotHandler
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log(f"Snapshot HTTP locale: http://{SNAPSHOT_HTTP_HOST}:{SNAPSHOT_HTTP_PORT}/snapshot.jpg")
    if SNAPSHOT_HTTP_HOST not in LOOPBACK_HOSTS:
        log("HTTP: ascolto su LAN, /open richiede token")
    return server


def ring_homekit_doorbell():
    url = (
        f"http://localhost:{HOMEBRIDGE_HTTP_PORT}/doorbell?"
        f"{quote(HOMEBRIDGE_DOORBELL_NAME)}"
    )
    try:
        with urlopen(url, timeout=3) as response:
            response.read(2048)
        log("HOMEKIT DOORBELL: evento inviato")
    except Exception as exc:
        log(f"HOMEKIT DOORBELL: invio fallito: {type(exc).__name__}: {exc}")


def _mqtt_encode_remaining_length(length):
    if length < 0 or length > 268435455:
        raise ValueError("lunghezza MQTT non valida")
    encoded = bytearray()
    while True:
        digit = length % 128
        length //= 128
        if length > 0:
            digit |= 0x80
        encoded.append(digit)
        if length == 0:
            break
    return bytes(encoded)


def _mqtt_pack_str(value):
    raw = value.encode("utf-8")
    if len(raw) > 0xFFFF:
        raise ValueError("stringa MQTT troppo lunga")
    return len(raw).to_bytes(2, "big") + raw


def _mqtt_read_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("connessione MQTT chiusa")
        data += chunk
    return data


def _mqtt_publish_once(topic, payload, retain=False):
    """Publish QoS0 senza dipendenze esterne (MQTT 3.1.1)."""
    if not MQTT_HOST:
        raise RuntimeError("mqtt.host non configurato")
    password = None
    if MQTT_PASSWORD_FILE:
        try:
            password = Path(MQTT_PASSWORD_FILE).expanduser().read_text(
                encoding="utf-8"
            ).strip() or None
        except OSError as exc:
            raise RuntimeError(f"password_file illeggibile: {exc}") from exc
    raw_sock = socket.create_connection(
        (MQTT_HOST, MQTT_PORT), timeout=max(1.0, MQTT_TIMEOUT)
    )
    sock = raw_sock
    try:
        sock.settimeout(max(1.0, MQTT_TIMEOUT))
        if MQTT_USE_TLS:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=MQTT_HOST)
        client_id = (MQTT_CLIENT_ID or f"bticino-{uuid.uuid4().hex[:8]}")[:23]
        flags = 0x02  # clean session
        if MQTT_USERNAME:
            flags |= 0x80
        if password is not None:
            if not MQTT_USERNAME:
                raise RuntimeError("mqtt.password_file senza mqtt.username")
            flags |= 0x40
        body = (
            _mqtt_pack_str("MQTT")
            + bytes((0x04, flags, 0x00, 0x3C))
            + _mqtt_pack_str(client_id)
        )
        if MQTT_USERNAME:
            body += _mqtt_pack_str(MQTT_USERNAME)
        if password is not None:
            body += _mqtt_pack_str(password)
        sock.sendall(
            bytes((0x10,)) + _mqtt_encode_remaining_length(len(body)) + body
        )
        header = _mqtt_read_exact(sock, 4)
        if header[0] != 0x20 or header[1] != 0x02 or header[3] != 0x00:
            raise RuntimeError(f"CONNACK rifiutato: rc={header[3]}")
        topic_raw = topic.encode("utf-8")
        if not topic_raw or len(topic_raw) > 0xFFFF:
            raise ValueError("topic MQTT non valido")
        publish_body = (
            len(topic_raw).to_bytes(2, "big") + topic_raw + payload
        )
        fixed = 0x30 | (0x01 if retain else 0x00)
        sock.sendall(
            bytes((fixed,))
            + _mqtt_encode_remaining_length(len(publish_body))
            + publish_body
        )
        try:
            sock.sendall(b"\xe0\x00")
        except OSError:
            pass
    finally:
        try:
            sock.close()
        except OSError:
            pass


def publish_mqtt_event(call_id, event):
    """Posta un evento JSON sul topic configurato, senza bloccare SIP."""
    if not MQTT_ENABLED:
        return
    try:
        payload = json.dumps(
            {
                "event": event,
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "doorbell": HOMEBRIDGE_DOORBELL_NAME,
                "call": call_reference(call_id),
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        _mqtt_publish_once(MQTT_TOPIC, payload, retain=MQTT_RETAIN)
        log(f"MQTT: {event} pubblicato su {MQTT_HOST}:{MQTT_PORT} topic={MQTT_TOPIC}")
    except Exception as exc:
        # Mai stampare username/password/topic sensibili oltre il nome topic.
        log(f"MQTT: invio fallito: {type(exc).__name__}: {exc}")


def publish_mqtt_ring(call_id):
    """Posta un JSON di chiamata sul topic configurato, senza bloccare SIP."""
    publish_mqtt_event(call_id, "ring")


def notify_incoming_call(call_id, snapshot_path=None, started_at=0.0,
                           doorbell_timeout=None):
    """Notifica MQTT subito; HomeKit subito o dopo la snapshot.

    iOS fotografa stillImageSource nell'istante dell'evento campanello: con
    attesa > 0 il ring parte solo quando la snapshot della chiamata esiste
    (foto vera invece del placeholder scuro), al costo di ritardare la
    notifica stessa. MQTT resta immediato in entrambi i casi.
    """
    threading.Thread(target=publish_mqtt_ring, args=(call_id,), daemon=True).start()
    wait = (DOORBELL_SNAPSHOT_TIMEOUT if doorbell_timeout is None
            else doorbell_timeout)
    if wait and wait > 0 and snapshot_path is not None:
        threading.Thread(
            target=ring_homekit_doorbell_delayed,
            args=(call_id, Path(snapshot_path), started_at, wait),
            daemon=True,
        ).start()
    else:
        threading.Thread(target=ring_homekit_doorbell, daemon=True).start()


def ring_homekit_doorbell_delayed(call_id, snapshot_path, started_at, wait):
    """Aspetta la snapshot (max `wait` s) prima di suonare in HomeKit."""
    deadline = time.time() + max(0.0, wait)
    while time.time() < deadline:
        try:
            stat = snapshot_path.stat()
            if stat.st_size > 0 and stat.st_mtime >= started_at:
                break
        except OSError:
            pass
        time.sleep(0.5)
    ring_homekit_doorbell()


def md5(text):
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def token(n=12):
    return secrets.token_hex(n)


def aes_cm_prf(master_key, master_salt, label, length):
    """RFC 3711 AES-CM PRF, with the default key-derivation rate of zero."""
    if len(master_key) != 16 or len(master_salt) != 14:
        raise ValueError("materiale master SRTP non valido")
    x = bytearray(master_salt)
    # label || r is right-aligned to the 112-bit master salt; r is zero.
    x[7] ^= label
    counter = int.from_bytes(x + b"\x00\x00", "big")
    blocks = b"".join(
        ((counter + i) & ((1 << 128) - 1)).to_bytes(16, "big")
        for i in range((length + 15) // 16)
    )
    if _HAS_CRYPTOGRAPHY:
        cipher = Cipher(algorithms.AES(master_key), modes.ECB())
        encryptor = cipher.encryptor()
        return (encryptor.update(blocks) + encryptor.finalize())[:length]
    result = subprocess.run(
        [OPENSSL, "enc", "-aes-128-ecb", "-K", master_key.hex(),
         "-nosalt", "-nopad"],
        input=blocks, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=True,
    )
    return result.stdout[:length]


def make_srtcp_pli(master_material, sender_ssrc, media_ssrc, index=0, auth_key=None):
    """Build authenticated, unencrypted compound SRTCP RR+SDES+PLI."""
    if len(master_material) != 30:
        raise ValueError("materiale SDES non valido")
    rr = b"\x80\xc9\x00\x01" + sender_ssrc.to_bytes(4, "big")
    cname = b"bticino-sniffer"
    sdes_body = (
        sender_ssrc.to_bytes(4, "big")
        + bytes((1, len(cname))) + cname + b"\x00"
    )
    sdes_body += b"\x00" * ((-len(sdes_body)) % 4)
    sdes = (
        b"\x81\xca"
        + (len(sdes_body) // 4).to_bytes(2, "big")
        + sdes_body
    )
    pli = (
        b"\x81\xce\x00\x02"
        + sender_ssrc.to_bytes(4, "big")
        + media_ssrc.to_bytes(4, "big")
    )
    plain = rr + sdes + pli
    # E=0: RTCP remains clear, but authentication is mandatory for SRTCP.
    trailer = (index & 0x7fffffff).to_bytes(4, "big")
    if auth_key is None:
        auth_key = aes_cm_prf(master_material[:16], master_material[16:], 0x04, 20)
    tag = hmac.new(auth_key, plain + trailer, hashlib.sha1).digest()[:10]
    return plain + trailer + tag


def make_srtcp_fir(master_material, sender_ssrc, media_ssrc, seq=0, index=0, auth_key=None):
    """Build authenticated, unencrypted compound SRTCP RR+SDES+FIR (RFC 5104)."""
    if len(master_material) != 30:
        raise ValueError("materiale SDES non valido")
    rr = b"\x80\xc9\x00\x01" + sender_ssrc.to_bytes(4, "big")
    cname = b"bticino-sniffer"
    sdes_body = (
        sender_ssrc.to_bytes(4, "big")
        + bytes((1, len(cname))) + cname + b"\x00"
    )
    sdes_body += b"\x00" * ((-len(sdes_body)) % 4)
    sdes = (
        b"\x81\xca"
        + (len(sdes_body) // 4).to_bytes(2, "big")
        + sdes_body
    )
    fir_entry = (
        media_ssrc.to_bytes(4, "big")
        + bytes((seq & 0xff, 0, 0, 0))
    )
    fir = (
        b"\x84\xce\x00\x04"
        + sender_ssrc.to_bytes(4, "big")
        + fir_entry
    )
    plain = rr + sdes + fir
    trailer = (index & 0x7fffffff).to_bytes(4, "big")
    if auth_key is None:
        auth_key = aes_cm_prf(master_material[:16], master_material[16:], 0x04, 20)
    tag = hmac.new(auth_key, plain + trailer, hashlib.sha1).digest()[:10]
    return plain + trailer + tag


def load_credentials():
    data = json.loads(CREDS_FILE.read_text())

    account = (
        data.get("SipAccount")
        or data.get("sipAccount")
        or data.get("sip_account")
    )

    password = (
        data.get("SipPassword")
        or data.get("sipPassword")
        or data.get("sip_password")
    )

    if not account:
        raise RuntimeError("SipAccount non trovato in sip_credentials.json")

    if not password:
        raise RuntimeError("SipPassword non trovato in sip_credentials.json")

    # SipAccount può essere:
    # user@domain
    # sip:user@domain
    account = account.removeprefix("sip:")

    username = account.split("@", 1)[0]

    return username, account, password


def make_tls_context():
    ctx = ssl.create_default_context(cafile=str(CA_FILE))

    # Il certificato del 3488 usa CN sip:<domain>.
    # Manteniamo comunque la verifica della CA BTicino.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED

    ctx.load_cert_chain(
        certfile=str(CERT_FILE),
        keyfile=str(KEY_FILE)
    )

    return ctx


# ------------------------------------------------------------
# SIP parsing
# ------------------------------------------------------------

class SIPStream:
    def __init__(self, sock):
        self.sock = sock
        self.buffer = b""

    def read_message(self, timeout=5):
        self.sock.settimeout(timeout)

        while True:
            while b"\r\n\r\n" not in self.buffer:
                chunk = self.sock.recv(16384)

                if not chunk:
                    raise ConnectionError("connessione SIP chiusa")

                self.buffer += chunk

            # Scarta eventuali CRLF di keepalive in arrivo (RFC 5626).
            self.buffer = self.buffer.lstrip(b"\r\n")
            if b"\r\n\r\n" not in self.buffer:
                continue

            header_end = self.buffer.index(b"\r\n\r\n") + 4

            header_blob = self.buffer[:header_end]
            header_text = header_blob.decode("utf-8", errors="replace")

            m = re.search(
                r"(?im)^Content-Length\s*:\s*(\d+)\s*$",
                header_text
            )

            body_len = int(m.group(1)) if m else 0
            total_len = header_end + body_len

            while len(self.buffer) < total_len:
                chunk = self.sock.recv(16384)

                if not chunk:
                    raise ConnectionError("connessione SIP chiusa durante body")

                self.buffer += chunk

            raw = self.buffer[:total_len]
            self.buffer = self.buffer[total_len:]

            if not raw.strip():
                continue

            return raw


def sip_first_line(raw):
    return raw.split(b"\r\n", 1)[0].decode(
        "utf-8",
        errors="replace"
    )


def sip_headers(raw):
    text = raw.decode("utf-8", errors="replace")

    head = text.split("\r\n\r\n", 1)[0]

    result = {}
    multi = {}

    for line in head.split("\r\n")[1:]:
        if ":" not in line:
            continue

        name, value = line.split(":", 1)
        name = name.strip()
        value = value.strip()

        result[name.lower()] = value
        multi.setdefault(name.lower(), []).append(value)

    return result, multi


def sip_body(raw):
    parts = raw.split(b"\r\n\r\n", 1)

    if len(parts) != 2:
        return ""

    return parts[1].decode("utf-8", errors="replace")


def has_obs_fold(raw):
    """Rileva header piegati (obs-fold): possibile vettore di injection."""
    head = raw.split(b"\r\n\r\n", 1)[0]
    return any(line[:1] in b" \t" for line in head.split(b"\r\n")[1:])


def valid_sip_contact(value):
    """Accetta solo Contact con URI sip:/sips: (anti-injection)."""
    text = (value or "").strip()
    if text.startswith("<"):
        text = text[1:].split(">", 1)[0]
    else:
        text = text.split(";", 1)[0]
    return text.lower().startswith(("sip:", "sips:"))


def valid_remote_ip(value):
    """Rifiuta loopback/unspecified/multicast/link-local per i media remoti."""
    try:
        parsed = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return False
    return not (parsed.is_loopback or parsed.is_unspecified
                or parsed.is_multicast or parsed.is_link_local)


def sdp_value(body, prefix):
    for line in body.replace("\r", "").split("\n"):
        if line.lower().startswith(prefix.lower()):
            return line[len(prefix):].strip()
    return None


def reserve_udp_pair(bind_ip, excluded_ports=(), start=MEDIA_PORT_START,
                     end=MEDIA_PORT_END):
    """Choose a free even RTP/RTCP pair inside the firewall-approved pool."""
    for port in range(start, end, 2):
        if port in excluded_ports or port + 1 in excluded_ports:
            continue
        rtp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rtcp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            rtp.bind((bind_ip, port))
            rtcp.bind((bind_ip, port + 1))
            return port
        except OSError:
            pass
        finally:
            rtp.close()
            rtcp.close()
    raise RuntimeError(
        f"nessuna coppia RTP/RTCP libera in UDP {start}-{end}"
    )


def status_code(raw):
    first = sip_first_line(raw)

    m = re.match(r"SIP/2\.0\s+(\d+)", first)

    return int(m.group(1)) if m else None


# ------------------------------------------------------------
# Digest authentication
# ------------------------------------------------------------

def parse_digest_challenge(value):
    params = {}

    if value.lower().startswith("digest "):
        value = value[7:]

    pattern = r'(\w+)=("([^"]*)"|([^,\s]+))'

    for match in re.finditer(pattern, value):
        key = match.group(1).lower()
        val = match.group(3) or match.group(4) or ""
        params[key] = val

    return params


def digest_authorization(
    username,
    password,
    method,
    uri,
    challenge
):
    realm = challenge["realm"]
    nonce = challenge["nonce"]

    qop_raw = challenge.get("qop", "")
    algorithm = challenge.get("algorithm", "MD5")

    if algorithm.upper() != "MD5":
        raise RuntimeError(
            f"Digest algorithm non supportato: {algorithm}"
        )

    ha1 = md5(f"{username}:{realm}:{password}")
    ha2 = md5(f"{method}:{uri}")

    parts = [
        f'username="{username}"',
        f'realm="{realm}"',
        f'nonce="{nonce}"',
        f'uri="{uri}"',
    ]

    if qop_raw:
        qops = [x.strip() for x in qop_raw.split(",")]

        qop = "auth" if "auth" in qops else qops[0]

        nc = "00000001"
        cnonce = token(8)

        response = md5(
            f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}"
        )

        parts += [
            f'response="{response}"',
            f"algorithm=MD5",
            f"qop={qop}",
            f"nc={nc}",
            f'cnonce="{cnonce}"',
        ]

    else:
        response = md5(f"{ha1}:{nonce}:{ha2}")

        parts += [
            f'response="{response}"',
            "algorithm=MD5",
        ]

    return "Digest " + ", ".join(parts)


# ------------------------------------------------------------
# SIP client
# ------------------------------------------------------------

class EarlyMediaCapture:
    """One short-lived FFmpeg receiver for a single INVITE."""

    def __init__(self, call_id, local_ip, local_port, internal_port, payload, fmtp,
                 remote_key, crypto_tag, media_order, audio, remote_ip,
                 remote_rtp_port, remote_rtcp_port):
        self.call_id = call_id
        self.local_ip = local_ip
        self.local_port = local_port
        self.internal_port = internal_port
        self.payload = payload
        self.fmtp = fmtp
        self.remote_key = remote_key
        self.crypto_tag = crypto_tag
        self.media_order = media_order
        self.audio = audio
        self.remote_ip = remote_ip
        self.remote_rtp_port = remote_rtp_port
        self.remote_rtcp_port = remote_rtcp_port
        self.audio_key = base64.b64encode(os.urandom(30)).decode("ascii")
        self.audio_sockets = []
        self.audio_packets = 0
        self.answer_key = base64.b64encode(os.urandom(30)).decode("ascii")
        self.auth_key = None
        self.process = None
        self.stderr_lines = collections.deque(maxlen=100)
        self.stderr_thread = None
        self.relay_sockets = []
        self.relay_sender = None
        self.relay_thread = None
        self.relay_stop = threading.Event()
        self.rtp_metadata_logged = False
        self.rtcp_rx_logged = False
        self.feedback_ssrc = secrets.randbits(32) or 1
        self.media_ssrc = None
        self.feedback_attempts = 0
        self.last_feedback = 0.0
        self.fir_seq = 0
        self.srtcp_index = 0
        self.snapshot_reported = False
        self.classification_reported = False
        self.started = time.time()
        self.snapshot = SNAPSHOT_DIR / (
            f"{stamp()}_{re.sub(r'[^A-Za-z0-9_.-]', '_', call_id)[:60]}.jpg"
        )
        self.sdp_path = RUNTIME_DIR / f"media-{uuid.uuid4().hex}.sdp"
        self.classification_path = RUNTIME_DIR / f"entrance-{uuid.uuid4().hex}.jpg"

    def _drain_stderr(self):
        proc = self.process
        if not proc or not proc.stderr:
            return
        try:
            for line in proc.stderr:
                self.stderr_lines.append(line)
        except Exception:
            pass
        finally:
            try:
                proc.stderr.close()
            except Exception:
                pass

    def get_stderr_tail(self, max_chars=2000):
        text = "".join(self.stderr_lines)
        return text[-max_chars:].strip()

    @property
    def sdp_ip(self):
        """IP pubblicizzato in SDP: override (IP o hostname DDNS) o IP locale."""
        if not MEDIA_IP_OVERRIDE:
            return self.local_ip
        try:
            ipaddress.ip_address(MEDIA_IP_OVERRIDE)
            return MEDIA_IP_OVERRIDE
        except ValueError:
            pass
        try:
            return socket.gethostbyname(MEDIA_IP_OVERRIDE)
        except OSError as exc:
            log(f"SDP media_ip: risoluzione {MEDIA_IP_OVERRIDE} fallita "
                f"({type(exc).__name__}), uso IP locale")
            return self.local_ip

    @property
    def answer_sdp(self):
        fmtp_line = f"a=fmtp:{self.payload} {self.fmtp}\r\n" if self.fmtp else ""
        video = (
            f"m=video {self.local_port} RTP/SAVP {self.payload}\r\n"
            f"a=rtcp:{self.local_port + 1}\r\n"
            f"a=rtpmap:{self.payload} H264/90000\r\n"
            f"{fmtp_line}"
            "a=rtcp-fb:* trr-int 5000\r\n"
            "a=rtcp-fb:* ccm tmmbr\r\n"
            f"a=rtcp-fb:{self.payload} nack pli\r\n"
            f"a=rtcp-fb:{self.payload} ccm fir\r\n"
            "a=recvonly\r\n"
            f"a=crypto:{self.crypto_tag} AES_CM_128_HMAC_SHA1_80 "
            f"inline:{self.answer_key}\r\n"
        )
        media = []
        video_inserted = False
        for kind, proto, payloads in self.media_order:
            if kind == "audio" and self.audio:
                media.append(
                    f"m=audio {self.audio['local_port']} {proto} {self.audio['payload']}\r\n"
                    f"a=rtcp:{self.audio['local_port'] + 1}\r\n"
                    f"a=rtpmap:{self.audio['payload']} {self.audio['rtpmap']}\r\n"
                    "a=rtcp-fb:* trr-int 5000\r\n"
                    "a=rtcp-fb:* ccm tmmbr\r\n"
                    "a=recvonly\r\n"
                    f"a=crypto:{self.audio['crypto_tag']} AES_CM_128_HMAC_SHA1_80 "
                    f"inline:{self.audio_key}\r\n"
                )
            elif kind == "video" and not video_inserted:
                media.append(video)
                video_inserted = True
            else:
                media.append(f"m={kind} 0 {proto} {' '.join(payloads)}\r\n")
        return (
            "v=0\r\n"
            f"o=bticino-sniffer {int(time.time())} 1 IN IP4 {self.sdp_ip}\r\n"
            "s=Early media snapshot\r\n"
            f"c=IN IP4 {self.sdp_ip}\r\n"
            "t=0 0\r\n"
            + "".join(media)
        )

    def start(self):
        stop_post_call_fallback("nuova chiamata")
        try:
            self._start_sockets_and_ffmpeg()
        except Exception:
            self.close_audio()
            self.close_relay()
            raise

    def _start_sockets_and_ffmpeg(self):
        if self.audio:
            for port in (self.audio["local_port"], self.audio["local_port"] + 1):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind((self.local_ip, port))
                sock.setblocking(False)
                self.audio_sockets.append(sock)
        for port in (self.local_port, self.local_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.local_ip, port))
            sock.setblocking(False)
            self.relay_sockets.append(sock)
        self.relay_sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.relay_thread = threading.Thread(target=self.relay_media, daemon=True)
        self.relay_thread.start()
        # FFmpeg reads the offerer's key because it decrypts packets sent by it.
        input_sdp = (
            "v=0\n"
            "o=- 0 0 IN IP4 127.0.0.1\n"
            "s=SRTP input\n"
            "c=IN IP4 127.0.0.1\n"
            "t=0 0\n"
            f"m=video {self.internal_port} RTP/SAVP {self.payload}\n"
            f"a=rtcp:{self.internal_port + 1}\n"
            f"a=rtpmap:{self.payload} H264/90000\n"
            + (f"a=fmtp:{self.payload} {self.fmtp}\n" if self.fmtp else "")
            + "a=rtcp-fb:* trr-int 5000\n"
            + "a=rtcp-fb:* ccm tmmbr\n"
            + f"a=rtcp-fb:{self.payload} nack pli\n"
            + f"a=rtcp-fb:{self.payload} ccm fir\n"
            + f"a=crypto:{self.crypto_tag} AES_CM_128_HMAC_SHA1_80 inline:{self.remote_key}\n"
            + "a=recvonly\n"
        )
        self.sdp_path.write_text(input_sdp, encoding="utf-8")
        os.chmod(self.sdp_path, 0o600)
        cmd = [
            FFMPEG, "-hide_banner", "-loglevel", "warning", "-nostdin",
            "-protocol_whitelist", "file,udp,rtp,srtp,crypto",
            "-rw_timeout", str(MEDIA_TIMEOUT * 1000000),
            "-i", str(self.sdp_path),
            # Inoltra continuamente l'H.264 decifrato a Homebridge. Il flusso
            # resta confinato al loopback e termina con la sessione SIP.
            "-map", "0:v:0",
            "-c:v", "copy",
            "-mpegts_flags", "+resend_headers",
            "-f", "mpegts",
            f"udp://{LIVE_VIDEO_HOST}:{LIVE_VIDEO_PORT}?pkt_size=1316",
            "-map", "0:v:0",
            # Il primo IDR può essere incompleto: scarta l'avvio e salva
            # un frame successivo, quando il decoder si è stabilizzato.
            "-vf", "select=gte(n\\,10)",
            "-frames:v", "1", "-q:v", "2", "-y",
            str(self.snapshot),
        ]
        if ENTRANCE_CLASSIFICATION_ENABLED and ENTRANCE_PROFILES:
            cmd += [
                "-map", "0:v:0",
                "-vf", (
                    f"select=gte(n\\,{ENTRANCE_CLASSIFICATION_FRAME}),"
                    f"scale={ENTRANCE_SIGNATURE_WIDTH}:{ENTRANCE_SIGNATURE_HEIGHT}:"
                    "flags=area,format=gray"
                ),
                "-frames:v", "1", "-q:v", "5", "-y",
                str(self.classification_path),
            ]
        self.process = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            text=True, close_fds=True,
        )
        self.stderr_lines.clear()
        self.stderr_thread = threading.Thread(
            target=self._drain_stderr, daemon=True
        )
        self.stderr_thread.start()
        set_snapshot_pending(self.call_id, True)

    def poll(self):
        for sock in self.audio_sockets:
            while True:
                try:
                    sock.recvfrom(65535)
                    self.audio_packets += 1
                except BlockingIOError:
                    break
        if (self.media_ssrc is not None and not self.snapshot_reported
                and self.feedback_attempts < self.FEEDBACK_MAX_ATTEMPTS
                and time.time() - self.last_feedback >= self.FEEDBACK_INTERVAL
                and self.process is not None and self.process.poll() is None
                and self.relay_sockets):
            self.send_feedback(self.media_ssrc)
        if (not self.classification_reported
                and self.classification_path.exists()
                and self.classification_path.stat().st_size > 0):
            self.classification_reported = True
            try:
                name, distance, reason = classify_entrance_image(self.classification_path)
                elapsed = time.time() - self.started
                if name:
                    log(f"ENTRANCE VISUAL: {name} distance={distance:.3f} elapsed={elapsed:.2f}s diagnostic-only")
                else:
                    shown = "n/a" if distance is None else f"{distance:.3f}"
                    log(f"ENTRANCE VISUAL: sconosciuto reason={reason} distance={shown} elapsed={elapsed:.2f}s diagnostic-only")
            except Exception as exc:
                log(f"ENTRANCE VISUAL: errore {type(exc).__name__}: {exc}")
        if (not self.snapshot_reported and self.snapshot.exists()
                and self.snapshot.stat().st_size > 0):
            os.chmod(self.snapshot, 0o600)
            set_snapshot_pending(self.call_id, False)
            self.snapshot_reported = True
            log(
                f"SNAPSHOT OK: {self.snapshot.name} "
                f"({self.snapshot.stat().st_size} byte); "
                f"audio_udp={self.audio_packets}; live=udp://{LIVE_VIDEO_HOST}:{LIVE_VIDEO_PORT}"
            )
            threading.Thread(
                target=publish_mqtt_event,
                args=(self.call_id, "snapshot_ready"), daemon=True,
            ).start()
            if ENTRANCE_CLASSIFICATION_ENABLED and not self.classification_reported:
                try:
                    name, distance, reason = classify_entrance_image(self.snapshot)
                    elapsed = time.time() - self.started
                    shown = "n/a" if distance is None else f"{distance:.3f}"
                    log(
                        f"ENTRANCE VISUAL FALLBACK: {name or 'sconosciuto'} "
                        f"reason={reason} distance={shown} elapsed={elapsed:.2f}s"
                    )
                except Exception as exc:
                    log(f"ENTRANCE VISUAL FALLBACK: errore {type(exc).__name__}: {exc}")
        if not self.process or self.process.poll() is None:
            return False
        stderr = self.get_stderr_tail(2000)
        if not self.snapshot_reported:
            set_snapshot_pending(self.call_id, False)
        log(f"SNAPSHOT FALLITO call={call_reference(self.call_id)} audio_udp={self.audio_packets}: {stderr or 'nessun frame decodificabile'}")
        self.close_audio()
        self.close_relay()
        self.cleanup_files()
        if self.snapshot_reported:
            start_post_call_fallback(self.snapshot)
        return True

    def stop(self, reason):
        set_snapshot_pending(self.call_id, False)
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        if self.stderr_thread and self.stderr_thread.is_alive():
            self.stderr_thread.join(timeout=0.5)
        tail = self.get_stderr_tail(800)
        if tail and not self.snapshot_reported:
            log(f"FFMPEG DIAG call={call_reference(self.call_id)}: {tail}")
        log(f"Media chiuso call={call_reference(self.call_id)}: {reason}")
        self.close_audio()
        self.close_relay()
        self.cleanup_files()
        if self.snapshot_reported:
            start_post_call_fallback(self.snapshot)

    def relay_media(self):
        destinations = {
            self.relay_sockets[0]: ("127.0.0.1", self.internal_port),
            self.relay_sockets[1]: ("127.0.0.1", self.internal_port + 1),
        }
        while not self.relay_stop.is_set():
            try:
                ready, _, _ = select.select(self.relay_sockets, [], [], 0.25)
            except (OSError, ValueError):
                break
            for sock in ready:
                try:
                    packet, _ = sock.recvfrom(65535)
                except (BlockingIOError, OSError):
                    continue
                if sock is self.relay_sockets[0] and not self.rtp_metadata_logged:
                    if len(packet) >= 12 and packet[0] >> 6 == 2:
                        payload = packet[1] & 0x7f
                        marker = int(bool(packet[1] & 0x80))
                        sequence = int.from_bytes(packet[2:4], "big")
                        ssrc = int.from_bytes(packet[8:12], "big")
                        log(
                            f"RTP META call={call_reference(self.call_id)}: "
                            f"ssrc=0x{ssrc:08x} pt={payload} "
                            f"seq={sequence} marker={marker}"
                        )
                        self.rtp_metadata_logged = True
                        self.media_ssrc = ssrc
                        self.send_feedback(ssrc)
                if (sock is self.relay_sockets[1]
                        and not self.rtcp_rx_logged and len(packet) >= 4):
                    self.rtcp_rx_logged = True
                    pt = packet[1]
                    log(
                        f"RTCP RX call={call_reference(self.call_id)}: "
                        f"pt={pt} len={len(packet)}"
                    )
                try:
                    self.relay_sender.sendto(packet, destinations[sock])
                except OSError:
                    pass

    FEEDBACK_INTERVAL = 2.5
    FEEDBACK_MAX_ATTEMPTS = 12

    def send_feedback(self, media_ssrc):
        """PLI + FIR autenticati; ripetuti finche' non arriva il keyframe."""
        try:
            material = base64.b64decode(self.answer_key, validate=True)
            if self.auth_key is None:
                self.auth_key = aes_cm_prf(material[:16], material[16:], 0x04, 20)
            # RFC 3711: l'indice SRTCP si incrementa a ogni pacchetto
            # inviato, altrimenti il ricevente scarta i duplicati come replay.
            # Invio su porta RTCP e RTP: alcuni relay inoltrano solo una via.
            targets = {self.remote_rtcp_port, self.remote_rtp_port}
            for port in sorted(targets):
                pli = make_srtcp_pli(
                    material, self.feedback_ssrc, media_ssrc,
                    index=self.srtcp_index, auth_key=self.auth_key,
                )
                self.srtcp_index = (self.srtcp_index + 1) & 0x7fffffff
                self.relay_sockets[1].sendto(
                    pli, (self.remote_ip, port)
                )
                fir = make_srtcp_fir(
                    material, self.feedback_ssrc, media_ssrc,
                    seq=self.fir_seq, index=self.srtcp_index,
                    auth_key=self.auth_key,
                )
                self.srtcp_index = (self.srtcp_index + 1) & 0x7fffffff
                self.fir_seq = (self.fir_seq + 1) & 0xff
                self.relay_sockets[1].sendto(
                    fir, (self.remote_ip, port)
                )
            self.feedback_attempts += 1
            self.last_feedback = time.time()
            log(
                f"SRTCP PLI+FIR inviati call={call_reference(self.call_id)} "
                f"(tentativo {self.feedback_attempts}): "
                f"media_ssrc=0x{media_ssrc:08x} -> "
                f"{self.remote_ip}:{self.remote_rtcp_port}"
            )
        except Exception as exc:
            log(
                f"SRTCP feedback fallito call={call_reference(self.call_id)}: "
                f"{type(exc).__name__}: {exc}"
            )

    def send_pli(self, media_ssrc):
        self.send_feedback(media_ssrc)

    def close_relay(self):
        self.relay_stop.set()
        if self.relay_thread and self.relay_thread.is_alive():
            self.relay_thread.join(timeout=1)
        for sock in self.relay_sockets:
            try:
                sock.close()
            except OSError:
                pass
        self.relay_sockets = []
        if self.relay_sender:
            try:
                self.relay_sender.close()
            except OSError:
                pass
            self.relay_sender = None

    def close_audio(self):
        for sock in self.audio_sockets:
            try:
                sock.close()
            except OSError:
                pass
        self.audio_sockets = []

    def cleanup_files(self):
        for path in (self.sdp_path, self.classification_path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass

class HomtouchListener:

    def __init__(self):
        self.username, self.account, self.password = load_credentials()

        self.sock = None
        self.stream = None

        self.local_ip = None
        self.local_port = None

        self.call_id = f"{uuid.uuid4().hex}@hometouch-listener"
        self.from_tag = token(8)
        self.instance_uuid = sip_instance_uuid()

        self.cseq = 1

        self.registered = False
        self.next_refresh = 0
        self.media = {}
        self.dialog_tags = {}
        self.send_lock = threading.Lock()
        self.keepalive_stop = threading.Event()
        self.link_dead = threading.Event()
        self.keepalive_thread = None


    def connect(self):
        ctx = make_tls_context()

        raw = socket.create_connection(
            (SERVER_IP, SERVER_PORT),
            timeout=15
        )

        self.sock = ctx.wrap_socket(
            raw,
            server_hostname=DOMAIN
        )

        self.stream = SIPStream(self.sock)

        self.local_ip, self.local_port = self.sock.getsockname()[:2]

        log(
            f"TLS collegato: "
            f"{self.local_ip}:{self.local_port} -> "
            f"{SERVER_IP}:{SERVER_PORT}"
        )


    def send(self, text):
        with self.send_lock:
            self.sock.sendall(text.encode("utf-8"))


    def keepalive_loop(self):
        """CRLF periodici (stile RFC 5626) per tenere viva la connessione."""
        while RUNNING and not self.keepalive_stop.wait(KEEPALIVE_INTERVAL):
            sock = self.sock
            if sock is None:
                break
            try:
                with self.send_lock:
                    if self.sock is not sock:
                        continue
                    sock.sendall(b"\r\n\r\n")
            except OSError as exc:
                log(f"SIP keepalive fallito ({type(exc).__name__}); riconnessione")
                self.link_dead.set()
                break


    def build_register(self, authorization=None, expires=REGISTER_EXPIRES):
        uri = f"sip:{DOMAIN}"

        identity = f"sip:{self.username}@{DOMAIN}"

        branch = f"z9hG4bK{token(8)}"

        contact = (
            f'<sip:{self.username}@'
            f'{self.local_ip}:{self.local_port};transport=tls>'
            f';+sip.instance="<urn:uuid:{self.instance_uuid}>"'
            f';reg-id=1'
        )

        cseq = self.cseq
        self.cseq += 1

        lines = [
            f"REGISTER {uri} SIP/2.0",
            (
                f"Via: SIP/2.0/TLS "
                f"{self.local_ip}:{self.local_port};"
                f"branch={branch};rport"
            ),
            "Max-Forwards: 70",
            f"From: <{identity}>;tag={self.from_tag}",
            f"To: <{identity}>",
            f"Call-ID: {self.call_id}",
            f"CSeq: {cseq} REGISTER",
            f"Contact: {contact};expires={expires}",
            f"Expires: {expires}",
            "Supported: replaces, outbound, gruu",
            (
                "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, "
                "REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO, UPDATE"
            ),
            f"User-Agent: {USER_AGENT}",
        ]

        if authorization:
            lines.append(f"Authorization: {authorization}")

        lines += [
            "Content-Length: 0",
            "",
            "",
        ]

        return "\r\n".join(lines)


    def wait_register_response(self):
        deadline = time.time() + 15

        while time.time() < deadline:
            remaining = max(1, deadline - time.time())

            raw = self.stream.read_message(
                timeout=min(remaining, 5)
            )

            first = sip_first_line(raw)

            log(f"REGISTER RX: {first}")

            code = status_code(raw)

            if code is not None:
                return raw

            # Se per assurdo arriva già qualche richiesta
            self.handle_request(raw)

        raise TimeoutError("nessuna risposta al REGISTER")


    def register(self):
        log("Invio REGISTER iniziale")

        self.send(self.build_register())

        response = self.wait_register_response()

        code = status_code(response)

        if code == 200:
            self.registration_success(response)
            return

        if code not in (401, 407):
            raise RuntimeError(
                f"REGISTER rifiutato: {sip_first_line(response)}"
            )

        headers, _ = sip_headers(response)

        challenge_value = (
            headers.get("www-authenticate")
            or headers.get("proxy-authenticate")
        )

        if not challenge_value:
            raise RuntimeError(
                "401/407 senza WWW-Authenticate/Proxy-Authenticate"
            )

        challenge = parse_digest_challenge(challenge_value)

        auth = digest_authorization(
            username=self.username,
            password=self.password,
            method="REGISTER",
            uri=f"sip:{DOMAIN}",
            challenge=challenge,
        )

        log("Challenge Digest ricevuta; invio REGISTER autenticato")

        self.send(
            self.build_register(
                authorization=auth
            )
        )

        response = self.wait_register_response()

        code = status_code(response)

        if code != 200:
            raise RuntimeError(
                "REGISTER autenticato fallito: "
                + sip_first_line(response)
            )

        self.registration_success(response)


    def registration_success(self, raw):
        headers, _ = sip_headers(raw)

        expiry = REGISTER_EXPIRES

        if headers.get("expires"):
            try:
                expiry = int(headers["expires"])
            except Exception:
                pass

        contact = headers.get("contact", "")

        match = re.search(
            r"expires\s*=\s*(\d+)",
            contact,
            flags=re.I,
        )

        if match:
            try:
                expiry = int(match.group(1))
            except Exception:
                pass

        # mai aspettare troppo vicino alla scadenza
        refresh_after = max(
            60,
            expiry - min(REFRESH_MARGIN, max(30, expiry // 5))
        )

        self.next_refresh = time.time() + refresh_after
        self.registered = True

        log(
            f"REGISTRAZIONE SIP OK — expires={expiry}s, "
            f"rinnovo fra circa {refresh_after}s"
        )


    def respond_basic(self, raw, code, reason, to_tag=None, body=None,
                        contact=None):
        headers, multi = sip_headers(raw)

        lines = [
            f"SIP/2.0 {code} {reason}"
        ]

        for via in multi.get("via", []):
            lines.append(f"Via: {via}")

        for hname, pretty in [
            ("from", "From"),
            ("to", "To"),
            ("call-id", "Call-ID"),
            ("cseq", "CSeq"),
        ]:
            if headers.get(hname):
                value = headers[hname]
                if hname == "to" and to_tag and ";tag=" not in value.lower():
                    value += f";tag={to_tag}"
                lines.append(
                    f"{pretty}: {value}"
                )

        if contact:
            lines.append(f"Contact: {contact}")

        lines.append(f"User-Agent: {USER_AGENT}")
        lines.append(
            "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, "
            "REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO, UPDATE"
        )
        lines.append("Supported: replaces, outbound, gruu")
        if body is not None:
            lines += ["Content-Type: application/sdp", f"Content-Length: {len(body.encode('utf-8'))}", "", body]
        else:
            lines += ["Content-Length: 0", "", ""]

        self.send("\r\n".join(lines))


    def parse_video_offer(self, raw):
        body = sip_body(raw)
        lines = body.replace("\r", "").split("\n")
        media_order = []
        for line in lines:
            if line.startswith("m="):
                parts = line[2:].split()
                if len(parts) >= 4:
                    media_order.append((parts[0], parts[2], parts[3:]))
        video_index = next((i for i, x in enumerate(lines) if x.startswith("m=video ")), None)
        if video_index is None:
            raise RuntimeError("INVITE senza m=video")
        media = lines[video_index:]
        next_media = next((i for i, x in enumerate(media[1:], 1) if x.startswith("m=")), len(media))
        media = media[:next_media]
        mparts = media[0].split()
        try:
            remote_rtp_port = int(mparts[1])
        except (ValueError, IndexError):
            raise RuntimeError("porta RTP video non valida")
        if not 1 <= remote_rtp_port <= 65535:
            raise RuntimeError("porta RTP video fuori range")
        remote_rtcp_port = remote_rtp_port + 1
        for line in media:
            match = re.match(r"a=rtcp:(\d+)", line, re.I)
            if match:
                candidate = int(match.group(1))
                if 1 <= candidate <= 65535:
                    remote_rtcp_port = candidate
                break
        remote_ip = sdp_value("\n".join(media), "c=IN IP4 ")
        if not remote_ip:
            remote_ip = sdp_value(body, "c=IN IP4 ") or SERVER_IP
        if not valid_remote_ip(remote_ip):
            raise RuntimeError("IP remoto media non valido")
        offered_payloads = mparts[3:]
        payload = None
        for line in media:
            match = re.match(r"a=rtpmap:(\d+)\s+H264/90000", line, re.I)
            if match and match.group(1) in offered_payloads:
                payload = match.group(1)
                break
        if payload is None:
            raise RuntimeError("nessun payload H264/90000 offerto")
        if not payload.isdigit() or not 0 <= int(payload) <= 127:
            raise RuntimeError("payload video non valido")
        fmtp = ""
        for line in media:
            match = re.match(rf"a=fmtp:{re.escape(payload)}\s+(.+)", line, re.I)
            if match:
                fmtp = match.group(1).strip()
                break
        selected = None
        for line in media:
            match = re.match(
                r"a=crypto:(\d+)\s+AES_CM_128_HMAC_SHA1_80\s+inline:([^|\s]+)",
                line, re.I,
            )
            if match:
                selected = (match.group(1), match.group(2))
                break
        if selected is None:
            raise RuntimeError("AES_CM_128_HMAC_SHA1_80 SDES non offerto")
        try:
            key = base64.b64decode(selected[1], validate=True)
        except Exception as exc:
            raise RuntimeError(f"chiave SDES non valida: {exc}") from exc
        if len(key) != 30:
            raise RuntimeError(f"chiave SDES lunga {len(key)} byte, attesi 30")
        audio = None
        audio_index = next((i for i, x in enumerate(lines) if x.startswith("m=audio ")), None)
        if audio_index is not None:
            audio_lines = lines[audio_index:]
            audio_end = next((i for i, x in enumerate(audio_lines[1:], 1) if x.startswith("m=")), len(audio_lines))
            audio_lines = audio_lines[:audio_end]
            audio_parts = audio_lines[0].split()
            try:
                audio_port = int(audio_parts[1])
            except (ValueError, IndexError):
                audio_port = 0
            if audio_port == 0:
                audio = None
                audio_map, audio_crypto = None, None
            else:
                if not 1 <= audio_port <= 65535:
                    audio = None
                    audio_map, audio_crypto = None, None
                else:
                    audio_payloads = audio_parts[3:]
                    audio_map = None
                    for line in audio_lines:
                        match = re.match(r"a=rtpmap:(\d+)\s+([^\s]+)", line, re.I)
                        if match and match.group(1) in audio_payloads:
                            audio_map = (match.group(1), match.group(2))
                            break
                    audio_crypto = None
                    for line in audio_lines:
                        match = re.match(
                            r"a=crypto:(\d+)\s+AES_CM_128_HMAC_SHA1_80\s+inline:([^|\s]+)",
                            line, re.I,
                        )
                        if match:
                            try:
                                key = base64.b64decode(match.group(2), validate=True)
                            except Exception:
                                continue
                            if len(key) != 30:
                                continue
                            audio_crypto = (match.group(1), match.group(2))
                            break
            if audio_map and audio_crypto:
                audio = {
                    "payload": audio_map[0], "rtpmap": audio_map[1],
                    "crypto_tag": audio_crypto[0], "remote_key": audio_crypto[1],
                }
            else:
                audio = None
        return (payload, fmtp, selected[0], selected[1], media_order, audio,
                remote_ip, remote_rtp_port, remote_rtcp_port)


    def start_early_media(self, raw):
        headers, _ = sip_headers(raw)
        call_id = headers.get("call-id", uuid.uuid4().hex)
        (payload, fmtp, crypto_tag, remote_key, media_order, audio,
         remote_ip, remote_rtp_port, remote_rtcp_port) = self.parse_video_offer(raw)
        local_port = reserve_udp_pair(self.local_ip)
        internal_port = reserve_udp_pair(
            "127.0.0.1", start=INTERNAL_MEDIA_PORT_START,
            end=INTERNAL_MEDIA_PORT_END,
        )
        if audio:
            try:
                audio["local_port"] = reserve_udp_pair(
                    self.local_ip, {local_port, local_port + 1}
                )
            except RuntimeError:
                log("AUDIO: nessuna coppia libera nel range media_ports, "
                    "audio rifiutato (solo diagnostica)")
                audio = None
        capture = EarlyMediaCapture(
            call_id, self.local_ip, local_port, internal_port, payload, fmtp,
            remote_key, crypto_tag, media_order, audio, remote_ip,
            remote_rtp_port, remote_rtcp_port,
        )
        capture.start()
        # Give FFmpeg a brief chance to bind before advertising the port.
        time.sleep(0.15)
        if capture.process.poll() is not None:
            error = capture.get_stderr_tail(2000)
            capture.stop("avvio FFmpeg fallito")
            raise RuntimeError(f"FFmpeg non ha aperto RTP: {error}")
        self.media[call_id] = capture
        to_tag = self.dialog_tags.setdefault(call_id, token(8))
        contact = (
            f"<sip:{self.username}@{self.local_ip}:{self.local_port}"
            ";transport=tls>"
        )
        self.respond_basic(raw, 183, "Session Progress", to_tag,
                           capture.answer_sdp, contact=contact)
        if ANSWER_CALLS:
            self.respond_basic(raw, 200, "OK", to_tag,
                               capture.answer_sdp, contact=contact)
            log("200 OK inviato (answer_calls attivo: gli altri posti "
                "potrebbero smettere di squillare)")
        log(
            f"183 inviato: call={call_reference(call_id)} RTP/SRTP attivo "
            f"H264 PT={payload} crypto-tag={crypto_tag} "
            f"local={self.local_ip}:{local_port} sdp={capture.sdp_ip} "
            f"audio={audio['local_port'] if audio else 'rifiutato'}"
        )
        # HomeKit deve notificare subito; la snapshot pulita continua a essere
        # generata in parallelo e sostituisce automaticamente quella precedente.
        notify_incoming_call(call_id, capture.snapshot, capture.started)


    def maintain_media(self):
        for call_id, capture in list(self.media.items()):
            if capture.poll():
                self.media.pop(call_id, None)
                self.dialog_tags.pop(call_id, None)
            elif time.time() - capture.started > MEDIA_TIMEOUT + 5:
                capture.stop("timeout")
                self.media.pop(call_id, None)
                self.dialog_tags.pop(call_id, None)


    def stop_media_for(self, raw, reason):
        headers, _ = sip_headers(raw)
        call_id = headers.get("call-id", "")
        capture = self.media.pop(call_id, None)
        if capture:
            capture.stop(reason)
        self.dialog_tags.pop(call_id, None)


    def save_raw(self, raw, kind):
        if not SAVE_RAW_SIP:
            return None
        filename = (
            LOGDIR
            / f"{stamp()}_{kind}_{uuid.uuid4().hex[:8]}.sip"
        )

        filename.write_bytes(raw)

        os.chmod(filename, 0o600)

        return filename


    def analyse_invite(self, raw):
        body = sip_body(raw)

        path = self.save_raw(raw, "INVITE")

        log("=" * 70)
        if path:
            log(f"INVITE SALVATO: {path.name}")
        else:
            log("INVITE RAW: salvataggio disabilitato")

        fingerprints = entrance_fingerprints(raw)
        log("ENTRANCE META v1: " + json.dumps(
            fingerprints, sort_keys=True, separators=(",", ":")
        ))

        video_lines = re.findall(
            r"(?im)^m=video.*$",
            body
        )

        if video_lines:
            for item in video_lines:
                log(f"VIDEO: {item.strip()}")
        else:
            log("VIDEO: nessuna riga m=video")

        h264 = re.findall(
            r"(?im)^a=rtpmap:.*H264.*$",
            body
        )

        for item in h264:
            log(f"H264: {item.strip()}")

        fmtp = re.findall(
            r"(?im)^a=fmtp:.*$",
            body
        )

        for item in fmtp:
            log(f"FMTP: {item.strip()}")

        crypto = re.findall(
            r"(?im)^a=crypto:.*$",
            body
        )

        if crypto:
            log(
                f"SRTP: presenti {len(crypto)} "
                f"parametri crypto "
                f"({'conservati nel file raw' if path else 'non salvati'})"
            )

        log("=" * 70)


    def handle_request(self, raw):
        first = sip_first_line(raw)

        method = first.split(" ", 1)[0].upper()

        log(f"SIP RX: {method or 'UNKNOWN'}")

        if method == "INVITE":
            if has_obs_fold(raw):
                log("INVITE scartato: header piegato (obs-fold)")
                self.respond_basic(raw, 400, "Bad Request")
                return
            headers, _ = sip_headers(raw)
            call_id = headers.get("call-id", "")
            if (not call_id or "from" not in headers or "to" not in headers
                    or not valid_sip_contact(headers.get("contact", ""))):
                log("INVITE scartato: headers mancanti o Contact non valido")
                self.respond_basic(raw, 400, "Bad Request")
                return
            existing = self.media.get(call_id)
            if (existing is not None and existing.process is not None
                    and existing.process.poll() is None):
                log(f"INVITE duplicato call={call_reference(call_id)}: "
                    "reinvio 183 senza nuova capture")
                to_tag = self.dialog_tags.setdefault(call_id, token(8))
                self.respond_basic(
                    raw, 100, "Trying")
                contact = (
                    f"<sip:{self.username}@{self.local_ip}:{self.local_port}"
                    ";transport=tls>"
                )
                self.respond_basic(raw, 183, "Session Progress", to_tag,
                                   existing.answer_sdp, contact=contact)
                return
            self.media.pop(call_id, None)
            self.analyse_invite(raw)
            self.respond_basic(
                raw,
                100,
                "Trying"
            )
            log("100 Trying inviato")
            try:
                self.start_early_media(raw)
            except Exception as exc:
                log(f"Early media non avviato: {type(exc).__name__}: {exc}")

        elif method == "OPTIONS":
            self.save_raw(raw, "OPTIONS")
            self.respond_basic(
                raw,
                200,
                "OK"
            )

        elif method == "CANCEL":
            self.save_raw(
                raw,
                "CANCEL"
            )

            self.respond_basic(
                raw,
                200,
                "OK"
            )
            self.stop_media_for(raw, "CANCEL ricevuto")

        elif method == "BYE":
            self.save_raw(
                raw,
                "BYE"
            )

            headers, _ = sip_headers(raw)
            call_id = headers.get("call-id", "")
            if call_id not in self.media and call_id not in self.dialog_tags:
                self.respond_basic(
                    raw,
                    481,
                    "Call/Transaction Does Not Exist"
                )
                return
            self.respond_basic(
                raw,
                200,
                "OK"
            )
            self.stop_media_for(raw, "BYE ricevuto")

        elif method in (
            "MESSAGE",
            "NOTIFY",
            "INFO",
        ):
            self.save_raw(
                raw,
                method
            )

            self.respond_basic(
                raw,
                200,
                "OK"
            )

        elif method == "ACK":
            self.save_raw(
                raw,
                "ACK"
            )

        else:
            self.save_raw(
                raw,
                method or "UNKNOWN"
            )


    def loop(self):
        self.connect()
        self.register()

        log(
            "Listener operativo. "
            "In attesa di chiamate..."
        )

        self.keepalive_stop.clear()
        self.link_dead.clear()
        self.keepalive_thread = threading.Thread(
            target=self.keepalive_loop, daemon=True)
        self.keepalive_thread.start()

        try:
            while RUNNING:

                if self.link_dead.is_set():
                    raise ConnectionError("connessione SIP caduta (keepalive)")

                self.maintain_media()

                if time.time() >= self.next_refresh:
                    log("Rinnovo registrazione SIP")
                    # Re-REGISTER sul medesimo socket TLS: nessun buco volontario.
                    self.register()
                    log("Rinnovo completato sulla stessa connessione TLS")

                try:
                    raw = self.stream.read_message(
                        timeout=5
                    )

                except socket.timeout:
                    continue

                if not raw.strip():
                    continue

                first = sip_first_line(raw)

                if first.startswith("SIP/2.0"):
                    log(f"SIP response inattesa: {first}")
                    try:
                        path = self.save_raw(raw, "RESPONSE")
                        log(f"Segnalazione successiva salvata: {path.name}")
                    except Exception as exc:
                        log(f"Impossibile salvare response: {exc}")
                    continue

                self.handle_request(raw)
        finally:
            self.keepalive_stop.set()


    def close(self):
        self.keepalive_stop.set()
        for capture in list(self.media.values()):
            capture.stop("connessione SIP chiusa")
        self.media.clear()
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass

        self.sock = None
        self.stream = None
        self.registered = False


def signal_handler(signum, frame):
    global RUNNING

    RUNNING = False
    log(
        f"Segnale {signum} ricevuto; "
        "arresto listener"
    )


signal.signal(
    signal.SIGTERM,
    signal_handler
)

signal.signal(
    signal.SIGINT,
    signal_handler
)


def main():
    global ENTRANCE_PROFILES
    validate_runtime_settings()
    BASE.mkdir(
        parents=True,
        exist_ok=True
    )

    LOGDIR.mkdir(
        parents=True,
        exist_ok=True
    )
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(LOGDIR, 0o700)
    os.chmod(SNAPSHOT_DIR, 0o700)
    os.chmod(RUNTIME_DIR, 0o700)
    ensure_placeholder_snapshot()
    if ENTRANCE_CLASSIFICATION_ENABLED:
        ENTRANCE_PROFILES = load_entrance_profiles()
        if len(ENTRANCE_PROFILES) < 2:
            raise RuntimeError("classificazione ingressi attiva ma servono almeno due profili")
    snapshot_server = start_snapshot_server()
    start_post_call_fallback(latest_snapshot())

    log("=" * 70)
    log("HOMETOUCH SIP diagnostic listener")
    log(
        f"Server: {SERVER_IP}:{SERVER_PORT}"
    )
    log(
        f"Domain: {DOMAIN}"
    )
    log(f"Pool RTP/RTCP: UDP {MEDIA_PORT_START}-{MEDIA_PORT_END}")
    if MQTT_ENABLED:
        log(f"MQTT: attivo verso {MQTT_HOST}:{MQTT_PORT} topic={MQTT_TOPIC}")
    else:
        log("MQTT: disabilitato")
    if ENTRANCE_CLASSIFICATION_ENABLED:
        log(f"Classificazione ingressi diagnostica: {len(ENTRANCE_PROFILES)} profili, frame={ENTRANCE_CLASSIFICATION_FRAME}")
    log("=" * 70)

    reconnect_delay = max(0.0, RECONNECT_INITIAL_DELAY)

    while RUNNING:

        client = HomtouchListener()
        connected_at = time.monotonic()
        delay = reconnect_delay

        try:
            client.loop()

        except Exception as e:
            connected_for = time.monotonic() - connected_at
            log(
                f"Connessione/listener interrotto: "
                f"{type(e).__name__}: {e}"
            )
            delay = next_reconnect_delay(reconnect_delay, connected_for)
            reconnect_delay = delay

        finally:
            client.close()

        if RUNNING:
            log(f"Riconnessione SIP fra {delay:.2f}s")
            time.sleep(delay)

    snapshot_server.shutdown()
    snapshot_server.server_close()
    stop_post_call_fallback("arresto listener")
    log("Listener terminato")


if __name__ == "__main__":
    main()
