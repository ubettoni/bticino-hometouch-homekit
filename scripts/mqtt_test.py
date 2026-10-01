#!/usr/bin/env python3
"""Test minimo di publish MQTT QoS0 (stdlib only, MQTT 3.1.1)."""
import argparse
import socket
import ssl
import sys
import uuid
from pathlib import Path


def encode_remaining_length(length):
    if length < 0 or length > 268435455:
        raise ValueError("lunghezza non valida")
    out = bytearray()
    while True:
        digit = length % 128
        length //= 128
        if length > 0:
            digit |= 0x80
        out.append(digit)
        if length == 0:
            break
    return bytes(out)


def pack_str(value):
    raw = value.encode("utf-8")
    if len(raw) > 0xFFFF:
        raise ValueError("stringa troppo lunga")
    return len(raw).to_bytes(2, "big") + raw


def read_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("connessione chiusa dal broker")
        data += chunk
    return data


def publish_once(host, port, topic, payload, client_id="mqtt-test",
                 username=None, password=None, use_tls=False, retain=False,
                 timeout=5.0):
    raw = socket.create_connection((host, port), timeout=timeout)
    sock = raw
    try:
        sock.settimeout(timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        cid = (client_id or f"test-{uuid.uuid4().hex[:8]}")[:23]
        flags = 0x02
        if username:
            flags |= 0x80
        if password is not None:
            if not username:
                raise ValueError("password senza username")
            flags |= 0x40
        body = pack_str("MQTT") + bytes((0x04, flags, 0x00, 0x3C)) + pack_str(cid)
        if username:
            body += pack_str(username)
        if password is not None:
            body += pack_str(password)
        sock.sendall(b"\x10" + encode_remaining_length(len(body)) + body)
        resp = read_exact(sock, 4)
        if resp[0] != 0x20 or resp[1] != 0x02 or resp[3] != 0x00:
            raise RuntimeError(f"CONNACK rifiutato rc={resp[3]}")
        t = topic.encode("utf-8")
        pbody = len(t).to_bytes(2, "big") + t + payload
        fixed = 0x30 | (0x01 if retain else 0x00)
        sock.sendall(bytes((fixed,)) + encode_remaining_length(len(pbody)) + pbody)
        try:
            sock.sendall(b"\xe0\x00")
        except OSError:
            pass
    finally:
        try:
            sock.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--topic", default="bticino/citofono/ring")
    ap.add_argument("--message", default='{"event":"test"}')
    ap.add_argument("--client-id", default="bticino-mqtt-test")
    ap.add_argument("--username", default="")
    ap.add_argument("--password", default=None)
    ap.add_argument("--password-file", default="")
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--retain", action="store_true")
    ap.add_argument("--timeout", type=float, default=5.0)
    a = ap.parse_args()

    password = a.password
    if a.password_file.strip():
        password = Path(a.password_file).expanduser().read_text(encoding="utf-8").strip() or None
    username = a.username.strip() or None

    try:
        publish_once(a.host, a.port, a.topic, a.message.encode("utf-8"),
                     client_id=a.client_id, username=username, password=password,
                     use_tls=a.tls, retain=a.retain, timeout=max(1.0, a.timeout))
    except Exception as exc:
        print(f"MQTT_FAIL {type(exc).__name__}: {exc}")
        return 1
    print(f"MQTT_OK host={a.host}:{a.port} topic={a.topic} bytes={len(a.message.encode())}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
