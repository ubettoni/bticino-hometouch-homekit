#!/usr/bin/env python3
"""Validate a private listener configuration without printing its contents."""

import argparse
import json
import os
import shutil
from pathlib import Path


REQUIRED_TEXT = (
    "sip_server",
    "sip_domain",
    "credentials_file",
    "certificate_file",
    "private_key_file",
    "ca_file",
)
PLACEHOLDERS = ("example.invalid", "192.0.2.", "/path/to/")


def resolve_executable(value, name):
    if value:
        candidate = Path(value).expanduser()
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
        raise ValueError(f"{name} non eseguibile")
    if shutil.which(name):
        return Path(shutil.which(name))
    raise ValueError(f"{name} non trovato")


def validate(path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("config.json assente, illeggibile o non valido") from exc
    if not isinstance(data, dict):
        raise ValueError("config.json deve contenere un oggetto JSON")

    for key in REQUIRED_TEXT:
        value = data.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"campo obbligatorio mancante: {key}")
        if any(marker in value for marker in PLACEHOLDERS):
            raise ValueError(f"sostituire il valore di esempio: {key}")

    port = data.get("sip_port", 5061)
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("sip_port deve essere compreso tra 1 e 65535")

    media_ip = str(data.get("media_ip", "") or "").strip()
    if media_ip:
        import ipaddress
        import re as _re
        try:
            ipaddress.ip_address(media_ip)
        except ValueError:
            if not _re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?",
                                 media_ip):
                raise ValueError("media_ip non valido") from None
    ports = str(data.get("media_ports", "") or "").strip() or "2202-2213"
    import re as _re2
    _m = _re2.fullmatch(r"(\d{1,5})\s*-\s*(\d{1,5})", ports)
    if not _m:
        raise ValueError("media_ports deve essere 'START-END' (es. 2202-2203)")
    _s, _e = int(_m.group(1)), int(_m.group(2))
    if not 1 <= _s <= 65535 or not 1 <= _e <= 65535:
        raise ValueError("media_ports fuori range 1-65535")
    if _s % 2 != 0 or _e <= _s:
        raise ValueError("media_ports: START pari e minore di END")

    for key in ("credentials_file", "certificate_file", "private_key_file", "ca_file"):
        if not Path(data[key]).expanduser().is_file():
            raise ValueError(f"file richiesto non trovato: {key}")

    try:
        credentials = json.loads(
            Path(data["credentials_file"]).expanduser().read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("credentials_file illeggibile o non valido") from exc
    account = credentials.get("SipAccount") or credentials.get("sip_account")
    password = (
        credentials.get("SipPassword")
        or credentials.get("Password")
        or credentials.get("sip_password")
    )
    if not account or not password:
        raise ValueError("credentials_file non contiene account e password SIP")

    resolve_executable(data.get("ffmpeg"), "ffmpeg")
    resolve_executable(data.get("openssl"), "openssl")
    opener = data.get("opener", {})
    if opener and not isinstance(opener, dict):
        raise ValueError("opener deve essere un oggetto")
    if isinstance(opener, dict) and opener.get("enabled", False):
        entrance = str(opener.get("entrance", "") or "").strip()
        if not entrance:
            raise ValueError("opener.entrance mancante (es. 4)")
        try:
            int(opener.get("cid", 0))
        except (TypeError, ValueError):
            raise ValueError("opener.cid deve essere un intero")
        timeout = opener.get("timeout", 10.0)
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("opener.timeout deve essere positivo")
    bind = str(data.get("http_bind", "127.0.0.1") or "127.0.0.1").strip()
    if bind not in ("127.0.0.1", "::1", "localhost"):
        token = ""
        if isinstance(opener, dict):
            token = str(opener.get("token", "") or "")
        if not token:
            raise ValueError("http_bind su LAN richiede opener.token")
    mqtt = data.get("mqtt", {})
    if mqtt and not isinstance(mqtt, dict):
        raise ValueError("mqtt deve essere un oggetto")
    if isinstance(mqtt, dict) and mqtt.get("enabled", False):
        host = mqtt.get("host", "")
        if not isinstance(host, str) or not host.strip():
            raise ValueError("mqtt.host mancante (broker MQTT)")
        if any(marker in host for marker in PLACEHOLDERS):
            raise ValueError("sostituire il valore di esempio: mqtt.host")
        port = mqtt.get("port", 1883)
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("mqtt.port deve essere compreso tra 1 e 65535")
        topic = mqtt.get("topic", "")
        if not isinstance(topic, str) or not topic.strip():
            raise ValueError("mqtt.topic mancante")
        password_file = mqtt.get("password_file", "")
        if isinstance(password_file, str) and password_file.strip():
            if any(marker in password_file for marker in PLACEHOLDERS):
                raise ValueError("sostituire il valore di esempio: mqtt.password_file")
            if not Path(password_file).expanduser().is_file():
                raise ValueError("file richiesto non trovato: mqtt.password_file")
            if mqtt.get("username", "") in (None, ""):
                raise ValueError("mqtt.username richiesto con password_file")
    classification = data.get("entrance_classification", {})
    if classification and not isinstance(classification, dict):
        raise ValueError("entrance_classification deve essere un oggetto")
    if classification.get("enabled", False):
        profiles = classification.get("profiles")
        if not isinstance(profiles, dict) or len(profiles) < 2:
            raise ValueError("servono almeno due profili visivi degli ingressi")
        for name, images in profiles.items():
            if not isinstance(name, str) or not name.strip():
                raise ValueError("nome profilo ingresso non valido")
            if isinstance(images, str):
                images = [images]
            if not isinstance(images, list) or not images:
                raise ValueError(f"profilo ingresso privo di immagini: {name}")
            if any(not isinstance(image, str) or not Path(image).expanduser().is_file()
                   for image in images):
                raise ValueError(f"immagine privata non trovata per il profilo: {name}")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args()
    try:
        validate(args.config.expanduser())
    except ValueError as exc:
        raise SystemExit(f"Configurazione non valida: {exc}")
    print("CONFIG_OK (contenuto privato non mostrato)")


if __name__ == "__main__":
    main()
