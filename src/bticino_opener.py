#!/usr/bin/env python3
"""Apertura cancellino BTicino HOMETOUCH via SIP MESSAGE (out-of-dialog).

Flusso ricostruito dall'app ufficiale Door Entry for HOMETOUCH 1.9.2
(VctLinphoneService.performActivationAction): due SIP MESSAGE text/plain
verso ``sip:MHT@<sip_domain>`` con payload ``*8*19*<ingresso>##`` e poi
``*8*20*<ingresso>##`` (CID 2009: ``*8*21`` / ``*8*22``).

Uso come modulo (dal listener, connessione TLS dedicata) o da CLI per test.
Non stampa mai password o chiavi nei log.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import socket
import ssl
import sys
import time
import uuid
from pathlib import Path


def load_config(path=None):
    path = Path(path or os.environ.get(
        "BTICINO_SNIFFER_CONFIG", "/opt/bticino-sniffer/config.json"
    ))
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


CONFIG = load_config()

BASE_OPTS = ("sip_server", "sip_domain")
USER_AGENT = "HOMETOUCH-Opener/1.0"


def _creds_paths():
    return (
        Path(CONFIG.get("credentials_file", "")),
        Path(CONFIG.get("certificate_file", "")),
        Path(CONFIG.get("private_key_file", "")),
        Path(CONFIG.get("ca_file", "")),
    )


def load_credentials():
    creds_file, _, _, _ = _creds_paths()
    data = json.loads(creds_file.read_text(encoding="utf-8"))
    account = data.get("SipAccount") or data.get("sipAccount")
    password = data.get("SipPassword") or data.get("sipPassword")
    if not account or not password:
        raise RuntimeError("account/password SIP assenti in credentials_file")
    account = account.removeprefix("sip:")
    return account.split("@", 1)[0], account, password


def make_tls_context():
    _, cert_file, key_file, ca_file = _creds_paths()
    ctx = ssl.create_default_context(cafile=str(ca_file))
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    return ctx


def opener_settings():
    raw = CONFIG.get("opener", {})
    opts = raw if isinstance(raw, dict) else {}
    entrance = str(opts.get("entrance", "4")).strip() or "4"
    if not re.fullmatch(r"[0-9A-Za-z_-]{1,16}", entrance):
        raise ValueError("opener.entrance non valido")
    cid = opts.get("cid", 0)
    try:
        cid = int(cid)
    except (TypeError, ValueError):
        raise ValueError("opener.cid deve essere un intero")
    domain = CONFIG.get("sip_domain", "")
    dest = str(opts.get("destination", "") or "").strip()
    if not dest:
        if not domain:
            raise RuntimeError("sip_domain mancante per il destinatario MHT")
        dest = f"sip:MHT@{domain}"
    if int(cid) == 2009:
        pair = ("*8*21", "*8*22")
    else:
        pair = ("*8*19", "*8*20")
    frames = [f"{pair[0]}*{entrance}##", f"{pair[1]}*{entrance}##"]
    return {
        "enabled": bool(opts.get("enabled", False)),
        "entrance": entrance,
        "cid": int(cid),
        "destination": dest,
        "frames": frames,
        "timeout": float(opts.get("timeout", 10.0)),
    }


def _md5(text):
    import hashlib
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def _token(n=8):
    return secrets.token_hex(n)


def parse_digest_challenge(value):
    params = {}
    if value.lower().startswith("digest "):
        value = value[7:]
    for match in re.finditer(r'(\w+)=("([^"]*)"|([^,\s]+))', value):
        params[match.group(1).lower()] = match.group(3) or match.group(4) or ""
    return params


def digest_authorization(username, password, method, uri, challenge, nc="00000001"):
    realm = challenge["realm"]
    nonce = challenge["nonce"]
    qop_raw = challenge.get("qop", "")
    opaque = challenge.get("opaque", "")
    ha1 = _md5(f"{username}:{realm}:{password}")
    ha2 = _md5(f"{method}:{uri}")
    parts = [f'username="{username}"', f'realm="{realm}"',
             f'nonce="{nonce}"', f'uri="{uri}"']
    if qop_raw:
        qops = [x.strip() for x in qop_raw.split(",")]
        qop = "auth" if "auth" in qops else qops[0]
        cnonce = _token(8)
        resp = _md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
        parts += [f'response="{resp}"', "algorithm=MD5",
                  f"qop={qop}", f"nc={nc}", f'cnonce="{cnonce}"']
    else:
        parts += [f'response="{_md5(f"{ha1}:{nonce}:{ha2}")}"', "algorithm=MD5"]
    if opaque:
        parts.append(f'opaque="{opaque}"')
    return "Digest " + ", ".join(parts)


class SipChannel:
    """Connessione TLS dedicata per l'invio dei MESSAGE."""

    def __init__(self, timeout=10.0):
        self.timeout = max(2.0, timeout)
        self.sock = None
        self.buf = b""
        self.local_ip = ""
        self.local_port = 0
        self.username, self.account, self.password = load_credentials()
        self.server = CONFIG.get("sip_server", "")
        self.port = int(CONFIG.get("sip_port", 5061))
        self.domain = CONFIG.get("sip_domain", "")
        if not self.server or not self.domain:
            raise RuntimeError("sip_server/sip_domain mancanti in config")

    def connect(self):
        raw = socket.create_connection((self.server, self.port), timeout=15)
        self.sock = make_tls_context().wrap_socket(raw, server_hostname=self.domain)
        self.sock.settimeout(self.timeout)
        self.local_ip, self.local_port = self.sock.getsockname()[:2]

    def close(self):
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        self.sock = None

    def _read_message(self):
        deadline = time.time() + self.timeout
        while b"\r\n\r\n" not in self.buf:
            if time.time() > deadline:
                raise TimeoutError("timeout risposta SIP")
            chunk = self.sock.recv(16384)
            if not chunk:
                raise ConnectionError("connessione SIP chiusa")
            self.buf += chunk
        head_end = self.buf.index(b"\r\n\r\n") + 4
        import re as _re
        m = _re.search(r"(?im)^Content-Length\s*:\s*(\d+)\s*$",
                       self.buf[:head_end].decode("utf-8", "replace"))
        total = head_end + (int(m.group(1)) if m else 0)
        while len(self.buf) < total:
            if time.time() > deadline:
                raise TimeoutError("timeout body SIP")
            chunk = self.sock.recv(16384)
            if not chunk:
                raise ConnectionError("connessione SIP chiusa durante body")
            self.buf += chunk
        raw = self.buf[:total]
        self.buf = self.buf[total:]
        return raw

    def build_message(self, dest_uri, body, call_id, cseq, auth=None,
                      auth_header="Authorization"):
        identity = f"sip:{self.username}@{self.domain}"
        lines = [
            f"MESSAGE {dest_uri} SIP/2.0",
            (f"Via: SIP/2.0/TLS {self.local_ip}:{self.local_port};"
             f"branch=z9hG4bK{_token(8)};rport"),
            "Max-Forwards: 70",
            f"From: <{identity}>;tag={_token(8)}",
            f"To: <{dest_uri}>",
            f"Call-ID: {call_id}",
            f"CSeq: {cseq} MESSAGE",
            f"User-Agent: {USER_AGENT}",
        ]
        if auth:
            lines.append(f"{auth_header}: {auth}")
        payload = body.encode("utf-8")
        lines += ["Content-Type: text/plain",
                  f"Content-Length: {len(payload)}", "", ""]
        return "\r\n".join(lines).encode("utf-8") + payload

    @staticmethod
    def _status(raw):
        first = raw.split(b"\r\n", 1)[0].decode("utf-8", "replace")
        m = re.match(r"SIP/2\.0\s+(\d+)", first)
        return int(m.group(1)) if m else None

    def send_text(self, dest_uri, body, debug=False):
        call_id = f"{uuid.uuid4().hex}@hometouch-opener"
        cseq = 1
        self.sock.sendall(self.build_message(dest_uri, body, call_id, cseq))
        deadline = time.time() + self.timeout
        auth_rounds = 0
        nc = 0
        provisionals = []
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                detail = f"timeout senza risposta finale (provvisorie: {provisionals or 'nessuna'})"
                raise TimeoutError(detail)
            old_timeout = self.sock.gettimeout()
            self.sock.settimeout(max(1.0, remaining))
            try:
                raw = self._read_message()
            except (socket.timeout, TimeoutError):
                raise TimeoutError(
                    f"timeout senza risposta finale (provvisorie: {provisionals or 'nessuna'})")
            finally:
                self.sock.settimeout(old_timeout)
            code = self._status(raw)
            first = raw.split(b"\r\n", 1)[0].decode("utf-8", "replace")
            if code is None:
                continue
            if 100 <= code < 200:
                provisionals.append(first)
                continue
            if code in (401, 407) and auth_rounds < 2:
                text = raw.decode("utf-8", "replace")
                m = re.search(r"(?im)^(?:www|proxy)-authenticate\s*:\s*(.+)\s*$", text)
                if not m:
                    raise RuntimeError(f"MESSAGE rifiutato ({code}) senza challenge")
                challenge = parse_digest_challenge(m.group(1).strip())
                if debug:
                    safe = {k: ("<presente>" if k in ("nonce", "opaque") else v)
                            for k, v in challenge.items()}
                    print(f"DEBUG challenge {code}: {safe}")
                    print(f"DEBUG auth user={self.username} method=MESSAGE uri={dest_uri}")
                algo = challenge.get("algorithm", "MD5")
                if algo.upper() != "MD5":
                    raise RuntimeError(
                        f"Digest algorithm non supportato: {algo} (serve verifica)")
                stale = challenge.get("stale", "").lower() == "true"
                if auth_rounds > 0 and not stale:
                    return code, first
                auth_rounds += 1
                nc += 1
                auth = digest_authorization(
                    self.username, self.password, "MESSAGE", dest_uri,
                    challenge, nc=f"{nc:08d}")
                # RFC 3261: 401 -> Authorization, 407 -> Proxy-Authorization
                header = "Proxy-Authorization" if code == 407 else "Authorization"
                cseq += 1
                self.sock.sendall(self.build_message(
                    dest_uri, body, call_id, cseq, auth, header))
                continue
            return code, first


def open_gate(dry_run=False, debug=False, entrance=None, cid=None, frames=None):
    """Invia i due frame di apertura. Ritorna (ok, dettaglio)."""
    settings = opener_settings()
    if entrance:
        entrance = str(entrance).strip()
        if not re.fullmatch(r"[0-9A-Za-z_-]{1,16}", entrance):
            raise ValueError("entrance non valido")
        settings["entrance"] = entrance
    if cid is not None:
        settings["cid"] = int(cid)
    if frames:
        settings["frames"] = list(frames)
    elif entrance is not None or cid is not None:
        pair = ("*8*21", "*8*22") if int(settings["cid"]) == 2009 else ("*8*19", "*8*20")
        settings["frames"] = [f"{pair[0]}*{settings['entrance']}##",
                               f"{pair[1]}*{settings['entrance']}##"]
    if not settings["enabled"] and not dry_run:
        return False, "opener disabilitato in config (opener.enabled)"
    if dry_run:
        return True, "DRY-RUN dest={} frames={}".format(
            settings["destination"], " ".join(settings["frames"]))
    channel = SipChannel(timeout=settings["timeout"])
    try:
        channel.connect()
        results = []
        for frame in settings["frames"]:
            code, first = channel.send_text(settings["destination"], frame,
                                            debug=debug)
            results.append(f"{frame}->{code}")
            if code not in (200, 202):
                return False, "; ".join(results) + f" (ultima: {first})"
            time.sleep(0.3)
        return True, "; ".join(results)
    finally:
        channel.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=None,
                        help="config.json (default $BTICINO_SNIFFER_CONFIG)")
    parser.add_argument("--dry-run", action="store_true",
                        help="mostra destinatario e frame senza inviare")
    parser.add_argument("--yes", action="store_true",
                        help="conferma invio reale (cancello fisico!)")
    parser.add_argument("--debug", action="store_true",
                        help="mostra challenge/auth senza segreti")
    parser.add_argument("--entrance", default=None,
                        help="ingresso/where (default da config)")
    parser.add_argument("--cid", type=int, default=None,
                        help="tipo posto esterno: 2009 usa *8*21/*8*22")
    parser.add_argument("--frames", default=None,
                        help="frame manuali separati da virgola")
    parser.add_argument("--probe", default=None,
                        help="prova ingressi (es. 1,2,3,4,5,20), chiede conferma a ogni passo")
    args = parser.parse_args(argv)
    global CONFIG
    if args.config:
        os.environ["BTICINO_SNIFFER_CONFIG"] = str(args.config)
        CONFIG = load_config(str(args.config))
    if not args.dry_run and not args.yes and not args.probe:
        print("Azione fisica sul cancellino: ripetere con --yes per inviare, "
              "oppure --dry-run per anteprima.")
        return 2
    if args.probe:
        entrances = [e.strip() for e in args.probe.split(",") if e.strip()]
        for entrance in entrances:
            try:
                ok, detail = open_gate(dry_run=False, debug=args.debug,
                                       entrance=entrance, cid=args.cid)
            except Exception as exc:
                print(f"entrance={entrance} OPEN_FAIL {type(exc).__name__}: {exc}")
                continue
            print(f"entrance={entrance} OPEN_{'OK' if ok else 'FAIL'} {detail}")
            if ok:
                try:
                    ans = input("Si e' aperto il cancellino? [y/N] ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print("\nProbe interrotta.")
                    return 3
                if ans in ("y", "yes", "s", "si"):
                    print(f"INGRESSO TROVATO: entrance={entrance}. "
                          f"Salvalo in config.json (opener.entrance).")
                    return 0
        print("Probe completata, nessun ingresso ha aperto. "
              "Provare altra coppia con --cid 2009 o frame manuali.")
        return 1
    frames = None
    if args.frames:
        frames = [f.strip() for f in args.frames.split(",") if f.strip()]
    try:
        ok, detail = open_gate(dry_run=args.dry_run, debug=args.debug,
                               entrance=args.entrance, cid=args.cid,
                               frames=frames)
    except Exception as exc:
        print(f"OPEN_FAIL {type(exc).__name__}: {exc}")
        return 1
    print(f"OPEN_{'OK' if ok else 'FAIL'} {detail}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
