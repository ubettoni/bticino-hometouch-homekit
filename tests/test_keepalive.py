import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch


SRC = Path(__file__).parents[1] / "src"
SPEC = importlib.util.spec_from_file_location(
    "bticino_keepalive", SRC / "bticino_hometouch_listener.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FakeSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)

    def settimeout(self, timeout):
        pass

    def recv(self, size):
        if not self.chunks:
            raise TimeoutError("no more data")
        return self.chunks.pop(0)


class KeepaliveTests(unittest.TestCase):
    def test_inbound_crlf_pings_are_skipped(self):
        stream = MODULE.SIPStream.__new__(MODULE.SIPStream)
        stream.sock = FakeSocket([
            b"\r\n\r\n",
            b"OPTIONS sip:x SIP/2.0\r\nContent-Length: 0\r\n\r\n",
        ])
        stream.buffer = b""
        raw = stream.read_message(timeout=5)
        self.assertTrue(raw.startswith(b"OPTIONS"))

    def test_leading_crlf_before_message_ignored(self):
        stream = MODULE.SIPStream.__new__(MODULE.SIPStream)
        stream.sock = FakeSocket([
            b"\r\nINVITE sip:x SIP/2.0\r\nContent-Length: 0\r\n\r\n",
        ])
        stream.buffer = b""
        raw = stream.read_message(timeout=5)
        self.assertTrue(raw.startswith(b"INVITE"))

    def test_empty_socket_raises(self):
        stream = MODULE.SIPStream.__new__(MODULE.SIPStream)
        stream.sock = FakeSocket([b""])
        stream.buffer = b""
        with self.assertRaises(ConnectionError):
            stream.read_message(timeout=5)


class InstanceUuidTests(unittest.TestCase):
    def test_stable_across_calls(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sip-instance.uuid"
            with patch.object(MODULE, "SIP_INSTANCE_FILE", path):
                with patch.object(MODULE, "RUNTIME_DIR", Path(directory)):
                    first = MODULE.sip_instance_uuid()
                    second = MODULE.sip_instance_uuid()
        self.assertEqual(first, second)
        import uuid
        uuid.UUID(first)

    def test_invalid_file_regenerated(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sip-instance.uuid"
            path.write_text("not-a-uuid\n", encoding="utf-8")
            with patch.object(MODULE, "SIP_INSTANCE_FILE", path):
                with patch.object(MODULE, "RUNTIME_DIR", Path(directory)):
                    value = MODULE.sip_instance_uuid()
        import uuid
        uuid.UUID(value)
        self.assertNotEqual(value, "not-a-uuid")


class MediaPortsTests(unittest.TestCase):
    def test_default_range(self):
        self.assertEqual(MODULE.parse_media_ports(None), (2202, 2213))
        self.assertEqual(MODULE.parse_media_ports(""), (2202, 2213))

    def test_single_pair(self):
        self.assertEqual(MODULE.parse_media_ports("2202-2203"), (2202, 2203))

    def test_rejects_odd_start(self):
        with self.assertRaises(ValueError):
            MODULE.parse_media_ports("2203-2204")

    def test_rejects_inverted(self):
        with self.assertRaises(ValueError):
            MODULE.parse_media_ports("2212-2202")

    def test_rejects_garbage(self):
        with self.assertRaises(ValueError):
            MODULE.parse_media_ports("2202")


if __name__ == "__main__":
    unittest.main()
