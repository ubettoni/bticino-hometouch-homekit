import importlib.util
import time
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


class CaptureInitTests(unittest.TestCase):
    def test_constructor_sets_all_runtime_attrs(self):
        capture = MODULE.EarlyMediaCapture(
            "call-test", "127.0.0.1", 2202, 22202, "96", "", "a2V5",
            "1", [("video", "RTP/SAVP", ["96"])], None,
            "192.0.2.1", 5000, 5001)
        for attr in ("sdp_path", "snapshot", "classification_path",
                     "relay_sockets", "audio_sockets", "stderr_lines",
                     "stderr_thread", "auth_key", "media_ssrc",
                     "feedback_attempts", "srtcp_index", "snapshot_reported"):
            self.assertTrue(hasattr(capture, attr), attr)
        self.assertTrue(callable(capture._drain_stderr))
        self.assertTrue(callable(capture.get_stderr_tail))
        self.assertEqual(capture.get_stderr_tail(), "")


class DoorbellDelayTests(unittest.TestCase):
    def test_immediate_by_default(self):
        fired = []
        with patch.object(MODULE, "ring_homekit_doorbell",
                          lambda: fired.append(1)), \
             patch.object(MODULE, "publish_mqtt_ring",
                          lambda call_id: fired.append("mqtt")), \
             patch.object(MODULE, "DOORBELL_SNAPSHOT_TIMEOUT", 0.0):
            MODULE.notify_incoming_call("cid", Path("/nonexistent.jpg"), 0.0)
            time.sleep(0.3)
        self.assertIn(1, fired)

    def test_delayed_until_snapshot_exists(self):
        import tempfile
        import time as time_mod
        with tempfile.TemporaryDirectory() as tmp:
            shot = Path(tmp) / "shot.jpg"
            fired = []
            with patch.object(MODULE, "ring_homekit_doorbell",
                              lambda: fired.append(1)), \
                 patch.object(MODULE, "publish_mqtt_ring",
                              lambda call_id: None):
                MODULE.notify_incoming_call("cid", shot, time_mod.time() - 1,
                                            doorbell_timeout=5.0)
                time.sleep(0.3)
                self.assertEqual(fired, [])
                shot.write_bytes(b"\xff\xd8" + bytes(100))
                time.sleep(1.0)
            self.assertEqual(fired, [1])

    def test_delayed_fires_on_timeout(self):
        fired = []
        with patch.object(MODULE, "ring_homekit_doorbell",
                          lambda: fired.append(1)), \
             patch.object(MODULE, "publish_mqtt_ring",
                          lambda call_id: None):
            MODULE.notify_incoming_call("cid", Path("/nonexistent.jpg"), 0.0,
                                        doorbell_timeout=0.2)
            time.sleep(1.0)
        self.assertEqual(fired, [1])


if __name__ == "__main__":
    unittest.main()
