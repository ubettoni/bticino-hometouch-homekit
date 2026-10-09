import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch


SRC = Path(__file__).parents[1] / "src"
OPENER_SPEC = importlib.util.spec_from_file_location(
    "bticino_opener", SRC / "bticino_opener.py")
OPENER = importlib.util.module_from_spec(OPENER_SPEC)
OPENER_SPEC.loader.exec_module(OPENER)

LISTENER_SPEC = importlib.util.spec_from_file_location(
    "bticino_listener_mqtt", SRC / "bticino_hometouch_listener.py")
LISTENER = importlib.util.module_from_spec(LISTENER_SPEC)
LISTENER_SPEC.loader.exec_module(LISTENER)


def opener_config(**overrides):
    base = {
        "sip_server": "198.51.100.10",
        "sip_port": 5061,
        "sip_domain": "gw-test.bs.iotleg.com",
        "opener": {"enabled": True, "entrance": "4", "cid": 0, "timeout": 10.0},
    }
    base["opener"].update(overrides.pop("opener", {}))
    base.update(overrides)
    return base


class OpenerFrameTests(unittest.TestCase):
    def settings(self, **overrides):
        with patch.object(OPENER, "CONFIG", opener_config(**overrides)):
            return OPENER.opener_settings()

    def test_default_frames_match_official_app(self):
        settings = self.settings()
        self.assertEqual(settings["destination"], "sip:MHT@gw-test.bs.iotleg.com")
        self.assertEqual(settings["frames"], ["*8*19*4##", "*8*20*4##"])

    def test_entrance_selects_where(self):
        settings = self.settings(opener={"entrance": "2"})
        self.assertEqual(settings["frames"], ["*8*19*2##", "*8*20*2##"])

    def test_cid_2009_selects_alternate_pair(self):
        settings = self.settings(opener={"cid": 2009})
        self.assertEqual(settings["frames"], ["*8*21*4##", "*8*22*4##"])

    def test_explicit_destination_wins(self):
        settings = self.settings(opener={"destination": "sip:MHT@other.example"})
        self.assertEqual(settings["destination"], "sip:MHT@other.example")

    def test_disabled_by_default(self):
        with patch.object(OPENER, "CONFIG", {"sip_domain": "gw-test.bs.iotleg.com"}):
            self.assertFalse(OPENER.opener_settings()["enabled"])

    def test_invalid_entrance_rejected(self):
        with patch.object(OPENER, "CONFIG", opener_config(opener={"entrance": "a/b"})):
            with self.assertRaises(ValueError):
                OPENER.opener_settings()

    def test_open_gate_refuses_when_disabled(self):
        with patch.object(OPENER, "CONFIG", opener_config(opener={"enabled": False})):
            ok, detail = OPENER.open_gate(dry_run=False)
            self.assertFalse(ok)
            self.assertIn("disabilitato", detail)


class OpenerDigestTests(unittest.TestCase):
    RFC_CHALLENGE = {
        "realm": "testrealm@host.com",
        "nonce": "dcd98b7102dd2f0e8b11d0f600bfb0c093",
        "opaque": "5ccc069c403ebaf9f0171e9517f40e41",
        "algorithm": "MD5",
        "qop": "auth",
    }

    def test_rfc2617_vector(self):
        with patch.object(OPENER, "_token", return_value="0a4f113b"):
            value = OPENER.digest_authorization(
                "Mufasa", "Circle Of Life", "GET", "/dir/index.html",
                dict(self.RFC_CHALLENGE), nc="00000001")
        self.assertIn('response="6629fae49393a05397450978507c4ef1"', value)
        self.assertIn('opaque="5ccc069c403ebaf9f0171e9517f40e41"', value)
        self.assertIn("qop=auth", value)
        self.assertIn("nc=00000001", value)

    def test_no_qop_omits_nonce_count(self):
        challenge = {"realm": "r", "nonce": "n"}
        with patch.object(OPENER, "_token", return_value="x"):
            value = OPENER.digest_authorization("u", "p", "MESSAGE", "sip:x@y", challenge)
        self.assertNotIn("qop=", value)
        self.assertNotIn("cnonce=", value)
        self.assertIn('response="', value)

    def test_challenge_parsing(self):
        raw = ('Digest realm="2090692.bs.iotleg.com", nonce="abc123", '
               'opaque="def456", algorithm=MD5, qop="auth"')
        parsed = OPENER.parse_digest_challenge(raw)
        self.assertEqual(parsed["realm"], "2090692.bs.iotleg.com")
        self.assertEqual(parsed["nonce"], "abc123")
        self.assertEqual(parsed["opaque"], "def456")
        self.assertEqual(parsed["algorithm"], "MD5")
        self.assertEqual(parsed["qop"], "auth")


class MqttEncodingTests(unittest.TestCase):
    def test_remaining_length_boundaries(self):
        self.assertEqual(LISTENER._mqtt_encode_remaining_length(0), b"\x00")
        self.assertEqual(LISTENER._mqtt_encode_remaining_length(127), b"\x7f")
        self.assertEqual(LISTENER._mqtt_encode_remaining_length(128), b"\x80\x01")
        self.assertEqual(LISTENER._mqtt_encode_remaining_length(321), b"\xc1\x02")

    def test_remaining_length_rejects_overflow(self):
        with self.assertRaises(ValueError):
            LISTENER._mqtt_encode_remaining_length(268435456)

    def test_pack_str(self):
        self.assertEqual(LISTENER._mqtt_pack_str("test"), b"\x00\x04test")

    def test_mqtt_disabled_by_default(self):
        self.assertFalse(LISTENER.MQTT_ENABLED)

    def test_publish_event_payload(self):
        import json
        import secrets
        sent = {}

        def fake_publish(topic, payload, retain=False):
            sent["topic"] = topic
            sent["payload"] = json.loads(payload.decode())
            sent["retain"] = retain

        LISTENER.DIAGNOSTIC_KEY = secrets.token_bytes(32)
        with patch.object(LISTENER, "MQTT_ENABLED", True), \
             patch.object(LISTENER, "MQTT_TOPIC", "t/ring"), \
             patch.object(LISTENER, "_mqtt_publish_once", fake_publish), \
             patch.object(LISTENER, "log", lambda *a: None):
            LISTENER.publish_mqtt_event("call-1", "snapshot_ready")
        self.assertEqual(sent["topic"], "t/ring")
        self.assertEqual(sent["payload"]["event"], "snapshot_ready")
        self.assertEqual(sent["payload"]["call"],
                         LISTENER.call_reference("call-1"))


if __name__ == "__main__":
    unittest.main()
