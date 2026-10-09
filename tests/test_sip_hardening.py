import base64
import importlib.util
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch


SRC = Path(__file__).parents[1] / "src"
SPEC = importlib.util.spec_from_file_location(
    "bticino_hardening", SRC / "bticino_hometouch_listener.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

CRYPTO_KEY = base64.b64encode(bytes(30)).decode("ascii")

SDP_VIDEO = (
    "v=0\r\n"
    "o=MHT 1 1 IN IP4 127.0.0.1\r\n"
    "s=Talk\r\n"
    "c=IN IP4 198.51.100.7\r\n"
    "t=0 0\r\n"
    "m=video 5004 RTP/SAVP 96\r\n"
    "a=rtpmap:96 H264/90000\r\n"
    f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{CRYPTO_KEY}\r\n"
)

SDP_AUDIO = (
    "m=audio 5006 RTP/SAVP 0\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{CRYPTO_KEY}\r\n"
)


def make_invite(call_id="cid-test-1", contact="sip:MHT@198.51.100.7",
                sdp=None, fold=False):
    headers = [
        "INVITE sip:user@example.test SIP/2.0",
        "Via: SIP/2.0/TLS 198.51.100.7:5061;branch=z9hG4bKabc",
        "From: <sip:MHT@example.test>;tag=from1",
        "To: <sip:user@example.test>",
        f"Call-ID: {call_id}",
        "CSeq: 20 INVITE",
        f"Contact: <{contact}>",
    ]
    if fold:
        headers.insert(3, " X-Folded: continued")
    body = (sdp if sdp is not None else SDP_VIDEO).encode("utf-8")
    head = "\r\n".join(headers) + "\r\n"
    head += f"Content-Length: {len(body)}\r\n\r\n"
    return head.encode("utf-8") + body


def make_listener(tmpdir):
    import secrets
    creds = Path(tmpdir) / "creds.json"
    creds.write_text(json.dumps({"SipAccount": "u@example.test",
                                 "SipPassword": "p"}))
    runtime = Path(tmpdir) / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    # Evita qualsiasi scrittura fuori tmpdir (chiave diagnostica in memoria).
    MODULE.DIAGNOSTIC_KEY = secrets.token_bytes(32)
    with patch.object(MODULE, "CREDS_FILE", creds), \
         patch.object(MODULE, "RUNTIME_DIR", runtime), \
         patch.object(MODULE, "SIP_INSTANCE_FILE", runtime / "i.uuid"), \
         patch.object(MODULE, "log", lambda *a: None):
        listener = MODULE.HomtouchListener()
    return listener


class HelperTests(unittest.TestCase):
    def test_valid_contact(self):
        self.assertTrue(MODULE.valid_sip_contact("<sip:x@y:5061;transport=tls>"))
        self.assertTrue(MODULE.valid_sip_contact("sips:x@y"))
        self.assertFalse(MODULE.valid_sip_contact("<http://evil>"))
        self.assertFalse(MODULE.valid_sip_contact(""))

    def test_obs_fold(self):
        self.assertTrue(MODULE.has_obs_fold(b"A: b\r\n folded: x\r\n\r\nbody"))
        self.assertFalse(MODULE.has_obs_fold(b"A: b\r\nC: d\r\n\r\nbody"))

    def test_valid_remote_ip(self):
        self.assertTrue(MODULE.valid_remote_ip("198.51.100.7"))
        for bad in ("127.0.0.1", "0.0.0.0", "224.0.1.1", "169.254.1.1", "nope", ""):
            self.assertFalse(MODULE.valid_remote_ip(bad), bad)


class InviteValidationTests(unittest.TestCase):
    def test_folded_invite_rejected_400(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            listener = make_listener(tmp)
            sent = []
            started = []
            with patch.object(MODULE, "log", lambda *a: None):
                listener.send = lambda text: sent.append(text)
                with patch.object(MODULE.HomtouchListener, "start_early_media",
                                  side_effect=lambda raw: started.append(1)):
                    listener.handle_request(make_invite(fold=True))
        self.assertEqual(started, [])
        self.assertTrue(any(b"400" in chunk.encode() for chunk in sent))

    def test_bad_contact_rejected_400(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            listener = make_listener(tmp)
            sent = []
            started = []
            with patch.object(MODULE, "log", lambda *a: None):
                listener.send = lambda text: sent.append(text)
                with patch.object(MODULE.HomtouchListener, "start_early_media",
                                  side_effect=lambda raw: started.append(1)):
                    listener.handle_request(
                        make_invite(contact="http://evil.example/"))
        self.assertEqual(started, [])
        self.assertTrue(any(b"400" in chunk.encode() for chunk in sent))

    def test_duplicate_invite_no_new_capture(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            listener = make_listener(tmp)
            sent = []
            started = []

            def fake_start(raw):
                started.append(1)
                headers, _ = MODULE.sip_headers(raw)
                cid = headers["call-id"]
                listener.media[cid] = SimpleNamespace(
                    answer_sdp="v=0\r\n",
                    process=SimpleNamespace(poll=lambda: None))
                listener.dialog_tags.setdefault(cid, "tag1")
                listener.respond_basic(raw, 183, "Session Progress",
                                       "tag1", "v=0\r\n")

            raw = make_invite()
            with patch.object(MODULE, "log", lambda *a: None):
                listener.send = lambda text: sent.append(text)
                with patch.object(MODULE.HomtouchListener, "start_early_media",
                                  side_effect=fake_start):
                    listener.handle_request(raw)
                    listener.handle_request(raw)
        self.assertEqual(len(started), 1)
        self.assertEqual(len(listener.media), 1)
        joined = "\n".join(sent)
        self.assertEqual(joined.count("183"), 2)


class ByeTests(unittest.TestCase):
    def bye(self, call_id):
        return (f"BYE sip:x SIP/2.0\r\n"
                f"Call-ID: {call_id}\r\n"
                "CSeq: 21 BYE\r\n"
                "From: <sip:a>;tag=1\r\n"
                "To: <sip:b>;tag=2\r\n"
                "Content-Length: 0\r\n\r\n").encode()

    def test_unknown_bye_gets_481(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            listener = make_listener(tmp)
            sent = []
            with patch.object(MODULE, "log", lambda *a: None):
                listener.send = lambda text: sent.append(text)
                listener.handle_request(self.bye("no-such-call"))
        self.assertTrue(any(b"481" in chunk.encode() for chunk in sent))

    def test_known_bye_gets_200_and_cleans_dialog(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            listener = make_listener(tmp)
            sent = []
            stopped = []
            listener.media["cid-9"] = SimpleNamespace(
                stop=lambda reason: stopped.append(reason))
            listener.dialog_tags["cid-9"] = "tag9"
            with patch.object(MODULE, "log", lambda *a: None):
                listener.send = lambda text: sent.append(text)
                listener.handle_request(self.bye("cid-9"))
        self.assertTrue(any(b"SIP/2.0 200" in chunk.encode() for chunk in sent))
        self.assertEqual(stopped, ["BYE ricevuto"])
        self.assertNotIn("cid-9", listener.media)
        self.assertNotIn("cid-9", listener.dialog_tags)


class AudioOfferTests(unittest.TestCase):
    def parse(self, sdp):
        raw = make_invite(sdp=sdp)
        return MODULE.HomtouchListener.parse_video_offer(None, raw)

    def test_audio_bad_port_degrades_to_none(self):
        sdp = SDP_VIDEO + SDP_AUDIO.replace("m=audio 5006", "m=audio 99999")
        result = self.parse(sdp)
        self.assertIsNone(result[5])

    def test_audio_port_zero_means_disabled(self):
        sdp = SDP_VIDEO + SDP_AUDIO.replace("m=audio 5006", "m=audio 0")
        result = self.parse(sdp)
        self.assertIsNone(result[5])

    def test_audio_bad_key_degrades_to_none(self):
        bad = base64.b64encode(bytes(10)).decode("ascii")
        sdp = SDP_VIDEO + SDP_AUDIO.replace(CRYPTO_KEY, bad)
        result = self.parse(sdp)
        self.assertIsNone(result[5])

    def test_video_loopback_ip_rejected(self):
        sdp = SDP_VIDEO.replace("198.51.100.7", "127.0.0.1")
        with self.assertRaises(RuntimeError):
            self.parse(sdp)

    def test_video_bad_port_rejected(self):
        sdp = SDP_VIDEO.replace("m=video 5004", "m=video 99999")
        with self.assertRaises(RuntimeError):
            self.parse(sdp)


if __name__ == "__main__":
    unittest.main()
