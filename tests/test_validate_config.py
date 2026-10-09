import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.validate_config import validate


class ValidateConfigTests(unittest.TestCase):
    def make_config(self, root):
        credentials = root / "credentials.json"
        credentials.write_text(json.dumps({
            "SipAccount": "redacted@example.test",
            "SipPassword": "redacted",
        }))
        files = {}
        for name in ("cert", "key", "ca"):
            files[name] = root / name
            files[name].write_text("test")
        return {
            "sip_server": "198.51.100.10",
            "sip_domain": "sip.example.test",
            "sip_port": 5061,
            "credentials_file": str(credentials),
            "certificate_file": str(files["cert"]),
            "private_key_file": str(files["key"]),
            "ca_file": str(files["ca"]),
        }

    def test_valid_private_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config.json"
            config.write_text(json.dumps(self.make_config(root)))
            with patch("scripts.validate_config.shutil.which", return_value="/usr/bin/tool"):
                self.assertEqual(validate(config)["sip_port"], 5061)

    def test_example_values_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = self.make_config(root)
            data["sip_domain"] = "example.invalid"
            config = root / "config.json"
            config.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "valore di esempio"):
                validate(config)

    def test_missing_secret_file_is_rejected_without_showing_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = self.make_config(root)
            data["private_key_file"] = str(root / "private-secret-name.key")
            config = root / "config.json"
            config.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "private_key_file") as caught:
                validate(config)
            self.assertNotIn("private-secret-name", str(caught.exception))

    def write_validated(self, root, data):
        config = root / "config.json"
        config.write_text(json.dumps(data))
        with patch("scripts.validate_config.shutil.which", return_value="/usr/bin/tool"):
            return validate(config)

    def test_mqtt_enabled_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = self.make_config(root)
            data["mqtt"] = {"enabled": True, "host": "198.51.100.20",
                            "port": 1883, "topic": "bticino/citofono/ring"}
            self.assertEqual(self.write_validated(root, data)["mqtt"]["port"], 1883)

    def test_mqtt_enabled_without_host_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = self.make_config(root)
            data["mqtt"] = {"enabled": True, "host": "", "topic": "t"}
            config = root / "config.json"
            config.write_text(json.dumps(data))
            with patch("scripts.validate_config.shutil.which", return_value="/usr/bin/tool"), \
                    self.assertRaisesRegex(ValueError, "mqtt.host"):
                validate(config)

    def test_mqtt_password_without_username_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pwd = root / "mqtt.pwd"
            pwd.write_text("secret")
            data = self.make_config(root)
            data["mqtt"] = {"enabled": True, "host": "198.51.100.20",
                            "topic": "t", "password_file": str(pwd)}
            config = root / "config.json"
            config.write_text(json.dumps(data))
            with patch("scripts.validate_config.shutil.which", return_value="/usr/bin/tool"), \
                    self.assertRaisesRegex(ValueError, "mqtt.username"):
                validate(config)

    def test_opener_enabled_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = self.make_config(root)
            data["opener"] = {"enabled": True, "entrance": "2", "cid": 0}
            self.assertEqual(
                self.write_validated(root, data)["opener"]["entrance"], "2")

    def test_opener_enabled_without_entrance_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = self.make_config(root)
            data["opener"] = {"enabled": True, "entrance": ""}
            config = root / "config.json"
            config.write_text(json.dumps(data))
            with patch("scripts.validate_config.shutil.which", return_value="/usr/bin/tool"), \
                    self.assertRaisesRegex(ValueError, "opener.entrance"):
                validate(config)

    def test_media_ports_single_pair_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = self.make_config(root)
            data["media_ports"] = "2202-2203"
            self.assertEqual(
                self.write_validated(root, data)["media_ports"], "2202-2203")

    def test_media_ports_odd_start_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = self.make_config(root)
            data["media_ports"] = "2203-2204"
            config = root / "config.json"
            config.write_text(json.dumps(data))
            with patch("scripts.validate_config.shutil.which", return_value="/usr/bin/tool"), \
                    self.assertRaisesRegex(ValueError, "media_ports"):
                validate(config)

    def test_answer_calls_must_be_bool(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = self.make_config(root)
            data["answer_calls"] = "yes"
            config = root / "config.json"
            config.write_text(json.dumps(data))
            with patch("scripts.validate_config.shutil.which", return_value="/usr/bin/tool"), \
                    self.assertRaisesRegex(ValueError, "answer_calls"):
                validate(config)

    def test_lan_bind_without_token_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = self.make_config(root)
            data["http_bind"] = "0.0.0.0"
            data["opener"] = {"enabled": True, "entrance": "2"}
            config = root / "config.json"
            config.write_text(json.dumps(data))
            with patch("scripts.validate_config.shutil.which", return_value="/usr/bin/tool"), \
                    self.assertRaisesRegex(ValueError, "opener.token"):
                validate(config)

    def test_lan_bind_with_token_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = self.make_config(root)
            data["http_bind"] = "0.0.0.0"
            data["opener"] = {"enabled": True, "entrance": "2", "token": "s3cret"}
            self.assertEqual(self.write_validated(root, data)["http_bind"], "0.0.0.0")


if __name__ == "__main__":
    unittest.main()
