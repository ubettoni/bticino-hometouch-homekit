import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "configure_homebridge.py"


def run_script(config, *extra):
    env = dict(__import__("os").environ, HOMEBRIDGE_CONFIG=str(config))
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--config", str(config), *extra],
        capture_output=True, text=True, env=env)


class ConfigureHomebridgeTests(unittest.TestCase):
    def base_config(self, root):
        config = root / "config.json"
        config.write_text(json.dumps({
            "bridge": {"name": "Test"},
            "platforms": [{
                "name": "Camera FFmpeg",
                "platform": "Camera-ffmpeg",
                "videoProcessor": "ffmpeg",
                "localhttp": False,
                "cameras": [{
                    "name": "Videocitofono",
                    "audio": True,
                    "motion": False,
                    "videoConfig": {
                        "source": "-i udp://127.0.0.1:22300",
                        "stillImageSource": "-i http://127.0.0.1:8766/x.jpg",
                    },
                }],
            }],
        }))
        return config

    def test_preview_writes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.base_config(Path(directory))
            before = config.read_text()
            result = run_script(config)
            self.assertEqual(result.returncode, 0)
            self.assertIn("CONFIG_OK=", result.stdout)
            self.assertEqual(config.read_text(), before)

    def test_apply_adds_porthttp_and_mpegts_preserving_user_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.base_config(Path(directory))
            result = run_script(config, "--apply")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("BACKUP=", result.stdout)
            data = json.loads(config.read_text())
            platform = next(p for p in data["platforms"]
                            if p.get("platform") == "Camera-ffmpeg")
            self.assertEqual(platform["porthttp"], 8767)
            camera = next(c for c in platform["cameras"]
                          if c.get("name") == "Videocitofono")
            self.assertIn("-f mpegts", camera["videoConfig"]["source"])
            self.assertIn("snapshot.jpg", camera["videoConfig"]["stillImageSource"])
            self.assertTrue(camera["doorbell"])
            # Chiavi utente preservate, non sovrascritte.
            self.assertTrue(camera["audio"])
            self.assertIn("motion", camera)


if __name__ == "__main__":
    unittest.main()
