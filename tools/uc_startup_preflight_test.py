import json
import tempfile
import unittest
from pathlib import Path
import uc_startup_preflight as preflight

class StartupPreflightTests(unittest.TestCase):
    def test_verified_entry_remains_blocked(self):
        result = preflight.inspect(Path(r"C:\Games\Need For Speed Undercover\nfs.exe"), Path(__file__).resolve().parents[1])
        self.assertEqual(result["entry"], "0x01FCA510")
        self.assertEqual(result["first_verified_blocking_edge"]["target"], "0x01FCA523")
        self.assertFalse(result["undercover_original_startup_prefix_in_browser"])

    def test_wrong_image_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory)/"wrong.exe"
            image.write_bytes(b"incorrect")
            with self.assertRaisesRegex(ValueError, "Source executable SHA"):
                preflight.inspect(image, Path(directory))

    def test_master_has_one_marker_per_emitted_address(self):
        directory = Path(__file__).resolve().parents[1]/"analysis"/"undercover"
        text = (directory/"nfs_undercover_full_decompile.c").read_text(encoding="utf-8")
        import re
        addresses = re.findall(r"/\* (?:UC_FUNCTION|RAW_LIFTER_FUNCTION) ([0-9a-f]+)", text)
        self.assertEqual(len(addresses), 17367+8401)
        self.assertEqual(len(addresses), len(set(addresses)))

if __name__ == "__main__":
    unittest.main()
