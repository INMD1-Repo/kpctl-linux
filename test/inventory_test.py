import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("inventory", Path(__file__).resolve().parents[1]/"deploy/kpctl-cve-inventory.py")
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


class VendorInventory(unittest.TestCase):
    def entry(self, ecosystem="Ubuntu:24.04:LTS", name="linux"):
        return {"id": "UBUNTU-CVE-2026-43083", "affected": [{"package": {"name": name, "ecosystem": ecosystem},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "6.8.0-137.137"}]}]}]}

    def test_source_not_binary_hwe_or_pro(self):
        self.assertIsNone(inventory.compact(self.entry(name="linux-image-6.8.0-136-generic")))
        self.assertIsNone(inventory.compact(self.entry(name="linux-hwe-6.8")))
        # Other release entries remain unknown, never converted to unaffected.
        self.assertEqual({}, inventory.compact(self.entry(ecosystem="Ubuntu:Pro:24.04:LTS"))["releases"])
        result = inventory.compact(self.entry())
        self.assertIn("noble", result["releases"])
        self.assertNotIn("resolute", result["releases"])
        self.assertEqual("6.8.0-137.137", result["releases"]["noble"]["ranges"][0]["events"][1]["fixed"])

    def test_withdrawn_and_duplicate_release(self):
        entry = self.entry()
        entry["withdrawn"] = "2026-11-02T00:00:00Z"
        self.assertIsNone(inventory.compact(entry))
        entry = self.entry()
        entry["affected"] *= 2
        with self.assertRaises(ValueError):
            inventory.compact(entry)


if __name__ == "__main__":
    unittest.main()
