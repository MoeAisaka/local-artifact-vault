import os
import json
import tempfile
import unittest
from pathlib import Path

from local_artifact_vault import Vault, VaultError
from local_artifact_vault.server import serve


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.vault = Vault(self.root / "vault")
        self.source = self.root / "report.txt"
        self.source.write_text("safe report\n", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_publish_and_resolve(self):
        result = self.vault.publish(self.source, ttl_seconds=60, base_url="https://example.invalid/artifacts")
        path, record = self.vault.resolve(result["artifactId"], result["expiresAt"], result["signature"], now=result["expiresAt"] - 1)
        self.assertEqual(path.read_text(encoding="utf-8"), "safe report\n")
        self.assertEqual(record["name"], "report.txt")
        self.assertEqual(record["mimeType"], "text/plain")
        self.assertTrue(result["url"].startswith("https://example.invalid/artifacts/download/"))

    def test_audit_is_owner_only_and_never_records_signature_or_source_content(self):
        result = self.vault.publish(self.source, ttl_seconds=60)
        with self.assertRaises(VaultError):
            self.vault.resolve(result["artifactId"], result["expiresAt"], "0" * 64)
        events = [
            json.loads(line)
            for line in self.vault.audit_file.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual([event["event"] for event in events], ["published", "resolve_rejected"])
        audit_text = self.vault.audit_file.read_text(encoding="utf-8")
        self.assertNotIn(result["signature"], audit_text)
        self.assertNotIn(str(self.source), audit_text)
        self.assertNotIn("safe report", audit_text)
        self.assertEqual(os.stat(self.vault.audit_file).st_mode & 0o777, 0o600)

    def test_bad_signature_is_rejected(self):
        result = self.vault.publish(self.source, ttl_seconds=60)
        with self.assertRaises(VaultError):
            self.vault.resolve(result["artifactId"], result["expiresAt"], "0" * 64)

    def test_expired_link_is_rejected_and_cleanup_removes_it(self):
        result = self.vault.publish(self.source, ttl_seconds=60)
        with self.assertRaises(VaultError):
            self.vault.resolve(result["artifactId"], result["expiresAt"], result["signature"], now=result["expiresAt"] + 1)
        self.assertEqual(self.vault.cleanup(now=result["expiresAt"] + 1), 1)

    def test_symlink_and_sensitive_filename_are_rejected(self):
        link = self.root / "link.txt"
        link.symlink_to(self.source)
        with self.assertRaises(VaultError):
            self.vault.publish(link)
        blocked = self.root / "credentials.txt"
        blocked.write_text("not actually secret", encoding="utf-8")
        with self.assertRaises(VaultError):
            self.vault.publish(blocked)

    def test_secret_pattern_is_rejected(self):
        blocked = self.root / "notes.txt"
        marker = "-----BEGIN " + "PRIVATE" + " KEY-----\n"
        blocked.write_text(marker, encoding="utf-8")
        with self.assertRaises(VaultError):
            self.vault.publish(blocked)

    def test_permissions_are_owner_only(self):
        self.vault.initialize()
        self.assertEqual(os.stat(self.vault.root).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(self.vault.secret_file).st_mode & 0o777, 0o600)

    def test_remote_bind_is_fail_closed(self):
        with self.assertRaises(VaultError):
            serve(self.vault.root, "0.0.0.0", 0)


if __name__ == "__main__":
    unittest.main()
