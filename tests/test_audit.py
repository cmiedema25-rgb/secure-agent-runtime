from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from secure_agent_runtime.audit import HashChainAuditLog


class AuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "audit.jsonl"
        self.audit = HashChainAuditLog(self.path, "a-secure-test-signing-key")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_empty_log_is_valid(self) -> None:
        result = self.audit.verify()
        self.assertTrue(result.valid)
        self.assertEqual(result.records, 0)

    def test_appended_records_verify(self) -> None:
        self.audit.append(event="one", request_id="req-1")
        self.audit.append(event="two", request_id="req-1")
        result = self.audit.verify()
        self.assertTrue(result.valid)
        self.assertEqual(result.records, 2)

    def test_records_form_chain(self) -> None:
        first = self.audit.append(event="one", request_id="req-1")
        second = self.audit.append(event="two", request_id="req-1")
        self.assertEqual(second["previous_hash"], first["record_hash"])

    def test_tampering_is_detected(self) -> None:
        self.audit.append(event="one", request_id="req-1")
        record = json.loads(self.path.read_text())
        record["event"] = "tampered"
        self.path.write_text(json.dumps(record) + "\n")
        result = self.audit.verify()
        self.assertFalse(result.valid)
        self.assertIn("hash mismatch", result.error or "")

    def test_secret_fields_are_redacted(self) -> None:
        self.audit.append(
            event="one",
            request_id="req-1",
            details={"api_token": "do-not-store", "status": "ok"},
        )
        raw = self.path.read_text()
        self.assertNotIn("do-not-store", raw)
        self.assertIn("[REDACTED]", raw)

    def test_sensitive_payload_is_only_stored_as_digest(self) -> None:
        self.audit.append(
            event="one",
            request_id="req-1",
            sensitive_payload="private prompt text",
        )
        self.assertNotIn("private prompt text", self.path.read_text())

    def test_short_signing_key_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            HashChainAuditLog(self.path, "short")


if __name__ == "__main__":
    unittest.main()
