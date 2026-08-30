"""Append-only, HMAC-authenticated audit chain with no raw prompt retention."""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import JsonValue
from .policy import redact_json


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class AuditVerification:
    valid: bool
    records: int
    error: str | None = None

    def to_dict(self) -> dict[str, JsonValue]:
        return {"valid": self.valid, "records": self.records, "error": self.error}


class HashChainAuditLog:
    """An append-only JSONL log whose entries form an HMAC hash chain."""

    def __init__(self, path: str | Path, signing_key: str | bytes) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        key = signing_key.encode("utf-8") if isinstance(signing_key, str) else signing_key
        if len(key) < 16:
            raise ValueError("audit signing key must contain at least 16 bytes")
        self._key = key
        self._lock = threading.Lock()

    def append(
        self,
        *,
        event: str,
        request_id: str,
        details: dict[str, JsonValue] | None = None,
        sensitive_payload: JsonValue = None,
    ) -> dict[str, JsonValue]:
        safe_details = redact_json(details or {})
        digest = hashlib.sha256(_canonical({"payload": sensitive_payload})).hexdigest()
        with self._lock:
            sequence, previous_hash = self._tail()
            record: dict[str, JsonValue] = {
                "sequence": sequence + 1,
                "timestamp": datetime.now(UTC).isoformat(),
                "event": event,
                "request_id": request_id,
                "details": safe_details,
                "payload_digest": digest,
                "previous_hash": previous_hash,
            }
            record_hash = hmac.new(self._key, _canonical(record), hashlib.sha256).hexdigest()
            record["record_hash"] = record_hash
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
                handle.flush()
            return record

    def verify(self) -> AuditVerification:
        with self._lock:
            if not self.path.exists():
                return AuditVerification(True, 0)
            previous_hash = "GENESIS"
            expected_sequence = 1
            try:
                with self.path.open(encoding="utf-8") as handle:
                    for line_number, line in enumerate(handle, start=1):
                        if not line.strip():
                            continue
                        record = json.loads(line)
                        actual_hash = record.pop("record_hash", None)
                        expected_hash = hmac.new(
                            self._key,
                            _canonical(record),
                            hashlib.sha256,
                        ).hexdigest()
                        if not isinstance(actual_hash, str) or not hmac.compare_digest(
                            actual_hash, expected_hash
                        ):
                            return AuditVerification(
                                False,
                                expected_sequence - 1,
                                f"record hash mismatch at line {line_number}",
                            )
                        if record.get("sequence") != expected_sequence:
                            return AuditVerification(
                                False,
                                expected_sequence - 1,
                                f"sequence mismatch at line {line_number}",
                            )
                        if record.get("previous_hash") != previous_hash:
                            return AuditVerification(
                                False,
                                expected_sequence - 1,
                                f"chain link mismatch at line {line_number}",
                            )
                        previous_hash = actual_hash
                        expected_sequence += 1
            except (OSError, json.JSONDecodeError, TypeError) as exc:
                return AuditVerification(False, expected_sequence - 1, str(exc))
            return AuditVerification(True, expected_sequence - 1)

    def _tail(self) -> tuple[int, str]:
        if not self.path.exists():
            return 0, "GENESIS"
        last: dict[str, Any] | None = None
        with self.path.open(encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last = json.loads(line)
        if last is None:
            return 0, "GENESIS"
        sequence = int(last["sequence"])
        record_hash = str(last["record_hash"])
        return sequence, record_hash
