from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from threading import Lock
from typing import Any

GENESIS_HASH = "0" * 64


@dataclass(frozen=True, slots=True)
class AuditEvent:
    timestamp: str
    correlation_id: str
    session_id: str
    tool: str
    decision: str
    reason: str
    argument_names: tuple[str, ...]
    result_type: str | None
    previous_hash: str
    event_hash: str


class AuditLog:
    """Append-only in-memory log with a SHA-256 hash chain."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._lock = Lock()

    @staticmethod
    def _digest(payload: dict[str, Any], previous_hash: str) -> str:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(f"{previous_hash}:{canonical}".encode()).hexdigest()

    def append(
        self,
        *,
        correlation_id: str,
        session_id: str,
        tool: str,
        decision: str,
        reason: str,
        arguments: dict[str, Any],
        result: Any = None,
    ) -> AuditEvent:
        with self._lock:
            previous = self._events[-1].event_hash if self._events else GENESIS_HASH
            body = {
                "timestamp": datetime.now(UTC).isoformat(),
                "correlation_id": correlation_id,
                "session_id": session_id,
                "tool": tool,
                "decision": decision,
                "reason": reason,
                "argument_names": tuple(sorted(arguments)),
                "result_type": type(result).__name__ if decision == "allowed" else None,
                "previous_hash": previous,
            }
            event = AuditEvent(**body, event_hash=self._digest(body, previous))
            self._events.append(event)
            return event

    def snapshot(self) -> tuple[AuditEvent, ...]:
        with self._lock:
            return tuple(self._events)

    def verify(self) -> bool:
        previous = GENESIS_HASH
        with self._lock:
            for event in self._events:
                body = asdict(event)
                event_hash = body.pop("event_hash")
                if body["previous_hash"] != previous:
                    return False
                if self._digest(body, previous) != event_hash:
                    return False
                previous = event_hash
        return True
