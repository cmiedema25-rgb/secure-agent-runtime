"""Red-team corpus runner and transparent metric computation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .models import Decision, JsonValue, Message
from .policy import PolicyEngine


@dataclass(frozen=True, slots=True)
class EvaluationCase:
    case_id: str
    category: str
    prompt: str
    expected: Decision
    attack: bool

    @classmethod
    def from_dict(cls, value: dict[str, JsonValue]) -> EvaluationCase:
        return cls(
            case_id=str(value["id"]),
            category=str(value["category"]),
            prompt=str(value["prompt"]),
            expected=Decision(str(value["expected"])),
            attack=bool(value["attack"]),
        )


def load_corpus(path: str | Path) -> tuple[EvaluationCase, ...]:
    cases: list[EvaluationCase] = []
    with Path(path).open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
                cases.append(EvaluationCase.from_dict(value))
            except (json.JSONDecodeError, KeyError, ValueError, TypeError) as exc:
                raise ValueError(f"invalid corpus record at line {line_number}") from exc
    if not cases:
        raise ValueError("evaluation corpus is empty")
    if len({case.case_id for case in cases}) != len(cases):
        raise ValueError("evaluation case identifiers must be unique")
    return tuple(cases)


def run_evaluation(policy: PolicyEngine, cases: tuple[EvaluationCase, ...]) -> dict[str, JsonValue]:
    rows: list[JsonValue] = []
    correct = 0
    attack_total = 0
    attack_stopped = 0
    benign_total = 0
    benign_allowed = 0

    for case in cases:
        result = policy.evaluate_input((Message(role="user", content=case.prompt),))
        matched = result.decision is case.expected
        correct += int(matched)
        if case.attack:
            attack_total += 1
            attack_stopped += int(result.decision is not Decision.ALLOW)
        else:
            benign_total += 1
            benign_allowed += int(result.decision is Decision.ALLOW)
        rows.append(
            {
                "id": case.case_id,
                "category": case.category,
                "expected": case.expected.value,
                "actual": result.decision.value,
                "score": result.score,
                "correct": matched,
                "finding_categories": [finding.category for finding in result.findings],
            }
        )

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "corpus_type": "curated regression benchmark",
        "cases": len(cases),
        "metrics": {
            "exact_decision_accuracy": round(correct / len(cases), 4),
            "attack_stop_rate": round(attack_stopped / max(attack_total, 1), 4),
            "benign_allow_rate": round(benign_allowed / max(benign_total, 1), 4),
            "attack_cases": attack_total,
            "benign_cases": benign_total,
        },
        "results": rows,
        "limitations": (
            "This self-contained corpus measures deterministic regression behavior; "
            "it is not an independent security certification or a substitute for "
            "adaptive human red teaming."
        ),
    }


def save_report(report: dict[str, JsonValue], path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
