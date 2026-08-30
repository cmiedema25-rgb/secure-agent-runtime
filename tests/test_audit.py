from secure_agent_runtime.audit import AuditLog


def test_audit_chain_verifies() -> None:
    log = AuditLog()
    first = log.append(
        correlation_id="c1",
        session_id="s1",
        tool="math.add",
        decision="allowed",
        reason="allowed",
        arguments={"a": 1, "b": 2},
        result=3,
    )
    second = log.append(
        correlation_id="c2",
        session_id="s1",
        tool="text.word_count",
        decision="denied",
        reason="capability_denied",
        arguments={"text": "test"},
    )

    assert second.previous_hash == first.event_hash
    assert log.verify() is True
