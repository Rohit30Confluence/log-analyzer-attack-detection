from app.response import evaluate_event


def event(
    *,
    severity="medium",
    confidence=0.50,
    occurrence_count=1,
    status="open",
):
    return {
        "event_type": "Brute Force",
        "detector": "BruteForceDetector",
        "rule_id": "auth.brute_force",
        "severity": severity,
        "confidence": confidence,
        "occurrence_count": occurrence_count,
        "status": status,
    }


def test_default_event_is_observe():
    decision = evaluate_event(event())

    assert decision.action == "observe"
    assert decision.policy_id == "response.default.v1"
    assert decision.requires_approval is False


def test_repeated_high_severity_event_notifies():
    decision = evaluate_event(
        event(
            severity="high",
            confidence=0.75,
            occurrence_count=2,
        )
    )

    assert decision.action == "notify"
    assert decision.requires_approval is False


def test_repeated_critical_high_confidence_event_requires_containment_approval():
    decision = evaluate_event(
        event(
            severity="critical",
            confidence=0.95,
            occurrence_count=3,
        )
    )

    assert decision.action == "contain"
    assert decision.requires_approval is True


def test_resolved_event_is_observe():
    decision = evaluate_event(
        event(
            severity="critical",
            confidence=1.0,
            occurrence_count=10,
            status="resolved",
        )
    )

    assert decision.action == "observe"
    assert decision.requires_approval is False


def test_critical_event_below_containment_threshold_is_notify():
    decision = evaluate_event(
        event(
            severity="critical",
            confidence=0.89,
            occurrence_count=3,
        )
    )

    assert decision.action == "notify"
    assert decision.requires_approval is False


def test_high_event_without_repeat_is_observe():
    decision = evaluate_event(
        event(
            severity="high",
            confidence=0.95,
            occurrence_count=1,
        )
    )

    assert decision.action == "observe"


def test_response_decision_is_serializable():
    decision = evaluate_event(
        event(
            severity="critical",
            confidence=0.95,
            occurrence_count=3,
        )
    )

    payload = {
        "action": decision.action,
        "policy_id": decision.policy_id,
        "reason": decision.reason,
        "requires_approval": decision.requires_approval,
    }

    assert payload == {
        "action": "contain",
        "policy_id": "response.default.v1",
        "reason": "critical event has high confidence and repeated occurrences",
        "requires_approval": True,
    }
