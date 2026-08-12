from app.response import ResponseExecutor


def test_observe_is_not_executed():
    result = ResponseExecutor().execute(
        event_id="evt-observe",
        action="observe",
        requires_approval=False,
    )

    assert result.status == "skipped"
    assert result.executed is False


def test_notify_is_not_executed():
    result = ResponseExecutor().execute(
        event_id="evt-notify",
        action="notify",
        requires_approval=False,
    )

    assert result.status == "skipped"
    assert result.executed is False


def test_containment_requires_approval():
    result = ResponseExecutor().execute(
        event_id="evt-contain",
        action="contain",
        requires_approval=True,
    )

    assert result.status == "pending_approval"
    assert result.executed is False


def test_approved_containment_executes_in_dry_run():
    result = ResponseExecutor().execute(
        event_id="evt-contain-approved",
        action="contain",
        requires_approval=True,
        approved=True,
    )

    assert result.status == "executed"
    assert result.executed is True
    assert result.event_id == "evt-contain-approved"


def test_containment_without_required_approval_can_execute():
    result = ResponseExecutor().execute(
        event_id="evt-contain-no-approval",
        action="contain",
        requires_approval=False,
    )

    assert result.status == "executed"
    assert result.executed is True


def test_unknown_action_is_rejected():
    try:
        ResponseExecutor().execute(
            event_id="evt-invalid",
            action="delete_everything",
            requires_approval=False,
        )
    except ValueError as exc:
        assert "unsupported response action" in str(exc)
    else:
        raise AssertionError("unsupported action was accepted")
