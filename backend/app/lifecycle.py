"""Security-event lifecycle and correlation constants."""

OPEN = "open"
ACKNOWLEDGED = "acknowledged"
INVESTIGATING = "investigating"
CONTAINED = "contained"
RESOLVED = "resolved"

STATUSES = {
    OPEN,
    ACKNOWLEDGED,
    INVESTIGATING,
    CONTAINED,
    RESOLVED,
}

TRANSITIONS = {
    OPEN: {ACKNOWLEDGED, INVESTIGATING, RESOLVED},
    ACKNOWLEDGED: {INVESTIGATING, CONTAINED, RESOLVED},
    INVESTIGATING: {CONTAINED, RESOLVED},
    CONTAINED: {INVESTIGATING, RESOLVED},
    RESOLVED: set(),
}


def can_transition(current: str, target: str) -> bool:
    if current == target:
        return True
    return target in TRANSITIONS.get(current, set())
