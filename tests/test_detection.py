from datetime import datetime, timedelta, timezone
import pytest
from sentinelx.models import AuthEvent
from sentinelx.detection import detect_brute_force

def event(event_id, second, kind="login_failure", ip="192.0.2.10", user="demo"):
    return AuthEvent(event_id=event_id, timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=second),
        source_ip=ip, username=user, event_type=kind)

def test_detects_threshold_within_window():
    alerts = detect_brute_force([event(f"e{i}", i * 10) for i in range(5)], threshold=5)
    assert alerts and alerts[0].rule_id == "AUTH-001"
    assert len(alerts[0].evidence_event_ids) == 5

def test_does_not_detect_below_threshold():
    assert detect_brute_force([event("a", 0), event("b", 10)], threshold=5) == []

def test_successes_do_not_count():
    events = [event(f"f{i}", i) for i in range(4)] + [event("ok", 5, "login_success")]
    assert detect_brute_force(events, threshold=5) == []

def test_accounts_are_not_combined():
    events = [event(f"a{i}", i, user="alice") for i in range(3)] + [event(f"b{i}", i, user="bob") for i in range(3)]
    assert detect_brute_force(events, threshold=5) == []

def test_invalid_configuration_is_rejected():
    with pytest.raises(ValueError): detect_brute_force([], threshold=1)
    with pytest.raises(ValueError): detect_brute_force([], window_seconds=0)

def test_alert_ids_are_deterministic():
    events = [event(f"e{i}", i) for i in range(5)]
    assert detect_brute_force(events) == detect_brute_force(events)
