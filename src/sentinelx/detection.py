"""Deterministic, explainable authentication detection rules."""
from collections import defaultdict
from datetime import timedelta
import hashlib
from .models import AuthEvent, DetectionAlert

def detect_brute_force(events: list[AuthEvent], threshold: int = 5, window_seconds: int = 300) -> list[DetectionAlert]:
    """Flag source/account pairs with threshold failures in a rolling time window."""
    if threshold < 2:
        raise ValueError("threshold must be at least 2")
    if window_seconds < 1:
        raise ValueError("window_seconds must be positive")
    groups: dict[tuple[str, str], list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.event_type == "login_failure":
            groups[(event.source_ip, event.username)].append(event)

    alerts: list[DetectionAlert] = []
    window = timedelta(seconds=window_seconds)
    for (source_ip, username), group in sorted(groups.items()):
        ordered = sorted(group, key=lambda e: (e.timestamp, e.event_id))
        left = 0
        for right, current in enumerate(ordered):
            while ordered[left].timestamp < current.timestamp - window:
                left += 1
            candidate = ordered[left:right + 1]
            if len(candidate) < threshold:
                continue
            evidence = tuple(event.event_id for event in candidate)
            digest = hashlib.sha256("|".join(evidence).encode()).hexdigest()[:12]
            count = len(candidate)
            severity = "critical" if count >= threshold * 3 else "high" if count >= threshold * 2 else "medium"
            alerts.append(DetectionAlert(
                alert_id=f"alert-{digest}", rule_id="AUTH-001",
                title="Repeated authentication failures", severity=severity,
                source_ip=source_ip, username=username,
                first_seen=candidate[0].timestamp, last_seen=current.timestamp,
                event_count=count, evidence_event_ids=list(evidence),
                explanation=f"{count} failed login events for account '{username}' from {source_ip} occurred within {window_seconds} seconds (configured threshold: {threshold})."
            ))
    # Keep the latest/strongest evidence window for each unique evidence signature.
    unique = {alert.alert_id: alert for alert in alerts}
    return sorted(unique.values(), key=lambda a: (a.first_seen, a.alert_id))

def predicted_suspicious_event_ids(alerts: list[DetectionAlert]) -> set[str]:
    """Return event IDs surfaced as evidence by at least one alert."""
    return {event_id for alert in alerts for event_id in alert.evidence_event_ids}
