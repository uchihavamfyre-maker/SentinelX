"""Deterministic, explainable authentication detection rules."""
from collections import defaultdict
from datetime import timedelta
import hashlib
from .models import AuthEvent, DetectionAlert


def detect_brute_force(
    events: list[AuthEvent],
    threshold: int = 5,
    window_seconds: int = 300,
) -> list[DetectionAlert]:
    """Return one consolidated incident per source/account pair.

    The incident evidence is the latest rolling window that reaches the
    configured threshold. Later failures update that incident's evidence and
    severity instead of creating a separate alert for every event.
    """
    if threshold < 2:
        raise ValueError("threshold must be at least 2")
    if window_seconds < 1:
        raise ValueError("window_seconds must be positive")

    groups: dict[tuple[str, str], list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.event_type == "login_failure":
            groups[(event.source_ip, event.username)].append(event)

    incidents: list[DetectionAlert] = []
    window = timedelta(seconds=window_seconds)

    for (source_ip, username), group in sorted(groups.items()):
        ordered = sorted(group, key=lambda event: (event.timestamp, event.event_id))
        left = 0
        latest_evidence: list[AuthEvent] = []

        for right, current in enumerate(ordered):
            while left <= right and ordered[left].timestamp < current.timestamp - window:
                left += 1
            candidate = ordered[left:right + 1]
            if len(candidate) >= threshold:
                latest_evidence = candidate

        if not latest_evidence:
            continue

        evidence_ids = [event.event_id for event in latest_evidence]
        digest_source = f"{source_ip}|{username}|AUTH-001"
        digest = hashlib.sha256(digest_source.encode()).hexdigest()[:12]
        count = len(latest_evidence)
        severity = (
            "critical" if count >= threshold * 3
            else "high" if count >= threshold * 2
            else "medium"
        )
        incidents.append(DetectionAlert(
            alert_id=f"incident-{digest}",
            rule_id="AUTH-001",
            title="Repeated authentication failures",
            severity=severity,
            source_ip=source_ip,
            username=username,
            first_seen=latest_evidence[0].timestamp,
            last_seen=latest_evidence[-1].timestamp,
            event_count=count,
            evidence_event_ids=evidence_ids,
            explanation=(
                f"{count} failed login events for account '{username}' from "
                f"{source_ip} occurred within {window_seconds} seconds "
                f"(configured threshold: {threshold})."
            ),
        ))

    return sorted(incidents, key=lambda incident: (incident.last_seen, incident.alert_id))


def predicted_suspicious_event_ids(alerts: list[DetectionAlert]) -> set[str]:
    """Return event IDs surfaced as evidence by at least one incident."""
    return {
        event_id
        for incident in alerts
        for event_id in incident.evidence_event_ids
    }
