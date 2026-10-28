"""Deterministic generator for safe, synthetic authentication events."""
from datetime import datetime, timedelta, timezone
import random
from .models import AuthEvent

def generate_events(seed: int = 7) -> list[AuthEvent]:
    rng = random.Random(seed)
    start = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    events: list[AuthEvent] = []
    counter = 0
    def add(offset: int, ip: str, username: str, kind: str, label: str) -> None:
        nonlocal counter
        counter += 1
        events.append(AuthEvent(event_id=f"evt-{counter:04d}", timestamp=start + timedelta(seconds=offset),
            source_ip=ip, username=username, event_type=kind, label=label))
    for i in range(24):
        offset = i * 47
        ip, user = f"192.0.2.{10 + (i % 8)}", f"user-{1 + (i % 6)}"
        if rng.random() < 0.25: add(offset, ip, user, "login_failure", "normal")
        add(offset + 3, ip, user, "login_success", "normal")
    for i in range(8): add(120 + i * 18, "198.51.100.23", "demo-admin", "login_failure", "suspicious")
    for i in range(3): add(900 + i * 40, "198.51.100.44", "demo-operator", "login_failure", "suspicious")
    for i in range(8): add(1100 + i * 61, f"192.0.2.{40 + i}", f"staff-{i}", "login_failure", "normal")
    return sorted(events, key=lambda e: (e.timestamp, e.event_id))
