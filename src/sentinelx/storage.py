"""Neon PostgreSQL persistence for SentinelX."""
import os
import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


def connect():
    url = os.getenv("DATABASE_URL", "").strip()
    if not url:
        raise RuntimeError("DATABASE_URL is not configured")
    return psycopg.connect(url, row_factory=dict_row)


def persist_batch(events, alerts, source_name="authorized-forwarder"):
    inserted_events = 0
    inserted_evidence = 0
    with connect() as conn:
        with conn.cursor() as cur:
            for event in events:
                cur.execute(
                    """INSERT INTO auth_events
                       (event_id, occurred_at, source_ip, username, event_type, label, source_name, raw_event)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                       ON CONFLICT (event_id) DO NOTHING""",
                    (event.event_id, event.timestamp, event.source_ip, event.username,
                     event.event_type, event.label, source_name, Jsonb(event.model_dump(mode="json"))),
                )
                inserted_events += cur.rowcount
            for alert in alerts:
                cur.execute(
                    """INSERT INTO incidents
                       (incident_id,fingerprint,rule_id,title,severity,source_ip,username,
                        first_seen,last_seen,event_count,explanation,updated_at)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now())
                       ON CONFLICT (fingerprint) DO UPDATE SET
                         severity=EXCLUDED.severity,
                         first_seen=LEAST(incidents.first_seen,EXCLUDED.first_seen),
                         last_seen=GREATEST(incidents.last_seen,EXCLUDED.last_seen),
                         event_count=GREATEST(incidents.event_count,EXCLUDED.event_count),
                         explanation=EXCLUDED.explanation,updated_at=now()
                       RETURNING incident_id""",
                    (alert.alert_id, alert.alert_id, alert.rule_id, alert.title, alert.severity,
                     alert.source_ip, alert.username, alert.first_seen, alert.last_seen,
                     alert.event_count, alert.explanation),
                )
                incident_id = cur.fetchone()["incident_id"]
                for event_id in alert.evidence_event_ids:
                    cur.execute(
                        """INSERT INTO incident_evidence (incident_id,event_id)
                           VALUES (%s,%s) ON CONFLICT DO NOTHING""",
                        (incident_id, event_id),
                    )
                    inserted_evidence += cur.rowcount
    return inserted_events, inserted_evidence
