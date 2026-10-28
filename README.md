# SentinelX — Threat Detection & Evaluation Lab

SentinelX is a research-oriented defensive security lab for analyzing **synthetic authentication events**. It demonstrates deterministic detection rules, explainable alerts, reproducible evaluation, and a lightweight Python API.

> **Safety scope:** This repository uses synthetic data only. It does not scan networks, contact external hosts, collect credentials, or perform attacks. Analyze only logs you own or are explicitly authorized to process.

## Features

- Validates newline-delimited JSON (JSONL) authentication events.
- Detects bursts of failed logins grouped by source IP and account within a configurable time window.
- Produces explainable alerts with severity, rule identifiers, evidence, and event IDs.
- Evaluates labeled synthetic scenarios using precision, recall, F1, false-positive rate, and confusion counts.
- Includes deterministic data generation, a FastAPI service, CLI commands, and automated tests.
- Includes a responsive React + TypeScript SOC dashboard with alert inspection, filters, exports, rule tuning, and threshold experiments.
- Includes a threat model, evaluation methodology, and CI workflow.

## Quick start

Python 3.11+ recommended.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m sentinelx.cli generate --out data/sample_events.jsonl
python -m sentinelx.cli analyze --input data/sample_events.jsonl --out reports/alerts.json
python -m sentinelx.cli evaluate --input data/sample_events.jsonl
pytest
```

Start the API with `uvicorn sentinelx.api:app --reload` and open `http://127.0.0.1:8000/docs`.

## Detection rule

**AUTH-001** groups failed logins by `(source_ip, username)` and emits an alert when at least five failures occur in a 300-second rolling window by default. Alert evidence contains the event IDs that triggered the rule.

## Evaluation methodology

The evaluator treats an event as predicted suspicious when its ID appears in alert evidence. Ground truth comes from the optional synthetic `label` field; labels are not used by the detector.

- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1 = harmonic mean of precision and recall
- False-positive rate = FP / (FP + TN)

Undefined denominators return 0.0. Always report dataset size, label balance, seed, threshold, time window, and scoring convention. Results on synthetic data do **not** establish real-world detection performance.

## Dashboard

The React + Vite dashboard lives in `dashboard/` and works in local synthetic-demo mode without a backend.

```bash
cd dashboard
npm install
npm run dev
```

To connect the dashboard to the API, enter the API base URL in **Backend connection**. Configure `SENTINELX_CORS_ORIGINS` on the API host with a comma-separated allowlist containing the dashboard's exact origin. Do not use a wildcard allowlist with credentials. The dashboard's local demo is explicitly labeled and uses synthetic events only.

Build the dashboard with `npm run build`.

## API

- `GET /health` — service status
- `POST /analyze` — analyze `{"events": [...]}`
- `POST /evaluate` — evaluate labeled events

## Roadmap

1. Baseline detector and regression tests.
2. Threshold/window parameter sweeps.
3. Held-out synthetic scenarios and error analysis.
4. Dashboard with incident timeline and metric visualizations.
5. Optional comparison of transparent rule variants.

## Limitations

This is an educational research prototype, not a production SIEM. Synthetic logs do not model NAT, distributed attacks, MFA, clock skew, log loss, or realistic attacker adaptation. A threshold rule can miss low-volume activity and produce false positives.

## License

MIT. See [LICENSE](LICENSE).
