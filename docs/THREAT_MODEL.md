# Threat model and safe-use boundaries

## Purpose
SentinelX is a defensive educational prototype for authentication-event analysis.

## Assets
- Integrity of event data and labels.
- Correctness and reproducibility of detections.
- Availability of the analysis API.
- Confidentiality of any logs an operator is authorized to analyze.

## Assumptions
- Inputs are synthetic or explicitly authorized.
- The API is used locally or behind an appropriate trusted boundary.
- Labels are evaluation metadata, not detector features.

## Out of scope
Network scanning, exploitation, credential collection, password guessing, persistence, evasion, or automated response against real infrastructure.

## Risks and mitigations
| Risk | Mitigation |
|---|---|
| Malformed input | Pydantic validation and bounded request size |
| Misleading metrics | Explicit scoring convention and synthetic-data caveat |
| False positives | Alert evidence and human-readable explanations |
| Sensitive log exposure | Synthetic samples by default; never commit private logs |
| Unsafe deployment | Keep API local during development; harden before public exposure |

Analyze only data you own or have permission to process. Alerts are triage signals, not proof of compromise.
