# SentinelX evaluation methodology

## Research question
How well does a transparent threshold rule identify labeled repeated authentication failures in deterministic synthetic data, and what errors occur under documented conditions?

## Hypothesis
A rule requiring five failures for the same source-IP/account pair in five minutes should identify a high-volume synthetic burst while missing smaller bursts and potentially flagging legitimate repeated failures.

## Dataset
A seeded generator combines routine successful logins, isolated failures labeled normal, an eight-event suspicious burst, a three-event suspicious sequence, and unrelated normal failures. IPs use documentation-only ranges. No real people, credentials, services, or network endpoints are involved.

## Detector
Rule AUTH-001 groups login_failure events by source IP and username. Defaults: threshold=5, window=300 seconds.

## Scoring unit
The scoring unit is the event, not the alert. An event is predicted positive if its ID appears in any alert evidence. Ground truth is the optional label field; the detector does not read labels.

## Metrics
Report TP, FP, TN, FN, precision, recall, F1, and false-positive rate. Undefined denominators return 0.0. Include dataset size, label balance, random seed, threshold, window, and scoring convention.

## Reproducibility
1. Record Python and package versions.
2. Generate data with a recorded seed and preserve the JSONL.
3. Record threshold and window.
4. Run pytest and preserve its output.
5. Save metrics with the run configuration.
6. Do not report tuning-set performance as independent held-out performance.

## Limitations
This synthetic dataset is small and does not model NAT, distributed attacks, account lockouts, MFA, clock skew, log loss, or attacker adaptation. Results demonstrate implementation behavior, not production effectiveness.
