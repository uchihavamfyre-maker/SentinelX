"""Event-level evaluation for labeled synthetic datasets."""
from .detection import detect_brute_force, predicted_suspicious_event_ids
from .models import AuthEvent, EvaluationMetrics

def safe_divide(numerator: int | float, denominator: int | float) -> float:
    return numerator / denominator if denominator else 0.0

def evaluate_detector(events: list[AuthEvent], threshold: int = 5, window_seconds: int = 300) -> EvaluationMetrics:
    labeled = [event for event in events if event.label is not None]
    predicted = predicted_suspicious_event_ids(detect_brute_force(events, threshold, window_seconds))
    tp = fp = tn = fn = 0
    for event in labeled:
        actual_positive = event.label == "suspicious"
        predicted_positive = event.event_id in predicted
        if actual_positive and predicted_positive: tp += 1
        elif not actual_positive and predicted_positive: fp += 1
        elif not actual_positive and not predicted_positive: tn += 1
        else: fn += 1
    precision = safe_divide(tp, tp + fp)
    recall = safe_divide(tp, tp + fn)
    f1 = safe_divide(2 * precision * recall, precision + recall)
    fpr = safe_divide(fp, fp + tn)
    return EvaluationMetrics(
        total_events=len(events), labeled_events=len(labeled),
        true_positive=tp, false_positive=fp, true_negative=tn, false_negative=fn,
        precision=round(precision, 6), recall=round(recall, 6),
        f1=round(f1, 6), false_positive_rate=round(fpr, 6)
    )
