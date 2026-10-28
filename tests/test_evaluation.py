from sentinelx.evaluation import evaluate_detector, safe_divide
from sentinelx.synthetic import generate_events

def test_safe_divide_zero_denominator(): assert safe_divide(1, 0) == 0.0
def test_generator_is_deterministic(): assert generate_events(12) == generate_events(12)
def test_metrics_are_bounded():
    metrics = evaluate_detector(generate_events())
    assert metrics.total_events == metrics.labeled_events
    for value in (metrics.precision, metrics.recall, metrics.f1, metrics.false_positive_rate):
        assert 0.0 <= value <= 1.0
def test_baseline_detects_labeled_burst():
    metrics = evaluate_detector(generate_events())
    assert metrics.true_positive > 0
    assert metrics.false_negative > 0
