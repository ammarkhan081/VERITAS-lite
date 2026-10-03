from backend.gates.normal_regression import NormalRegressionGate


def test_drop_exactly_at_threshold_passes():
    result = NormalRegressionGate().check_batch([True] * 10, [True] * 9 + [False], {
        "normal_task_accuracy_threshold": 0.10,
    })
    assert result.passed


def test_drop_above_threshold_fails():
    result = NormalRegressionGate().check_batch([True] * 10, [True] * 8 + [False] * 2, {
        "normal_task_accuracy_threshold": 0.10,
    })
    assert not result.passed


def test_no_accuracy_drop_passes():
    assert NormalRegressionGate().check_batch([True] * 10, [True] * 10, {}).passed


def test_empty_baseline_passes():
    assert NormalRegressionGate().check_batch([], [False, False], {}).passed


def test_custom_threshold_is_more_sensitive():
    result = NormalRegressionGate().check_batch([True] * 20, [True] * 19 + [False], {
        "normal_task_accuracy_threshold": 0.02,
    })
    assert not result.passed


def test_failure_evidence_contains_accuracies():
    result = NormalRegressionGate().check_batch([True] * 10, [True] * 7 + [False] * 3, {
        "normal_task_accuracy_threshold": 0.10,
    })
    assert result.evidence["before_accuracy"] == 1.0
    assert result.evidence["after_accuracy"] == 0.7
