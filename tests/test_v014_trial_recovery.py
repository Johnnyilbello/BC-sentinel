import pytest

from sentinel import beta13_commercial_readiness as commercial


def test_non_utf8_trial_is_unavailable_without_crashing_or_overwriting(tmp_path):
    path = tmp_path / 'trial.json'
    raw = b'\xff\xfe\x00broken-state'
    path.write_bytes(raw)
    result = commercial.load_trial(path, now=1800000000.0)
    assert result.status == commercial.UNAVAILABLE
    assert result.protection_enabled is True
    assert path.read_bytes() == raw


@pytest.mark.parametrize('field,value', [
    ('started_at', float('nan')), ('started_at', float('inf')),
    ('started_at', float('-inf')), ('started_at', 10**5000),
    ('trial_days', float('inf')), ('trial_days', True), ('trial_days', 1.5),
], ids=['nan', 'inf', 'negative-inf', 'huge-int', 'infinite-days', 'bool-days', 'fraction-days'])
def test_invalid_trial_values_fail_closed_without_crashing(field, value):
    data = {'schema': commercial.TRIAL_SCHEMA, 'started_at': 1800000000.0, 'trial_days': 14}
    data[field] = value
    result = commercial.evaluate_trial(data, now=1800000000.0)
    assert result.status == commercial.UNAVAILABLE
    assert result.protection_enabled is True
