import pytest  # type: ignore
from helpers import Helpers

# Test case 1: valid input with minutes and seconds
def test_duration_to_seconds_1():
    input_duration = '04:13'
    expected_output = 253
    assert Helpers.duration_to_seconds(input_duration) == expected_output

# Test case 2: valid input with minutes and seconds
def test_duration_to_seconds_2():
    input_duration = '4:13'
    expected_output = 253
    assert Helpers.duration_to_seconds(input_duration) == expected_output

# Test case 3: valid input with hours, minutes, and seconds
def test_duration_to_seconds_3():
    input_duration = '1:23:45'
    expected_output = 5025
    assert Helpers.duration_to_seconds(input_duration) == expected_output

# Test case 4: valid input with hours, minutes, and seconds
def test_duration_to_seconds_4():
    input_duration = '1:00:00'
    expected_output = 3600
    assert Helpers.duration_to_seconds(input_duration) == expected_output

def test_duration_to_seconds_rounding_decimal():
    input_duration = '1:00:00.001'
    expected_output = 3600
    assert Helpers.duration_to_seconds(input_duration) == expected_output

    input_duration = '4:00.501'
    expected_output = 241
    assert Helpers.duration_to_seconds(input_duration) == expected_output

    input_duration = '0:53.501'
    expected_output = 54
    assert Helpers.duration_to_seconds(input_duration) == expected_output

    input_duration = '0:55.999'
    expected_output = 56
    assert Helpers.duration_to_seconds(input_duration) == expected_output

    input_duration = '0:55.9'
    expected_output = 56
    assert Helpers.duration_to_seconds(input_duration) == expected_output

    input_duration = '0:55.90'
    expected_output = 56
    assert Helpers.duration_to_seconds(input_duration) == expected_output

    input_duration = '0:55.95'
    expected_output = 56
    assert Helpers.duration_to_seconds(input_duration) == expected_output

# Test case 5: invalid input with missing minutes
def test_duration_to_seconds_invalid_missing_minutes():
    input_duration = ':45'
    try:
        Helpers.duration_to_seconds(input_duration)
    except ValueError as e:
        assert str(e) == "Invalid duration format for ':45'."

# Test case 6: invalid input with missing seconds
def test_duration_to_seconds_invalid_missing_seconds():
    input_duration = '1:'
    try:
        Helpers.duration_to_seconds(input_duration)
    except ValueError as e:
        assert str(e) == "Invalid duration format for '1:'."

def test_duration_to_seconds_invalid():
    # Test case 7: invalid input with missing minutes and seconds
    input_duration = ':'
    try:
        Helpers.duration_to_seconds(input_duration)
    except ValueError as e:
        assert str(e) == "Invalid duration format for ':'."

def test_normalize_qid_with_valid_qid():
    assert Helpers.normalize_qid('Q123') == 123
    assert Helpers.normalize_qid('123') == 123
    assert Helpers.normalize_qid(None) == None
    assert Helpers.normalize_qid('') == None

def test_normalize_qid_with_invalid_qid():
    with pytest.raises(ValueError):
        Helpers.normalize_qid('Q')
    with pytest.raises(ValueError):
        Helpers.normalize_qid('Qabc')
    with pytest.raises(ValueError):
        Helpers.normalize_qid('abc')
