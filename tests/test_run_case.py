"""Unit tests for the parts of harness/run_case.py that need no case checkout."""

from harness.run_case import error_fields

GATEWAY_422 = (
    "Error code: 422 - {'error': {'message': 'Budget has been exceeded! "
    "Key=team-alias-1234-abcd (sk-...zZ9q) Current cost: 1.0053221, Max budget: 1.0'}}"
)


def caught(message: str) -> tuple[str, str]:
    try:
        raise RuntimeError(message)
    except RuntimeError as exc:
        return error_fields(exc)


def test_recorded_error_keeps_the_type_and_the_message():
    error, _ = caught("setup.sh exited 1")
    assert error == "RuntimeError: setup.sh exited 1"


def test_recorded_error_does_not_name_the_key():
    # record.json is committed: 10 of them carried the gateway key alias (2026-10-18).
    error, _ = caught(GATEWAY_422)
    assert "Budget has been exceeded" in error
    assert "team-alias-1234-abcd" not in error and "zZ9q" not in error


def test_saved_traceback_does_not_name_the_key():
    # traceback.txt is committed too, and repeats the exception message.
    _, trace = caught(GATEWAY_422)
    assert trace.startswith("Traceback")
    assert "team-alias-1234-abcd" not in trace and "zZ9q" not in trace
