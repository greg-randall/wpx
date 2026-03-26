from wpx import _is_version_affected, _ver_status
from wpx_output import strip_ansi


# --- _is_version_affected ---

def test_affected_when_older():
    assert _is_version_affected("1.2.0", "1.3.0") is True


def test_not_affected_when_equal():
    assert _is_version_affected("1.3.0", "1.3.0") is False


def test_not_affected_when_newer():
    assert _is_version_affected("2.0.0", "1.3.0") is False


def test_affected_when_no_fix():
    assert _is_version_affected("1.0.0", None) is True
    assert _is_version_affected("1.0.0", "N/A") is True


def test_affected_when_version_unknown():
    assert _is_version_affected("Unknown", "1.3.0") is True
    assert _is_version_affected(None, "1.3.0") is True


def test_affected_when_unparseable():
    assert _is_version_affected("bad-ver", "1.0.0") is True


# --- _ver_status ---

def test_ver_status_unknown_version():
    assert _ver_status({"version": "Unknown"}, None) == "Unknown"


def test_ver_status_no_api_result():
    assert _ver_status({"version": "1.0.0"}, None) == "1.0.0"


def test_ver_status_up_to_date():
    result = strip_ansi(_ver_status({"version": "1.2.0"}, {"latest_version": "1.2.0"}))
    assert "up to date" in result
    assert "1.2.0" in result


def test_ver_status_outdated():
    result = strip_ansi(_ver_status({"version": "1.0.0"}, {"latest_version": "1.2.0"}))
    assert "outdated" in result
    assert "1.2.0" in result


def test_ver_status_no_latest_in_api():
    result = _ver_status({"version": "1.0.0"}, {"other_key": "x"})
    assert result == "1.0.0"
