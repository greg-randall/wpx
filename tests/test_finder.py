import re
import time
import pytest
from wpx_finder import ScanIdleTimeout


# --- _extract_version ---

def test_extract_version_named_group(finder):
    m = re.search(r'(?P<v>[\d.]+)', "version 1.2.3")
    assert finder._extract_version(m) == "1.2.3"


def test_extract_version_positional_group(finder):
    m = re.search(r'([\d.]+)', "version 1.2.3")
    assert finder._extract_version(m) == "1.2.3"


def test_extract_version_no_groups(finder):
    m = re.search(r'[\d.]+', "1.2.3")
    assert finder._extract_version(m) == "1.2.3"


# --- find_version_from_content: HeaderPattern ---

def test_find_version_header_pattern(finder):
    pattern = re.compile(r'(?P<v>[\d.]+)')
    rules = {"HeaderPattern": {"header": "X-WP-Version", "pattern": pattern}}
    headers = {"X-WP-Version": "5.9.3"}
    ver, conf, found_by, _ = finder.find_version_from_content("", headers, rules)
    assert ver == "5.9.3"
    assert conf == 100
    assert "HeaderPattern" in found_by


def test_find_version_header_case_insensitive(finder):
    pattern = re.compile(r'(?P<v>[\d.]+)')
    rules = {"HeaderPattern": {"header": "x-wp-version", "pattern": pattern}}
    headers = {"X-WP-Version": "6.0.0"}
    ver, conf, _, _ = finder.find_version_from_content("", headers, rules)
    assert ver == "6.0.0"


def test_find_version_header_no_match(finder):
    pattern = re.compile(r'(?P<v>[\d.]+)')
    rules = {"HeaderPattern": {"header": "X-WP-Version", "pattern": pattern}}
    ver, conf, found_by, _ = finder.find_version_from_content("", {}, rules)
    assert ver == "Unknown"
    assert conf == 0
    assert found_by is None


# --- find_version_from_content: QueryParameter ---

def test_find_version_query_parameter(finder):
    finder.homepage_content = (
        '<link rel="stylesheet" href="/wp-content/plugins/my-plugin/style.css?ver=2.1.0">'
    )
    rules = {"QueryParameter": {"files": ["style.css"]}}
    ver, conf, found_by, src = finder.find_version_from_content("", {}, rules, slug="my-plugin")
    assert ver == "2.1.0"
    assert conf == 100
    assert "QueryParameter" in found_by
    assert "ver=2.1.0" in src


def test_find_version_query_parameter_wrong_plugin(finder):
    finder.homepage_content = (
        '<link rel="stylesheet" href="/wp-content/plugins/other-plugin/style.css?ver=2.1.0">'
    )
    rules = {"QueryParameter": {"files": ["style.css"]}}
    ver, conf, _, _ = finder.find_version_from_content("", {}, rules, slug="my-plugin")
    assert ver == "Unknown"


def test_find_version_no_rules(finder):
    ver, conf, found_by, _ = finder.find_version_from_content("body", {}, {})
    assert ver == "Unknown"
    assert conf == 0


# --- detect_multisite ---

def test_detect_multisite_found(mocker, finder):
    signup_resp = mocker.MagicMock()
    signup_resp.status_code = 200
    signup_resp.text = "Welcome! Create a new site here."

    activate_resp = mocker.MagicMock()
    activate_resp.status_code = 200
    activate_resp.text = "Activation key"

    finder.core.session.get.side_effect = [signup_resp, activate_resp]
    finder.detect_multisite()

    assert finder.multisite is not None
    assert finder.multisite["confidence"] == 100
    assert "wp-signup.php" in finder.multisite["url"]


def test_detect_multisite_signup_404(mocker, finder):
    resp = mocker.MagicMock()
    resp.status_code = 404
    finder.core.session.get.return_value = resp
    finder.detect_multisite()
    assert finder.multisite is None


def test_detect_multisite_no_keywords(mocker, finder):
    resp = mocker.MagicMock()
    resp.status_code = 200
    resp.text = "This is a normal WordPress page with no registration forms."
    finder.core.session.get.return_value = resp
    finder.detect_multisite()
    assert finder.multisite is None


def test_detect_multisite_90_confidence_when_activate_fails(mocker, finder):
    signup_resp = mocker.MagicMock()
    signup_resp.status_code = 200
    signup_resp.text = "Create a new site here"

    activate_resp = mocker.MagicMock()
    activate_resp.status_code = 403

    finder.core.session.get.side_effect = [signup_resp, activate_resp]
    finder.detect_multisite()

    assert finder.multisite is not None
    assert finder.multisite["confidence"] == 90


# --- _probe_author_archives ---

def test_probe_author_archives_redirect(mocker, finder):
    tech = {"name": "Author Archive (?author=N)", "confidence": 85}
    resp = mocker.MagicMock()
    resp.status_code = 301
    resp.headers = {"Location": "https://example.com/author/janedoe/"}
    finder.core.session.get.return_value = resp

    seen = set()
    finder._probe_author_archives(tech, users_limit=1, base="https://example.com", seen_slugs=seen)

    assert len(finder.found_users) == 1
    assert finder.found_users[0]["login"] == "janedoe"
    assert finder.found_users[0]["id"] == 1


def test_probe_author_archives_blocked(mocker, finder):
    tech = {"name": "Author Archive (?author=N)", "confidence": 85}
    resp = mocker.MagicMock()
    resp.status_code = 404
    finder.core.session.get.return_value = resp

    seen = set()
    finder._probe_author_archives(tech, users_limit=2, base="https://example.com", seen_slugs=seen)

    assert finder.found_users == []
    assert tech["name"] in finder.user_enum_blocked


def test_probe_author_archives_deduplication(mocker, finder):
    tech = {"name": "Author Archive (?author=N)", "confidence": 85}
    resp = mocker.MagicMock()
    resp.status_code = 301
    resp.headers = {"Location": "https://example.com/author/admin/"}
    finder.core.session.get.return_value = resp

    seen = {"admin"}  # already known
    finder._probe_author_archives(tech, users_limit=1, base="https://example.com", seen_slugs=seen)
    assert finder.found_users == []  # not added again


# --- _stealth_delay ---

def test_stealth_delay_sleeps_when_active(mocker, finder):
    finder.stealth = 1.5
    mock_sleep = mocker.patch("wpx_finder.time.sleep")
    finder._stealth_delay()
    mock_sleep.assert_called_once()
    delay = mock_sleep.call_args[0][0]
    assert 1.0 <= delay <= 3.0


def test_stealth_delay_noop_when_none(mocker, finder):
    finder.stealth = None
    mock_sleep = mocker.patch("wpx_finder.time.sleep")
    finder._stealth_delay()
    mock_sleep.assert_not_called()


def test_stealth_delay_range_scales_with_value(mocker, finder):
    finder.stealth = 10.0
    mock_sleep = mocker.patch("wpx_finder.time.sleep")
    # call several times to check the range stays within 1–20s
    for _ in range(20):
        finder._stealth_delay()
    for call in mock_sleep.call_args_list:
        delay = call[0][0]
        assert 1.0 <= delay <= 20.0


# --- _touch_response / _check_idle ---

def test_touch_response_resets_clock(finder):
    finder.last_response_time = 0.0  # very old
    finder._touch_response()
    assert time.time() - finder.last_response_time < 1.0


def test_check_idle_raises_when_expired(finder):
    finder.idle_timeout = 30
    finder.last_response_time = time.time() - 60  # 60s ago
    with pytest.raises(ScanIdleTimeout):
        finder._check_idle()


def test_check_idle_silent_within_window(finder):
    finder.idle_timeout = 60
    finder.last_response_time = time.time()  # just now
    finder._check_idle()  # should not raise


def test_check_idle_disabled_when_zero(finder):
    finder.idle_timeout = 0
    finder.last_response_time = time.time() - 9999  # ancient
    finder._check_idle()  # should not raise
