import asyncio
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


# --- stealth delay call sites: check_core_files ---

def test_check_core_files_stealth_delay_called_per_request(mocker, finder):
    finder.stealth = 1.5
    mock_delay = mocker.patch.object(finder, "_stealth_delay")

    resp = mocker.MagicMock()
    resp.status_code = 404
    finder.core.session.get.return_value = resp

    finder.check_core_files()

    # 4 files → 4 delays
    assert mock_delay.call_count == 4


def test_check_core_files_no_delay_without_stealth(mocker, finder):
    finder.stealth = None
    mock_sleep = mocker.patch("wpx_finder.time.sleep")

    resp = mocker.MagicMock()
    resp.status_code = 404
    finder.core.session.get.return_value = resp

    finder.check_core_files()

    mock_sleep.assert_not_called()


# --- stealth delay call sites: detect_multisite ---

def test_detect_multisite_stealth_delay_called(mocker, finder):
    finder.stealth = 1.5
    mock_delay = mocker.patch.object(finder, "_stealth_delay")

    resp = mocker.MagicMock()
    resp.status_code = 404
    finder.core.session.get.return_value = resp

    finder.detect_multisite()

    # at least the signup request must have been preceded by a delay
    assert mock_delay.call_count >= 1


def test_detect_multisite_no_delay_without_stealth(mocker, finder):
    finder.stealth = None
    mock_sleep = mocker.patch("wpx_finder.time.sleep")

    resp = mocker.MagicMock()
    resp.status_code = 404
    finder.core.session.get.return_value = resp

    finder.detect_multisite()

    mock_sleep.assert_not_called()


# --- detect_wp_version ---

def test_detect_wp_version_from_meta_generator(mocker, finder):
    content = '<meta name="generator" content="WordPress 6.4.2" />'

    # RSS confirmation request returns no match
    rss_resp = mocker.MagicMock()
    rss_resp.text = "<rss>no version here</rss>"
    finder.core.session.get.return_value = rss_resp

    # _check_wp_latest hits api.wordpress.org — stub it out
    mocker.patch.object(finder, "_check_wp_latest", return_value=(True, "6.4.2", "2024-01-01"))

    result = finder.detect_wp_version(content)

    assert result is not None
    assert result["version"] == "6.4.2"
    assert result["found_by"] == "Meta Generator (Passive Detection)"


def test_detect_wp_version_from_rss_only(mocker, finder):
    content = "<html>no generator tag here</html>"

    rss_resp = mocker.MagicMock()
    rss_resp.text = (
        "<rss><channel>"
        "<generator>https://wordpress.org/?v=6.3.1</generator>"
        "</channel></rss>"
    )
    finder.core.session.get.return_value = rss_resp

    mocker.patch.object(finder, "_check_wp_latest", return_value=(False, "6.4.2", "2024-01-01"))

    result = finder.detect_wp_version(content)

    assert result is not None
    assert result["version"] == "6.3.1"
    assert result["found_by"] == "Rss Generator (Aggressive Detection)"


def test_detect_wp_version_returns_none_when_not_found(mocker, finder):
    content = "<html>no generator</html>"

    rss_resp = mocker.MagicMock()
    rss_resp.text = "<rss>nothing useful</rss>"
    finder.core.session.get.return_value = rss_resp

    result = finder.detect_wp_version(content)

    assert result is None


def test_detect_wp_version_stealth_delay_called(mocker, finder):
    finder.stealth = 1.5
    mock_delay = mocker.patch.object(finder, "_stealth_delay")

    rss_resp = mocker.MagicMock()
    rss_resp.text = "<rss>nothing</rss>"
    finder.core.session.get.return_value = rss_resp

    finder.detect_wp_version("<html></html>")

    assert mock_delay.call_count >= 1


# --- async stealth delay: _scan_plugins_async ---

@pytest.mark.asyncio
async def test_scan_plugins_async_stealth_delay_awaited(mocker, finder):
    finder.stealth = 2.0

    sleep_calls = []

    async def fake_sleep(duration):
        sleep_calls.append(duration)

    mocker.patch("wpx_finder.asyncio.sleep", side_effect=fake_sleep)

    mock_resp = mocker.MagicMock()
    mock_resp.status_code = 404

    async def fake_get(*args, **kwargs):
        return mock_resp

    mock_session = mocker.MagicMock()
    mock_session.get = fake_get
    mock_session.__aenter__ = mocker.AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = mocker.AsyncMock(return_value=False)

    mocker.patch("curl_cffi.requests.AsyncSession", return_value=mock_session)
    mocker.patch("wpx_finder.print_progress")
    mocker.patch("wpx_finder.print_progress_done")

    await finder._scan_plugins_async(["akismet", "jetpack"], concurrency=1)

    assert len(sleep_calls) == 2
    for d in sleep_calls:
        assert 1.0 <= d <= 4.0  # stealth=2.0 → uniform(1.0, 4.0)


@pytest.mark.asyncio
async def test_scan_plugins_async_no_sleep_without_stealth(mocker, finder):
    finder.stealth = None

    sleep_calls = []

    async def fake_sleep(duration):
        sleep_calls.append(duration)

    mocker.patch("wpx_finder.asyncio.sleep", side_effect=fake_sleep)

    mock_resp = mocker.MagicMock()
    mock_resp.status_code = 404

    async def fake_get(*args, **kwargs):
        return mock_resp

    mock_session = mocker.MagicMock()
    mock_session.get = fake_get
    mock_session.__aenter__ = mocker.AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = mocker.AsyncMock(return_value=False)

    mocker.patch("curl_cffi.requests.AsyncSession", return_value=mock_session)
    mocker.patch("wpx_finder.print_progress")
    mocker.patch("wpx_finder.print_progress_done")

    await finder._scan_plugins_async(["akismet", "jetpack"], concurrency=2)

    assert sleep_calls == []


# --- async stealth delay: _detect_versions_async ---

@pytest.mark.asyncio
async def test_detect_versions_async_stealth_delay_awaited(mocker, finder):
    finder.stealth = 2.0
    finder.found_plugins = {"akismet": {}}
    finder.threads = 1

    sleep_calls = []

    async def fake_sleep(duration):
        sleep_calls.append(duration)

    mocker.patch("wpx_finder.asyncio.sleep", side_effect=fake_sleep)

    # data returns a Readme rule for the plugin
    finder.data.get_plugin_rules.return_value = {"Readme": {"path": "readme.txt"}}

    mock_resp = mocker.MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "Stable tag: 1.2.3"

    async def fake_get(*args, **kwargs):
        return mock_resp

    mock_session = mocker.MagicMock()
    mock_session.get = fake_get
    mock_session.__aenter__ = mocker.AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = mocker.AsyncMock(return_value=False)

    mocker.patch("curl_cffi.requests.AsyncSession", return_value=mock_session)
    mocker.patch("wpx_finder.print_progress")
    mocker.patch("wpx_finder.print_progress_done")

    await finder._detect_versions_async()

    assert len(sleep_calls) == 1
    assert 1.0 <= sleep_calls[0] <= 4.0


@pytest.mark.asyncio
async def test_detect_versions_async_no_sleep_without_stealth(mocker, finder):
    finder.stealth = None
    finder.found_plugins = {"akismet": {}}
    finder.threads = 2

    sleep_calls = []

    async def fake_sleep(duration):
        sleep_calls.append(duration)

    mocker.patch("wpx_finder.asyncio.sleep", side_effect=fake_sleep)

    finder.data.get_plugin_rules.return_value = {"Readme": {"path": "readme.txt"}}

    mock_resp = mocker.MagicMock()
    mock_resp.status_code = 404

    async def fake_get(*args, **kwargs):
        return mock_resp

    mock_session = mocker.MagicMock()
    mock_session.get = fake_get
    mock_session.__aenter__ = mocker.AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = mocker.AsyncMock(return_value=False)

    mocker.patch("curl_cffi.requests.AsyncSession", return_value=mock_session)
    mocker.patch("wpx_finder.print_progress")
    mocker.patch("wpx_finder.print_progress_done")

    await finder._detect_versions_async()

    assert sleep_calls == []
