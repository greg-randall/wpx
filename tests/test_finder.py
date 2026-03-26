import re


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
