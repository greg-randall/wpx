import re
import yaml


def test_ruby_regexp_simple():
    from wpx_data import WPXData
    data = WPXData.__new__(WPXData)

    node = yaml.ScalarNode(tag="!ruby/regexp", value="/foo/")
    loader = yaml.SafeLoader("")
    result = data._ruby_regexp_constructor(loader, node)
    assert isinstance(result, re.Pattern)
    assert result.search("foo") is not None


def test_ruby_regexp_case_insensitive():
    from wpx_data import WPXData
    data = WPXData.__new__(WPXData)

    node = yaml.ScalarNode(tag="!ruby/regexp", value="/FOO/i")
    loader = yaml.SafeLoader("")
    result = data._ruby_regexp_constructor(loader, node)
    assert result.flags & re.IGNORECASE
    assert result.search("foo") is not None


def test_ruby_regexp_named_group_conversion():
    from wpx_data import WPXData
    data = WPXData.__new__(WPXData)

    node = yaml.ScalarNode(tag="!ruby/regexp", value="/(?<v>[0-9.]+)/")
    loader = yaml.SafeLoader("")
    result = data._ruby_regexp_constructor(loader, node)
    m = result.search("version 1.2.3")
    assert m and m.group("v") == "1.2.3"


def test_ruby_regexp_bad_pattern_returns_never_match():
    from wpx_data import WPXData
    data = WPXData.__new__(WPXData)

    node = yaml.ScalarNode(tag="!ruby/regexp", value="/(?P<bad[/")
    loader = yaml.SafeLoader("")
    result = data._ruby_regexp_constructor(loader, node)
    assert result.search("anything") is None
