import pytest
import sys
from wpx import _parse_enumerate, _ALL_TOKENS


# --- _parse_enumerate: default (no value) ---

def test_parse_enumerate_none_returns_all_tokens():
    assert _parse_enumerate(None) == _ALL_TOKENS


def test_parse_enumerate_empty_string_returns_all_tokens():
    assert _parse_enumerate("") == _ALL_TOKENS


# --- _parse_enumerate: valid single tokens ---

def test_parse_enumerate_plugins():
    assert _parse_enumerate("p") == {"p"}


def test_parse_enumerate_users():
    assert _parse_enumerate("u") == {"u"}


def test_parse_enumerate_config_backups():
    assert _parse_enumerate("cb") == {"cb"}


def test_parse_enumerate_theme():
    assert _parse_enumerate("t") == {"t"}


# --- _parse_enumerate: combinations ---

def test_parse_enumerate_plugins_and_users():
    assert _parse_enumerate("p,u") == {"p", "u"}


def test_parse_enumerate_plugins_users_backups():
    assert _parse_enumerate("p,u,cb") == {"p", "u", "cb"}


def test_parse_enumerate_all_tokens_explicit():
    assert _parse_enumerate("p,u,cb,t") == {"p", "u", "cb", "t"}


def test_parse_enumerate_whitespace_stripped():
    assert _parse_enumerate("p, u, cb") == {"p", "u", "cb"}


def test_parse_enumerate_uppercase_normalised():
    assert _parse_enumerate("P,U,CB") == {"p", "u", "cb"}


# --- _parse_enumerate: invalid tokens ---

def test_parse_enumerate_invalid_token_exits(capsys):
    with pytest.raises(SystemExit) as exc_info:
        _parse_enumerate("x")
    assert exc_info.value.code == 2


def test_parse_enumerate_invalid_token_prints_warning(capsys):
    with pytest.raises(SystemExit):
        _parse_enumerate("vp")
    # warning goes to stdout via print_warn
    captured = capsys.readouterr()
    assert "vp" in captured.out


def test_parse_enumerate_mixed_valid_invalid_exits(capsys):
    with pytest.raises(SystemExit):
        _parse_enumerate("p,z")


# --- token boolean derivation ---

def test_do_flags_from_all_tokens():
    tokens = _parse_enumerate(None)
    assert "p" in tokens
    assert "u" in tokens
    assert "cb" in tokens
    assert "t" in tokens


def test_do_flags_users_only():
    tokens = _parse_enumerate("u")
    assert "p" not in tokens
    assert "u" in tokens
    assert "cb" not in tokens
    assert "t" not in tokens


def test_do_flags_plugins_and_backups():
    tokens = _parse_enumerate("p,cb")
    assert "p" in tokens
    assert "cb" in tokens
    assert "u" not in tokens
    assert "t" not in tokens
