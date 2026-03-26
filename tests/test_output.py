from wpx_output import strip_ansi


def test_strip_ansi_removes_color_codes():
    assert strip_ansi("\033[31mred\033[0m") == "red"


def test_strip_ansi_removes_bold():
    assert strip_ansi("\033[1mbold\033[0m") == "bold"


def test_strip_ansi_passthrough_plain():
    assert strip_ansi("plain text") == "plain text"


def test_strip_ansi_empty():
    assert strip_ansi("") == ""


def test_strip_ansi_mixed():
    assert strip_ansi("\033[32mgreen\033[0m and plain") == "green and plain"
