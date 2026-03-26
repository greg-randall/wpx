import pytest


@pytest.fixture
def mock_core(mocker):
    """Minimal WPXCore stub with a session and target_url."""
    core = mocker.MagicMock()
    core.target_url = "https://example.com"
    return core


@pytest.fixture
def mock_data(mocker):
    """Minimal WPXData stub."""
    return mocker.MagicMock()


@pytest.fixture
def finder(mock_core, mock_data):
    from wpx_finder import WPXFinder
    return WPXFinder(mock_core, mock_data)
