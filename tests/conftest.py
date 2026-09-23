from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="session")
def synthetic_export():
    """A made-up OPNsense config export used to test the engine itself."""
    return FIXTURES / "config-synthetic.xml"
