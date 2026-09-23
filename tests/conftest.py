from pathlib import Path

import pytest

from netdevops.intent import load_intent
from netdevops.policy import PolicyEvaluator

REPO = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="session")
def intent():
    """The repo's own intent files. Policy tests run against these.

    Until `netdevops import <export.xml>` has populated network/, tests that
    need real intent are skipped rather than failed.
    """
    loaded = load_intent(REPO / "network")
    if not loaded.rules:
        pytest.skip("network/ is empty; bootstrap it with `netdevops import <export.xml>`")
    return loaded


@pytest.fixture(scope="session")
def evaluator(intent):
    return PolicyEvaluator(intent)


@pytest.fixture(scope="session")
def synthetic_export():
    """A made-up OPNsense config export used to test the engine itself."""
    return FIXTURES / "config-synthetic.xml"
