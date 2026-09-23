"""Model validation: structurally invalid intent must never load."""

import pydantic
import pytest

from netdevops.models import Alias, Intent, Rule


def _rule(**overrides):
    base = dict(
        description="test", interface=["lan"], sequence=10, action="pass",
    )
    base.update(overrides)
    return base


def test_rejects_unknown_interface():
    with pytest.raises(pydantic.ValidationError, match="unknown interface"):
        Rule(**_rule(interface=["opt99"]))


def test_rejects_bad_action():
    with pytest.raises(pydantic.ValidationError):
        Rule(**_rule(action="allow"))


def test_rejects_unknown_alias_reference():
    with pytest.raises(pydantic.ValidationError, match="not an alias"):
        Intent(rules=[Rule(**_rule(destination_net="_no_such_alias"))])


def test_rejects_duplicate_sequence():
    with pytest.raises(pydantic.ValidationError, match="sequence 10 already used"):
        Intent(rules=[Rule(**_rule()), Rule(**_rule(description="other"))])


def test_rejects_duplicate_match_key():
    with pytest.raises(pydantic.ValidationError, match="duplicate .interface"):
        Intent(rules=[Rule(**_rule()), Rule(**_rule(sequence=20))])


def test_rejects_port_alias_of_wrong_type():
    host_alias = Alias(name="_hosts", type="host", content=["10.0.0.1"])
    with pytest.raises(pydantic.ValidationError, match="port"):
        Intent(aliases=[host_alias], rules=[Rule(**_rule(destination_port="_hosts"))])


def test_rejects_invalid_alias_content():
    with pytest.raises(pydantic.ValidationError, match="invalid network entry"):
        Alias(name="_bad", type="network", content=["not-a-network"])


def test_rejects_invalid_vip():
    with pytest.raises(pydantic.ValidationError):
        Intent(vips=["not-an-ip"])


def test_accepts_self_token():
    intent = Intent(rules=[Rule(**_rule(destination_net="(self)"))])
    assert intent.rules[0].destination_net == "(self)"
