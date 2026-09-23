"""Diff/plan engine: pure-data tests, no firewall needed."""

from netdevops.diff import build_plan, rule_payload
from netdevops.models import Alias, Intent, Rule

RULE = Rule(
    description="Allow web",
    interface=["lan"],
    sequence=100,
    action="pass",
    protocol="TCP",
    destination_net="any",
    destination_port="443",
    log=True,
)

# what the firewall would hold after applying RULE (flattened API form)
LIVE_RULE = {
    "enabled": "1",
    "sequence": "100",
    "action": "pass",
    "quick": "1",
    "interface": "lan",
    "direction": "in",
    "ipprotocol": "inet",
    "protocol": "TCP",
    "source_net": "any",
    "source_not": "0",
    "source_port": "",
    "destination_net": "any",
    "destination_not": "0",
    "destination_port": "443",
    "log": "1",
    "description": "Allow web",
}


def plan_for(intent, live_rules=None, live_aliases=None, live_snat=None):
    return build_plan(intent, live_aliases or {}, live_rules or {}, live_snat or {})


def test_no_changes_when_live_matches_intent():
    plan = plan_for(Intent(rules=[RULE]), live_rules={"uuid-1": dict(LIVE_RULE)})
    assert plan.empty and not plan.unmanaged


def test_missing_rule_is_created():
    plan = plan_for(Intent(rules=[RULE]))
    assert [change.label for change in plan.creates] == ["seq 100: Allow web"]
    assert plan.creates[0].payload == rule_payload(RULE)


def test_field_drift_is_detected():
    live = dict(LIVE_RULE, destination_port="80", log="0")
    plan = plan_for(Intent(rules=[RULE]), live_rules={"uuid-1": live})
    (change,) = plan.updates
    assert change.uuid == "uuid-1"
    assert sorted(change.changed) == ["destination_port", "log"]


def test_interface_order_is_not_drift():
    rule = RULE.model_copy(update={"interface": ["opt1", "lan"]})
    live = dict(LIVE_RULE, interface="lan,opt1")
    plan = plan_for(Intent(rules=[rule]), live_rules={"uuid-1": live})
    assert plan.empty


def test_live_only_rule_reported_not_deleted():
    plan = plan_for(Intent(), live_rules={"uuid-9": dict(LIVE_RULE)})
    assert plan.empty
    assert [change.label for change in plan.unmanaged] == ["Allow web"]
    assert plan.unmanaged[0].uuid == "uuid-9"


def test_alias_content_compared_as_set():
    alias = Alias(name="_dcs", type="host", content=["10.0.0.2", "10.0.0.1"])
    live = {
        "u1": {
            "enabled": "1",
            "name": "_dcs",
            "type": "host",
            "content": "10.0.0.1,10.0.0.2",  # flattened selected options
            "description": "",
        }
    }
    plan = plan_for(Intent(aliases=[alias]), live_aliases=live)
    assert plan.empty


def test_alias_content_change_detected():
    alias = Alias(name="_dcs", type="host", content=["10.0.0.1", "10.0.0.3"])
    live = {
        "u1": {
            "enabled": "1",
            "name": "_dcs",
            "type": "host",
            "content": "10.0.0.1,10.0.0.2",
            "description": "",
        }
    }
    plan = plan_for(Intent(aliases=[alias]), live_aliases=live)
    (change,) = plan.updates
    assert change.changed == ["content"]
