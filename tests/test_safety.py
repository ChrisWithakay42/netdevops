"""Pre-activation checks: pure functions over live state, no firewall needed."""

from netdevops.safety import pass_all_rules, stray_uuids

PASS_ALL = {
    "enabled": "1",
    "action": "pass",
    "interface": "lan,opt1,opt2",
    "source_net": "any",
    "source_not": "0",
    "destination_net": "any",
    "destination_not": "0",
    "destination_port": "",
    "description": "",
}


def test_stray_uuids_none_when_only_our_creates_appeared():
    before = {"a", "b", "c"}
    after = {"a", "b", "new1"}
    assert stray_uuids(before, after, created={"new1"}, deleted={"c"}) == set()


def test_stray_uuids_reports_a_uuid_nobody_created():
    # the 2026-11-13 failure: a set on a mistyped uuid created a new rule
    before = {"a", "b"}
    after = {"a", "b", "rogue"}
    assert stray_uuids(before, after, created=set(), deleted=set()) == {"rogue"}


def test_pass_all_detects_default_rule_signature():
    assert pass_all_rules({"u1": PASS_ALL}, allowed=set()) == ["u1"]


def test_pass_all_ignores_disabled_restricted_and_allowed():
    disabled = PASS_ALL | {"enabled": "0"}
    with_source = PASS_ALL | {"source_net": "opt5"}
    with_port = PASS_ALL | {"destination_port": "443"}
    blocking = PASS_ALL | {"action": "block"}
    inverted = PASS_ALL | {"destination_not": "1"}
    allowed = PASS_ALL | {"description": "Owner-approved any-any"}
    live = {
        "d": disabled,
        "s": with_source,
        "p": with_port,
        "b": blocking,
        "i": inverted,
        "a": allowed,
    }
    assert pass_all_rules(live, allowed={"Owner-approved any-any"}) == []
