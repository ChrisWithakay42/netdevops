"""Apply orchestration against an in-memory fake firewall."""

import pytest

from netdevops.apply import ApplyAborted, fetch_live, plan_from_live, run_apply
from netdevops.models import Alias, Intent, Rule, VirtualIP

RULE = Rule(
    description="Allow web",
    interface=["lan"],
    sequence=100,
    action="pass",
    protocol="TCP",
    destination_port="443",
)
ROGUE = {
    "enabled": "1",
    "action": "pass",
    "interface": "lan,wan",
    "source_net": "any",
    "destination_net": "any",
    "destination_port": "",
    "description": "",
}


class FakeFirewall:
    """Holds flat rows per kind and records every call in order."""

    def __init__(self):
        self.aliases: dict[str, dict] = {}
        self.rules: dict[str, dict] = {}
        self.snat: dict[str, dict] = {}
        self.vips: dict[str, dict] = {}
        self.calls: list[str] = []
        self.counter = 0
        self.on_rule_write = None  # hook to simulate firewall misbehaviour

    def _new_uuid(self):
        self.counter += 1
        return f"00000000-0000-4000-8000-{self.counter:012d}"

    # reads
    def get_aliases(self):
        return dict(self.aliases)

    def get_filter_model(self):
        return dict(self.rules), dict(self.snat)

    def get_vips(self):
        return dict(self.vips)

    def download_config(self):
        self.calls.append("backup")
        return b"<opnsense/>"

    # writes
    def add_alias(self, payload):
        self.calls.append("add_alias")
        uuid = self._new_uuid()
        self.aliases[uuid] = dict(payload)
        return uuid

    def add_rule(self, payload):
        self.calls.append("add_rule")
        uuid = self._new_uuid()
        self.rules[uuid] = dict(payload)
        if self.on_rule_write:
            self.on_rule_write(self)
        return uuid

    def set_rule(self, uuid, payload):
        self.calls.append("set_rule")
        self.rules[uuid] = dict(payload)
        if self.on_rule_write:
            self.on_rule_write(self)

    def del_rule(self, uuid):
        self.calls.append(f"del_rule {uuid}")
        del self.rules[uuid]

    def add_vip(self, payload):
        self.calls.append("add_vip")
        uuid = self._new_uuid()
        address, bits = payload["network"].split("/")
        self.vips[uuid] = {
            "mode": "ipalias",
            "interface": payload["interface"],
            "subnet": address,
            "subnet_bits": bits,
            "descr": payload["descr"],
        }
        return uuid

    def del_vip(self, uuid):
        self.calls.append("del_vip")

    def reconfigure_aliases(self):
        self.calls.append("reconfigure_aliases")

    def reconfigure_vips(self):
        self.calls.append("reconfigure_vips")

    def apply_filter(self):
        self.calls.append("apply_filter")


def apply(firewall, intent, prune=False, backup=None):
    live = fetch_live(firewall)
    plan = plan_from_live(intent, live)
    run_apply(
        firewall, intent, plan, live, prune=prune,
        backup=backup or (lambda: firewall.download_config()), echo=lambda message: None,
    )
    return plan


def test_stages_run_in_order_with_backup_first():
    firewall = FakeFirewall()
    intent = Intent(
        aliases=[Alias(name="DNS_SERVER", type="host", content=["10.20.0.53"])],
        virtual_ips=[VirtualIP(address="10.20.0.53/32", interface="lo0")],
        rules=[RULE],
    )
    apply(firewall, intent)
    assert firewall.calls == [
        "backup",
        "add_alias", "reconfigure_aliases",
        "add_vip", "reconfigure_vips",
        "add_rule", "apply_filter",
    ]


def test_second_apply_is_a_no_op():
    firewall = FakeFirewall()
    intent = Intent(virtual_ips=[VirtualIP(address="10.20.0.53/32", interface="lo0")])
    apply(firewall, intent)
    firewall.calls.clear()
    plan = apply(firewall, intent)
    assert plan.empty
    assert firewall.calls == []


def test_stray_rule_is_removed_and_filter_never_applied():
    firewall = FakeFirewall()

    def spawn_rogue(fw):
        if "11111111-1111-4111-8111-111111111111" not in fw.rules:
            fw.rules["11111111-1111-4111-8111-111111111111"] = dict(ROGUE)

    firewall.on_rule_write = spawn_rogue
    with pytest.raises(ApplyAborted, match="stray"):
        apply(firewall, Intent(rules=[RULE]))
    assert "apply_filter" not in firewall.calls
    assert "del_rule 11111111-1111-4111-8111-111111111111" in firewall.calls


def test_pass_all_rule_blocks_activation():
    firewall = FakeFirewall()
    firewall.rules["22222222-2222-4222-8222-222222222222"] = dict(ROGUE, description="old")
    with pytest.raises(ApplyAborted, match="pass any"):
        apply(firewall, Intent(rules=[RULE]))
    assert "apply_filter" not in firewall.calls


def test_pass_all_allowed_when_intent_says_so():
    firewall = FakeFirewall()
    allowed = Rule(
        description="Lab any-any", interface=["lan"], sequence=5, action="pass",
        allow_any_any=True,
    )
    apply(firewall, Intent(rules=[allowed]))
    assert firewall.calls[-1] == "apply_filter"


def test_prune_never_deletes_vips():
    firewall = FakeFirewall()
    firewall.vips["33333333-3333-4333-8333-333333333333"] = {
        "mode": "ipalias", "interface": "opt5", "subnet": "192.168.50.1",
        "subnet_bits": "29", "descr": "old ADM gateway",
    }
    apply(firewall, Intent(), prune=True)
    assert "del_vip" not in firewall.calls


def test_no_backup_no_writes():
    firewall = FakeFirewall()

    def failing_backup():
        raise OSError("disk full")

    with pytest.raises(OSError):
        apply(firewall, Intent(rules=[RULE]), backup=failing_backup)
    assert firewall.rules == {}
