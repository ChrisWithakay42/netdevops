"""Apply orchestration against an in-memory fake firewall."""

import pytest

from netdevops.apply import ApplyAborted, fetch_live, plan_from_live, run_apply
from netdevops.client import WriteGuardError
from netdevops.models import Alias, Intent, Rule, VirtualIP

RULE = Rule(
    description="Allow web",
    interface=["lan"],
    sequence=100,
    action="pass",
    protocol="TCP",
    destination_port="443",
)
DNS_VIP = VirtualIP(address="10.20.0.53/32", interface="lo0")
DNS_ALIAS = Alias(name="DNS_SERVER", type="host", content=["10.20.0.53"])
ROGUE = {
    "enabled": "1",
    "action": "pass",
    "interface": "lan,wan",
    "source_net": "any",
    "destination_net": "any",
    "destination_port": "",
    "description": "",
}
ROGUE_UUID = "11111111-1111-4111-8111-111111111111"
ACTIVATIONS = {"reconfigure_aliases", "reconfigure_vips", "apply_filter"}


class FakeFirewall:
    """Holds flat rows per kind and records every call in order."""

    def __init__(self):
        self.store = {"alias": {}, "rule": {}, "snat": {}, "vip": {}}
        self.calls: list[str] = []
        self.counter = 0
        self.after_write = None  # hook to simulate firewall misbehaviour
        self.fail_on = None  # method name that raises

    def _new_uuid(self):
        self.counter += 1
        return f"00000000-0000-4000-8000-{self.counter:012d}"

    # reads
    def get_aliases(self):
        return dict(self.store["alias"])

    def get_filter_model(self):
        return dict(self.store["rule"]), dict(self.store["snat"])

    def get_vips(self):
        return dict(self.store["vip"])

    # writes (the real client's guards are tested separately)
    def _record(self, name):
        self.calls.append(name)
        if self.fail_on == name:
            raise WriteGuardError(f"simulated failure in {name}")

    def _row(self, kind, payload):
        if kind == "vip":
            address, bits = payload["network"].split("/")
            return {
                "mode": payload["mode"], "interface": payload["interface"],
                "subnet": address, "subnet_bits": bits, "descr": payload["descr"],
            }
        if kind == "alias":
            return dict(payload, content=payload["content"].replace("\n", ","))
        return dict(payload)

    def _add(self, kind, payload):
        self._record(f"add_{kind}")
        uuid = self._new_uuid()
        self.store[kind][uuid] = self._row(kind, payload)
        if self.after_write:
            self.after_write(self)
        return uuid

    def _set(self, kind, uuid, payload):
        self._record(f"set_{kind}")
        self.store[kind][uuid] = self._row(kind, payload)
        if self.after_write:
            self.after_write(self)

    def _del(self, kind, uuid):
        self._record(f"del_{kind} {uuid}")
        del self.store[kind][uuid]

    def __getattr__(self, name):
        operation, _, kind = name.partition("_")
        if operation in ("add", "set", "del") and kind in ("alias", "rule", "snat", "vip"):
            return lambda *args: getattr(self, f"_{operation}")(kind, *args)
        raise AttributeError(name)

    def reconfigure_aliases(self):
        self.calls.append("reconfigure_aliases")

    def reconfigure_vips(self):
        self.calls.append("reconfigure_vips")

    def apply_filter(self):
        self.calls.append("apply_filter")


def apply(firewall, intent, prune=False, backup=None, between_plan_and_apply=None):
    live = fetch_live(firewall)
    plan = plan_from_live(intent, live)
    if between_plan_and_apply:
        between_plan_and_apply(firewall)
    run_apply(
        firewall, intent, plan, live, prune=prune,
        backup=backup or (lambda: firewall.calls.append("backup")),
        echo=lambda message: None,
    )
    return plan


def activated(firewall):
    return [call for call in firewall.calls if call in ACTIVATIONS]


def test_all_writes_and_checks_happen_before_any_activation():
    # alias/reconfigure runs "filter reload" on 26.7, so nothing may be
    # activated until every kind is written and checked
    firewall = FakeFirewall()
    apply(firewall, Intent(aliases=[DNS_ALIAS], virtual_ips=[DNS_VIP], rules=[RULE]))
    assert firewall.calls == [
        "backup",
        "add_alias", "add_vip", "add_rule",
        "reconfigure_aliases", "reconfigure_vips", "apply_filter",
    ]


def test_only_changed_kinds_are_activated():
    firewall = FakeFirewall()
    apply(firewall, Intent(virtual_ips=[DNS_VIP]))
    assert activated(firewall) == ["reconfigure_vips"]


def test_second_apply_is_a_no_op():
    firewall = FakeFirewall()
    intent = Intent(aliases=[DNS_ALIAS], virtual_ips=[DNS_VIP], rules=[RULE])
    apply(firewall, intent)
    firewall.calls.clear()
    plan = apply(firewall, intent)
    assert plan.empty
    assert firewall.calls == []


def test_live_change_after_plan_aborts_before_writes():
    firewall = FakeFirewall()

    def gui_edit(fw):
        fw.store["alias"]["22222222-2222-4222-8222-222222222222"] = {"name": "NEW_IN_GUI"}

    with pytest.raises(ApplyAborted, match="changed since the plan"):
        apply(firewall, Intent(rules=[RULE]), between_plan_and_apply=gui_edit)
    assert firewall.calls == ["backup"]


def test_preexisting_pass_all_aborts_before_writes():
    firewall = FakeFirewall()
    firewall.store["rule"][ROGUE_UUID] = dict(ROGUE, description="old")
    with pytest.raises(ApplyAborted, match="pass any"):
        apply(firewall, Intent(rules=[RULE]))
    assert firewall.calls == ["backup"]


def test_pass_all_stray_is_removed_writes_rolled_back_nothing_activated():
    firewall = FakeFirewall()

    def spawn_rogue(fw):
        fw.store["rule"].setdefault(ROGUE_UUID, dict(ROGUE))

    firewall.after_write = spawn_rogue
    with pytest.raises(ApplyAborted, match="stray"):
        apply(firewall, Intent(aliases=[DNS_ALIAS], rules=[RULE]))
    assert activated(firewall) == []
    assert firewall.store["rule"] == {}  # rogue removed, our rule rolled back
    assert firewall.store["alias"] == {}  # our alias rolled back


def test_ordinary_stray_is_reported_not_deleted():
    # most likely a GUI edit made during the run: never delete someone's work
    firewall = FakeFirewall()
    gui_uuid = "33333333-3333-4333-8333-333333333333"

    def gui_adds_rule(fw):
        fw.store["rule"].setdefault(gui_uuid, {"description": "GUI", "action": "block"})

    firewall.after_write = gui_adds_rule
    with pytest.raises(ApplyAborted, match="stray"):
        apply(firewall, Intent(rules=[RULE]))
    assert gui_uuid in firewall.store["rule"]
    assert activated(firewall) == []


def test_stray_vip_is_never_deleted():
    firewall = FakeFirewall()
    stray_uuid = "55555555-5555-4555-8555-555555555555"

    def spawn_vip(fw):
        fw.store["vip"].setdefault(stray_uuid, {
            "mode": "ipalias", "interface": "opt5", "subnet": "192.168.50.1",
            "subnet_bits": "29", "descr": "appeared",
        })

    firewall.after_write = spawn_vip
    with pytest.raises(ApplyAborted, match="stray"):
        apply(firewall, Intent(virtual_ips=[DNS_VIP]))
    assert stray_uuid in firewall.store["vip"]
    assert activated(firewall) == []


def test_carp_vips_are_not_mistaken_for_strays():
    firewall = FakeFirewall()
    carp_uuid = "44444444-4444-4444-8444-444444444444"
    firewall.store["vip"][carp_uuid] = {
        "mode": "carp", "interface": "lan", "subnet": "192.168.1.2",
        "subnet_bits": "24", "descr": "CARP",
    }
    apply(firewall, Intent(virtual_ips=[DNS_VIP]))
    assert carp_uuid in firewall.store["vip"]
    assert activated(firewall) == ["reconfigure_vips"]


def test_failure_mid_write_rolls_back_creates_and_updates():
    firewall = FakeFirewall()
    existing_uuid = "66666666-6666-4666-8666-666666666666"
    firewall.store["alias"][existing_uuid] = {
        "enabled": "1", "name": "DNS_SERVER", "type": "host",
        "content": "192.168.30.5", "description": "",
    }
    firewall.fail_on = "add_rule"
    intent = Intent(
        aliases=[DNS_ALIAS.model_copy(update={"content": ["192.168.30.5", "10.20.0.53"]})],
        virtual_ips=[DNS_VIP],
        rules=[RULE],
    )
    with pytest.raises(ApplyAborted, match="rolled back"):
        apply(firewall, intent)
    assert firewall.store["alias"][existing_uuid]["content"] == "192.168.30.5"
    assert firewall.store["vip"] == {}
    assert activated(firewall) == []


def test_allow_any_any_only_exempts_the_same_interface_set():
    firewall = FakeFirewall()
    allowed = Rule(
        description="Lab any-any", interface=["lan"], sequence=5, action="pass",
        allow_any_any=True,
    )
    firewall.store["rule"]["77777777-7777-4777-8777-777777777777"] = dict(
        ROGUE, description="Lab any-any", interface="lan,wan"
    )
    with pytest.raises(ApplyAborted, match="pass any"):
        apply(firewall, Intent(rules=[allowed]))
    assert activated(firewall) == []


def test_allow_any_any_rule_applies():
    firewall = FakeFirewall()
    allowed = Rule(
        description="Lab any-any", interface=["lan"], sequence=5, action="pass",
        allow_any_any=True,
    )
    apply(firewall, Intent(rules=[allowed]))
    assert activated(firewall) == ["apply_filter"]


def test_prune_never_deletes_vips():
    firewall = FakeFirewall()
    firewall.store["vip"]["88888888-8888-4888-8888-888888888888"] = {
        "mode": "ipalias", "interface": "opt5", "subnet": "192.168.50.1",
        "subnet_bits": "29", "descr": "old ADM gateway",
    }
    apply(firewall, Intent(), prune=True)
    assert not any(call.startswith("del_vip") for call in firewall.calls)


def test_no_backup_no_writes():
    firewall = FakeFirewall()

    def failing_backup():
        raise OSError("disk full")

    with pytest.raises(OSError):
        apply(firewall, Intent(rules=[RULE]), backup=failing_backup)
    assert firewall.store["rule"] == {}
