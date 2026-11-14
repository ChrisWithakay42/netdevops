"""Pure diff engine: desired intent vs live firewall state -> Plan.

Everything here operates on plain data (no I/O), so it is fully unit-testable.
Live state is the flattened form produced by client.flatten_row().

Match keys (how a desired object is paired with a live one):
  alias -> name
  rule  -> (description, interface set)
  snat  -> description
  vip   -> address (CIDR); IP-alias VIPs only, CARP VIPs are not managed

Live objects with no matching desired object are reported as `unmanaged` and
only deleted when apply is run with --prune. VIPs are never pruned: removing
one can cut off the management path, so that stays a manual step.

A desired object whose match key hits more than one live object is an error:
picking one would leave the other "live-only", and --prune would delete it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Alias, Intent, Rule, SnatRule, VirtualIP

NEVER_PRUNED = {"vip"}

_API_BOOL = {True: "1", False: "0"}

# intent field -> API/model field, for rules
RULE_FIELDS = {
    "enabled": "enabled",
    "sequence": "sequence",
    "action": "action",
    "quick": "quick",
    "interface": "interface",
    "direction": "direction",
    "ip_protocol": "ipprotocol",
    "protocol": "protocol",
    "source_net": "source_net",
    "source_invert": "source_not",
    "source_port": "source_port",
    "destination_net": "destination_net",
    "destination_invert": "destination_not",
    "destination_port": "destination_port",
    "log": "log",
    "description": "description",
}

SNAT_FIELDS = {
    "enabled": "enabled",
    "sequence": "sequence",
    "interface": "interface",
    "ip_protocol": "ipprotocol",
    "protocol": "protocol",
    "source_net": "source_net",
    "destination_net": "destination_net",
    "target": "target",
    "log": "log",
    "description": "description",
}


def alias_payload(alias: Alias) -> dict:
    return {
        "enabled": _API_BOOL[alias.enabled],
        "name": alias.name,
        "type": alias.type,
        "content": "\n".join(alias.content),
        "description": alias.description,
    }


def _payload_from_fields(data: dict, field_map: dict[str, str]) -> dict:
    payload = {}
    for intent_field, api_field in field_map.items():
        value = data[intent_field]
        if isinstance(value, bool):
            value = _API_BOOL[value]
        elif isinstance(value, list):
            value = ",".join(value)
        payload[api_field] = str(value)
    return payload


def rule_payload(rule: Rule) -> dict:
    return _payload_from_fields(rule.model_dump(), RULE_FIELDS)


def snat_payload(snat_rule: SnatRule) -> dict:
    return _payload_from_fields(snat_rule.model_dump(), SNAT_FIELDS)


def vip_payload(vip: VirtualIP) -> dict:
    return {
        "mode": "ipalias",
        "interface": vip.interface,
        "network": vip.address,
        "descr": vip.description,
    }


def live_vip_rows(live_vips: dict[str, dict]) -> dict[str, dict]:
    """Keep IP-alias VIPs and add the combined `network` field vip_payload uses."""
    rows = {}
    for uuid, row in live_vips.items():
        if row.get("mode") != "ipalias":
            continue
        rows[uuid] = row | {"network": f"{row.get('subnet', '')}/{row.get('subnet_bits', '')}"}
    return rows


def _changed_fields(payload: dict, live_row: dict) -> list[str]:
    changed = []
    for field_name, desired_value in payload.items():
        live_value = live_row.get(field_name, "")
        if field_name in ("interface", "source_net", "destination_net"):
            if set(desired_value.split(",")) != set(live_value.split(",")):
                changed.append(field_name)
        elif field_name == "content":
            if set(desired_value.split("\n")) - {""} != set(live_value.split(",")) - {""}:
                changed.append(field_name)
        elif desired_value != live_value:
            changed.append(field_name)
    return changed


@dataclass
class Change:
    kind: str  # alias | rule | snat
    label: str
    payload: dict
    uuid: str | None = None  # None -> create
    changed: list[str] = field(default_factory=list)


@dataclass
class Plan:
    creates: list[Change] = field(default_factory=list)
    updates: list[Change] = field(default_factory=list)
    unmanaged: list[Change] = field(default_factory=list)  # live-only; deleted with --prune

    @property
    def empty(self) -> bool:
        return not (self.creates or self.updates)

    def prunable(self) -> list[Change]:
        return [change for change in self.unmanaged if change.kind not in NEVER_PRUNED]

    def summary(self) -> str:
        return (
            f"{len(self.creates)} to create, {len(self.updates)} to update, "
            f"{len(self.unmanaged)} live-only (use --prune to delete)"
        )


def _diff_kind(plan, kind, desired_items, live, key_of_desired, key_of_live, payload_of, label_of):
    live_by_key: dict = {}
    for uuid, live_row in live.items():
        live_by_key.setdefault(key_of_live(live_row), []).append((uuid, live_row))
    matched_uuids = set()
    for desired_item in desired_items:
        match_key = key_of_desired(desired_item)
        payload = payload_of(desired_item)
        if match_key in live_by_key:
            if len(live_by_key[match_key]) > 1:
                duplicate_uuids = [uuid for uuid, _ in live_by_key[match_key]]
                raise ValueError(
                    f"duplicate live {kind} key {label_of(desired_item)!r}: {duplicate_uuids}; "
                    "make them unique on the firewall first"
                )
            uuid, live_row = live_by_key[match_key][0]
            matched_uuids.add(uuid)
            changed = _changed_fields(payload, live_row)
            if changed:
                plan.updates.append(Change(kind, label_of(desired_item), payload, uuid, changed))
        else:
            plan.creates.append(Change(kind, label_of(desired_item), payload))
    for uuid, live_row in live.items():
        if uuid not in matched_uuids:
            label = (
                live_row.get("description")
                or live_row.get("name")
                or live_row.get("network")
                or uuid
            )
            plan.unmanaged.append(Change(kind, label, {}, uuid))


def build_plan(
    intent: Intent,
    live_aliases: dict[str, dict],
    live_rules: dict[str, dict],
    live_snat: dict[str, dict],
    live_vips: dict[str, dict] | None = None,
) -> Plan:
    """live_vips must already be normalised by live_vip_rows()."""
    plan = Plan()
    _diff_kind(
        plan, "alias", intent.aliases, live_aliases,
        key_of_desired=lambda alias: alias.name,
        key_of_live=lambda live_row: live_row.get("name", ""),
        payload_of=alias_payload,
        label_of=lambda alias: alias.name,
    )
    _diff_kind(
        plan, "rule", intent.rules, live_rules,
        key_of_desired=lambda rule: (rule.description, frozenset(rule.interface)),
        key_of_live=lambda live_row: (
            live_row.get("description", ""),
            frozenset(name for name in live_row.get("interface", "").split(",") if name),
        ),
        payload_of=rule_payload,
        label_of=lambda rule: f"seq {rule.sequence}: {rule.description}",
    )
    _diff_kind(
        plan, "snat", intent.snat_rules, live_snat,
        key_of_desired=lambda snat_rule: snat_rule.description,
        key_of_live=lambda live_row: live_row.get("description", ""),
        payload_of=snat_payload,
        label_of=lambda snat_rule: snat_rule.description,
    )
    _diff_kind(
        plan, "vip", intent.virtual_ips, live_vips or {},
        key_of_desired=lambda vip: vip.address,
        key_of_live=lambda live_row: live_row.get("network", ""),
        payload_of=vip_payload,
        label_of=lambda vip: vip.address,
    )
    return plan
