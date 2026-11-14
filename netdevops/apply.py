"""Apply a plan in stages, checking live state before each activation.

Stages run in dependency order: aliases (rules and NAT reference them), then
IP-alias VIPs (a rule or service may need the address), then filter rules and
source NAT. Each stage writes, re-reads the live uuids, refuses to activate if
any object appeared that this run did not create (removing it first), and only
then reconfigures. The filter stage also refuses to load any enabled
"pass any -> any" rule the intent does not explicitly allow.

There is no cross-service transaction, so a failure leaves earlier stages
applied; the backup taken first is the way back.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from . import diff as diff_mod
from .client import flatten_row
from .models import Intent
from .safety import pass_all_rules, stray_uuids


class ApplyAborted(RuntimeError):
    pass


@dataclass
class LiveState:
    aliases: dict[str, dict]
    rules: dict[str, dict]
    snat: dict[str, dict]
    vips: dict[str, dict]  # IP-alias only, normalised by diff.live_vip_rows


def fetch_live(client) -> LiveState:
    raw_rules, raw_snat = client.get_filter_model()
    return LiveState(
        aliases={uuid: flatten_row(row) for uuid, row in client.get_aliases().items()},
        rules={uuid: flatten_row(row) for uuid, row in raw_rules.items()},
        snat={uuid: flatten_row(row) for uuid, row in raw_snat.items()},
        vips=diff_mod.live_vip_rows(
            {uuid: flatten_row(row) for uuid, row in client.get_vips().items()}
        ),
    )


def plan_from_live(intent: Intent, live: LiveState) -> diff_mod.Plan:
    return diff_mod.build_plan(intent, live.aliases, live.rules, live.snat, live_vips=live.vips)


def _write_kind(client, plan, kind, prune, echo) -> tuple[set[str], set[str]]:
    """Run one kind's creates, updates and prunes; return (created, deleted) uuids."""
    created, deleted = set(), set()
    for change in plan.creates:
        if change.kind == kind:
            created.add(getattr(client, f"add_{kind}")(change.payload))
            echo(f"created {kind}: {change.label}")
    for change in plan.updates:
        if change.kind == kind:
            getattr(client, f"set_{kind}")(change.uuid, change.payload)
            echo(f"updated {kind}: {change.label}")
    if prune:
        for change in plan.prunable():
            if change.kind == kind:
                getattr(client, f"del_{kind}")(change.uuid)
                deleted.add(change.uuid)
                echo(f"deleted {kind}: {change.label}")
    return created, deleted


def _check_strays(client, kind, before, after, created, deleted, echo) -> None:
    """`before` and `after` must be filtered the same way (e.g. IP-alias VIPs only)."""
    strays = stray_uuids(set(before), set(after), created, deleted)
    if not strays:
        return
    if kind in diff_mod.NEVER_PRUNED:
        raise ApplyAborted(
            f"stray {kind} object(s) {sorted(strays)} appeared during the writes; "
            "left in place (never auto-deleted) and did not activate this stage"
        )
    for uuid in sorted(strays):
        getattr(client, f"del_{kind}")(uuid)
        echo(f"removed stray {kind} {uuid}")
    raise ApplyAborted(
        f"stray {kind} object(s) {sorted(strays)} appeared during the writes; "
        "removed them and did not activate this stage"
    )


def _has_changes(plan, kinds, prune) -> bool:
    pending = plan.creates + plan.updates + (plan.prunable() if prune else [])
    return any(change.kind in kinds for change in pending)


def run_apply(
    client,
    intent: Intent,
    plan: diff_mod.Plan,
    before: LiveState,
    prune: bool,
    backup: Callable[[], object],
    echo: Callable[[str], None] = print,
) -> None:
    if not _has_changes(plan, {"alias", "vip", "rule", "snat"}, prune):
        return
    backup()  # no backup, no writes

    if _has_changes(plan, {"alias"}, prune):
        created, deleted = _write_kind(client, plan, "alias", prune, echo)
        _check_strays(client, "alias", before.aliases, client.get_aliases(), created, deleted, echo)
        client.reconfigure_aliases()

    if _has_changes(plan, {"vip"}, prune):
        created, deleted = _write_kind(client, plan, "vip", prune, echo)
        after_vips = diff_mod.live_vip_rows(
            {uuid: flatten_row(row) for uuid, row in client.get_vips().items()}
        )
        _check_strays(client, "vip", before.vips, after_vips, created, deleted, echo)
        client.reconfigure_vips()

    if _has_changes(plan, {"rule", "snat"}, prune):
        rules_created, rules_deleted = _write_kind(client, plan, "rule", prune, echo)
        snat_created, snat_deleted = _write_kind(client, plan, "snat", prune, echo)
        raw_rules, raw_snat = client.get_filter_model()
        _check_strays(client, "rule", before.rules, raw_rules, rules_created, rules_deleted, echo)
        _check_strays(client, "snat", before.snat, raw_snat, snat_created, snat_deleted, echo)
        allowed = {
            (rule.description, frozenset(rule.interface))
            for rule in intent.rules
            if rule.allow_any_any
        }
        live_rules = {uuid: flatten_row(row) for uuid, row in raw_rules.items()}
        offenders = pass_all_rules(live_rules, allowed)
        if offenders:
            raise ApplyAborted(
                f"enabled pass any -> any rule(s) {offenders} in the saved ruleset; "
                "filter NOT applied. Fix them, or mark the intent rule allow_any_any"
            )
        client.apply_filter()
