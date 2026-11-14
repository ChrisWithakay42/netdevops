"""Apply a plan: write everything, check it, and only then activate.

Activation must come last because on OPNsense 26.7 alias/reconfigure also runs
"filter reload": the moment aliases are activated, every saved filter rule goes
live. So the flow is:

1. Backup, then re-read live state; abort if it changed since the plan (a
   concurrent GUI edit) or already holds an unapproved pass any -> any rule.
2. Write all kinds: aliases, IP-alias VIPs, filter rules, source NAT. Aliases
   first because rules reference them.
3. Re-read everything. Abort if an object appeared that this run did not
   create, or the saved ruleset holds an unapproved pass any -> any rule.
4. Activate only the kinds that changed.

Any failure in steps 2-3 undoes this run's own writes from the pre-images
(creates deleted, updates restored), so nothing half-written is left saved for
the next filter reload to pick up. A stray is auto-deleted only when it has the
pass-all signature; anything else is most likely someone's GUI work and is
reported instead. Deletions made by --prune can't be undone here; restore them
from the backup.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from . import diff as diff_mod
from .client import flatten_row
from .models import Intent
from .safety import any_aliases, pass_all_rules, stray_uuids

KINDS = ("alias", "vip", "rule", "snat")
ACTIVATE = {
    "alias": "reconfigure_aliases",
    "vip": "reconfigure_vips",
    "rule": "apply_filter",
    "snat": "apply_filter",
}


class ApplyAborted(RuntimeError):
    pass


@dataclass
class LiveState:
    aliases: dict[str, dict]
    rules: dict[str, dict]
    snat: dict[str, dict]
    vips: dict[str, dict]  # IP-alias only, normalised by diff.live_vip_rows

    def of(self, kind: str) -> dict[str, dict]:
        return {"alias": self.aliases, "rule": self.rules, "snat": self.snat, "vip": self.vips}[
            kind
        ]


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


def _approved_any_any(intent: Intent) -> set[tuple[str, frozenset[str]]]:
    return {
        (rule.description, frozenset(rule.interface))
        for rule in intent.rules
        if rule.allow_any_any
    }


def _pass_all(intent: Intent, live: LiveState) -> list[str]:
    return pass_all_rules(live.rules, _approved_any_any(intent), any_aliases(live.aliases))


def _restore_payload(kind: str, change: diff_mod.Change, before_row: dict) -> dict:
    """The pre-image in the payload's shape, limited to the fields this run changed."""
    restored = {field_name: before_row.get(field_name, "") for field_name in change.payload}
    if kind == "alias":  # flattened content is comma-joined; the API wants newlines
        restored["content"] = restored["content"].replace(",", "\n")
    return restored


@dataclass
class _Journal:
    created: dict[str, set[str]] = field(default_factory=lambda: {kind: set() for kind in KINDS})
    updated: list[tuple[str, diff_mod.Change]] = field(default_factory=list)
    deleted: dict[str, set[str]] = field(default_factory=lambda: {kind: set() for kind in KINDS})

    def touched(self) -> set[str]:
        return {
            kind
            for kind in KINDS
            if self.created[kind] or self.deleted[kind]
        } | {kind for kind, _ in self.updated}


def _write(client, plan, prune, journal, echo) -> None:
    for kind in KINDS:
        for change in plan.creates:
            if change.kind == kind:
                journal.created[kind].add(getattr(client, f"add_{kind}")(change.payload))
                echo(f"created {kind}: {change.label}")
        for change in plan.updates:
            if change.kind == kind:
                getattr(client, f"set_{kind}")(change.uuid, change.payload)
                journal.updated.append((kind, change))
                echo(f"updated {kind}: {change.label}")
    if prune:
        for kind in reversed(KINDS):  # rules before the aliases they reference
            for change in plan.prunable():
                if change.kind == kind:
                    getattr(client, f"del_{kind}")(change.uuid)
                    journal.deleted[kind].add(change.uuid)
                    echo(f"deleted {kind}: {change.label}")


def _check(client, intent, before, journal, echo) -> None:
    after = fetch_live(client)
    problems = []
    for kind in KINDS:
        strays = stray_uuids(
            set(before.of(kind)), set(after.of(kind)), journal.created[kind], journal.deleted[kind]
        )
        if not strays:
            continue
        pass_all_strays = (
            set(_pass_all(intent, after)) & strays if kind == "rule" else set()
        )
        for uuid in sorted(pass_all_strays):
            client.del_rule(uuid)
            echo(f"removed stray pass-all rule {uuid}")
        left = sorted(strays - pass_all_strays)
        problems.append(
            f"stray {kind} object(s) appeared during the writes: "
            f"removed pass-all {sorted(pass_all_strays)}, left in place {left}"
        )
    offenders = _pass_all(intent, fetch_live(client)) if not problems else []
    if offenders:
        problems.append(f"enabled pass any -> any rule(s) {offenders} in the saved ruleset")
    if problems:
        raise ApplyAborted("; ".join(problems))


def _rollback(client, before, journal, echo) -> list[str]:
    """Undo in reverse dependency order: per kind, restore updates, then delete
    creates, so a rule stops referencing a new alias before the alias goes."""
    failures = []
    for kind in reversed(KINDS):
        for update_kind, change in reversed(journal.updated):
            if update_kind != kind:
                continue
            try:
                payload = _restore_payload(kind, change, before.of(kind)[change.uuid])
                getattr(client, f"set_{kind}")(change.uuid, payload)
                echo(f"rolled back update {kind}: {change.label}")
            except Exception as error:  # keep going: undo as much as possible
                failures.append(f"restore {kind} {change.label}: {error}")
        for uuid in sorted(journal.created[kind]):
            try:
                getattr(client, f"del_{kind}")(uuid)
                echo(f"rolled back create {kind} {uuid}")
            except Exception as error:
                failures.append(f"delete {kind} {uuid}: {error}")
    for kind in KINDS:
        for uuid in sorted(journal.deleted[kind]):
            failures.append(f"pruned {kind} {uuid} is gone; restore it from the backup")
    # An add the firewall saved but whose reply never reached us (Ctrl-C,
    # timeout) isn't in the journal. Report it; it can't be told apart from a
    # concurrent GUI edit, so it is not deleted.
    try:
        now = fetch_live(client)
    except Exception as error:
        return failures + [f"could not re-read live state after rollback: {error}"]
    for kind in KINDS:
        unrecorded = set(now.of(kind)) - set(before.of(kind)) - journal.created[kind]
        if unrecorded:
            failures.append(
                f"unrecorded new {kind} object(s) {sorted(unrecorded)} are saved; "
                "check them in the GUI before the next filter reload"
            )
    return failures


def _unchanged(before: LiveState, now: LiveState) -> bool:
    return all(before.of(kind) == now.of(kind) for kind in KINDS)


def run_apply(
    client,
    intent: Intent,
    plan: diff_mod.Plan,
    before: LiveState,
    prune: bool,
    backup: Callable[[], object],
    echo: Callable[[str], None] = print,
) -> None:
    pending = plan.creates + plan.updates + (plan.prunable() if prune else [])
    if not pending:
        return
    backup()  # no backup, no writes

    if not _unchanged(before, fetch_live(client)):
        raise ApplyAborted("live state changed since the plan (GUI edit?); re-run plan")
    offenders = _pass_all(intent, before)
    if offenders:
        raise ApplyAborted(
            f"live ruleset already holds enabled pass any -> any rule(s) {offenders}; "
            "nothing written. Fix them, or mark the intent rule allow_any_any"
        )

    journal = _Journal()
    try:
        _write(client, plan, prune, journal, echo)
        _check(client, intent, before, journal, echo)
    except BaseException as error:  # Ctrl-C too: never leave a half-written config saved
        failures = _rollback(client, before, journal, echo)
        detail = "; ".join(failures) if failures else "all writes undone"
        if not isinstance(error, Exception):
            echo(f"interrupted; rolled back this run's writes ({detail})")
            raise
        raise ApplyAborted(
            f"{error}. Nothing activated; rolled back this run's writes ({detail})"
        ) from error

    for method in dict.fromkeys(ACTIVATE[kind] for kind in KINDS if kind in journal.touched()):
        getattr(client, method)()
