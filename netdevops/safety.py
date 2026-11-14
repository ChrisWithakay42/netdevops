"""Checks run after writes and before activation, over flattened live state.

Both exist because of 2026-11-13: a setRule on a mistyped uuid created a
default "pass any -> any on every interface" rule, which went live with the
next filter apply. Either check would have stopped it before activation.
"""

from __future__ import annotations

ANY_NETS = {"any", "", "0.0.0.0/0", "::/0"}
ANY_PORTS = {"", "any", "1:65535", "0:65535"}


def any_aliases(live_aliases: dict[str, dict]) -> set[str]:
    """Names of network/host aliases whose content includes the whole address space."""
    return {
        row.get("name", "")
        for row in live_aliases.values()
        if row.get("type") in ("network", "host")
        and ANY_NETS & set(row.get("content", "").replace("\n", ",").split(",")) - {""}
    }


def stray_uuids(
    before: set[str], after: set[str], created: set[str], deleted: set[str]
) -> set[str]:
    """uuids present after the writes that neither existed before nor were created by us."""
    return after - (before - deleted) - created


def pass_all_rules(
    live_rules: dict[str, dict],
    allowed: set[tuple[str, frozenset[str]]],
    any_aliases: set[str] = frozenset(),
) -> list[str]:
    """uuids of enabled pass rules with no source, destination or port restriction.

    `allowed` holds the (description, interface set) match keys of rules the
    intent marks allow_any_any: the same identity plan/apply use, so a rule
    with the same description on other interfaces is not exempt.
    `any_aliases` are alias names that resolve to the whole address space.
    """
    means_any = ANY_NETS | set(any_aliases)
    found = []
    for uuid, row in live_rules.items():
        live_key = (
            row.get("description", ""),
            frozenset(name for name in row.get("interface", "").split(",") if name),
        )
        if (
            row.get("enabled") == "1"
            and row.get("action") == "pass"
            and row.get("source_net", "any") in means_any
            and row.get("destination_net", "any") in means_any
            and row.get("source_not", "0") != "1"
            and row.get("destination_not", "0") != "1"
            and row.get("destination_port", "") in ANY_PORTS
            and live_key not in allowed
        ):
            found.append(uuid)
    return found
