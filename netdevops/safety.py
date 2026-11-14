"""Checks run after writes and before activation, over flattened live state.

Both exist because of 2026-11-13: a setRule on a mistyped uuid created a
default "pass any -> any on every interface" rule, which went live with the
next filter apply. Either check would have stopped it before activation.
"""

from __future__ import annotations


def stray_uuids(
    before: set[str], after: set[str], created: set[str], deleted: set[str]
) -> set[str]:
    """uuids present after the writes that neither existed before nor were created by us."""
    return after - (before - deleted) - created


def pass_all_rules(live_rules: dict[str, dict], allowed: set[str]) -> list[str]:
    """uuids of enabled pass rules with no source, destination or port restriction.

    `allowed` holds descriptions of rules the intent marks allow_any_any.
    """
    found = []
    for uuid, row in live_rules.items():
        if (
            row.get("enabled") == "1"
            and row.get("action") == "pass"
            and row.get("source_net", "any") in ("any", "")
            and row.get("destination_net", "any") in ("any", "")
            and row.get("source_not", "0") != "1"
            and row.get("destination_not", "0") != "1"
            and not row.get("destination_port")
            and row.get("description", "") not in allowed
        ):
            found.append(uuid)
    return found
