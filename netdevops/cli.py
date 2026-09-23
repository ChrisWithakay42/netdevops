"""netdevops CLI: validate | import | sanitize | plan | apply | backup."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from . import diff as diff_mod
from .client import OPNsenseClient, flatten_row
from .export import parse_export, write_intent
from .intent import load_intent
from .sanitize import sanitize_file


def _load(directory: str):
    try:
        return load_intent(directory)
    except Exception as validation_error:
        print(f"intent validation FAILED:\n{validation_error}", file=sys.stderr)
        raise SystemExit(1) from validation_error


def cmd_validate(args) -> int:
    intent = _load(args.dir)
    print(
        f"OK: {len(intent.aliases)} aliases, {len(intent.rules)} rules, "
        f"{len(intent.snat_rules)} SNAT rules, {len(intent.interfaces)} interfaces"
    )
    return 0


def cmd_import(args) -> int:
    intent = parse_export(args.export)
    for written_path in write_intent(intent, args.dir):
        print(f"wrote {written_path}")
    print("Review with `git diff` before committing.")
    return 0


def cmd_sanitize(args) -> int:
    sanitized_path = sanitize_file(args.export)
    print(f"wrote {sanitized_path}")
    return 0


_ONLY_KINDS = {"aliases": "alias", "rules": "rule", "nat": "snat"}


def _build_plan(args):
    intent = _load(args.dir)
    client = OPNsenseClient.from_env()
    live_aliases = {uuid: flatten_row(row) for uuid, row in client.get_aliases().items()}
    raw_rules, raw_snat = client.get_filter_model()
    live_rules = {uuid: flatten_row(row) for uuid, row in raw_rules.items()}
    live_snat = {uuid: flatten_row(row) for uuid, row in raw_snat.items()}
    plan = diff_mod.build_plan(intent, live_aliases, live_rules, live_snat)
    if getattr(args, "only", None):
        kind = _ONLY_KINDS[args.only]
        for change_list in (plan.creates, plan.updates, plan.unmanaged):
            change_list[:] = [change for change in change_list if change.kind == kind]
    return client, plan


def _print_plan(plan) -> None:
    for change in plan.creates:
        print(f"  + create {change.kind}: {change.label}")
    for change in plan.updates:
        print(f"  ~ update {change.kind}: {change.label}  ({', '.join(change.changed)})")
    for change in plan.unmanaged:
        print(f"  ! live-only {change.kind}: {change.label}")
    print(f"\nPlan: {plan.summary()}")


def cmd_plan(args) -> int:
    _, plan = _build_plan(args)
    if plan.empty and not plan.unmanaged:
        print("No changes. Firewall matches intent.")
        return 0
    _print_plan(plan)
    return 2 if not plan.empty else 0  # terraform-style: 2 = diff present


def cmd_apply(args) -> int:
    client, plan = _build_plan(args)
    if plan.empty and not (args.prune and plan.unmanaged):
        print("No changes. Firewall matches intent.")
        return 0
    _print_plan(plan)

    if not args.yes:
        answer = input("\nApply these changes? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return 1

    create_actions = {"alias": client.add_alias, "rule": client.add_rule, "snat": client.add_snat}
    update_actions = {"alias": client.set_alias, "rule": client.set_rule, "snat": client.set_snat}
    delete_actions = {"alias": client.del_alias, "rule": client.del_rule, "snat": client.del_snat}

    for change in plan.creates:
        create_actions[change.kind](change.payload)
        print(f"created {change.kind}: {change.label}")
    for change in plan.updates:
        update_actions[change.kind](change.uuid, change.payload)
        print(f"updated {change.kind}: {change.label}")
    if args.prune:
        for change in plan.unmanaged:
            delete_actions[change.kind](change.uuid)
            print(f"deleted {change.kind}: {change.label}")

    client.apply()
    print("Applied. HA-sync will replicate to the secondary.")
    return 0


def cmd_backup(args) -> int:
    client = OPNsenseClient.from_env()
    timestamp = time.strftime("%Y%m%d%H%M%S", time.gmtime())
    raw_path = Path("exports/raw") / f"config-{client.host}-{timestamp}.xml"
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_bytes(client.download_config())
    print(f"wrote {raw_path} (raw, gitignored)")
    sanitized_path = sanitize_file(raw_path)
    print(f"wrote {sanitized_path} (sanitized, safe to commit)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netdevops", description=__doc__)
    parser.add_argument("--dir", default="network", help="intent directory (default: network)")
    subcommands = parser.add_subparsers(dest="command", required=True)

    def add_command(name: str, help_text: str, handler):
        subparser = subcommands.add_parser(name, help=help_text)
        # accept --dir after the subcommand too; SUPPRESS keeps the global
        # default when the flag is not repeated here
        subparser.add_argument("--dir", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        subparser.set_defaults(func=handler)
        return subparser

    add_command("validate", "validate the intent files offline", cmd_validate)

    subparser = add_command(
        "import", "config export XML -> intent YAML (adoption/resync)", cmd_import
    )
    subparser.add_argument("export")

    subparser = add_command(
        "sanitize", "redact secrets from an export for committing", cmd_sanitize
    )
    subparser.add_argument("export")

    subparser = add_command("plan", "diff intent vs live firewall (read-only)", cmd_plan)
    subparser.add_argument("--only", choices=sorted(_ONLY_KINDS), help="limit to one object kind")

    subparser = add_command("apply", "apply intent to the firewall", cmd_apply)
    subparser.add_argument("--yes", action="store_true", help="skip confirmation prompt")
    subparser.add_argument(
        "--prune", action="store_true", help="delete live objects not in intent"
    )
    subparser.add_argument("--only", choices=sorted(_ONLY_KINDS), help="limit to one object kind")

    add_command("backup", "download config.xml (raw + sanitized)", cmd_backup)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
