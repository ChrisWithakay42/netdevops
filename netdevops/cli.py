"""netdevops CLI: validate | import | sanitize | plan | apply | backup."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .apply import ApplyAborted, fetch_live, plan_from_live, run_apply
from .backup import state_dir_from_env, take_backup
from .client import OPNsenseClient, _ssl_verify_from_env
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
        f"{len(intent.snat_rules)} SNAT rules, {len(intent.virtual_ips)} virtual IPs, "
        f"{len(intent.interfaces)} interfaces"
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


_ONLY_KINDS = {"aliases": "alias", "rules": "rule", "nat": "snat", "vips": "vip"}


def _build_plan(args):
    intent = _load(args.dir)
    client = OPNsenseClient.from_env()
    live = fetch_live(client)
    try:
        plan = plan_from_live(intent, live)
    except ValueError as conflict:
        print(f"plan FAILED: {conflict}", file=sys.stderr)
        raise SystemExit(1) from conflict
    if getattr(args, "only", None):
        kind = _ONLY_KINDS[args.only]
        for change_list in (plan.creates, plan.updates, plan.unmanaged):
            change_list[:] = [change for change in change_list if change.kind == kind]
    return client, intent, live, plan


def _print_plan(plan) -> None:
    for change in plan.creates:
        print(f"  + create {change.kind}: {change.label}")
    for change in plan.updates:
        print(f"  ~ update {change.kind}: {change.label}  ({', '.join(change.changed)})")
    for change in plan.unmanaged:
        note = "" if change in plan.prunable() else " (never pruned)"
        print(f"  ! live-only {change.kind}: {change.label}{note}")
    print(f"\nPlan: {plan.summary()}")


def cmd_plan(args) -> int:
    _, _, _, plan = _build_plan(args)
    if plan.empty and not plan.unmanaged:
        print("No changes. Firewall matches intent.")
        return 0
    _print_plan(plan)
    return 2 if not plan.empty else 0  # terraform-style: 2 = diff present


def cmd_apply(args) -> int:
    client, intent, live, plan = _build_plan(args)
    if plan.empty and not (args.prune and plan.prunable()):
        print("No changes. Firewall matches intent.")
        return 0
    _print_plan(plan)

    if not args.yes:
        answer = input("\nApply these changes? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return 1

    try:
        run_apply(client, intent, plan, live, prune=args.prune, backup=lambda: _backup(args))
    except ApplyAborted as aborted:
        print(f"ABORTED: {aborted}", file=sys.stderr)
        return 3
    except Exception as error:
        # run_apply rolls back on errors during writes; anything reaching here
        # came from the backup/pre-checks (nothing written) or the activation
        # calls (writes saved and possibly partly live).
        print(
            f"FAILED: {error!r}\nCheck the firewall: saved config may differ from what "
            "is running. Re-run plan; restore from the backup if in doubt.",
            file=sys.stderr,
        )
        return 4
    print("Applied.")
    return 0


def _backup_client() -> OPNsenseClient:
    """Separate credentials for config download when OPNSENSE_BACKUP_API_KEY is set.

    Lets the apply key go without the backup privilege (which on 26.7 also
    grants config restore).
    """
    if "OPNSENSE_BACKUP_API_KEY" not in os.environ:
        return OPNsenseClient.from_env()
    return OPNsenseClient(
        host=os.environ["OPNSENSE_HOST"],
        api_key=os.environ["OPNSENSE_BACKUP_API_KEY"],
        api_secret=os.environ["OPNSENSE_BACKUP_API_SECRET"],
        ssl_verify=_ssl_verify_from_env(),
    )


def _backup(args) -> None:
    sanitized_dir = Path(args.dir).resolve().parent / "exports" / "sanitized"
    raw_path, sanitized_path = take_backup(_backup_client(), state_dir_from_env(), sanitized_dir)
    print(f"wrote {raw_path} (raw, private, outside the repo)")
    print(f"wrote {sanitized_path} (sanitized; site repo only)")


def cmd_backup(args) -> int:
    _backup(args)
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
