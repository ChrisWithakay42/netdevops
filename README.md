# netdevops

Infrastructure-as-code for OPNsense firewalls.

`netdevops` keeps firewall policy in version-controlled YAML and reconciles it
against a live OPNsense instance through the HTTP API. It follows the
plan/apply model: every change is previewed as a diff before anything is
written to the firewall, and nothing is deleted unless explicitly requested.

A built-in policy evaluator simulates packets through the rule set so that
reachability invariants (for example, "the guest VLAN can never reach the
management network") can be asserted with `pytest` on every change, before
the change reaches production.

## How it works

```
                 import                  plan / apply
config.xml  ───────────►  network/*.yml  ─────────────►  OPNsense API
 (export)                 (intent, in git)      ▲
                                │               │
                                ▼               │
                        validate + pytest ──────┘
                        (schema, cross-refs,
                         policy invariants)
```

1. **Import.** Adopt an existing firewall by converting a `config.xml` export
   into intent files. Re-running the import against a fresh export and reading
   `git diff` shows exactly what changed out-of-band.
2. **Validate.** Intent files are parsed into typed Pydantic models. Alias
   references, interface names, port syntax, duplicate match keys and sequence
   collisions are all checked offline.
3. **Test.** The policy evaluator runs simulated packets through the rule set.
   Tests assert outcomes rather than individual rules, so the rule set can be
   refactored freely while the guarantees stay pinned.
4. **Plan.** Live aliases, filter rules and source NAT rules are fetched from
   the firewall and diffed against intent. The plan lists creates, updates and
   live-only objects.
5. **Apply.** The plan is executed and the firewall reconfigured. Live-only
   objects are left untouched unless `--prune` is passed.

## Managed objects

| Object            | OPNsense section              | Match key                    |
| ----------------- | ----------------------------- | ---------------------------- |
| Aliases           | Firewall › Aliases            | `name`                       |
| Filter rules      | Firewall › Automation › Filter| `description` + interface set|
| Source NAT rules  | Firewall › Automation › Source NAT | `description`           |

Interfaces and CARP virtual IPs are read from the export for documentation
and policy simulation only. They are never pushed to the firewall.

Because rules are matched on their description, every rule must have a
description that is unique per interface. The validator reports collisions.

## Requirements

- Python 3.12 or newer
- An OPNsense instance with the API enabled
- An API user with these privileges only:
  - Firewall: Alias: Edit
  - Firewall: Automation: Filter
  - Firewall: Automation: Source NAT
  - System: Backup API
- [`just`](https://github.com/casey/just) (optional, for the task runner)

## Installation

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

Or, with `just`:

```sh
just deps
```

## Configuration

The API client is configured entirely through environment variables.

| Variable              | Required | Description                                          |
| --------------------- | -------- | ---------------------------------------------------- |
| `OPNSENSE_HOST`       | yes      | Hostname or IP of the firewall. There is no default. |
| `OPNSENSE_API_KEY`    | yes      | API key of the automation user.                      |
| `OPNSENSE_API_SECRET` | yes      | API secret of the automation user.                   |
| `OPNSENSE_SSL_VERIFY` | no       | `1`, or a path to the firewall's certificate. Default `0`.|

`OPNSENSE_HOST` has no default, so a missing variable fails immediately
instead of targeting the wrong device.

OPNsense ships a self-signed certificate, so TLS verification is off by
default. Pointing `OPNSENSE_SSL_VERIFY` at a copy of the firewall's own
certificate keeps verification on without a publicly trusted CA; the API
credentials and `backup`'s `config.xml` both travel over that connection.

In a high-availability pair, point `OPNSENSE_HOST` at the primary node only.
OPNsense HA-sync replicates aliases, rules and NAT to the secondary; writing
to both nodes would conflict with the sync.

## Quick start

Adopt an existing firewall:

```sh
# 1. In the OPNsense UI: System > Configuration > Backups > Download.
#    Save the file under exports/raw/ (gitignored).

# 2. Generate intent files from the export.
netdevops import exports/raw/config.xml
git diff network/

# 3. Configure credentials and confirm the plan is clean.
export OPNSENSE_HOST=192.0.2.1
export OPNSENSE_API_KEY=...
export OPNSENSE_API_SECRET=...
netdevops plan
```

Day-to-day workflow:

```sh
# Edit network/*.yml, then:
netdevops validate          # offline schema and cross-reference checks
pytest                      # engine tests plus policy invariants
netdevops plan              # read-only diff against the firewall
netdevops apply             # execute the plan (prompts for confirmation)
```

With `just`, `just plan` and `just apply` run lint and tests first.

## Commands

```
netdevops [--dir DIR] <command>

  validate            Validate the intent files offline.
  import <export.xml> Convert a config.xml export into intent YAML.
  sanitize <export.xml>
                      Write a redacted copy of an export to exports/sanitized/.
  plan [--only KIND]  Diff intent against the live firewall. Read-only.
  apply [--yes] [--prune] [--only KIND]
                      Apply the plan. Prompts unless --yes is given.
  backup              Download config.xml as a raw (gitignored) and a
                      sanitized (committable) copy.
```

`--dir` selects the intent directory and defaults to `network/`. It may be
given before or after the subcommand.

`--only` restricts `plan` and `apply` to one object kind: `aliases`, `rules`
or `nat`.

Exit codes for `plan`: `0` when the firewall matches intent, `2` when a diff
is present, `1` on error.

## Intent files

`netdevops import` writes four files. Each top-level key may appear in only one
file, but the split is otherwise free-form.

| File             | Keys                    |
| ---------------- | ----------------------- |
| `aliases.yml`    | `aliases`               |
| `rules.yml`      | `rules`                 |
| `nat.yml`        | `snat_rules`            |
| `interfaces.yml` | `interfaces`, `vips`    |

Example:

```yaml
aliases:
  - name: mgmt_hosts
    type: host
    content: [10.0.10.5, 10.0.10.6]
    description: Management servers

rules:
  - description: Guest to Internet
    interface: [opt2]
    sequence: 100
    action: pass
    protocol: any
    source_net: opt2
    destination_net: "(self)"
    destination_invert: true
    quick: true
    log: false
    enabled: true

  - description: Guest block all
    interface: [opt2]
    sequence: 110
    action: block
    log: true
```

Networks accept OPNsense's built-in tokens (`any`, `lan`, `opt1`, `lanip`,
`(self)`, and so on), alias names, or CIDR literals. Ports accept a port, a
`start:end` range, or the name of a `port` alias.

## Policy tests

`netdevops.policy.PolicyEvaluator` models the pf evaluation order used by
OPNsense:

- Only enabled rules on the packet's ingress interface with direction `in`
  are considered, in sequence order.
- A matching rule with `quick: true` decides immediately.
- Among matching rules with `quick: false`, the last match wins.
- No match results in the implicit default deny.

Floating and group rules, state tracking, policy routing, IPv6, schedules and
the anti-lockout rule are not modelled. The evaluator is meant for inter-VLAN
reachability assertions, not as a replacement for testing on the device.

Invariants live in `tests/test_policy.py` and receive an `evaluator` fixture
built from the repository's own `network/` directory:

```python
from netdevops.policy import Packet


def test_guest_cannot_reach_management(evaluator):
    packet = Packet("opt2", "10.0.30.40", "10.0.10.5", "tcp", 22)
    assert not evaluator.evaluate(packet).allowed
```

Policy tests are skipped automatically while `network/` is empty, so the
engine's own test suite passes on a fresh checkout.

## Safety model

- **Plan before apply.** `apply` prints the same plan as `plan` and asks for
  confirmation. `--yes` is opt-in for automation.
- **No implicit deletion.** Live objects with no counterpart in intent are
  reported as live-only. They are deleted only with `--prune`.
- **Fail closed on configuration.** A missing `OPNSENSE_HOST` aborts before
  any request is made.
- **Secrets stay out of git.** `exports/raw/` and `*.xml` are gitignored.
  `sanitize` and `backup` redact password hashes, API keys, pre-shared keys,
  private keys and similar fields, then scan the output for known secret
  markers and discard it if any remain.

## Repository layout

```
netdevops/        Engine: models, intent loader, diff/plan, API client,
                  export parser, sanitizer, policy evaluator, CLI
network/          Intent files (source of truth)
tests/            Engine tests, policy invariants, synthetic fixtures
exports/raw/      Raw config.xml exports (gitignored)
exports/sanitized/
                  Redacted exports, safe to commit
```

## Development

```sh
just lint         # ruff, yamllint, intent validation
just test         # pytest
```

The engine tests run against a synthetic export in `tests/fixtures/` and do
not require a firewall.
