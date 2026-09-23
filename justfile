venv := ".venv/bin"

# List available recipes
default:
    @just --list

# Create venv and install the package + dev tools
deps:
    python3 -m venv .venv
    {{ venv }}/pip install -e '.[dev]'

# Run the test suite (includes policy invariant tests)
test:
    {{ venv }}/pytest -q

# Static checks: ruff + yamllint + intent validation
lint:
    {{ venv }}/ruff check netdevops tests
    {{ venv }}/yamllint network/ .gitlab-ci.yml
    {{ venv }}/netdevops validate

# Offline validation of network/ intent files
validate:
    {{ venv }}/netdevops validate

# Read-only diff of intent vs live firewall
plan: lint test
    {{ venv }}/netdevops plan

# Apply intent to the HA primary (HA-sync replicates to the secondary)
apply: lint test
    {{ venv }}/netdevops apply

# Pull config.xml: raw (local only) + sanitized (committable)
backup:
    {{ venv }}/netdevops backup
