"""Load the network/ YAML intent files into a validated Intent model."""

from __future__ import annotations

from pathlib import Path

import yaml

from .models import Intent

# A file may carry more than one section (interfaces.yml also holds vips).
KNOWN_KEYS = {"aliases", "rules", "snat_rules", "interfaces", "vips"}


def load_intent(directory: str | Path = "network") -> Intent:
    directory = Path(directory)
    data: dict = {}
    for path in sorted(directory.glob("*.yml")):
        loaded = yaml.safe_load(path.read_text()) or {}
        if not isinstance(loaded, dict):
            raise ValueError(f"{path}: expected a mapping at top level")
        unknown = set(loaded) - KNOWN_KEYS
        if unknown:
            raise ValueError(f"{path}: unknown top-level key(s) {sorted(unknown)}")
        for key, value in loaded.items():
            if key in data:
                raise ValueError(f"{path}: {key!r} already defined in another file")
            data[key] = value or []
    return Intent(**data)
