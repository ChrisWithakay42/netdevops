"""Redact secrets from an OPNsense config export so it can be committed.

Raw exports contain live credentials and must never be committed
(exports/raw/ is gitignored). This produces a redacted copy, kept in git for
history/diffing of everything that is not yet managed as intent.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

REDACTED = "***REDACTED***"

# Any element with one of these tag names has its text replaced, wherever it
# appears in the tree.
SECRET_TAGS = {
    "password",
    "otp_seed",
    "apikeys",
    "authorizedkeys",
    "prv",  # certificate/CA private key (base64)
    "psk",
    "pre-shared-key",
    "sharedkey",
    "secret",
    "radius_secret",
    "varusersfreeradiuspassword",
    "privatekey",
    "pubkey_seed",
}

# If any of these substrings survive sanitization, refuse to bless the output.
CANARIES = ("$2y$", "BEGIN PRIVATE", "BEGIN RSA", "BEGIN EC PRIVATE")


def sanitize_tree(tree: ET.ElementTree) -> int:
    count = 0
    for element in tree.getroot().iter():
        if element.tag.lower() in SECRET_TAGS and (element.text or "").strip():
            element.text = REDACTED
            count += 1
    return count


def sanitize_file(source_path: str | Path, output_dir: str | Path = "exports/sanitized") -> Path:
    source_path = Path(source_path)
    output_path = Path(output_dir) / source_path.name
    output_path.parent.mkdir(parents=True, exist_ok=True)

    tree = ET.parse(source_path)
    sanitize_tree(tree)
    tree.write(output_path, encoding="utf-8", xml_declaration=True)

    remaining = output_path.read_text()
    leaked = [canary for canary in CANARIES if canary in remaining]
    if leaked:
        output_path.unlink()
        raise RuntimeError(f"sanitization incomplete, output discarded (found {leaked})")
    return output_path
