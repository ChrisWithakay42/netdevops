"""Take a config.xml backup: raw copy private and outside any repo, plus a
sanitized copy for the (private) site repo.

The raw file holds plaintext private keys, PSKs and password hashes, so it
lives in a 0700 state directory (default ~/.local/state/netdevops/backups,
override with NETDEVOPS_BACKUP_DIR), never under the working directory.
"""

from __future__ import annotations

import os
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from .sanitize import sanitize_file

DEFAULT_STATE_DIR = "~/.local/state/netdevops/backups"


class BackupError(RuntimeError):
    pass


def state_dir_from_env() -> Path:
    return Path(os.environ.get("NETDEVOPS_BACKUP_DIR", DEFAULT_STATE_DIR)).expanduser()


def take_backup(client, state_dir: Path, sanitized_dir: Path) -> tuple[Path, Path]:
    state_dir.mkdir(parents=True, exist_ok=True)
    state_dir.chmod(0o700)
    timestamp = time.strftime("%Y%m%d%H%M%S", time.gmtime())
    raw_path = state_dir / f"config-{client.host}-{timestamp}.xml"

    body = client.download_config()
    descriptor = os.open(raw_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as raw_file:
        raw_file.write(body)
    try:
        root_tag = ET.parse(raw_path).getroot().tag
    except ET.ParseError as error:
        raw_path.unlink()
        raise BackupError(f"downloaded config is not XML: {error}") from error
    if root_tag != "opnsense":
        raw_path.unlink()
        raise BackupError(f"downloaded config has root <{root_tag}>, expected <opnsense>")

    sanitized_path = sanitize_file(raw_path, sanitized_dir)
    return raw_path, sanitized_path
