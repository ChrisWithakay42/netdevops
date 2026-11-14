"""Backups: raw config.xml kept private, outside any repo, and validated."""

import stat

import pytest

from netdevops.backup import BackupError, take_backup

CONFIG = (
    b"<?xml version='1.0'?>"
    b"<opnsense><system><user><password>$2y$x</password></user></system></opnsense>"
)


class Client:
    host = "fw.test"

    def __init__(self, body):
        self.body = body

    def download_config(self):
        return self.body


def mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_raw_backup_is_private(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o755)  # pre-existing and too open: must be tightened
    raw_path, sanitized_path = take_backup(Client(CONFIG), state_dir, tmp_path / "sanitized")
    assert mode(state_dir) == 0o700
    assert mode(raw_path) == 0o600
    assert raw_path.read_bytes() == CONFIG
    assert "$2y$" not in sanitized_path.read_text()


@pytest.mark.parametrize("body", [b"", b"<html>login</html>", b"not xml"])
def test_download_that_is_not_a_config_is_refused_and_removed(tmp_path, body):
    state_dir = tmp_path / "state"
    with pytest.raises(BackupError):
        take_backup(Client(body), state_dir, tmp_path / "sanitized")
    assert list(state_dir.iterdir()) == []
