from pathlib import Path

import pytest

from truenas_backup.cli import (
    TrueNASBackupError,
    build_download_url,
    files_are_identical,
    parse_backup_file,
    prune_old_backups,
    verify_backup_file,
)


def test_parse_backup_file(tmp_path: Path) -> None:
    path = tmp_path / "config-123.4567.db"
    path.write_bytes(b"config")

    backup = parse_backup_file(path)

    assert backup.path == path
    assert backup.timestamp == 123.4567


def test_build_download_url() -> None:
    assert build_download_url("nas.example.com", "/download?id=1") == (
        "https://nas.example.com/download?id=1"
    )
    assert build_download_url("nas.example.com", "https://nas.example.com/download") == (
        "https://nas.example.com/download"
    )


def test_files_are_identical(tmp_path: Path) -> None:
    first = tmp_path / "first.db"
    second = tmp_path / "second.db"
    first.write_bytes(b"same")
    second.write_bytes(b"same")
    assert files_are_identical(first, second)

    second.write_bytes(b"different")
    assert not files_are_identical(first, second)


def test_verify_backup_rejects_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "empty.db"
    path.touch()

    with pytest.raises(TrueNASBackupError, match="empty"):
        verify_backup_file(path, ".db")


def test_prune_old_backups(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    old = tmp_path / "config-100.0000.db"
    recent = tmp_path / "config-190.0000.db"
    old.write_bytes(b"old")
    recent.write_bytes(b"recent")
    monkeypatch.setattr("truenas_backup.cli.time.time", lambda: 200.0)

    removed = prune_old_backups(tmp_path, keep_days=50 / 86400)

    assert [backup.path for backup in removed] == [old]
    assert not old.exists()
    assert recent.exists()
