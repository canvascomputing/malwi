import sys
import os
from pathlib import Path
import io
import tarfile
import pytest

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cli.cargo import CargoScanner, validate_tar_member


def test_parse_dependencies_from_lock(tmp_path):
    lock_content = """
[[package]]
name = "foo"
version = "1.0.0"

[[package]]
name = "bar"
version = "0.2.1"
"""
    (tmp_path / "Cargo.lock").write_text(lock_content)
    scanner = CargoScanner(temp_dir=tmp_path)
    deps = scanner.parse_dependencies(tmp_path)
    assert "foo 1.0.0" in deps
    assert "bar 0.2.1" in deps


def test_parse_dependencies_from_toml(tmp_path):
    toml_content = """
[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = "1.0"
rand = { version = "0.8" }
"""
    (tmp_path / "Cargo.toml").write_text(toml_content)
    scanner = CargoScanner(temp_dir=tmp_path)
    deps = scanner.parse_dependencies(tmp_path)
    assert "serde 1.0" in deps
    assert "rand 0.8" in deps


def test_validate_tar_member_allows_safe_file(tmp_path):
    tar_path = tmp_path / "safe.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tar:
        info = tarfile.TarInfo(name="file.txt")
        data = b"safe"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    with tarfile.open(tar_path, "r:gz") as tar:
        for member in tar.getmembers():
            validate_tar_member(member, tmp_path)


def test_validate_tar_member_rejects_path_traversal(tmp_path):
    tar_path = tmp_path / "traversal.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tar:
        info = tarfile.TarInfo(name="../evil.txt")
        data = b"evil"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    with tarfile.open(tar_path, "r:gz") as tar:
        member = tar.getmembers()[0]
        with pytest.raises(Exception):
            validate_tar_member(member, tmp_path)


def test_validate_tar_member_rejects_link_outside(tmp_path):
    tar_path = tmp_path / "link.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tar:
        info = tarfile.TarInfo(name="link")
        info.type = tarfile.SYMTYPE
        info.linkname = "../outside"
        tar.addfile(info)
    with tarfile.open(tar_path, "r:gz") as tar:
        member = tar.getmembers()[0]
        with pytest.raises(Exception):
            validate_tar_member(member, tmp_path)


def test_validate_tar_member_rejects_hard_link_outside(tmp_path):
    tar_path = tmp_path / "hardlink.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tar:
        info = tarfile.TarInfo(name="dir/link")
        info.type = tarfile.LNKTYPE
        info.linkname = "../outside"
        tar.addfile(info)
    with tarfile.open(tar_path, "r:gz") as tar:
        member = tar.getmembers()[0]
        with pytest.raises(Exception):
            validate_tar_member(member, tmp_path)
