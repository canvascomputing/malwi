import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cli.cargo import CargoScanner


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
