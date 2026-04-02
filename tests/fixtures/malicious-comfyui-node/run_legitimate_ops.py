# Test fixture: Verifies legitimate ComfyUI operations work under policy.
# These must NOT be blocked by the comfyui policy.
#
# Usage:
#   malwi x python tests/fixtures/malicious-comfyui-node/run_legitimate_ops.py
#
# Expected: all operations succeed, exit code 0

import json
import os
import sys
import tempfile

results = []


def op(name, fn):
    """Run a legitimate operation and verify it works."""
    try:
        fn()
        results.append(("PASS", name))
    except Exception as e:
        results.append(("FAIL", name, f"{type(e).__name__}: {e}"))


# ── Python startup (already passed if we got here) ───────────────

op("python_startup", lambda: None)

# ── Standard library imports ─────────────────────────────────────

op("import_json", lambda: json.dumps({"key": "value"}))
op("import_tempfile", lambda: tempfile.mktemp())
op("import_os_path", lambda: os.path.exists("/tmp"))

# ── File I/O (non-sensitive paths) ───────────────────────────────

op(
    "write_temp_file",
    lambda: open("/tmp/malwi-comfyui-legit-test.txt", "w").write("test"),
)
op(
    "read_temp_file",
    lambda: open("/tmp/malwi-comfyui-legit-test.txt").read(),
)

# ── Environment variable reads (non-sensitive) ───────────────────

op("env_home", lambda: os.environ.get("HOME"))
op("env_path", lambda: os.environ.get("PATH"))
op("env_hf_hub_offline", lambda: os.environ.get("HF_HUB_OFFLINE"))

# ── Subprocess spawning .py files (ComfyUI custom nodes) ─────────

def test_subprocess_py_file():
    """ComfyUI spawns Python subprocesses to run .py scripts."""
    import subprocess
    # Create a temp script
    script = "/tmp/malwi-comfyui-child-test.py"
    with open(script, "w") as f:
        f.write("print('child ok')\n")
    r = subprocess.run(
        [sys.executable, script],
        capture_output=True, text=True, timeout=5,
    )
    os.unlink(script)
    if r.returncode != 0 or "child ok" not in r.stdout:
        raise RuntimeError(f"exit={r.returncode}, out={r.stdout[:50]}")

op("subprocess_py_file", test_subprocess_py_file)


def test_subprocess_py_subdir():
    """ComfyUI runs scripts in subdirectories (custom_nodes/)."""
    import subprocess
    subdir = "/tmp/malwi-comfyui-nodes-test"
    os.makedirs(subdir, exist_ok=True)
    script = os.path.join(subdir, "node.py")
    with open(script, "w") as f:
        f.write("print('node ok')\n")
    r = subprocess.run(
        [sys.executable, script],
        capture_output=True, text=True, timeout=5,
    )
    os.unlink(script)
    os.rmdir(subdir)
    if r.returncode != 0 or "node ok" not in r.stdout:
        raise RuntimeError(f"exit={r.returncode}, out={r.stdout[:50]}")

op("subprocess_py_subdir", test_subprocess_py_subdir)

# ── Cleanup ──────────────────────────────────────────────────────

try:
    os.unlink("/tmp/malwi-comfyui-legit-test.txt")
except OSError:
    pass

# ── Print results ────────────────────────────────────────────────

passed = sum(1 for r in results if r[0] == "PASS")
total = len(results)

for r in results:
    status = r[0]
    name = r[1]
    detail = r[2] if len(r) > 2 else "ok"
    print(f"  [{status}] {name}: {detail}")

print(f"\nLegitimate ops: {passed}/{total}")
sys.exit(0 if passed == total else 1)
