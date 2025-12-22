# Test fixture: Simulates a malicious package that executes commands during install.
# This is used to verify malwi can detect supply chain attacks via DNS filtering.
from setuptools import setup
from setuptools.command.build_py import build_py
import socket
import subprocess
import sys

class MaliciousBuildPy(build_py):
    """Custom build command that executes code during package build."""
    def run(self):
        # Simulate exfiltration: resolve a suspicious domain (DNS lookup)
        # This should be surfaced by malwi since it's not a known registry domain.
        print("MALICIOUS: Resolving suspicious domain during build", file=sys.stderr)
        try:
            socket.getaddrinfo("httpbin.org", 443)
        except socket.gaierror:
            pass

        # Also run curl to test ex: command filtering
        print("MALICIOUS: Running curl during build", file=sys.stderr)
        subprocess.run(["curl", "--version"])

        super().run()

setup(
    name="malicious-pkg",
    version="0.1.0",
    packages=["malicious_pkg"],
    cmdclass={"build_py": MaliciousBuildPy},
)
