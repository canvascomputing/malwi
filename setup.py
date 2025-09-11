from setuptools import setup, find_packages
import os
import sys

# Add src to path to import version
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from malwi._version import __version__

setup(
    name="malwi",
    version=__version__,
    author="Marvin Schirrmacher",
    author_email="m@schirrmacher.io",
    description="malwi - AI Python Malware Scanner",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/schirrmacher/malwi",
    packages=find_packages(where="src", exclude=["research", "research.*"]),
    package_dir={"": "src"},
    include_package_data=True,
    python_requires=">=3.12",
    package_data={
        "common.syntax_mapping": [
            "function_mapping.json",
            "import_mapping.json",
            "sensitive_files.json",
            "target_files.json",
            "rust/*.json",
        ]
    },
    install_requires=[
        # Add any dependencies here
    ],
)
