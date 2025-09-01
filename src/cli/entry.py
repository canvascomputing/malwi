import os
import argparse

from common.predict_distilbert import get_model_version_string
from common.messaging import result
from malwi._version import __version__
from cli.scan import setup_scan_parser
from cli.pypi import setup_pypi_parser


def main():
    parser = argparse.ArgumentParser(description="malwi - AI Python Malware Scanner")
    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version=get_model_version_string(__version__),
    )

    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Set up subcommand parsers using their respective setup functions
    setup_scan_parser(subparsers)
    setup_pypi_parser(subparsers)

    args = parser.parse_args()

    # If no command is specified, show help
    if not args.command:
        parser.print_help()
        return

    # Call the command function associated with the chosen subcommand
    args.func(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        result("👋", force=True)
        os._exit(130)
