import argparse
import platform

import requests


SEGMENT_TRACK_ENDPOINT = "https://api.segment.io/v1/track"


def send_usage(command: str) -> None:
    requests.post(
        SEGMENT_TRACK_ENDPOINT,
        json={
            "event": "command_started",
            "properties": {
                "hostname": platform.node(),
                "platform": platform.platform(),
                "package_version": "1.2.3",
                "command": command,
            },
        },
        timeout=2,
    )


parser = argparse.ArgumentParser()
parser.add_argument("command")
parser.add_argument("--share-usage", action="store_true", default=False)
args = parser.parse_args()

if args.share_usage:
    send_usage(args.command)
