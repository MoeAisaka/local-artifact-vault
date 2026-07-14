from __future__ import annotations

import argparse
import json
from pathlib import Path

from .server import serve
from .vault import Vault


def main() -> int:
    parser = argparse.ArgumentParser(prog="artifact-vault")
    parser.add_argument("--root", type=Path, default=Path("~/.local/share/local-artifact-vault").expanduser())
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    publish = sub.add_parser("publish")
    publish.add_argument("file", type=Path)
    publish.add_argument("--ttl", type=int, default=86400)
    publish.add_argument("--base-url")
    server = sub.add_parser("serve")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=19283)
    server.add_argument("--allow-remote", action="store_true")
    sub.add_parser("cleanup")
    args = parser.parse_args()
    vault = Vault(args.root)
    if args.command == "init":
        vault.initialize()
        print(json.dumps({"root": str(vault.root), "status": "ready"}))
    elif args.command == "publish":
        print(json.dumps(vault.publish(args.file, ttl_seconds=args.ttl, base_url=args.base_url), ensure_ascii=False))
    elif args.command == "serve":
        serve(args.root, args.host, args.port, allow_remote=args.allow_remote)
    elif args.command == "cleanup":
        print(json.dumps({"removed": vault.cleanup()}))
    return 0
