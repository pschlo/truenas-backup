#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import ssl
import sys
import urllib.parse
import urllib.request

import websocket


class TrueNASBackupError(Exception):
    pass


def utc_timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def recv_json(ws: websocket.WebSocket, timeout: float) -> dict:
    ws.settimeout(timeout)
    raw = ws.recv()
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise TrueNASBackupError(f"Invalid JSON from server: {raw!r}") from exc


def rpc_call(
    ws: websocket.WebSocket,
    request_id: int,
    method: str,
    params: list,
    timeout: float,
) -> object:
    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params,
    }
    ws.send(json.dumps(payload))

    while True:
        msg = recv_json(ws, timeout)

        if "id" not in msg:
            continue
        if msg.get("id") != request_id:
            continue

        if "error" in msg:
            raise TrueNASBackupError(
                f"RPC error calling {method}: {json.dumps(msg['error'], ensure_ascii=False)}"
            )

        if "result" not in msg:
            raise TrueNASBackupError(f"Malformed RPC response for {method}: {msg!r}")

        return msg["result"]


def make_sslopt(insecure: bool) -> dict:
    if insecure:
        return {"cert_reqs": ssl.CERT_NONE}
    return {"cert_reqs": ssl.CERT_REQUIRED}


def connect_ws(host: str, insecure: bool, timeout: float) -> websocket.WebSocket:
    ws_url = f"wss://{host}/api/current"
    try:
        return websocket.create_connection(
            ws_url,
            sslopt=make_sslopt(insecure),
            timeout=timeout,
            enable_multithread=False,
        )
    except Exception as exc:
        raise TrueNASBackupError(f"Failed to connect to {ws_url}: {exc}") from exc


def authenticate(ws: websocket.WebSocket, api_key: str, timeout: float) -> None:
    result = rpc_call(ws, 1, "auth.login_with_api_key", [api_key], timeout)
    if result is not True:
        raise TrueNASBackupError("API key authentication failed")


def request_download(
    ws: websocket.WebSocket,
    *,
    secretseed: bool,
    root_authorized_keys: bool,
    timeout: float,
) -> tuple[int, str]:
    options = {
        "secretseed": secretseed,
        "root_authorized_keys": root_authorized_keys,
    }

    ext = "tar" if (secretseed or root_authorized_keys) else "db"
    suggested_filename = f"truenas-config-backup.{ext}"

    result = rpc_call(
        ws,
        2,
        "core.download",
        [
            "config.save",
            [options],
            suggested_filename,
        ],
        timeout,
    )

    if (
        not isinstance(result, list)
        or len(result) != 2
        or not isinstance(result[0], int)
        or not isinstance(result[1], str)
    ):
        raise TrueNASBackupError(f"Unexpected core.download result: {result!r}")

    return result[0], result[1]


def build_download_url(host: str, path: str) -> str:
    parsed = urllib.parse.urlparse(path)
    if parsed.scheme and parsed.netloc:
        return path
    return urllib.parse.urlunparse(("https", host, parsed.path, "", parsed.query, ""))


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download_file(url: str, dest: pathlib.Path, insecure: bool, timeout: float) -> None:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
        if getattr(resp, "status", 200) != 200:
            raise TrueNASBackupError(f"Download failed with HTTP status {resp.status}")

        with dest.open("wb") as out:
            while True:
                chunk = resp.read(1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)


def prune_old_backups(outdir: pathlib.Path, prefix: str, keep: int) -> list[pathlib.Path]:
    if keep <= 0:
        return []

    candidates = sorted(
        [p for p in outdir.iterdir() if p.is_file() and p.name.startswith(prefix + "-config-")],
        key=lambda p: p.name,
        reverse=True,
    )
    to_delete = candidates[keep:]
    removed: list[pathlib.Path] = []

    for p in to_delete:
        try:
            p.unlink()
            removed.append(p)
            sha = pathlib.Path(str(p) + ".sha256")
            if sha.exists():
                sha.unlink()
        except FileNotFoundError:
            pass

    return removed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Back up a TrueNAS SCALE config via the JSON-RPC WebSocket API"
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("TRUENAS_HOST"),
        help="TrueNAS hostname or IP, or set TRUENAS_HOST",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("TRUENAS_API_KEY"),
        help="API key, or set TRUENAS_API_KEY",
    )
    parser.add_argument(
        "--outdir",
        default=os.environ.get("TRUENAS_OUTDIR", "."),
        help="Output directory, default: current directory or TRUENAS_OUTDIR",
    )
    parser.add_argument(
        "--name-prefix",
        default=os.environ.get("TRUENAS_NAME_PREFIX", "truenas"),
        help="Filename prefix",
    )
    parser.add_argument(
        "--keep",
        type=int,
        default=int(os.environ.get("TRUENAS_KEEP", "0")),
        help="Keep only newest N backups; 0 disables pruning",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(os.environ.get("TRUENAS_TIMEOUT", "30")),
        help="Network timeout in seconds",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification",
    )
    parser.add_argument(
        "--no-secretseed",
        action="store_true",
        help="Do not include secret seed",
    )
    parser.add_argument(
        "--include-root-authorized-keys",
        action="store_true",
        help="Include /root/.ssh/authorized_keys",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.host:
        print(
            "No TrueNAS host supplied. Use --host or set TRUENAS_HOST.",
            file=sys.stderr,
        )
        return 2

    if not args.api_key:
        print(
            "No API key supplied. Use --api-key or set TRUENAS_API_KEY.",
            file=sys.stderr,
        )
        return 2

    outdir = pathlib.Path(args.outdir).expanduser().resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    ext = ".tar" if (not args.no_secretseed or args.include_root_authorized_keys) else ".db"
    filename = f"{args.name_prefix}-config-{utc_timestamp()}{ext}"
    dest = outdir / filename

    ws = None
    try:
        ws = connect_ws(args.host, args.insecure, args.timeout)
        authenticate(ws, args.api_key, args.timeout)

        job_id, download_path = request_download(
            ws,
            secretseed=not args.no_secretseed,
            root_authorized_keys=args.include_root_authorized_keys,
            timeout=args.timeout,
        )

        download_url = build_download_url(args.host, download_path)
        download_file(download_url, dest, args.insecure, args.timeout)

        digest = sha256_file(dest)
        sha_path = pathlib.Path(str(dest) + ".sha256")
        sha_path.write_text(f"{digest}  {dest.name}\n", encoding="utf-8")

        removed = prune_old_backups(outdir, args.name_prefix, args.keep)

        print(json.dumps({
            "ok": True,
            "host": args.host,
            "job_id": job_id,
            "saved_to": str(dest),
            "sha256": digest,
            "pruned": [str(p) for p in removed],
        }, indent=2))
        return 0

    except TrueNASBackupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"ERROR: Unexpected failure: {exc}", file=sys.stderr)
        return 1
    finally:
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())