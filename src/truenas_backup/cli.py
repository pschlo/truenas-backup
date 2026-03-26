#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
import pathlib
import ssl
import sys
import tarfile
import time
import tempfile
import urllib.parse
import urllib.request

import websocket


class TrueNASBackupError(Exception):
    pass


@dataclass
class BackupFile:
    path: pathlib.Path
    timestamp: float


def unix_timestamp() -> str:
    return f"{time.time():.4f}"


def parse_backup_file(path: pathlib.Path) -> BackupFile:
    if not path.is_file():
        raise TrueNASBackupError(f"Not a file: {path.name}")
    if path.suffix not in (".db", ".tar"):
        raise TrueNASBackupError(f"Invalid filename suffix: {path.suffix}")
    if not path.name.startswith("config-"):
        raise TrueNASBackupError(f"Invalid filename: {path.name}")

    timestamp_part = ".".join(path.name[len("config-"):].split(".", 2)[:2])
    return BackupFile(path, float(timestamp_part))


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


def verify_backup_file(path: pathlib.Path, expected_ext: str) -> None:
    if not path.exists():
        raise TrueNASBackupError(f"Downloaded file does not exist: {path}")

    size = path.stat().st_size
    if size <= 0:
        raise TrueNASBackupError(f"Downloaded file is empty: {path}")

    if expected_ext == ".tar" and not tarfile.is_tarfile(path):
        raise TrueNASBackupError(f"Downloaded file is not a valid tar archive: {path}")


def download_to_temp(
    url: str,
    outdir: pathlib.Path,
    temp_prefix: str,
    insecure: bool,
    timeout: float,
) -> tuple[pathlib.Path, int]:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, method="GET")
    bytes_written = 0
    tmp_path: pathlib.Path | None = None

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            status = getattr(resp, "status", 200)
            if status != 200:
                raise TrueNASBackupError(f"Download failed with HTTP status {status}")

            content_length_header = resp.headers.get("Content-Length")
            expected_length = int(content_length_header) if content_length_header else None

            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=outdir,
                prefix=temp_prefix + ".",
                suffix=".tmp",
                delete=False,
            ) as tmp:
                tmp_path = pathlib.Path(tmp.name)

                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    tmp.write(chunk)
                    bytes_written += len(chunk)

        if expected_length is not None and bytes_written != expected_length:
            raise TrueNASBackupError(
                f"Download size mismatch: expected {expected_length} bytes, got {bytes_written} bytes"
            )

        if tmp_path is None:
            raise TrueNASBackupError("Temporary download file was not created")

        return tmp_path, bytes_written

    except Exception:
        if tmp_path is not None:
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass
        raise


def files_are_identical(a: pathlib.Path, b: pathlib.Path) -> bool:
    if a.stat().st_size != b.stat().st_size:
        return False

    with a.open("rb") as fa, b.open("rb") as fb:
        while True:
            ba = fa.read(1024 * 1024)
            bb = fb.read(1024 * 1024)
            if ba != bb:
                return False
            if not ba:
                return True


def list_backup_files(outdir: pathlib.Path) -> list[BackupFile]:
    candidates: list[BackupFile] = []

    for p in outdir.iterdir():
        if p.is_file() and p.suffix == ".tmp":
            # Skip temp file
            continue
        backup_file = parse_backup_file(p)
        candidates.append(backup_file)

    candidates.sort(key=lambda b: b.timestamp, reverse=True)
    return candidates


def latest_backup_file(outdir: pathlib.Path) -> BackupFile | None:
    candidates = list_backup_files(outdir)
    return candidates[0] if candidates else None


def prune_old_backups(outdir: pathlib.Path, keep_days: int) -> list[BackupFile]:
    cutoff = time.time() - keep_days * 86400
    removed: list[BackupFile] = []

    for p in list_backup_files(outdir):
        if p.timestamp < cutoff:
            try:
                p.path.unlink()
                removed.append(p)
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
        required=True,
        help="Output directory",
    )
    parser.add_argument(
        "--keep-days",
        type=int,
        help="Keep all backups from the last N days",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30,
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
        "--no-root-authorized-keys",
        action="store_true",
        help="Do not include /root/.ssh/authorized_keys",
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
    if not outdir.exists():
        raise TrueNASBackupError(f"Output directory does not exist: {outdir}")

    if not outdir.is_dir():
        raise TrueNASBackupError(f"Output path is not a directory: {outdir}")

    if not os.access(outdir, os.W_OK):
        raise TrueNASBackupError(f"Output directory is not writable: {outdir}")

    include_secretseed = not args.no_secretseed
    include_root_authorized_keys = not args.no_root_authorized_keys

    ext = ".tar" if (include_secretseed or include_root_authorized_keys) else ".db"
    filename = f"config-{unix_timestamp()}{ext}"
    dest = outdir / filename

    ws = None
    tmp_download: pathlib.Path | None = None

    try:
        ws = connect_ws(args.host, args.insecure, args.timeout)
        authenticate(ws, args.api_key, args.timeout)

        job_id, download_path = request_download(
            ws,
            secretseed=include_secretseed,
            root_authorized_keys=include_root_authorized_keys,
            timeout=args.timeout,
        )

        download_url = build_download_url(args.host, download_path)
        tmp_download, bytes_written = download_to_temp(
            download_url,
            outdir,
            temp_prefix=dest.name,
            insecure=args.insecure,
            timeout=args.timeout,
        )
        verify_backup_file(tmp_download, ext)

        previous = latest_backup_file(outdir)
        unchanged = previous is not None and previous.path.suffix == ext and files_are_identical(tmp_download, previous.path)

        if unchanged:
            assert previous is not None
            tmp_download.unlink()
            tmp_download = None
            saved_to = str(previous.path)
            print(f"Backup unchanged, skipped write: {saved_to}", file=sys.stderr)
        else:
            tmp_download.replace(dest)
            saved_to = str(dest)
            print(f"Backup changed, wrote new file: {saved_to}", file=sys.stderr)

        if args.keep_days is not None:
            removed = prune_old_backups(outdir, args.keep_days)
        else:
            removed = []

        if removed:
            print(f"Pruned {len(removed)} old backup(s):", file=sys.stderr)
            for backup in removed:
                print(f"  {backup.path}", file=sys.stderr)
        else:
            print("Pruned 0 old backup(s)", file=sys.stderr)

        return 0

    except TrueNASBackupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"ERROR: Unexpected failure: {exc}", file=sys.stderr)
        return 1
    finally:
        if tmp_download is not None:
            try:
                tmp_download.unlink()
            except FileNotFoundError:
                pass

        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
