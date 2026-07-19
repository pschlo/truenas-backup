# TrueNAS Backup

Back up a TrueNAS SCALE configuration through its JSON-RPC WebSocket API.

## Run

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), set
`TRUENAS_HOST` and `TRUENAS_API_KEY`, then run:

```console
uvx https://github.com/pschlo/truenas-backup/archive/refs/heads/main.zip --outdir path/to/backups
```

The output directory must already exist. By default, backups include the secret
seed and root authorized keys and are therefore stored as tar archives. Append
`--help` to see retention, timeout, TLS, and content options.

Configuration backups and API keys are sensitive. Protect the output directory
and use `--insecure` only on a trusted network when certificate verification
cannot be configured correctly.

## Development

```console
uv sync --locked
uv run pytest
uv build
```
