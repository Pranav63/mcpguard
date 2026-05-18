"""stdio transport: relay newline-delimited JSON-RPC to an upstream MCP subprocess."""

import json
import os
import subprocess
import sys

import structlog
import yaml

from mcpshield.proxy.pipeline import (
    block_response,
    init,
    inspect,
    request_id_from_raw,
)

log = structlog.get_logger()


def _load_config() -> dict:
    path = os.environ.get("MCPSHIELD_CONFIG", "config.yaml")
    if not os.path.exists(path):
        raise FileNotFoundError(f"config not found: {path}")
    with open(path) as f:
        return yaml.safe_load(f)


def run() -> None:
    cfg = _load_config()
    init(cfg)

    upstream = cfg["upstream"]
    command = upstream["command"]
    args = upstream.get("args", [])

    log.info("stdio_bridge_starting", command=command, args=args)

    proc = subprocess.Popen(
        [command, *args],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        bufsize=1,
    )

    assert proc.stdin and proc.stdout

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        req_id = request_id_from_raw(line)
        clean, violation = inspect(line, context="stdio:request")

        if violation and violation.action == "block":
            print(block_response(req_id, violation.detail), flush=True)
            continue

        proc.stdin.write(clean + "\n")
        proc.stdin.flush()

        resp_line = proc.stdout.readline()
        if not resp_line:
            break

        resp_line = resp_line.strip()
        if not resp_line:
            continue

        clean_resp, resp_violation = inspect(
            resp_line, context="stdio:response", record_taint=True
        )

        if resp_violation and resp_violation.action == "block":
            print(
                block_response(req_id, "Response blocked by MCPShield policy."),
                flush=True,
            )
            continue

        print(clean_resp, flush=True)

    proc.terminate()
