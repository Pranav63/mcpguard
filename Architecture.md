# MCPShield Architecture

MCPShield sits between an AI agent and an MCP server. Every JSON RPC message is scanned before it crosses the boundary.

## Data flow

```
Agent  ──►  Transport (HTTP or stdio)  ──►  Pipeline  ──►  Upstream MCP server
                │                            │
                │                     1. taint check
                │                     2. secret scan
                │                     3. PII scan
                │                     4. apply block / redact / flag
                ▼                            │
           audit log ◄───────────────────────┘
```

Responses follow the same path in reverse. Taint labels are recorded on the way back.

## Components

| Module | Role |
|--------|------|
| `proxy/server.py` | HTTP transport (FastAPI) |
| `proxy/stdio_bridge.py` | stdio transport (Claude Desktop, Cursor) |
| `proxy/pipeline.py` | Shared inspect logic for all transports |
| `policy/engine.py` | Map detector hits → block / redact / flag |
| `detectors/secrets.py` | Credential patterns + entropy |
| `detectors/pii.py` | PII patterns + redaction |
| `session/taint.py` | In-memory session taint store |

## Policy actions

| Action | Request | Response |
|--------|---------|----------|
| `block` | JSON-RPC error, upstream not called | Error returned to agent |
| `redact` | Sensitive substrings replaced, then forwarded | Redacted body returned |
| `flag` | Allowed; logged | Allowed; matched values marked tainted |

Default for unknown detectors: `flag`.

## Session taint (v1)

Problem: a secret read by `read_file` can reappear in `send_email` two calls later.

Simple v1 approach (no protobuf):

1. On **responses**, any detector match with length ≥ 12 is stored in an in-memory set.
2. On **requests**, if the body contains a stored substring → `block` with `taint_leak`.

Limitations (accepted for v1):

- Process-local only (restarts clear taint)
- Substring match (not semantic equivalence)
- No per-field provenance graph

Good enough to demo cross-tool leakage prevention.

## Transports

### HTTP (`transport: http`)

Agent POSTs JSON-RPC to `127.0.0.1:4444`. Shield forwards to `upstream.url`.

Use when the MCP server exposes HTTP.

### stdio (`transport: stdio`)

Shield spawns the upstream MCP server as a subprocess and relays newline-delimited JSON on stdin/stdout.

Use for Claude Desktop / Cursor MCP config:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "python",
      "args": ["-m", "mcpshield", "stdio"],
      "env": { "MCPSHIELD_CONFIG": "/path/to/config.yaml" }
    }
  }
}
```

## Configuration

```yaml
transport: stdio   # or http (default)

proxy:
  host: "127.0.0.1"
  port: 4444

upstream:
  # HTTP
  url: "http://localhost:3000"
  # stdio
  command: "npx"
  args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]

policy:
  rules:
    - detector: aws_access_key
      action: block

taint:
  enabled: true
  min_length: 12
```

## Extension points (later)

- **SSE transport** — same pipeline, different framing
- **Persistent audit** — ship structlog events to SQLite / OTel
- **Taint v2** — label per `tools/call` result field, propagate by reference
- **Dashboard** — read-only view over audit store

## Design principles

1. One pipeline, many transports, no duplicated policy logic
2. Prefer block + redact over clever ML in v1
3. Keep detectors pure functions (text in → list of hits out)
4. Add complexity only when a transport or feature needs it
