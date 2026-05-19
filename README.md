# MCPShield

A security proxy for the Model Context Protocol (MCP). Sits between your AI agent and MCP tool servers, inspecting every tool call for secrets and policy violations in real time.

## How It Works

```
AI Agent → MCPShield (:4444) → MCP Server
                ↓
          secret detection
          policy enforcement
          audit log
```

Requests **and** responses are scanned. Violations are blocked before they reach the upstream server.

## Detects

| Pattern | Examples |
|---------|---------|
| Known credentials | AWS keys, GitHub tokens, OpenAI/Anthropic keys, GCP API keys, Stripe live keys |
| Private keys | RSA, EC, OpenSSH PEM blocks |
| Tokens | JWTs |
| Unknown secrets | High-entropy strings via Shannon entropy scoring |

## Actions

| Rule match | Action |
|------------|--------|
| Known credential | Block — JSON-RPC error returned, upstream never called |
| JWT / high-entropy | Flag — allowed through, logged as warning |

## Quickstart

**1. Clone and install**
```bash
git clone https://github.com/yourhandle/mcpshield
cd mcpshield
pip install -e .
```

**2. Configure your upstream MCP server**
```yaml
# config.yaml
proxy:
  host: "127.0.0.1"
  port: 4444

upstream:
  url: "http://localhost:3000"  # your MCP server
```

**3. Run from the project root**
```bash
# must be run from repo root where config.yaml lives
python -m mcpshield
```

Proxy is live at `http://127.0.0.1:4444`. Point your AI agent or Claude Desktop here instead of your MCP server directly.

## Test It

**Secret blocked:**
```bash
curl -s -X POST http://127.0.0.1:4444 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "write_file",
      "arguments": {"content": "key=AKIAIOSFODNN7EXAMPLE"}
    }
  }' | jq
```

Expected response:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32600,
    "message": "Detected 'aws_access_key' in method=tools/call. Request blocked."
  }
}
```

**Clean request (proxied through):**
```bash
curl -s -X POST http://127.0.0.1:4444 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | jq
```

## Run Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for transports (HTTP + stdio), policy pipeline, and session taint.

**stdio mode** (Claude Desktop / Cursor):

```bash
cp config.yaml.example config.yaml
# set upstream.command / upstream.args and taint.enabled
python -m mcpshield stdio
```

## Roadmap

- [x] Week 1: Transparent proxy with real-time secret detection
- [x] Week 2: Policy-as-config, PII detection, redaction
- [x] Week 3: Session-level taint propagation (v1, in-memory)
- [ ] Week 4: Audit dashboard

## Contributing

Pattern contributions welcome — add detection rules to `mcpshield/detectors/secrets.py` and open a PR.

