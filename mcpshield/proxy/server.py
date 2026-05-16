import json
import os

import structlog
import uvicorn
import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from mcpshield.policy.engine import  evaluate_and_redact, load_policy
from mcpshield.proxy.forwarder import MCPForwarder
from mcpshield.proxy.models import JSONRPCRequest, JSONRPCResponse

log = structlog.get_logger()
app = FastAPI(title="MCPShield Proxy", version="0.1.0")

_forwarder: MCPForwarder | None = None


def _load_config(path: str = "config.yaml") -> dict:
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"config.yaml not found in {os.getcwd()} — run mcpshield from your project root"
        )
    with open(path) as f:
        return yaml.safe_load(f)


@app.on_event("startup")
async def startup():
    global _forwarder
    cfg = _load_config()
    load_policy(cfg)  # load rules from config.yaml
    upstream = cfg["upstream"]["url"]
    log.info("mcpshield_starting", upstream=upstream)
    _forwarder = MCPForwarder(upstream_url=upstream)


@app.on_event("shutdown")
async def shutdown():
    if _forwarder:
        await _forwarder.aclose()


@app.post("/")
async def proxy(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    rpc = JSONRPCRequest.model_validate(body)
    raw = json.dumps(body)

    clean_raw, violation = evaluate_and_redact(raw, context=f"method={rpc.method}")

    if violation and violation.action == "block":
        return JSONResponse(
            status_code=200,
            content=JSONRPCResponse(
                id=rpc.id,
                error={"code": -32600, "message": violation.detail},
            ).model_dump(exclude_none=True),
        )

    # if redacted, re-parse the cleaned body
    if violation and violation.action == "redact":
        body = json.loads(clean_raw)
        rpc = JSONRPCRequest.model_validate(body)

    try:
        upstream_response = await _forwarder.forward(rpc)
    except Exception as e:
        log.error("forward_failed", error=str(e))
        raise HTTPException(status_code=502, detail="Upstream MCP server unreachable")

    resp_raw = json.dumps(upstream_response.model_dump())
    _, resp_violation = evaluate_and_redact(
        resp_raw, context=f"response method={rpc.method}"
    )

    if resp_violation and resp_violation.action == "block":
        log.warning("response_blocked", method=rpc.method)
        return JSONResponse(
            status_code=200,
            content=JSONRPCResponse(
                id=rpc.id,
                error={
                    "code": -32600,
                    "message": "Response blocked by MCPShield policy.",
                },
            ).model_dump(exclude_none=True),
        )

    return JSONResponse(content=upstream_response.model_dump(exclude_none=True))


def main():
    try:
        cfg = _load_config()
        host = cfg.get("proxy", {}).get("host", "127.0.0.1")
        port = cfg.get("proxy", {}).get("port", 4444)
        log.info("mcpshield_starting", host=host, port=port)
        uvicorn.run("mcpshield.proxy.server:app", host=host, port=port, reload=False)
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        raise SystemExit(1)
    except Exception as e:
        print(f"ERROR: {e}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
