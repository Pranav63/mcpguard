import httpx
import structlog

from mcpshield.proxy.models import JSONRPCRequest, JSONRPCResponse

log = structlog.get_logger()


class MCPForwarder:
    def __init__(self, upstream_url: str):
        self._upstream = upstream_url
        self._client = httpx.AsyncClient(timeout=30.0)

    async def forward(self, request: JSONRPCRequest) -> JSONRPCResponse:
        try:
            resp = await self._client.post(
                self._upstream,
                json=request.model_dump(exclude_none=True),
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            return JSONRPCResponse.model_validate(resp.json())
        except httpx.HTTPStatusError as e:
            log.error(
                "upstream_http_error",
                status=e.response.status_code,
                upstream=self._upstream,
            )
            raise
        except httpx.RequestError as e:
            log.error("upstream_unreachable", error=str(e), upstream=self._upstream)
            raise

    async def aclose(self):
        await self._client.aclose()
