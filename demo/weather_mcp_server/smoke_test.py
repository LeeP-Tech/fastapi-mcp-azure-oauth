"""End-to-end smoke test for the weather MCP demo server.

Starts the app in-process with token validation stubbed out and checks that
the MCP endpoint is reachable, enforces auth and Host checks, and lists the
weather tools.  Run from the repository root:

    python -m demo.weather_mcp_server.smoke_test
"""

from __future__ import annotations

import json
import os
from unittest.mock import AsyncMock

os.environ.setdefault("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000001")
os.environ.setdefault("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000002")
os.environ.setdefault("AZURE_CLIENT_SECRET", "dummy")
os.environ.setdefault("PUBLIC_BASE_URL", "https://mcp.example.com")

from fastapi.testclient import TestClient  # noqa: E402

from . import server  # noqa: E402

HEADERS = {
    "Authorization": "Bearer test-token",
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}


def _rpc(client: TestClient, method: str, params: dict, req_id: int, session: str | None = None):
    headers = dict(HEADERS)
    if session:
        headers["mcp-session-id"] = session
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": req_id, "method": method, "params": params},
        headers=headers,
    )
    assert resp.status_code == 200, (method, resp.status_code, resp.text)
    data = next(
        json.loads(line[len("data:"):])
        for line in resp.text.splitlines()
        if line.startswith("data:")
    )
    return resp, data


def main() -> None:
    server.validator.validate_token_async = AsyncMock(return_value={"scp": "access_as_user"})

    with TestClient(server.app, base_url="https://mcp.example.com") as client:
        # Unauthenticated requests are rejected before reaching MCP.
        resp = client.post("/mcp", json={}, headers={"Accept": HEADERS["Accept"]})
        assert resp.status_code == 401, resp.status_code

        # Requests for a host other than PUBLIC_BASE_URL are rejected.
        resp = client.post("/mcp", json={}, headers={**HEADERS, "Host": "evil.example.com"})
        assert resp.status_code == 421, resp.status_code

        resp, init = _rpc(
            client,
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "smoke-test", "version": "1"},
            },
            1,
        )
        assert init["result"]["serverInfo"]["name"] == "Weather MCP Server", init
        session = resp.headers.get("mcp-session-id")

        client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers={**HEADERS, **({"mcp-session-id": session} if session else {})},
        )

        _, tools = _rpc(client, "tools/list", {}, 2, session)
        names = {t["name"] for t in tools["result"]["tools"]}
        assert names == {"get_weather_alerts", "get_weather_forecast"}, names

    print("Demo smoke test passed")


if __name__ == "__main__":
    main()
