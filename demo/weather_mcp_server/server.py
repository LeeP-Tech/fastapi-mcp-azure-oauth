"""Weather MCP Server — demo of fastapi-mcp-azure-oauth.

Run with:
    uvicorn demo.weather_mcp_server.server:app --reload
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator
from urllib.parse import urlparse

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from fastapi_mcp_azure_oauth import TokenValidator, build_oauth_router

from .weather import get_alerts, get_forecast

# ---------------------------------------------------------------------------
# Configuration — read from environment variables
# ---------------------------------------------------------------------------
APP_ID        = os.environ["AZURE_CLIENT_ID"]
TENANT_ID     = os.environ["AZURE_TENANT_ID"]
CLIENT_SECRET = os.environ["AZURE_CLIENT_SECRET"]
# Public URL of this server, e.g. https://weather-mcp.example.com
BASE_URL      = os.environ.get("PUBLIC_BASE_URL")
# Comma-separated tenant IDs allowed to call the server (defaults to the home tenant)
ALLOWED_TENANT_IDS = [
    t.strip()
    for t in os.environ.get("AZURE_ALLOWED_TENANT_IDS", TENANT_ID).split(",")
    if t.strip()
]
# Comma-separated client redirect URIs that POST /register may enrol in Azure AD
ALLOWED_REDIRECT_URIS = [
    u.strip() for u in os.environ.get("ALLOWED_REDIRECT_URIS", "").split(",") if u.strip()
]

# DNS rebinding protection for the MCP endpoint: only accept requests whose
# Host header matches the public URL.  Without PUBLIC_BASE_URL, the MCP SDK
# defaults to accepting localhost only.
TRANSPORT_SECURITY = (
    TransportSecuritySettings(
        allowed_hosts=[urlparse(BASE_URL).netloc],
        allowed_origins=[BASE_URL.rstrip("/")],
    )
    if BASE_URL
    else None
)

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    # Mounted sub-apps don't get their own lifespan run, so start the MCP
    # session manager here.
    async with mcp.session_manager.run():
        yield


app = FastAPI(
    title="Weather MCP Server",
    description="Demonstrates fastapi-mcp-azure-oauth with a simple weather MCP server.",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# 1 — Mount the OAuth discovery / registration endpoints (public)
# ---------------------------------------------------------------------------
app.include_router(
    build_oauth_router(
        app_id=APP_ID,
        tenant_id=TENANT_ID,
        client_secret=CLIENT_SECRET,
        api_scope="access_as_user",
        resource_path="/mcp",
        allowed_tenant_ids=ALLOWED_TENANT_IDS,
        base_url=BASE_URL,
        allowed_redirect_uris=ALLOWED_REDIRECT_URIS,
    )
)

# ---------------------------------------------------------------------------
# 2 — Token validator
# ---------------------------------------------------------------------------
validator = TokenValidator(
    app_id=APP_ID,
    allowed_tenant_ids=ALLOWED_TENANT_IDS,
    required_scopes=["access_as_user"],
)


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Validates Azure AD Bearer tokens on every request to /mcp."""

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        if request.url.path.startswith("/mcp"):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Authentication required. Provide Authorization: Bearer <token>"},
                    headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
                )
            try:
                await validator.validate_token_async(auth[7:])
            except Exception:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid or expired token"},
                    headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
                )
        return await call_next(request)


app.add_middleware(BearerAuthMiddleware)

# ---------------------------------------------------------------------------
# 3 — MCP server with weather tools, served at /mcp
# ---------------------------------------------------------------------------
mcp = MCPServer("Weather MCP Server")


@mcp.tool()
async def get_weather_alerts(state: str) -> str:
    """Get active weather alerts for a US state.

    Args:
        state: Two-letter US state code (e.g. CA, TX, NY).
    """
    if len(state) != 2 or not state.isalpha():
        return "Please provide a valid two-letter US state code (e.g. CA, TX, NY)."
    return await get_alerts(state)


@mcp.tool()
async def get_weather_forecast(latitude: float, longitude: float) -> str:
    """Get the weather forecast for a location by latitude and longitude.

    Only works for US locations. Returns a multi-period forecast.

    Args:
        latitude:  Latitude of the location (e.g. 37.7749 for San Francisco).
        longitude: Longitude of the location (e.g. -122.4194 for San Francisco).
    """
    if not (-90 <= latitude <= 90):
        return "Latitude must be between -90 and 90."
    if not (-180 <= longitude <= 180):
        return "Longitude must be between -180 and 180."
    return await get_forecast(latitude, longitude)


# Mount the MCP ASGI app last so the OAuth routes above take precedence; it
# serves the MCP endpoint at /mcp.  Auth is enforced by BearerAuthMiddleware.
app.mount(
    "/",
    mcp.streamable_http_app(
        streamable_http_path="/mcp",
        transport_security=TRANSPORT_SECURITY,
    ),
)
