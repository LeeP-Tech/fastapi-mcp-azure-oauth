"""Weather MCP Server — demo of fastapi-mcp-azure-oauth.

Run with:
    uvicorn demo.weather_mcp_server.server:app --reload
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from mcp.server.fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from fastapi_mcp_azure_oauth import TokenValidator, build_oauth_router

from .weather import get_alerts, get_forecast

# ---------------------------------------------------------------------------
# Configuration — read from environment variables
# ---------------------------------------------------------------------------
APP_ID        = os.environ["AZURE_CLIENT_ID"]
TENANT_ID     = os.environ["AZURE_TENANT_ID"]
CLIENT_SECRET = os.environ["AZURE_CLIENT_SECRET"]

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Weather MCP Server",
    description="Demonstrates fastapi-mcp-azure-oauth with a simple weather MCP server.",
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
    )
)

# ---------------------------------------------------------------------------
# 2 — Token validator
# ---------------------------------------------------------------------------
validator = TokenValidator(app_id=APP_ID)


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
                validator.validate_token(auth[7:])
            except Exception:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid or expired token"},
                    headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
                )
        return await call_next(request)


app.add_middleware(BearerAuthMiddleware)

# ---------------------------------------------------------------------------
# 3 — MCP server with weather tools, mounted at /mcp
# ---------------------------------------------------------------------------
mcp = FastMCP("Weather MCP Server")


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


# Mount the MCP ASGI app — auth is enforced by BearerAuthMiddleware above
app.mount("/mcp", mcp.streamable_http_app())
