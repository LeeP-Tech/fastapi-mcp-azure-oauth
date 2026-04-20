"""US weather data helpers using api.weather.gov (no API key required)."""

from __future__ import annotations

import httpx

_BASE = "https://api.weather.gov"
_HEADERS = {"User-Agent": "weather-mcp-demo/1.0 (demo)"}


async def get_alerts(state: str) -> str:
    """Return active weather alerts for a two-letter US state code."""
    async with httpx.AsyncClient(headers=_HEADERS, timeout=15) as client:
        resp = await client.get(f"{_BASE}/alerts/active", params={"area": state.upper()})
        resp.raise_for_status()
        data = resp.json()

    features = data.get("features", [])
    if not features:
        return f"No active weather alerts for {state.upper()}."

    lines = [f"Active weather alerts for {state.upper()}:"]
    for feature in features:
        props = feature.get("properties", {})
        headline = props.get("headline", "")
        severity = props.get("severity", "Unknown")
        desc = (props.get("description") or "").replace("\n", " ")
        if headline:
            lines.append(f"• {headline} (Severity: {severity})")
        if desc:
            lines.append(f"  {desc}")

    return "\n".join(lines)


async def get_forecast(latitude: float, longitude: float) -> str:
    """Return a multi-period weather forecast for a US lat/lon coordinate."""
    async with httpx.AsyncClient(headers=_HEADERS, timeout=15) as client:
        # Step 1 — resolve grid point
        points_resp = await client.get(f"{_BASE}/points/{latitude},{longitude}")
        points_resp.raise_for_status()
        forecast_url = points_resp.json()["properties"]["forecast"]

        # Step 2 — fetch the forecast
        forecast_resp = await client.get(forecast_url)
        forecast_resp.raise_for_status()
        periods = forecast_resp.json()["properties"]["periods"]

    lines = [f"Forecast for ({latitude}, {longitude}):"]
    for period in periods[:5]:
        lines.append(f"\n{period['name']}: {period['detailedForecast']}")

    return "\n".join(lines)
