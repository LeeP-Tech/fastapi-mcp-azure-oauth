# Weather MCP Server Demo

A minimal FastAPI MCP server that exposes US weather data from [api.weather.gov](https://api.weather.gov)
(free, no API key required), protected with Azure AD Bearer token validation via `fastapi-mcp-azure-oauth`.

## Running locally

```bash
pip install -r demo/weather_mcp_server/requirements.txt

# Set your Azure AD credentials as environment variables
export AZURE_CLIENT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export AZURE_TENANT_ID="yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
export AZURE_CLIENT_SECRET="your-client-secret"

uvicorn demo.weather_mcp_server.server:app --reload
```

The server will be available at `http://localhost:8000`.

## Available MCP tools

| Tool | Description |
|---|---|
| `get_weather_alerts` | Active alerts for a US state (e.g. `CA`, `TX`) |
| `get_weather_forecast` | Multi-period forecast for a lat/lon coordinate |

## Connecting from Copilot Studio

Point Copilot Studio at `https://your-server/mcp` and it will autodiscover the OAuth endpoints via `/.well-known/`.
