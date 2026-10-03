# fastapi-mcp-azure-oauth

[![CI](https://github.com/LeeP-Tech/fastapi-mcp-azure-oauth/actions/workflows/ci.yml/badge.svg)](https://github.com/LeeP-Tech/fastapi-mcp-azure-oauth/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/fastapi-mcp-azure-oauth)](https://pypi.org/project/fastapi-mcp-azure-oauth/)
[![Python](https://img.shields.io/pypi/pyversions/fastapi-mcp-azure-oauth)](https://pypi.org/project/fastapi-mcp-azure-oauth/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)](https://github.com/LeeP-Tech/fastapi-mcp-azure-oauth/actions)

RFC-compliant Azure AD OAuth 2.0 router for **FastAPI MCP servers**, with first-class support for **Copilot Studio** and other Azure AD clients.

---

## What it does

Drop a single call into any FastAPI application to get:

| Standard | Endpoint | Purpose |
|---|---|---|
| [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) | `GET /.well-known/oauth-authorization-server` | Delegates clients to Azure AD's real auth endpoints |
| [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) | `GET /register` | Returns the client ID (Copilot Studio GET-variant) |
| [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) | `POST /register` | Dynamic Client Registration + Azure AD enrolment of allowlisted redirect URIs |
| [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728) | `GET /.well-known/oauth-protected-resource/{slug}` | Protected resource metadata for MCP autodiscovery |
| — | `GET /oauth/callback` | Minimal callback (echoes code + state for client-side exchange) |
| — | `GET /oauth/config` | MSAL-compatible configuration for browser clients |

Plus a **`TokenValidator`** that:

- Verifies Azure AD JWT signatures via JWKS with per-tenant key caching
- Supports both **single-tenant** and **multi-tenant** (`/organizations`) deployments
- Enforces explicit issuer binding _after_ signature verification (closes PyJWT `verify_iss` no-op gap)
- Rejects `api://{app_id}/.default` as an audience (it's a scope suffix, not a valid token audience)
- Accepts only access tokens: delegated tokens need an `scp` claim (optionally a specific scope); ID tokens and app-only tokens are rejected unless you opt in via `required_roles`
- Rejects non-GUID tenant IDs before any JWKS fetch, and caps the JWKS client cache at 50 tenants with FIFO eviction
- Offers `validate_token_async()` so JWKS fetches never block the event loop

---

## Installation

```bash
pip install fastapi-mcp-azure-oauth
```

**Requires Python 3.10+ and FastAPI 0.115+.**

---

## Quick start

```python
from fastapi import FastAPI, Depends
from fastapi_mcp_azure_oauth import build_oauth_router, TokenValidator

app = FastAPI()

# 1 — Mount the OAuth router (all RFC-required endpoints)
app.include_router(
    build_oauth_router(
        app_id="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",   # Azure AD App (client) ID
        tenant_id="yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy", # Home tenant ID
        client_secret="your-client-secret",
        api_scope="access_as_user",                       # exposed under api://{app_id}/
        resource_path="/mcp",                             # your protected resource path
        base_url="https://mcp.example.com",               # public URL of this server
        allowed_tenant_ids=["yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"],
    )
)

# 2 — Validate incoming Bearer tokens on protected endpoints
validator = TokenValidator(
    app_id="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    allowed_tenant_ids=["yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"],
    required_scopes=["access_as_user"],
)

@app.post("/mcp")
async def mcp_handler(claims: dict = Depends(validator.as_dependency)):
    user_id = validator.get_user_id(claims)
    return {"user": user_id}
```

---

## Configuration reference

### `build_oauth_router()`

| Parameter | Type | Default | Description |
|---|---|---|---|
| `app_id` | `str` | **required** | Azure AD Application (client) ID |
| `tenant_id` | `str` | **required** | Home tenant ID — used for Graph API calls and single-tenant discovery. Pass the home tenant even in multi-tenant deployments. |
| `client_secret` | `str` | **required** | Azure AD client secret — used only for Graph API calls; never returned by any endpoint |
| `api_scope` | `str` | `"access_as_user"` | Scope name under `api://{app_id}/` |
| `resource_path` | `str` | `"/mcp"` | Path to your protected resource — drives `/.well-known` slugs and the `resource` field |
| `allowed_tenant_ids` | `list[str] \| None` | `None` | Restrict discovery to specific tenants. `None` advertises `/organizations`. |
| `config_redirect_uri_path` | `str` | `"/oauth/callback"` | Server-relative path returned as `redirect_uri` in `GET /oauth/config` |
| `base_url` | `str \| None` | `None` | Public base URL of this server. **Recommended.** Without it, URLs in responses come from the request's `Host` header and the server's own callback is never enrolled in Azure AD. |
| `allowed_redirect_uris` | `list[str] \| None` | `None` | Exact `https://` redirect URIs that `POST /register` may add to the Azure AD app registration. `None` enrols no client-supplied URIs. |

### `TokenValidator()`

| Parameter | Type | Default | Description |
|---|---|---|---|
| `app_id` | `str` | **required** | Azure AD Application (client) ID |
| `allowed_tenant_ids` | `list[str] \| None` | `None` | Restrict token acceptance. `None` accepts all Azure AD tenants. |
| `required_scopes` | `list[str] \| None` | `None` | Delegated tokens must carry at least one of these scopes in `scp`. `None` accepts any non-empty `scp`. |
| `required_roles` | `list[str] \| None` | `None` | Accept app-only (client credentials) tokens carrying at least one of these app roles. `None` rejects all app-only tokens. |

Use `await validator.validate_token_async(token)` from async code (middleware etc.). `as_dependency` already does this.

---

## How it works

```
Client                    This server               Azure AD / Graph
  │                           │                           │
  │  GET /.well-known/...     │                           │
  │──────────────────────────>│                           │
  │<── auth/token endpoints ──│  (points at Azure AD)     │
  │                           │                           │
  │  POST /register           │                           │
  │──────────────────────────>│  POST /oauth2/token ─────>│
  │                           │<── access_token ──────────│
  │                           │  PATCH /applications ─────>│
  │<── client_id ─────────────│<── 204 ───────────────────│
  │                           │                           │
  │  GET /authorize (→ AAD)   │                           │
  │──────────────────────────────────────────────────────>│
  │<────────────────────── code ──────────────────────────│
  │  POST /token (→ AAD)      │                           │
  │──────────────────────────────────────────────────────>│
  │<──────────────── access_token ────────────────────────│
  │                           │                           │
  │  POST /mcp                │                           │
  │  Authorization: Bearer .. │                           │
  │──────────────────────────>│  GET /discovery/v2.0/keys>│
  │                           │<── JWKS ──────────────────│
  │                           │  Verify signature         │
  │                           │  Check iss binding        │
  │                           │  Check aud                │
  │<─── MCP response ─────────│                           │
```

**Step 3 (auth code flow) and step 4 (token exchange) happen entirely on Microsoft's side — this server is not involved.**

---

## Azure AD app registration requirements

1. Register an app in [Azure AD / Entra ID](https://portal.azure.com).
2. Create a **Client secret** and note it. Configure it directly in your MCP client (e.g. Copilot Studio's connector settings) — this server never hands it out.
3. Under **Expose an API**, add a scope (e.g. `access_as_user`).
4. Under **Authentication**, add the following as SPA redirect URIs:
   - `https://your-server/oauth/callback`
   - Any other redirect URIs your clients use
5. _Optional:_ to let `POST /register` enrol redirect URIs automatically, grant the app the `Application.ReadWrite.OwnedBy` Microsoft Graph permission and list the permitted URIs in `allowed_redirect_uris`. If you register redirect URIs manually (step 4), skip this — the app then needs no Graph permissions at all.

---

## Upgrading from 1.x

2.0.0 is a security release with breaking changes:

- `GET /register` and `POST /register` no longer return `client_secret`. Configure the secret in your client directly.
- `POST /register` only enrols redirect URIs listed in `allowed_redirect_uris`, and only enrols the server's own callback when `base_url` is set.
- `TokenValidator` rejects ID tokens, tokens without `exp`, app-only tokens (unless `required_roles` is set) and non-GUID tenant IDs.

If you ran 1.x on a reachable server, **rotate the client secret** and review the app registration's redirect URIs and credentials for anything you did not add.

---

## Multi-tenant deployments

Pass `allowed_tenant_ids=None` (the default) and use `tenant_id` as your app's home tenant:

```python
build_oauth_router(
    app_id="...",
    tenant_id="your-home-tenant-id",   # used for Graph API only
    client_secret="...",
    allowed_tenant_ids=None,            # accept tokens from any AAD tenant
)

validator = TokenValidator(
    app_id="...",
    allowed_tenant_ids=None,            # accept tokens from any AAD tenant
    required_scopes=["access_as_user"],
)
```

> Accepting every tenant means any Microsoft work or school account can obtain a token for your API. Do your own authorisation on the returned claims, or restrict tenants as below.

To restrict to a specific set of tenants:

```python
validator = TokenValidator(
    app_id="...",
    allowed_tenant_ids=[
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
    ],
)
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions are welcome.

---

## Security

Please report security vulnerabilities privately. See [SECURITY.md](SECURITY.md).

---

## License

[MIT](LICENSE) © 2026 Lee Pasifull
