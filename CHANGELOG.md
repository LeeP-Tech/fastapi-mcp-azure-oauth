# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [2.0.0] — 2026-10-03

Security release. **Breaking changes** — see "Upgrading from 1.x" in the README.
If you ran 1.x on a reachable server, rotate the Azure AD client secret and review the
app registration's redirect URIs and credentials.

### Security

- `GET /register` and `POST /register` no longer return the Azure AD `client_secret`. Previously any unauthenticated caller could retrieve it.
- `POST /register` only enrols redirect URIs listed in the new `allowed_redirect_uris` parameter. Previously any unauthenticated caller could add arbitrary `https://` redirect URIs to the app registration, enabling authorization-code theft.
- The server callback enrolled by `POST /register` is derived from the new `base_url` parameter, never from the `Host` header. Discovery documents also use `base_url` when set.
- Each redirect URI is enrolled via Microsoft Graph at most once per process.
- `TokenValidator` now rejects ID tokens and app-only tokens. Delegated tokens must carry `scp`; new `required_scopes` and `required_roles` parameters control which scopes/roles are accepted.
- `TokenValidator` rejects non-GUID tenant IDs before fetching JWKS, and requires the `exp` claim.
- Raised minimum versions: `starlette>=0.49.1`, `PyJWT>=2.10.1`; demo now requires `mcp>=1.23.0,<2`.
- CI: actions pinned to commit SHAs, read-only default token permissions, `pip-audit` job gating releases, Dependabot enabled.

### Added

- `TokenValidator.validate_token_async()` — runs validation in a worker thread so JWKS fetches don't block the event loop. `as_dependency()` now uses it.

### Changed

- Successful validations are logged at `DEBUG` rather than `INFO`.
- Demo server restricts tokens to the home tenant (configurable via `AZURE_ALLOWED_TENANT_IDS`), requires the `access_as_user` scope, and supports `PUBLIC_BASE_URL` / `ALLOWED_REDIRECT_URIS`.

### Fixed

- `__version__` now matches the package version.
- Demo no longer breaks on mcp 2.x (pinned to `<2`).

---

## [1.0.0] — 2026-04-18

### Added

- `build_oauth_router()` factory — returns a FastAPI `APIRouter` with all RFC-required endpoints:
  - **RFC 8414** `GET /.well-known/oauth-authorization-server` and resource-scoped alias
  - **RFC 7591** `GET /register` (Copilot Studio GET-variant compatibility)
  - **RFC 7591** `POST /register` with automatic Azure AD redirect URI enrolment via Microsoft Graph
  - **RFC 9728** `GET /.well-known/oauth-protected-resource/{slug}`
  - `GET /oauth/callback` — minimal authorization code relay endpoint
  - `GET /oauth/config` — MSAL-compatible configuration helper
- `TokenValidator` class — multi-tenant Azure AD JWT verification:
  - Per-tenant JWKS client cache with FIFO eviction at 50 entries
  - Explicit post-signature issuer binding (closes PyJWT `verify_iss` no-op gap)
  - Correct audience validation — rejects `api://{app_id}/.default` (scope suffix, not audience)
  - `as_dependency()` FastAPI dependency method
  - `get_user_id()` and `get_user_principal_name()` claim helpers
- `add_redirect_uri_to_azure_ad()` async helper — adds SPA redirect URIs to Azure AD via Microsoft Graph using client-credentials flow
- `ClientRegistrationRequest` Pydantic model for DCR request bodies
- Full test suite — 100% coverage on all modules
- GitHub Actions CI workflow for Python 3.10 – 3.13

[Unreleased]: https://github.com/LeeP-Tech/fastapi-mcp-azure-oauth/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/LeeP-Tech/fastapi-mcp-azure-oauth/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/LeeP-Tech/fastapi-mcp-azure-oauth/releases/tag/v1.0.0
