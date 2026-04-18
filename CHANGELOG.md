# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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

[Unreleased]: https://github.com/LeeP-Tech/fastapi-mcp-azure-oauth/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/LeeP-Tech/fastapi-mcp-azure-oauth/releases/tag/v1.0.0
