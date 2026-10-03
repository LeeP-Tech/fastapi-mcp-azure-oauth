# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 2.x     | ✅ Yes    |
| 1.x     | ❌ No — upgrade to 2.x (1.x exposes the client secret via `/register`) |

---

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report security issues privately by emailing **lee@pasifull.co.uk** with:

- A description of the vulnerability
- Steps to reproduce (proof-of-concept if available)
- Affected versions
- Your assessment of severity

You will receive an acknowledgement within **48 hours** and a resolution timeline within **5 business days**. We will coordinate a disclosure date with you before publishing anything publicly.

If you believe a vulnerability is being actively exploited in the wild, please say so — we will prioritise accordingly.

---

## Security model

This library is a **pass-through OAuth delegation layer**. It does not issue its own tokens; it delegates authentication to Microsoft Azure AD. The security properties depend on:

1. **Azure AD** correctly verifying user identities and issuing signed JWTs.
2. **The consuming application** correctly protecting its own secrets (`client_secret`) — treat these the same as database passwords.
3. **HTTPS** between all parties.

The `client_secret` is used only for Microsoft Graph calls and is never returned by any endpoint. `POST /register` is unauthenticated, so it only enrols redirect URIs from the configured `allowed_redirect_uris` allowlist, and only derives the server callback from the configured `base_url` (never from the `Host` header).

### What this library validates

- JWT **signature** via JWKS from `login.microsoftonline.com`
- Token **expiry**
- **Issuer binding** — the signed `iss` claim must match the tenant ID used to select the signing key
- **Audience** — only `{app_id}` and `api://{app_id}` are accepted; `api://{app_id}/.default` is rejected
- **Tenant allowlist** (when configured); tenant IDs must be GUIDs
- **Token type** — delegated tokens must carry `scp` (and one of `required_scopes`, when configured); ID tokens are rejected; app-only tokens are rejected unless they carry one of `required_roles`
- **`exp`** must be present

### What this library does NOT validate

- `nbf` (not-before) — delegated to PyJWT default behaviour
- Fine-grained authorisation beyond `required_scopes` / `required_roles` — the consuming application is responsible for that
- PKCE parameters — PKCE verification is performed by Azure AD, not this server
