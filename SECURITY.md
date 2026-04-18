# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Yes    |

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
3. **HTTPS** between all parties — the `GET /register` endpoint intentionally returns the `client_secret` to the requesting client (this is the RFC 7591 DCR model), which is only safe over TLS.

### What this library validates

- JWT **signature** via JWKS from `login.microsoftonline.com`
- Token **expiry**
- **Issuer binding** — the signed `iss` claim must match the tenant ID used to select the signing key
- **Audience** — only `{app_id}` and `api://{app_id}` are accepted; `api://{app_id}/.default` is rejected
- **Tenant allowlist** (when configured)

### What this library does NOT validate

- `nbf` (not-before) — delegated to PyJWT default behaviour
- `scp` or `roles` claims — the consuming application is responsible for authorisation
- PKCE parameters — PKCE verification is performed by Azure AD, not this server
