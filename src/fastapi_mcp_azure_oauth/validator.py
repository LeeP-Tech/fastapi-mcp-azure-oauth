"""Azure AD JWT token validation for FastAPI."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import jwt
from fastapi import Header, HTTPException
from jwt import PyJWKClient

logger = logging.getLogger(__name__)


class TokenValidator:
    """Validates Azure AD JWT tokens for a FastAPI application.

    Supports both single-tenant and multi-tenant (``/organizations``) deployments.
    JWKS clients are cached per-tenant with a bounded eviction policy to prevent
    unbounded memory growth in unrestricted multi-tenant deployments.

    Example::

        validator = TokenValidator(app_id="your-app-id")

        @app.post("/protected")
        async def handler(claims: dict = Depends(validator.as_dependency)):
            user_id = validator.get_user_id(claims)
            ...
    """

    # Maximum number of per-tenant JWKS clients to hold in memory.
    _JWKS_CACHE_MAX = 50

    def __init__(
        self,
        app_id: str,
        allowed_tenant_ids: Optional[List[str]] = None,
    ) -> None:
        """
        Args:
            app_id:             Azure AD Application (client) ID.
            allowed_tenant_ids: Optional allowlist of tenant IDs. Tokens from
                                other tenants are rejected with HTTP 403.
                                ``None`` (default) accepts all Azure AD tenants.
        """
        self.app_id = app_id
        self.allowed_tenants: List[str] = allowed_tenant_ids or []
        self.jwks_clients: Dict[str, PyJWKClient] = {}
        logger.info("TokenValidator initialised for app: %s", app_id)
        if self.allowed_tenants:
            logger.info("Tenant allowlist: %s", self.allowed_tenants)

    # ------------------------------------------------------------------
    # JWKS client cache
    # ------------------------------------------------------------------

    def _get_jwks_client(self, tenant_id: str) -> PyJWKClient:
        """Return a cached JWKS client for *tenant_id*, evicting the oldest
        entry when the cache is at capacity."""
        if tenant_id not in self.jwks_clients:
            if len(self.jwks_clients) >= self._JWKS_CACHE_MAX:
                oldest = next(iter(self.jwks_clients))
                del self.jwks_clients[oldest]
                logger.debug("JWKS cache full — evicted tenant %s", oldest)
            jwks_uri = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
            self.jwks_clients[tenant_id] = PyJWKClient(jwks_uri, cache_keys=True)
        return self.jwks_clients[tenant_id]

    # ------------------------------------------------------------------
    # Token validation
    # ------------------------------------------------------------------

    def validate_token(self, token: str) -> Dict[str, Any]:
        """Validate an Azure AD Bearer token and return verified claims.

        Steps performed:
        1. Decode without verification to extract ``iss`` / tenant ID.
        2. Check the tenant against the optional allowlist.
        3. Fetch the correct signing key from Microsoft's JWKS endpoint.
        4. Verify signature and expiry with ``RS256``.
        5. Explicitly confirm the signed ``iss`` matches the tenant used to
           select the JWKS key (prevents key-confusion attacks).
        6. Verify ``aud`` is either ``{app_id}`` or ``api://{app_id}``.

        Args:
            token: Raw JWT string (without ``Bearer `` prefix).

        Returns:
            Verified claims dict.

        Raises:
            :class:`fastapi.HTTPException` (401/403) on any failure.
        """
        unverified_claims: Dict[str, Any] = {}
        try:
            unverified_claims = jwt.decode(token, options={"verify_signature": False})

            # Step 1 — extract tenant from issuer
            issuer = unverified_claims.get("iss", "")
            if issuer.startswith("https://login.microsoftonline.com/"):
                tenant_id = issuer.split("/")[-2]
            elif issuer.startswith("https://sts.windows.net/"):
                tenant_id = issuer.split("/")[-2]
            else:
                raise HTTPException(status_code=401, detail="Token issuer is not Azure AD")

            # Step 2 — tenant allowlist check
            if self.allowed_tenants and tenant_id not in self.allowed_tenants:
                raise HTTPException(
                    status_code=403,
                    detail=f"Tenant {tenant_id} is not authorized",
                )

            # Step 3 — fetch signing key
            jwks_client = self._get_jwks_client(tenant_id)
            signing_key = jwks_client.get_signing_key_from_jwt(token)

            # Step 4 — verify signature and expiry
            # verify_iss is intentionally omitted: PyJWT silently skips issuer
            # comparison unless an issuer= kwarg is supplied, making it a no-op.
            # We perform an explicit check in step 5 instead.
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_aud": False,
                },
            )

            # Step 5 — explicit issuer binding
            verified_iss = claims.get("iss", "")
            expected_issuers = [
                f"https://login.microsoftonline.com/{tenant_id}/v2.0",
                f"https://sts.windows.net/{tenant_id}/",
            ]
            if verified_iss not in expected_issuers:
                raise jwt.InvalidIssuerError(
                    f"Issuer mismatch after signature verification: {verified_iss}"
                )

            # Step 6 — audience check
            # Only the bare app_id GUID and the api:// URI are valid audiences.
            # api://{app_id}/.default is a scope designator, not a token audience.
            token_audience = claims.get("aud")
            accepted_audiences = [self.app_id, f"api://{self.app_id}"]
            if token_audience not in accepted_audiences:
                raise jwt.InvalidAudienceError(
                    f"Token audience {token_audience!r} is not accepted"
                )

            logger.info("Token validated for user: %s", claims.get("oid", "unknown"))
            return claims

        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=401,
                detail="Token has expired",
                headers={
                    "WWW-Authenticate": (
                        'Bearer error="invalid_token", '
                        'error_description="The access token expired"'
                    )
                },
            )
        except jwt.InvalidAudienceError:
            actual_aud = unverified_claims.get("aud", "unknown")
            raise HTTPException(
                status_code=401,
                detail=(
                    f"Invalid token audience. "
                    f"Expected api://{self.app_id}, got: {actual_aud}"
                ),
                headers={
                    "WWW-Authenticate": (
                        'Bearer error="invalid_token", '
                        'error_description="Invalid audience"'
                    )
                },
            )
        except jwt.InvalidIssuerError:
            raise HTTPException(
                status_code=401,
                detail="Invalid token issuer",
                headers={
                    "WWW-Authenticate": (
                        'Bearer error="invalid_token", '
                        'error_description="Invalid issuer"'
                    )
                },
            )
        except jwt.InvalidSignatureError:
            raise HTTPException(
                status_code=401,
                detail="Invalid token signature",
                headers={
                    "WWW-Authenticate": (
                        'Bearer error="invalid_token", '
                        'error_description="Invalid signature"'
                    )
                },
            )
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("Token validation error: %s", exc)
            raise HTTPException(
                status_code=401,
                detail="Token validation failed",
                headers={
                    "WWW-Authenticate": (
                        'Bearer error="invalid_token", '
                        'error_description="Token validation failed"'
                    )
                },
            )

    # ------------------------------------------------------------------
    # FastAPI dependency
    # ------------------------------------------------------------------

    async def as_dependency(
        self, authorization: Optional[str] = Header(None)
    ) -> Dict[str, Any]:
        """FastAPI dependency that extracts and validates a Bearer token.

        Inject into route handlers::

            @app.post("/protected")
            async def handler(claims: dict = Depends(validator.as_dependency)):
                ...
        """
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=401,
                detail="Authentication required. Provide Authorization: Bearer <token>",
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )
        return self.validate_token(authorization[7:])

    # ------------------------------------------------------------------
    # Claim helpers
    # ------------------------------------------------------------------

    def get_user_id(self, claims: Dict[str, Any]) -> str:
        """Return ``oid`` claim, falling back to ``sub``, then ``"unknown"``."""
        return claims.get("oid", claims.get("sub", "unknown"))

    def get_user_principal_name(self, claims: Dict[str, Any]) -> Optional[str]:
        """Return ``upn`` claim, falling back to ``preferred_username``."""
        return claims.get("upn") or claims.get("preferred_username")
