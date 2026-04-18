"""OAuth router factory for FastAPI MCP servers backed by Azure AD."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Request

from .graph import add_redirect_uri_to_azure_ad
from .models import ClientRegistrationRequest

logger = logging.getLogger(__name__)


def build_oauth_router(
    app_id: str,
    tenant_id: str,
    client_secret: str,
    *,
    api_scope: str = "access_as_user",
    resource_path: str = "/mcp",
    allowed_tenant_ids: Optional[List[str]] = None,
    config_redirect_uri_path: str = "/oauth/callback",
) -> APIRouter:
    """Build and return a FastAPI ``APIRouter`` with all OAuth 2.0 discovery,
    registration, callback, and configuration endpoints.

    The router implements:

    * **RFC 8414** ``/.well-known/oauth-authorization-server`` — points clients
      at Azure AD's real authorization and token endpoints.
    * **RFC 7591** ``GET``/``POST /register`` — Dynamic Client Registration.
      ``POST`` auto-registers redirect URIs in Azure AD via Microsoft Graph.
    * **RFC 9728** ``/.well-known/oauth-protected-resource/{slug}`` — protected
      resource metadata for MCP client autodiscovery.
    * ``GET /oauth/callback`` — minimal callback endpoint (echoes code + state).
    * ``GET /oauth/config`` — convenience endpoint with MSAL configuration.

    Args:
        app_id:                   Azure AD Application (client) ID.
        tenant_id:                Home tenant ID — used for Graph API calls and
                                  as the ``tenant`` in discovery documents when
                                  ``allowed_tenant_ids`` contains exactly one entry.
                                  Pass ``"organizations"`` for fully multi-tenant
                                  deployments where no restriction is desired.
        client_secret:            Azure AD client secret.
        api_scope:                Scope name exposed under ``api://{app_id}/``.
                                  Defaults to ``"access_as_user"``.
        resource_path:            Path to the protected MCP resource, e.g. ``"/mcp"``.
                                  Drives the ``/.well-known`` path slugs and the
                                  ``resource`` field in the protected-resource document.
        allowed_tenant_ids:       Optional list of permitted tenant IDs.  ``None``
                                  (default) accepts all Azure AD tenants and advertises
                                  ``/organizations`` in discovery documents.
        config_redirect_uri_path: Server-relative path returned as ``redirect_uri``
                                  in ``GET /oauth/config``.  Defaults to
                                  ``"/oauth/callback"``.

    Returns:
        A configured :class:`fastapi.APIRouter`.

    Example::

        from fastapi import FastAPI
        from fastapi_mcp_azure_oauth import build_oauth_router

        app = FastAPI()
        app.include_router(
            build_oauth_router(
                app_id="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                tenant_id="yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
                client_secret="your-secret",
                api_scope="access_as_user",
                resource_path="/mcp",
            )
        )
    """
    # Normalise resource path
    resource_path = "/" + resource_path.lstrip("/")
    resource_slug = resource_path.lstrip("/")

    # ------------------------------------------------------------------
    # Internal helpers (closures over configuration)
    # ------------------------------------------------------------------

    def _authority_tenant() -> str:
        """Return the tenant segment to embed in Azure AD URLs.

        * Single allowed tenant  → that tenant ID
        * Multiple or none       → "organizations" (works for any AAD tenant)
        """
        if not allowed_tenant_ids:
            return "organizations"
        if len(allowed_tenant_ids) == 1:
            return allowed_tenant_ids[0]
        return "organizations"

    def _discovery_doc(tenant: str, base_url: str) -> Dict[str, Any]:
        doc: Dict[str, Any] = {
            "issuer": f"https://login.microsoftonline.com/{tenant}/v2.0",
            "authorization_endpoint": (
                f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
            ),
            "token_endpoint": (
                f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
            ),
            "jwks_uri": (
                f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"
            ),
            "scopes_supported": [
                f"{app_id}/.default",
                "openid",
                "profile",
                "email",
                "offline_access",
            ],
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
            "code_challenge_methods_supported": ["S256"],
        }
        if base_url:
            doc["registration_endpoint"] = f"{base_url}/register"
        return doc

    # ------------------------------------------------------------------
    # Router and routes
    # ------------------------------------------------------------------

    router = APIRouter()

    @router.get(
        "/.well-known/oauth-authorization-server",
        summary="RFC 8414 authorization server metadata",
        tags=["OAuth"],
    )
    async def oauth_discovery(request: Request) -> Dict[str, Any]:
        """Return RFC 8414 authorization server metadata pointing at Azure AD."""
        base_url = str(request.base_url).rstrip("/")
        return _discovery_doc(_authority_tenant(), base_url)

    @router.get(
        f"/.well-known/oauth-authorization-server/{resource_slug}",
        summary="RFC 8414 authorization server metadata (resource-scoped alias)",
        tags=["OAuth"],
    )
    async def oauth_discovery_alias(request: Request) -> Dict[str, Any]:
        """Resource-scoped alias for ``/.well-known/oauth-authorization-server``."""
        base_url = str(request.base_url).rstrip("/")
        return _discovery_doc(_authority_tenant(), base_url)

    @router.get(
        f"/.well-known/oauth-protected-resource/{resource_slug}",
        summary="RFC 9728 protected resource metadata",
        tags=["OAuth"],
    )
    async def oauth_protected_resource(request: Request) -> Dict[str, Any]:
        """Return RFC 9728 protected resource metadata for MCP client autodiscovery."""
        tenant = _authority_tenant()
        base_url = str(request.base_url).rstrip("/")
        return {
            "resource": f"{base_url}{resource_path}",
            "authorization_servers": [
                f"https://login.microsoftonline.com/{tenant}/v2.0"
            ],
            "scope": f"api://{app_id}/{api_scope}",
        }

    @router.get(
        "/register",
        summary="RFC 7591 Dynamic Client Registration (GET)",
        tags=["OAuth"],
    )
    async def oauth_register_get() -> Dict[str, Any]:
        """Return pre-provisioned app credentials.

        This ``GET`` variant exists for Copilot Studio compatibility — it sends
        ``GET /register`` rather than ``POST`` when first discovering credentials.
        """
        return {
            "client_id": app_id,
            "client_secret": client_secret,
            "token_endpoint_auth_method": "client_secret_post",
            "scope": f"{app_id}/.default openid profile email offline_access",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
        }

    @router.post(
        "/register",
        status_code=201,
        summary="RFC 7591 Dynamic Client Registration (POST)",
        tags=["OAuth"],
    )
    async def oauth_register(
        body: ClientRegistrationRequest, request: Request
    ) -> Dict[str, Any]:
        """Register a client and auto-enroll redirect URIs in Azure AD.

        For each ``https://`` redirect URI in the request, the server calls
        Microsoft Graph to add it to the app registration's ``spa.redirectUris``.
        The server's own ``/oauth/callback`` is always enrolled.

        Failures are logged as warnings and do not abort the response —
        successfully registered URIs are returned in ``redirect_uris``.
        """
        base_url = str(request.base_url).rstrip("/")
        server_callback = f"{base_url}/oauth/callback"
        registered_uris: List[str] = []

        try:
            await add_redirect_uri_to_azure_ad(
                server_callback,
                app_id=app_id,
                tenant_id=tenant_id,
                client_secret=client_secret,
            )
            registered_uris.append(server_callback)
        except Exception as exc:
            logger.warning(
                "Failed to register server callback URI %s: %s", server_callback, exc
            )

        for uri in body.redirect_uris:
            if uri.startswith("https://"):
                try:
                    await add_redirect_uri_to_azure_ad(
                        uri,
                        app_id=app_id,
                        tenant_id=tenant_id,
                        client_secret=client_secret,
                    )
                    registered_uris.append(uri)
                except Exception as exc:
                    logger.warning(
                        "Failed to register redirect URI %s: %s", uri, exc
                    )

        return {
            "client_id": app_id,
            "client_secret": client_secret,
            "token_endpoint_auth_method": "client_secret_post",
            "scope": f"{app_id}/.default openid profile email offline_access",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "redirect_uris": registered_uris,
        }

    @router.get(
        "/oauth/callback",
        summary="OAuth authorization code callback",
        tags=["OAuth"],
    )
    async def oauth_callback(
        code: Optional[str] = None,
        state: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Receive an authorization code from Azure AD.

        This endpoint exists so the server's own origin can be registered as a
        redirect URI in Azure AD.  The client (e.g. Copilot Studio) performs
        the token exchange; this server simply echoes code and state.
        """
        return {"code": code, "state": state, "status": "success"}

    @router.get(
        "/oauth/config",
        summary="OAuth configuration (MSAL helper)",
        tags=["OAuth"],
    )
    async def oauth_config(request: Request) -> Dict[str, Any]:
        """Return MSAL-compatible configuration for browser-based clients."""
        tenant = _authority_tenant()
        base_url = str(request.base_url).rstrip("/")
        return {
            "client_id": app_id,
            "tenant_id": tenant,
            "authority": f"https://login.microsoftonline.com/{tenant}",
            "scopes": [f"api://{app_id}/{api_scope}"],
            "redirect_uri": f"{base_url}{config_redirect_uri_path}",
        }

    return router
