"""Microsoft Graph API helpers for managing Azure AD app registrations."""

from __future__ import annotations

import logging
from typing import Any, Dict

import httpx

logger = logging.getLogger(__name__)


async def add_redirect_uri_to_azure_ad(
    redirect_uri: str,
    *,
    app_id: str,
    tenant_id: str,
    client_secret: str,
) -> Dict[str, Any]:
    """Add a redirect URI to an Azure AD app registration via Microsoft Graph.

    Acquires a client-credentials token scoped to ``https://graph.microsoft.com/.default``,
    reads the current ``spa.redirectUris`` list, and PATCHes the app registration with the
    new URI appended (idempotent — skips if already present).

    Args:
        redirect_uri:   The redirect URI to register.
        app_id:         Azure AD Application (client) ID.
        tenant_id:      Azure AD tenant ID (home tenant of the app registration).
        client_secret:  Azure AD client secret used for the client-credentials grant.

    Returns:
        ``{"success": True, "redirect_uri": redirect_uri}``

    Raises:
        httpx.HTTPStatusError: If any Graph API call returns a non-2xx response.
        ValueError: If the application cannot be found in Microsoft Graph.
    """
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

    async with httpx.AsyncClient(timeout=30) as client:
        token_response = await client.post(
            token_url,
            data={
                "client_id": app_id,
                "client_secret": client_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            },
        )
        token_response.raise_for_status()
        access_token = token_response.json().get("access_token")

        headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}

        app_query = await client.get(
            "https://graph.microsoft.com/v1.0/applications",
            headers=headers,
            params={"$filter": f"appId eq '{app_id}'"},
        )
        app_query.raise_for_status()
        values = app_query.json().get("value", [])
        if not values:
            raise ValueError("Azure AD application not found in Microsoft Graph")

        app_object = values[0]
        app_object_id = app_object["id"]
        spa = app_object.get("spa") or {}
        redirect_uris = set(spa.get("redirectUris", []))
        redirect_uris.add(redirect_uri)

        patch = await client.patch(
            f"https://graph.microsoft.com/v1.0/applications/{app_object_id}",
            headers=headers,
            json={"spa": {"redirectUris": sorted(list(redirect_uris))}},
        )
        patch.raise_for_status()

    return {"success": True, "redirect_uri": redirect_uri}
