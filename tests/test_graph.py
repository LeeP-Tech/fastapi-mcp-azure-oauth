"""Tests for fastapi_mcp_azure_oauth.graph — add_redirect_uri_to_azure_ad."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi_mcp_azure_oauth.graph import add_redirect_uri_to_azure_ad


CREDS = dict(app_id="app-id", tenant_id="tenant-id", client_secret="secret")


def _make_mock_client(app_object_id="obj-123", existing_uris=None):
    """Return a mock async context manager simulating Graph API responses."""
    existing_uris = existing_uris or []

    token_resp = MagicMock()
    token_resp.raise_for_status = MagicMock()
    token_resp.json.return_value = {"access_token": "fake-token"}

    apps_resp = MagicMock()
    apps_resp.raise_for_status = MagicMock()
    apps_resp.json.return_value = {
        "value": [{"id": app_object_id, "spa": {"redirectUris": existing_uris}}]
    }

    patch_resp = MagicMock()
    patch_resp.raise_for_status = MagicMock()

    inner = AsyncMock()
    inner.post.return_value = token_resp
    inner.get.return_value = apps_resp
    inner.patch.return_value = patch_resp

    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=inner)
    ctx.__aexit__ = AsyncMock(return_value=None)
    return ctx


class TestAddRedirectUriToAzureAd:
    @pytest.mark.asyncio
    async def test_adds_new_uri_successfully(self):
        ctx = _make_mock_client()
        with patch("fastapi_mcp_azure_oauth.graph.httpx.AsyncClient", return_value=ctx):
            result = await add_redirect_uri_to_azure_ad(
                "https://new.example.com/cb", **CREDS
            )
        assert result == {"success": True, "redirect_uri": "https://new.example.com/cb"}

    @pytest.mark.asyncio
    async def test_idempotent_when_uri_already_exists(self):
        """Adding a URI that already exists in the list should not error."""
        existing = "https://already.example.com/cb"
        ctx = _make_mock_client(existing_uris=[existing])
        with patch("fastapi_mcp_azure_oauth.graph.httpx.AsyncClient", return_value=ctx):
            result = await add_redirect_uri_to_azure_ad(existing, **CREDS)
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_raises_when_app_not_found(self):
        token_resp = MagicMock()
        token_resp.raise_for_status = MagicMock()
        token_resp.json.return_value = {"access_token": "fake-token"}

        empty_resp = MagicMock()
        empty_resp.raise_for_status = MagicMock()
        empty_resp.json.return_value = {"value": []}

        inner = AsyncMock()
        inner.post.return_value = token_resp
        inner.get.return_value = empty_resp

        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(return_value=inner)
        ctx.__aexit__ = AsyncMock(return_value=None)

        with patch("fastapi_mcp_azure_oauth.graph.httpx.AsyncClient", return_value=ctx):
            with pytest.raises(ValueError, match="not found"):
                await add_redirect_uri_to_azure_ad(
                    "https://x.example.com/cb", **CREDS
                )

    @pytest.mark.asyncio
    async def test_calls_token_endpoint_with_correct_tenant(self):
        ctx = _make_mock_client()
        with patch("fastapi_mcp_azure_oauth.graph.httpx.AsyncClient", return_value=ctx) as mock_cls:
            await add_redirect_uri_to_azure_ad("https://x.example.com/cb", **CREDS)
        inner = await ctx.__aenter__()
        post_call_kwargs = inner.post.call_args
        assert "tenant-id" in post_call_kwargs.args[0]

    @pytest.mark.asyncio
    async def test_patch_includes_new_uri_in_sorted_list(self):
        ctx = _make_mock_client(existing_uris=["https://b.example.com/cb"])
        with patch("fastapi_mcp_azure_oauth.graph.httpx.AsyncClient", return_value=ctx):
            await add_redirect_uri_to_azure_ad("https://a.example.com/cb", **CREDS)
        inner = await ctx.__aenter__()
        patch_json = inner.patch.call_args.kwargs["json"]
        uris = patch_json["spa"]["redirectUris"]
        assert uris == sorted(uris)
        assert "https://a.example.com/cb" in uris
        assert "https://b.example.com/cb" in uris
