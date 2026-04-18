"""Tests for fastapi_mcp_azure_oauth.router — build_oauth_router."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_mcp_azure_oauth import build_oauth_router

APP_ID = "aaaaaaaa-0000-0000-0000-aaaaaaaaaaaa"
TENANT_ID = "bbbbbbbb-0000-0000-0000-bbbbbbbbbbbb"
SECRET = "test-secret"


# ---------------------------------------------------------------------------
# Shared test app
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    app = FastAPI()
    app.include_router(
        build_oauth_router(
            app_id=APP_ID,
            tenant_id=TENANT_ID,
            client_secret=SECRET,
            api_scope="access_as_user",
            resource_path="/mcp",
        )
    )
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# RFC 8414 discovery
# ---------------------------------------------------------------------------

class TestOAuthDiscovery:
    def test_discovery_200(self, client):
        assert client.get("/.well-known/oauth-authorization-server").status_code == 200

    def test_discovery_has_required_fields(self, client):
        data = client.get("/.well-known/oauth-authorization-server").json()
        assert "issuer" in data
        assert "authorization_endpoint" in data
        assert "token_endpoint" in data
        assert "code_challenge_methods_supported" in data

    def test_discovery_scopes_include_default(self, client):
        data = client.get("/.well-known/oauth-authorization-server").json()
        scopes = data["scopes_supported"]
        assert any(APP_ID in s for s in scopes)
        assert "openid" in scopes
        assert "email" in scopes

    def test_discovery_registration_endpoint(self, client):
        data = client.get("/.well-known/oauth-authorization-server").json()
        assert data["registration_endpoint"].endswith("/register")

    def test_discovery_alias_same_as_main(self, client):
        main = client.get("/.well-known/oauth-authorization-server").json()
        alias = client.get("/.well-known/oauth-authorization-server/mcp").json()
        assert main["issuer"] == alias["issuer"]
        assert main["token_endpoint"] == alias["token_endpoint"]

    def test_discovery_uses_organizations_by_default(self, client):
        data = client.get("/.well-known/oauth-authorization-server").json()
        assert "organizations" in data["issuer"]


# ---------------------------------------------------------------------------
# RFC 9728 protected resource
# ---------------------------------------------------------------------------

class TestProtectedResource:
    def test_protected_resource_200(self, client):
        assert client.get("/.well-known/oauth-protected-resource/mcp").status_code == 200

    def test_protected_resource_fields(self, client):
        data = client.get("/.well-known/oauth-protected-resource/mcp").json()
        assert "resource" in data
        assert "authorization_servers" in data
        assert "scope" in data

    def test_protected_resource_scope_contains_api_scope(self, client):
        data = client.get("/.well-known/oauth-protected-resource/mcp").json()
        assert "access_as_user" in data["scope"]
        assert APP_ID in data["scope"]

    def test_protected_resource_resource_ends_with_mcp(self, client):
        data = client.get("/.well-known/oauth-protected-resource/mcp").json()
        assert data["resource"].endswith("/mcp")


# ---------------------------------------------------------------------------
# Dynamic Client Registration
# ---------------------------------------------------------------------------

class TestRegister:
    def test_get_register_200(self, client):
        assert client.get("/register").status_code == 200

    def test_get_register_fields(self, client):
        data = client.get("/register").json()
        assert data["client_id"] == APP_ID
        assert "grant_types" in data

    def test_get_register_scope_string(self, client):
        data = client.get("/register").json()
        assert "openid" in data["scope"]
        assert "email" in data["scope"]
        assert "profile" in data["scope"]

    def test_post_register_with_no_uris(self, client):
        with patch(
            "fastapi_mcp_azure_oauth.router.add_redirect_uri_to_azure_ad",
            new_callable=AsyncMock,
            side_effect=Exception("no graph"),
        ):
            resp = client.post("/register", json={"redirect_uris": []})
        assert resp.status_code == 201
        assert resp.json()["client_id"] == APP_ID

    def test_post_register_https_uris_registered(self, client):
        async def fake_add(uri, **_kw):
            return {"success": True, "redirect_uri": uri}

        with patch("fastapi_mcp_azure_oauth.router.add_redirect_uri_to_azure_ad", side_effect=fake_add):
            resp = client.post(
                "/register",
                json={"redirect_uris": ["https://copilot.example.com/cb"]},
            )
        assert resp.status_code == 201
        data = resp.json()
        assert "https://copilot.example.com/cb" in data["redirect_uris"]
        assert any("oauth/callback" in u for u in data["redirect_uris"])

    def test_post_register_http_uris_skipped(self, client):
        async def fake_add(uri, **_kw):
            return {"success": True, "redirect_uri": uri}

        with patch("fastapi_mcp_azure_oauth.router.add_redirect_uri_to_azure_ad", side_effect=fake_add):
            resp = client.post(
                "/register",
                json={"redirect_uris": ["http://insecure.example.com/cb"]},
            )
        assert "http://insecure.example.com/cb" not in resp.json()["redirect_uris"]

    def test_post_register_partial_failure_returns_successes(self, client):
        async def fake_add(uri, **_kw):
            if "fail" in uri:
                raise Exception("graph error")
            return {"success": True, "redirect_uri": uri}

        with patch("fastapi_mcp_azure_oauth.router.add_redirect_uri_to_azure_ad", side_effect=fake_add):
            resp = client.post(
                "/register",
                json={
                    "redirect_uris": [
                        "https://good.example.com/cb",
                        "https://fail.example.com/cb",
                    ]
                },
            )
        assert resp.status_code == 201
        uris = resp.json()["redirect_uris"]
        assert "https://good.example.com/cb" in uris
        assert "https://fail.example.com/cb" not in uris


# ---------------------------------------------------------------------------
# OAuth callback
# ---------------------------------------------------------------------------

class TestOAuthCallback:
    def test_callback_echoes_code_and_state(self, client):
        data = client.get("/oauth/callback?code=abc&state=xyz").json()
        assert data["code"] == "abc"
        assert data["state"] == "xyz"
        assert data["status"] == "success"

    def test_callback_without_params_returns_none(self, client):
        data = client.get("/oauth/callback").json()
        assert data["code"] is None
        assert data["state"] is None


# ---------------------------------------------------------------------------
# OAuth config
# ---------------------------------------------------------------------------

class TestOAuthConfig:
    def test_config_200(self, client):
        assert client.get("/oauth/config").status_code == 200

    def test_config_fields(self, client):
        data = client.get("/oauth/config").json()
        for field in ("client_id", "tenant_id", "authority", "scopes", "redirect_uri"):
            assert field in data

    def test_config_app_id(self, client):
        assert client.get("/oauth/config").json()["client_id"] == APP_ID

    def test_config_scopes_contain_api_scope(self, client):
        scopes = client.get("/oauth/config").json()["scopes"]
        assert any("access_as_user" in s for s in scopes)


# ---------------------------------------------------------------------------
# Parameterisation — custom api_scope and resource_path
# ---------------------------------------------------------------------------

class TestCustomParameters:
    @pytest.fixture(scope="class")
    def custom_client(self):
        app = FastAPI()
        app.include_router(
            build_oauth_router(
                app_id=APP_ID,
                tenant_id=TENANT_ID,
                client_secret=SECRET,
                api_scope="custom_scope",
                resource_path="/api/v1",
                allowed_tenant_ids=["specific-tenant"],
                config_redirect_uri_path="/my/callback",
            )
        )
        with TestClient(app) as c:
            yield c

    def test_custom_resource_path_in_protected_resource(self, custom_client):
        data = custom_client.get("/.well-known/oauth-protected-resource/api/v1").json()
        assert data["resource"].endswith("/api/v1")

    def test_custom_api_scope_in_protected_resource(self, custom_client):
        data = custom_client.get("/.well-known/oauth-protected-resource/api/v1").json()
        assert "custom_scope" in data["scope"]

    def test_single_allowed_tenant_in_discovery(self, custom_client):
        data = custom_client.get("/.well-known/oauth-authorization-server").json()
        assert "specific-tenant" in data["issuer"]

    def test_custom_config_redirect_uri(self, custom_client):
        data = custom_client.get("/oauth/config").json()
        assert data["redirect_uri"].endswith("/my/callback")
