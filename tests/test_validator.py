"""Tests for fastapi_mcp_azure_oauth.validator — TokenValidator."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException
import jwt

from fastapi_mcp_azure_oauth import TokenValidator


APP_ID = "aaaaaaaa-0000-0000-0000-aaaaaaaaaaaa"
TENANT = "tenant-abc"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_validator(app_id=APP_ID, allowed_tenant_ids=None):
    return TokenValidator(app_id=app_id, allowed_tenant_ids=allowed_tenant_ids)


def _signed_claims(tid=TENANT, aud=None, iss=None):
    aud = aud or f"api://{APP_ID}"
    iss = iss or f"https://login.microsoftonline.com/{tid}/v2.0"
    return {"tid": tid, "oid": "user-1", "aud": aud, "iss": iss, "exp": 9999999999}


def _fake_token(tid=TENANT, aud=None, iss=None):
    import base64, json
    aud = aud or f"api://{APP_ID}"
    iss = iss or f"https://login.microsoftonline.com/{tid}/v2.0"
    header = base64.urlsafe_b64encode(b'{"alg":"RS256","kid":"k1"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps({"tid": tid, "oid": "user-1", "aud": aud, "iss": iss, "exp": 9999999999}).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{payload}.fakesig"


def _stub_jwks(validator):
    mock_key = MagicMock()
    mock_client = MagicMock()
    mock_client.get_signing_key_from_jwt.return_value = mock_key
    validator._get_jwks_client = MagicMock(return_value=mock_client)
    return mock_key


# ---------------------------------------------------------------------------
# Constructor
# ---------------------------------------------------------------------------

class TestTokenValidatorInit:
    def test_stores_app_id(self):
        v = _make_validator()
        assert v.app_id == APP_ID

    def test_stores_allowed_tenants(self):
        v = _make_validator(allowed_tenant_ids=["t1", "t2"])
        assert v.allowed_tenants == ["t1", "t2"]

    def test_empty_allowed_tenants_when_none(self):
        v = _make_validator()
        assert v.allowed_tenants == []


# ---------------------------------------------------------------------------
# Claim helpers
# ---------------------------------------------------------------------------

class TestGetUserId:
    def test_returns_oid(self):
        assert _make_validator().get_user_id({"oid": "u1"}) == "u1"

    def test_falls_back_to_sub(self):
        assert _make_validator().get_user_id({"sub": "s1"}) == "s1"

    def test_returns_unknown_when_missing(self):
        assert _make_validator().get_user_id({}) == "unknown"


class TestGetUserPrincipalName:
    def test_returns_upn(self):
        assert _make_validator().get_user_principal_name({"upn": "u@co.com"}) == "u@co.com"

    def test_fallback_to_preferred_username(self):
        assert _make_validator().get_user_principal_name({"preferred_username": "u@x.com"}) == "u@x.com"

    def test_returns_none_when_missing(self):
        assert _make_validator().get_user_principal_name({}) is None


# ---------------------------------------------------------------------------
# Tenant restrictions (pre-JWKS)
# ---------------------------------------------------------------------------

class TestTenantRestrictions:
    def test_rejects_non_azure_issuer(self):
        import base64, json
        header = base64.urlsafe_b64encode(b'{"alg":"RS256"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            json.dumps({"iss": "https://evil.example.com"}).encode()
        ).rstrip(b"=").decode()
        with pytest.raises(HTTPException) as exc:
            _make_validator().validate_token(f"{header}.{payload}.sig")
        assert exc.value.status_code == 401
        assert "issuer" in exc.value.detail.lower()

    def test_rejects_disallowed_tenant(self):
        import base64, json
        header = base64.urlsafe_b64encode(b'{"alg":"RS256"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            json.dumps({"iss": "https://login.microsoftonline.com/other/v2.0"}).encode()
        ).rstrip(b"=").decode()
        v = _make_validator(allowed_tenant_ids=["allowed"])
        with pytest.raises(HTTPException) as exc:
            v.validate_token(f"{header}.{payload}.sig")
        assert exc.value.status_code == 403
        assert "not authorized" in exc.value.detail.lower()


# ---------------------------------------------------------------------------
# Full validate_token path (JWKS + jwt.decode mocked)
# ---------------------------------------------------------------------------

class TestValidateTokenFullPath:
    def test_happy_path_returns_claims(self):
        v = _make_validator()
        _stub_jwks(v)
        with patch("jwt.decode", side_effect=[_signed_claims(), _signed_claims()]):
            result = v.validate_token(_fake_token())
        assert result["oid"] == "user-1"

    def test_happy_path_v1_issuer(self):
        v = _make_validator()
        _stub_jwks(v)
        iss_v1 = f"https://sts.windows.net/{TENANT}/"
        claims = _signed_claims(iss=iss_v1)
        with patch("jwt.decode", side_effect=[{**_signed_claims(), "iss": iss_v1}, claims]):
            result = v.validate_token(_fake_token())
        assert result["oid"] == "user-1"

    def test_happy_path_bare_app_id_audience(self):
        v = _make_validator()
        _stub_jwks(v)
        claims = _signed_claims(aud=APP_ID)
        with patch("jwt.decode", side_effect=[_signed_claims(aud=APP_ID), claims]):
            result = v.validate_token(_fake_token(aud=APP_ID))
        assert result["aud"] == APP_ID

    def test_expired_token_raises_401(self):
        v = _make_validator()
        _stub_jwks(v)
        with patch("jwt.decode", side_effect=[_signed_claims(), jwt.ExpiredSignatureError()]):
            with pytest.raises(HTTPException) as exc:
                v.validate_token(_fake_token())
        assert exc.value.status_code == 401
        assert "expired" in exc.value.detail.lower()
        assert "WWW-Authenticate" in exc.value.headers

    def test_wrong_audience_raises_401(self):
        v = _make_validator()
        _stub_jwks(v)
        claims = _signed_claims(aud="api://other-app")
        with patch("jwt.decode", side_effect=[_signed_claims(aud="api://other-app"), claims]):
            with pytest.raises(HTTPException) as exc:
                v.validate_token(_fake_token(aud="api://other-app"))
        assert exc.value.status_code == 401
        assert "audience" in exc.value.detail.lower()

    def test_issuer_mismatch_after_signature_raises_401(self):
        v = _make_validator()
        _stub_jwks(v)
        drifted = _signed_claims(iss="https://login.microsoftonline.com/different/v2.0")
        with patch("jwt.decode", side_effect=[_signed_claims(), drifted]):
            with pytest.raises(HTTPException) as exc:
                v.validate_token(_fake_token())
        assert exc.value.status_code == 401
        assert "issuer" in exc.value.detail.lower()

    def test_invalid_signature_raises_401(self):
        v = _make_validator()
        _stub_jwks(v)
        with patch("jwt.decode", side_effect=[_signed_claims(), jwt.InvalidSignatureError()]):
            with pytest.raises(HTTPException) as exc:
                v.validate_token(_fake_token())
        assert exc.value.status_code == 401
        assert "signature" in exc.value.detail.lower()

    def test_generic_exception_raises_401(self):
        v = _make_validator()
        _stub_jwks(v)
        with patch("jwt.decode", side_effect=[_signed_claims(), RuntimeError("unexpected")]):
            with pytest.raises(HTTPException) as exc:
                v.validate_token(_fake_token())
        assert exc.value.status_code == 401
        assert "failed" in exc.value.detail.lower()

    def test_default_scope_not_accepted_as_audience(self):
        """api://{app_id}/.default is a scope — never a valid token audience."""
        v = _make_validator()
        _stub_jwks(v)
        bad_aud = f"api://{APP_ID}/.default"
        claims = _signed_claims(aud=bad_aud)
        with patch("jwt.decode", side_effect=[_signed_claims(aud=bad_aud), claims]):
            with pytest.raises(HTTPException) as exc:
                v.validate_token(_fake_token(aud=bad_aud))
        assert exc.value.status_code == 401


# ---------------------------------------------------------------------------
# JWKS cache eviction
# ---------------------------------------------------------------------------

class TestJwksCacheEviction:
    def test_evicts_oldest_when_full(self):
        v = TokenValidator(app_id="app")
        with patch("fastapi_mcp_azure_oauth.validator.PyJWKClient", return_value=MagicMock()):
            for i in range(TokenValidator._JWKS_CACHE_MAX):
                v._get_jwks_client(f"tenant-{i}")
            assert len(v.jwks_clients) == TokenValidator._JWKS_CACHE_MAX
            v._get_jwks_client("tenant-overflow")
            assert "tenant-0" not in v.jwks_clients
            assert "tenant-overflow" in v.jwks_clients
            assert len(v.jwks_clients) == TokenValidator._JWKS_CACHE_MAX

    def test_cache_hit_does_not_evict(self):
        v = TokenValidator(app_id="app")
        with patch("fastapi_mcp_azure_oauth.validator.PyJWKClient", return_value=MagicMock()):
            v._get_jwks_client("existing")
            initial_len = len(v.jwks_clients)
            v._get_jwks_client("existing")
            assert len(v.jwks_clients) == initial_len


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------

class TestAsDependency:
    @pytest.mark.asyncio
    async def test_missing_header_raises_401(self):
        v = _make_validator()
        with pytest.raises(HTTPException) as exc:
            await v.as_dependency(None)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_non_bearer_raises_401(self):
        v = _make_validator()
        with pytest.raises(HTTPException) as exc:
            await v.as_dependency("Basic dXNlcjpwYXNz")
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_valid_token_returns_claims(self):
        v = _make_validator()
        _stub_jwks(v)
        with patch("jwt.decode", side_effect=[_signed_claims(), _signed_claims()]):
            claims = await v.as_dependency(f"Bearer {_fake_token()}")
        assert claims["oid"] == "user-1"
