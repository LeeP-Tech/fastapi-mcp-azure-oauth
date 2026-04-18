"""fastapi-mcp-azure-oauth — RFC-compliant Azure AD OAuth 2.0 for FastAPI MCP servers."""

from .graph import add_redirect_uri_to_azure_ad
from .models import ClientRegistrationRequest
from .router import build_oauth_router
from .validator import TokenValidator

__all__ = [
    "build_oauth_router",
    "TokenValidator",
    "ClientRegistrationRequest",
    "add_redirect_uri_to_azure_ad",
]

__version__ = "1.0.0"
