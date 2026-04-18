"""Pydantic request/response models."""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel


class ClientRegistrationRequest(BaseModel):
    """RFC 7591 Dynamic Client Registration request body."""

    client_name: str = "Copilot Studio"
    redirect_uris: List[str] = []
    grant_types: List[str] = ["authorization_code"]
    response_types: List[str] = ["code"]
    token_endpoint_auth_method: str = "none"
    scope: Optional[str] = None
