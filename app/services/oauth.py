from __future__ import annotations

from authlib.integrations.starlette_client import OAuth

from app.core.config import get_settings

oauth = OAuth()

_settings = get_settings()

oauth.register(
    name="google",
    client_id=_settings.google_client_id,
    client_secret=_settings.google_client_secret,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)