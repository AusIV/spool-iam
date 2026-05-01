from datetime import timedelta

import jwt
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone


DEFAULT_ALGORITHM = "RS256"
DEFAULT_ISSUER = "django-iam"
DEFAULT_TTL_SECONDS = 60 * 60


class TokenError(Exception):
    """Raised when a session token cannot be decoded or trusted."""


def issue_session_token(user):
    now = timezone.now()
    expires_at = now + timedelta(seconds=_get_token_ttl_seconds())
    payload = {
        "iss": _get_issuer(),
        "sub": str(user.pk),
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "typ": "session",
    }
    audience = _get_audience()
    if audience:
        payload["aud"] = audience

    return jwt.encode(
        payload,
        _get_private_key(),
        algorithm=_get_algorithm(),
        headers=_get_headers(),
    )


def decode_session_token(token):
    options = {"require": ["exp", "iat", "iss", "sub", "typ"]}
    kwargs = {
        "algorithms": [_get_algorithm()],
        "issuer": _get_issuer(),
        "options": options,
    }
    audience = _get_audience()
    if audience:
        kwargs["audience"] = audience
    else:
        kwargs["options"]["verify_aud"] = False

    try:
        payload = jwt.decode(token, _get_public_key(), **kwargs)
    except jwt.PyJWTError as exc:
        raise TokenError("Invalid session token.") from exc

    if payload.get("typ") != "session":
        raise TokenError("Invalid session token type.")

    return payload


def get_public_key():
    return _get_public_key()


def get_token_metadata():
    return {
        "algorithm": _get_algorithm(),
        "issuer": _get_issuer(),
        "audience": _get_audience(),
        "key_id": getattr(settings, "IAM_JWT_KEY_ID", None),
    }


def _get_private_key():
    return _get_required_setting("IAM_JWT_PRIVATE_KEY")


def _get_public_key():
    return _get_required_setting("IAM_JWT_PUBLIC_KEY")


def _get_required_setting(name):
    value = getattr(settings, name, None)
    if not value:
        raise ImproperlyConfigured(f"{name} must be configured.")
    return value


def _get_algorithm():
    return getattr(settings, "IAM_JWT_ALGORITHM", DEFAULT_ALGORITHM)


def _get_issuer():
    return getattr(settings, "IAM_JWT_ISSUER", DEFAULT_ISSUER)


def _get_audience():
    return getattr(settings, "IAM_JWT_AUDIENCE", None)


def _get_token_ttl_seconds():
    return getattr(settings, "IAM_JWT_TTL_SECONDS", DEFAULT_TTL_SECONDS)


def _get_headers():
    key_id = getattr(settings, "IAM_JWT_KEY_ID", None)
    if not key_id:
        return None
    return {"kid": key_id}
