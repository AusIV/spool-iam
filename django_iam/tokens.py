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
    return _issue_token(str(user.pk), token_type="session")


def issue_assumed_session_token(actor_user, actor_principal, target_principal, duration_seconds):
    claims = {
        "principal": {
            "id": target_principal.pk,
            "type": target_principal.principal_type,
            "name": target_principal.name,
        },
        "actor": {
            "sub": str(actor_user.pk),
            "principal_type": actor_principal.principal_type,
            "principal_name": actor_principal.name,
        },
    }
    return _issue_token(
        f"principal:{target_principal.pk}",
        token_type="assumed_session",
        ttl_seconds=duration_seconds,
        extra_claims=claims,
    )


def _issue_token(subject, token_type, ttl_seconds=None, extra_claims=None):
    now = timezone.now()
    expires_at = now + timedelta(seconds=ttl_seconds or _get_token_ttl_seconds())
    payload = {
        "iss": _get_issuer(),
        "sub": str(subject),
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "typ": token_type,
    }
    if extra_claims:
        payload.update(extra_claims)

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

    if payload.get("typ") not in {"session", "assumed_session"}:
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


def get_assume_role_max_ttl_seconds():
    return getattr(settings, "IAM_ASSUME_ROLE_MAX_TTL_SECONDS", _get_token_ttl_seconds())


def _get_headers():
    key_id = getattr(settings, "IAM_JWT_KEY_ID", None)
    if not key_id:
        return None
    return {"kid": key_id}
