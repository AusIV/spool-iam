from datetime import timedelta
from uuid import UUID, uuid4
import secrets

import jwt
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django.utils import timezone
from django.utils.crypto import salted_hmac

from .models import IssuedToken, RefreshToken


DEFAULT_ALGORITHM = "RS256"
DEFAULT_ISSUER = "django-iam"
DEFAULT_TTL_SECONDS = 60 * 60
DEFAULT_REFRESH_TOKEN_TTL_SECONDS = 24 * 60 * 60
DEFAULT_REFRESH_TOKEN_MAX_REFRESHES = 64
REFRESH_TOKEN_SALT = "django_iam.refresh_token"


class TokenError(Exception):
    """Raised when a session token cannot be decoded or trusted."""


class RefreshTokenError(Exception):
    """Raised when a refresh token cannot be rotated."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def issue_session_pair(user):
    refresh_secret, refresh_token = _create_refresh_token(
        user=user,
        family_id=uuid4(),
        generation=0,
        refreshes_remaining=get_refresh_token_max_refreshes(),
        parent=None,
    )
    session_token = issue_session_token(user, refresh_token=refresh_token)
    return _token_response(session_token, refresh_secret, refresh_token)


def refresh_session(refresh_secret):
    if not isinstance(refresh_secret, str) or not refresh_secret:
        raise RefreshTokenError("missing_refresh_token", "A refresh token is required.")

    replay_error = None
    with transaction.atomic():
        refresh_token = (
            RefreshToken.objects.select_for_update()
            .select_related("user")
            .filter(token_hash=_hash_refresh_token(refresh_secret))
            .first()
        )
        if refresh_token is None:
            raise RefreshTokenError("invalid_refresh_token", "Invalid refresh token.")

        now = timezone.now()
        if refresh_token.used_at is not None:
            _revoke_descendants(refresh_token, now)
            replay_error = RefreshTokenError(
                "refresh_token_reused",
                "Refresh token has already been used.",
            )
            session_token = None
            next_secret = None
            next_refresh_token = None
        elif refresh_token.revoked_at is not None:
            raise RefreshTokenError("invalid_refresh_token", "Refresh token has been revoked.")
        elif refresh_token.expires_at <= now:
            raise RefreshTokenError("refresh_token_expired", "Refresh token has expired.")
        elif refresh_token.refreshes_remaining < 1:
            raise RefreshTokenError(
                "refresh_token_exhausted",
                "Refresh token has no refreshes remaining.",
            )
        elif not refresh_token.user.is_active:
            raise RefreshTokenError("invalid_refresh_token", "Refresh token user is inactive.")
        else:
            refresh_token.used_at = now
            refresh_token.save(update_fields=["used_at"])
            next_secret, next_refresh_token = _create_refresh_token(
                user=refresh_token.user,
                family_id=refresh_token.family_id,
                generation=refresh_token.generation + 1,
                refreshes_remaining=refresh_token.refreshes_remaining - 1,
                parent=refresh_token,
            )
            session_token = issue_session_token(
                refresh_token.user,
                refresh_token=next_refresh_token,
            )

    if replay_error is not None:
        raise replay_error

    return _token_response(session_token, next_secret, next_refresh_token)


def issue_session_token(user, refresh_token=None):
    if refresh_token is None:
        _, refresh_token = _create_refresh_token(
            user=user,
            family_id=uuid4(),
            generation=0,
            refreshes_remaining=get_refresh_token_max_refreshes(),
            parent=None,
        )
    return _issue_token(
        str(user.pk),
        token_type="session",
        user=user,
        family_id=refresh_token.family_id,
        generation=refresh_token.generation,
    )


def issue_assumed_session_token(
    actor_user,
    actor_principal,
    target_principal,
    duration_seconds,
    source_payload=None,
):
    family_id = _payload_family_id(source_payload)
    generation = source_payload.get("generation", 0) if source_payload else 0
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
        user=actor_user,
        family_id=family_id,
        generation=generation,
    )


def _issue_token(
    subject,
    token_type,
    user,
    family_id,
    generation,
    ttl_seconds=None,
    extra_claims=None,
):
    now = timezone.now()
    expires_at = now + timedelta(seconds=ttl_seconds or get_token_ttl_seconds())
    jti = uuid4()
    payload = {
        "iss": _get_issuer(),
        "sub": str(subject),
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "typ": token_type,
        "jti": str(jti),
        "family_id": str(family_id),
        "generation": generation,
    }
    if extra_claims:
        payload.update(extra_claims)

    audience = _get_audience()
    if audience:
        payload["aud"] = audience

    IssuedToken.objects.create(
        jti=jti,
        user=user,
        token_type=token_type,
        subject=str(subject),
        family_id=family_id,
        generation=generation,
        expires_at=expires_at,
    )

    return jwt.encode(
        payload,
        _get_private_key(),
        algorithm=_get_algorithm(),
        headers=_get_headers(),
    )


def decode_session_token(token):
    options = {"require": ["exp", "iat", "iss", "sub", "typ", "jti"]}
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

    try:
        jti = UUID(str(payload["jti"]))
    except (TypeError, ValueError) as exc:
        raise TokenError("Invalid session token.") from exc

    issued_token = IssuedToken.objects.filter(jti=jti).first()
    if issued_token is None:
        raise TokenError("Invalid session token.")
    if issued_token.revoked_at is not None:
        raise TokenError("Session token has been revoked.")
    if issued_token.expires_at <= timezone.now():
        raise TokenError("Session token has expired.")

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


def get_token_ttl_seconds():
    return getattr(settings, "IAM_JWT_TTL_SECONDS", DEFAULT_TTL_SECONDS)


def get_refresh_token_ttl_seconds():
    return getattr(
        settings,
        "IAM_REFRESH_TOKEN_TTL_SECONDS",
        DEFAULT_REFRESH_TOKEN_TTL_SECONDS,
    )


def get_refresh_token_max_refreshes():
    return getattr(
        settings,
        "IAM_REFRESH_TOKEN_MAX_REFRESHES",
        DEFAULT_REFRESH_TOKEN_MAX_REFRESHES,
    )


def _create_refresh_token(user, family_id, generation, refreshes_remaining, parent):
    now = timezone.now()
    refresh_secret = secrets.token_urlsafe(32)
    refresh_token = RefreshToken.objects.create(
        user=user,
        token_hash=_hash_refresh_token(refresh_secret),
        family_id=family_id,
        generation=generation,
        parent=parent,
        refreshes_remaining=refreshes_remaining,
        expires_at=now + timedelta(seconds=get_refresh_token_ttl_seconds()),
    )
    return refresh_secret, refresh_token


def _token_response(session_token, refresh_secret, refresh_token):
    return {
        "token": session_token,
        "token_type": "Bearer",
        "expires_in": get_token_ttl_seconds(),
        "refresh_token": refresh_secret,
        "refresh_token_expires_at": refresh_token.expires_at.isoformat(),
        "refreshes_remaining": refresh_token.refreshes_remaining,
    }


def _hash_refresh_token(refresh_secret):
    return salted_hmac(
        REFRESH_TOKEN_SALT,
        refresh_secret,
        secret=_get_refresh_token_hash_secret(),
    ).hexdigest()


def _revoke_descendants(refresh_token, revoked_at):
    RefreshToken.objects.filter(
        family_id=refresh_token.family_id,
        generation__gt=refresh_token.generation,
        revoked_at__isnull=True,
    ).update(revoked_at=revoked_at)
    IssuedToken.objects.filter(
        family_id=refresh_token.family_id,
        generation__gt=refresh_token.generation,
        revoked_at__isnull=True,
    ).update(revoked_at=revoked_at)


def _payload_family_id(payload):
    if not payload or not payload.get("family_id"):
        return uuid4()
    try:
        return UUID(str(payload["family_id"]))
    except (TypeError, ValueError):
        return uuid4()


def _get_private_key():
    return _get_required_setting("IAM_JWT_PRIVATE_KEY")


def _get_public_key():
    return _get_required_setting("IAM_JWT_PUBLIC_KEY")


def _get_required_setting(name):
    value = getattr(settings, name, None)
    if not value:
        raise ImproperlyConfigured(f"{name} must be configured.")
    return value


def _get_refresh_token_hash_secret():
    return getattr(settings, "IAM_REFRESH_TOKEN_HASH_SECRET", settings.SECRET_KEY)


def _get_algorithm():
    return getattr(settings, "IAM_JWT_ALGORITHM", DEFAULT_ALGORITHM)


def _get_issuer():
    return getattr(settings, "IAM_JWT_ISSUER", DEFAULT_ISSUER)


def _get_audience():
    return getattr(settings, "IAM_JWT_AUDIENCE", None)


def get_assume_role_max_ttl_seconds():
    return getattr(settings, "IAM_ASSUME_ROLE_MAX_TTL_SECONDS", get_token_ttl_seconds())


def _get_headers():
    key_id = getattr(settings, "IAM_JWT_KEY_ID", None)
    if not key_id:
        return None
    return {"kid": key_id}
