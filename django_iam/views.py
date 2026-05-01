import json
from types import SimpleNamespace

from django.contrib.auth import authenticate, get_user_model
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from .enforcement import enforce
from .exceptions import MissingContextValue, PermissionDenied
from .tokens import (
    TokenError,
    decode_session_token,
    get_public_key,
    get_token_metadata,
    issue_session_token,
)


@csrf_exempt
@require_POST
def authenticate_session(request):
    data = _read_json(request)
    if data is None:
        return _error("invalid_json", "Request body must be valid JSON.", status=400)

    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return _error(
            "missing_credentials",
            "Both username and password are required.",
            status=400,
        )

    user = authenticate(request, username=username, password=password)
    if user is None:
        return _error("invalid_credentials", "Invalid credentials.", status=401)
    if not user.is_active:
        return _error("inactive_user", "User is inactive.", status=403)

    return JsonResponse({"token": issue_session_token(user), "token_type": "Bearer"})


@csrf_exempt
@require_POST
def enforce_batch(request):
    data = _read_json(request)
    if data is None:
        return _error("invalid_json", "Request body must be valid JSON.", status=400)

    token = data.get("token") or _bearer_token(request)
    if not token:
        return _error("missing_token", "A session token is required.", status=401)

    try:
        payload = decode_session_token(token)
    except TokenError as exc:
        return _error("invalid_token", str(exc), status=401)

    user = (
        get_user_model()
        .objects.filter(pk=payload["sub"], is_active=True)
        .first()
    )
    if user is None:
        return _error("invalid_token", "Token subject is not an active user.", status=401)

    checks = data.get("checks")
    if not isinstance(checks, list):
        return _error("invalid_checks", "checks must be a list.", status=400)

    auth_request = SimpleNamespace(user=user)
    results = [_evaluate_check(auth_request, check) for check in checks]
    return JsonResponse({"results": results})


@require_GET
def public_key(request):
    metadata = get_token_metadata()
    return JsonResponse(
        {
            "algorithm": metadata["algorithm"],
            "issuer": metadata["issuer"],
            "audience": metadata["audience"],
            "key_id": metadata["key_id"],
            "public_key": get_public_key(),
        }
    )


def _evaluate_check(auth_request, check):
    if not isinstance(check, dict):
        return {
            "allowed": False,
            "reason": "invalid_check",
            "error": "Each check must be an object.",
        }

    resource = check.get("object", check.get("resource"))
    action = check.get("action")
    context = check.get("context", {})
    if not isinstance(resource, str) or not resource:
        return {
            "allowed": False,
            "reason": "invalid_check",
            "error": "object must be a non-empty string.",
        }
    if not isinstance(action, str) or not action:
        return {
            "allowed": False,
            "reason": "invalid_check",
            "error": "action must be a non-empty string.",
        }
    if not isinstance(context, dict):
        return {
            "allowed": False,
            "reason": "invalid_check",
            "error": "context must be an object.",
        }

    try:
        enforce(auth_request, resource, action, context=context)
    except MissingContextValue as exc:
        return {"allowed": False, "reason": "missing_context", "error": str(exc)}
    except PermissionDenied as exc:
        reason = "explicit_deny" if exc.denied_by else "missing_allow"
        return {"allowed": False, "reason": reason, "error": str(exc)}

    return {"allowed": True, "reason": "allowed"}


def _read_json(request):
    try:
        return json.loads(request.body.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _bearer_token(request):
    header = request.headers.get("Authorization", "")
    prefix = "Bearer "
    if not header.startswith(prefix):
        return None
    return header[len(prefix) :].strip()


def _error(code, message, status):
    return JsonResponse({"error": code, "message": message}, status=status)
