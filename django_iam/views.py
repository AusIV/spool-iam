import json
from types import SimpleNamespace

from django.contrib.auth import authenticate, get_user_model
from django.db import IntegrityError, transaction
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST, require_http_methods

from .enforcement import enforce
from .exceptions import MissingContextValue, PermissionDenied
from .models import Policy, Principal, PrincipalRole, Role, RolePolicy
from .tokens import (
    TokenError,
    decode_session_token,
    get_public_key,
    get_token_metadata,
    issue_session_token,
)


USER_FIELDS = ("email", "first_name", "last_name", "is_active")


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


@csrf_exempt
@require_http_methods(["GET", "POST"])
def manage_users(request):
    auth_request, response = _management_auth_request(request)
    if response is not None:
        return response

    if request.method == "GET":
        response = _authorize_management(auth_request, "iam:ListUsers", "iam:userlist")
        if response is not None:
            return response

        users = get_user_model().objects.order_by("username")
        return JsonResponse({"users": [_serialize_user(user) for user in users]})

    data = _read_json(request)
    if data is None:
        return _error("invalid_json", "Request body must be valid JSON.", status=400)

    username = data.get("username")
    if not isinstance(username, str) or not username:
        return _error("invalid_user", "username must be a non-empty string.", status=400)

    response = _authorize_management(auth_request, "iam:CreateUser", _user_resource(username))
    if response is not None:
        return response

    try:
        with transaction.atomic():
            user = get_user_model()(username=username)
            _apply_user_fields(user, data)
            password = data.get("password")
            if password:
                user.set_password(password)
            else:
                user.set_unusable_password()
            user.save()
            Principal.objects.create(
                principal_type=Principal.USER,
                user=user,
                name=username,
            )
    except IntegrityError:
        return _error("conflict", "User or principal already exists.", status=409)

    return JsonResponse({"user": _serialize_user(user)}, status=201)


@csrf_exempt
@require_http_methods(["GET", "PATCH", "PUT", "DELETE"])
def manage_user(request, username):
    auth_request, response = _management_auth_request(request)
    if response is not None:
        return response

    user = get_user_model().objects.filter(username=username).first()
    if user is None:
        return _error("not_found", "User does not exist.", status=404)

    action = {
        "GET": "iam:GetUser",
        "PATCH": "iam:UpdateUser",
        "PUT": "iam:UpdateUser",
        "DELETE": "iam:DeleteUser",
    }[request.method]
    response = _authorize_management(auth_request, action, _user_resource(username))
    if response is not None:
        return response

    if request.method == "GET":
        return JsonResponse({"user": _serialize_user(user)})

    if request.method == "DELETE":
        user.delete()
        return JsonResponse({"deleted": True})

    data = _read_json(request)
    if data is None:
        return _error("invalid_json", "Request body must be valid JSON.", status=400)
    if "username" in data and data["username"] != username:
        return _error("invalid_user", "username cannot be changed.", status=400)

    _apply_user_fields(user, data)
    if data.get("password"):
        user.set_password(data["password"])
    user.save()
    return JsonResponse({"user": _serialize_user(user)})


@csrf_exempt
@require_http_methods(["GET", "POST"])
def manage_principals(request):
    auth_request, response = _management_auth_request(request)
    if response is not None:
        return response

    if request.method == "GET":
        response = _authorize_management(
            auth_request, "iam:ListPrincipals", "iam:principallist"
        )
        if response is not None:
            return response

        principals = Principal.objects.select_related("user").prefetch_related("roles")
        return JsonResponse(
            {"principals": [_serialize_principal(principal) for principal in principals]}
        )

    data = _read_json(request)
    if data is None:
        return _error("invalid_json", "Request body must be valid JSON.", status=400)

    principal_type = data.get("principal_type", Principal.USER)
    name = data.get("name")
    if principal_type != Principal.USER:
        return _error("invalid_principal", "Only user principals are supported.", status=400)
    if not isinstance(name, str) or not name:
        return _error("invalid_principal", "name must be a non-empty string.", status=400)

    response = _authorize_management(
        auth_request, "iam:CreatePrincipal", _principal_resource(principal_type, name)
    )
    if response is not None:
        return response

    user = _get_principal_user(data, default_username=name)
    if isinstance(user, JsonResponse):
        return user

    try:
        principal = Principal.objects.create(
            principal_type=principal_type,
            user=user,
            name=name,
        )
    except IntegrityError:
        return _error("conflict", "Principal already exists.", status=409)

    return JsonResponse({"principal": _serialize_principal(principal)}, status=201)


@csrf_exempt
@require_http_methods(["GET", "PATCH", "PUT", "DELETE"])
def manage_principal(request, principal_type, name):
    auth_request, response = _management_auth_request(request)
    if response is not None:
        return response

    principal = (
        Principal.objects.select_related("user")
        .prefetch_related("roles")
        .filter(principal_type=principal_type, name=name)
        .first()
    )
    if principal is None:
        return _error("not_found", "Principal does not exist.", status=404)

    action = {
        "GET": "iam:GetPrincipal",
        "PATCH": "iam:UpdatePrincipal",
        "PUT": "iam:UpdatePrincipal",
        "DELETE": "iam:DeletePrincipal",
    }[request.method]
    response = _authorize_management(
        auth_request, action, _principal_resource(principal_type, name)
    )
    if response is not None:
        return response

    if request.method == "GET":
        return JsonResponse({"principal": _serialize_principal(principal)})

    if request.method == "DELETE":
        principal.delete()
        return JsonResponse({"deleted": True})

    data = _read_json(request)
    if data is None:
        return _error("invalid_json", "Request body must be valid JSON.", status=400)
    if data.get("principal_type", principal_type) != principal_type:
        return _error("invalid_principal", "principal_type cannot be changed.", status=400)
    if data.get("name", name) != name:
        return _error("invalid_principal", "name cannot be changed.", status=400)

    user = _get_principal_user(data, default_username=name)
    if isinstance(user, JsonResponse):
        return user
    principal.user = user
    try:
        principal.save()
    except IntegrityError:
        return _error("conflict", "Principal user is already linked.", status=409)

    return JsonResponse({"principal": _serialize_principal(principal)})


@csrf_exempt
@require_http_methods(["GET", "POST"])
def manage_roles(request):
    auth_request, response = _management_auth_request(request)
    if response is not None:
        return response

    if request.method == "GET":
        response = _authorize_management(auth_request, "iam:ListRoles", "iam:rolelist")
        if response is not None:
            return response

        roles = Role.objects.prefetch_related("policies", "principals")
        return JsonResponse({"roles": [_serialize_role(role) for role in roles]})

    data = _read_json(request)
    if data is None:
        return _error("invalid_json", "Request body must be valid JSON.", status=400)
    role_name = data.get("name")
    if not isinstance(role_name, str) or not role_name:
        return _error("invalid_role", "name must be a non-empty string.", status=400)

    response = _authorize_management(auth_request, "iam:CreateRole", _role_resource(role_name))
    if response is not None:
        return response

    try:
        role = Role.objects.create(name=role_name)
    except IntegrityError:
        return _error("conflict", "Role already exists.", status=409)

    return JsonResponse({"role": _serialize_role(role)}, status=201)


@csrf_exempt
@require_http_methods(["GET", "PATCH", "PUT", "DELETE"])
def manage_role(request, name):
    auth_request, response = _management_auth_request(request)
    if response is not None:
        return response

    role = Role.objects.prefetch_related("policies", "principals").filter(name=name).first()
    if role is None:
        return _error("not_found", "Role does not exist.", status=404)

    action = {
        "GET": "iam:GetRole",
        "PATCH": "iam:UpdateRole",
        "PUT": "iam:UpdateRole",
        "DELETE": "iam:DeleteRole",
    }[request.method]
    response = _authorize_management(auth_request, action, _role_resource(name))
    if response is not None:
        return response

    if request.method == "GET":
        return JsonResponse({"role": _serialize_role(role)})

    if request.method == "DELETE":
        role.delete()
        return JsonResponse({"deleted": True})

    data = _read_json(request)
    if data is None:
        return _error("invalid_json", "Request body must be valid JSON.", status=400)
    role_name = data.get("name", name)
    if not isinstance(role_name, str) or not role_name:
        return _error("invalid_role", "name must be a non-empty string.", status=400)
    role.name = role_name
    try:
        role.save()
    except IntegrityError:
        return _error("conflict", "Role already exists.", status=409)

    return JsonResponse({"role": _serialize_role(role)})


@csrf_exempt
@require_GET
def manage_role_principals(request, name):
    auth_request, response = _management_auth_request(request)
    if response is not None:
        return response

    role = Role.objects.filter(name=name).first()
    if role is None:
        return _error("not_found", "Role does not exist.", status=404)

    response = _authorize_management(
        auth_request, "iam:ListPrincipals", _role_principal_list_resource(name)
    )
    if response is not None:
        return response

    principals = (
        Principal.objects.select_related("user")
        .prefetch_related("roles")
        .filter(roles=role)
        .order_by("principal_type", "name")
    )
    return JsonResponse(
        {
            "role": role.name,
            "principals": [_serialize_principal(principal) for principal in principals],
        }
    )


@csrf_exempt
@require_http_methods(["GET", "POST"])
def manage_policies(request):
    auth_request, response = _management_auth_request(request)
    if response is not None:
        return response

    if request.method == "GET":
        response = _authorize_management(auth_request, "iam:ListPolicies", "iam:policylist")
        if response is not None:
            return response

        return JsonResponse(
            {"policies": [_serialize_policy(policy) for policy in Policy.objects.all()]}
        )

    data = _read_json(request)
    if data is None:
        return _error("invalid_json", "Request body must be valid JSON.", status=400)
    error_response = _validate_policy_payload(data)
    if error_response is not None:
        return error_response

    response = _authorize_management(auth_request, "iam:CreatePolicy", _policy_resource(data["name"]))
    if response is not None:
        return response

    try:
        policy = Policy.objects.create(name=data["name"], document=data["document"])
    except IntegrityError:
        return _error("conflict", "Policy already exists.", status=409)

    return JsonResponse({"policy": _serialize_policy(policy)}, status=201)


@csrf_exempt
@require_http_methods(["GET", "PATCH", "PUT", "DELETE"])
def manage_policy(request, name):
    auth_request, response = _management_auth_request(request)
    if response is not None:
        return response

    policy = Policy.objects.filter(name=name).first()
    if policy is None:
        return _error("not_found", "Policy does not exist.", status=404)

    action = {
        "GET": "iam:GetPolicy",
        "PATCH": "iam:UpdatePolicy",
        "PUT": "iam:UpdatePolicy",
        "DELETE": "iam:DeletePolicy",
    }[request.method]
    response = _authorize_management(auth_request, action, _policy_resource(name))
    if response is not None:
        return response

    if request.method == "GET":
        return JsonResponse({"policy": _serialize_policy(policy)})

    if request.method == "DELETE":
        policy.delete()
        return JsonResponse({"deleted": True})

    data = _read_json(request)
    if data is None:
        return _error("invalid_json", "Request body must be valid JSON.", status=400)
    next_name = data.get("name", name)
    next_document = data.get("document", policy.document)
    error_response = _validate_policy_payload({"name": next_name, "document": next_document})
    if error_response is not None:
        return error_response

    policy.name = next_name
    policy.document = next_document
    try:
        policy.save()
    except IntegrityError:
        return _error("conflict", "Policy already exists.", status=409)

    return JsonResponse({"policy": _serialize_policy(policy)})


@csrf_exempt
@require_http_methods(["PUT", "DELETE"])
def manage_principal_role(request, principal_type, name, role_name):
    auth_request, response = _management_auth_request(request)
    if response is not None:
        return response

    action = "iam:AssignRole" if request.method == "PUT" else "iam:UnassignRole"
    response = _authorize_management(
        auth_request,
        action,
        _principal_role_resource(principal_type, name, role_name),
    )
    if response is not None:
        return response

    principal = Principal.objects.filter(principal_type=principal_type, name=name).first()
    if principal is None:
        return _error("not_found", "Principal does not exist.", status=404)
    role = Role.objects.filter(name=role_name).first()
    if role is None:
        return _error("not_found", "Role does not exist.", status=404)

    if request.method == "PUT":
        PrincipalRole.objects.get_or_create(principal=principal, role=role)
        return JsonResponse(
            {"principal_role": _serialize_principal_role(principal, role)}, status=201
        )

    PrincipalRole.objects.filter(principal=principal, role=role).delete()
    return JsonResponse({"deleted": True})


@csrf_exempt
@require_http_methods(["PUT", "DELETE"])
def manage_role_policy(request, role_name, policy_name):
    auth_request, response = _management_auth_request(request)
    if response is not None:
        return response

    action = "iam:AttachPolicy" if request.method == "PUT" else "iam:DetachPolicy"
    response = _authorize_management(
        auth_request,
        action,
        _role_policy_resource(role_name, policy_name),
    )
    if response is not None:
        return response

    role = Role.objects.filter(name=role_name).first()
    if role is None:
        return _error("not_found", "Role does not exist.", status=404)
    policy = Policy.objects.filter(name=policy_name).first()
    if policy is None:
        return _error("not_found", "Policy does not exist.", status=404)

    if request.method == "PUT":
        RolePolicy.objects.get_or_create(role=role, policy=policy)
        return JsonResponse({"role_policy": _serialize_role_policy(role, policy)}, status=201)

    RolePolicy.objects.filter(role=role, policy=policy).delete()
    return JsonResponse({"deleted": True})


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


def _management_auth_request(request):
    token = _bearer_token(request)
    if not token:
        return None, _error("missing_token", "A session token is required.", status=401)

    try:
        payload = decode_session_token(token)
    except TokenError as exc:
        return None, _error("invalid_token", str(exc), status=401)

    user = get_user_model().objects.filter(pk=payload["sub"], is_active=True).first()
    if user is None:
        return None, _error(
            "invalid_token", "Token subject is not an active user.", status=401
        )

    return SimpleNamespace(user=user), None


def _authorize_management(auth_request, action, resource):
    try:
        enforce(auth_request, resource, action, context=_management_context(auth_request))
    except MissingContextValue as exc:
        return _error("missing_context", str(exc), status=403)
    except PermissionDenied as exc:
        return _error("permission_denied", str(exc), status=403)
    return None


def _management_context(auth_request):
    user = auth_request.user
    return {
        "principalName": user.username,
        "username": user.username,
        "userId": str(user.pk),
    }


def _serialize_user(user):
    principal = getattr(user, "iam_principal", None)
    return {
        "id": user.pk,
        "username": user.username,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "is_active": user.is_active,
        "principal": _serialize_principal_identity(principal) if principal else None,
    }


def _serialize_principal(principal):
    return {
        "id": principal.pk,
        "principal_type": principal.principal_type,
        "name": principal.name,
        "user": _serialize_user_identity(principal.user) if principal.user else None,
        "roles": [role.name for role in principal.roles.all()],
    }


def _serialize_role(role):
    return {
        "id": role.pk,
        "name": role.name,
        "policies": [policy.name for policy in role.policies.all()],
        "principals": [
            _serialize_principal_identity(principal)
            for principal in role.principals.all()
        ],
    }


def _serialize_policy(policy):
    return {
        "id": policy.pk,
        "name": policy.name,
        "document": policy.document,
    }


def _serialize_principal_role(principal, role):
    return {
        "principal": _serialize_principal_identity(principal),
        "role": role.name,
    }


def _serialize_role_policy(role, policy):
    return {
        "role": role.name,
        "policy": policy.name,
    }


def _serialize_user_identity(user):
    return {"id": user.pk, "username": user.username}


def _serialize_principal_identity(principal):
    return {
        "id": principal.pk,
        "principal_type": principal.principal_type,
        "name": principal.name,
    }


def _apply_user_fields(user, data):
    for field in USER_FIELDS:
        if field in data:
            setattr(user, field, data[field])


def _get_principal_user(data, default_username):
    user_model = get_user_model()
    user_id = data.get("user_id")
    username = data.get("username", default_username)

    if user_id is not None:
        user = user_model.objects.filter(pk=user_id).first()
    elif isinstance(username, str) and username:
        user = user_model.objects.filter(username=username).first()
    else:
        user = None

    if user is None:
        return _error("not_found", "Linked user does not exist.", status=404)
    return user


def _validate_policy_payload(data):
    name = data.get("name")
    document = data.get("document")
    if not isinstance(name, str) or not name:
        return _error("invalid_policy", "name must be a non-empty string.", status=400)
    if not isinstance(document, dict):
        return _error("invalid_policy", "document must be an object.", status=400)
    if not isinstance(document.get("Statements"), list):
        return _error(
            "invalid_policy", "document.Statements must be a list.", status=400
        )
    return None


def _user_resource(username):
    return f"iam:user:{username}"


def _principal_resource(principal_type, name):
    return f"iam:principal:{principal_type}:{name}"


def _role_resource(name):
    return f"iam:role:{name}"


def _policy_resource(name):
    return f"iam:policy:{name}"


def _principal_role_resource(principal_type, principal_name, role_name):
    return f"iam:principal-role:{principal_type}:{principal_name}:{role_name}"


def _role_principal_list_resource(role_name):
    return f"iam:role-principallist:{role_name}"


def _role_policy_resource(role_name, policy_name):
    return f"iam:role-policy:{role_name}:{policy_name}"


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
