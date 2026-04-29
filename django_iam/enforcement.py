import fnmatch
import re

from django.contrib.auth.models import AnonymousUser

from .exceptions import MissingContextValue, PermissionDenied
from .models import AuditLog, Policy, Principal


RESOURCE_TEMPLATE_RE = re.compile(r"{(?P<key>[A-Za-z_][A-Za-z0-9_]*)}")


def enforce(request, resource, action, context=None):
    """Authorize a request principal for an action on a resource.

    Raises PermissionDenied when no Allow matches or any Deny matches.
    Raises MissingContextValue when a matching statement resource template
    references a context key that is not supplied.
    """

    context = context or {}
    principal = get_principal(request)
    matched_statements = []
    allowed = False
    denied = False
    reason = ""

    try:
        for statement in get_cumulative_policy(request)["Statements"]:
            if not _action_matches(statement, action):
                continue

            statement_resource = _render_resource(statement.get("Resource", "*"), context)
            if not fnmatch.fnmatchcase(resource, statement_resource):
                continue

            effect = statement.get("Effect")
            match = {
                "Effect": effect,
                "Action": action,
                "Resource": statement_resource,
            }
            matched_statements.append(match)

            if effect == "Deny":
                denied = True
            elif effect == "Allow":
                allowed = True

        if denied:
            reason = "explicit_deny"
            raise PermissionDenied(action, resource, denied_by=matched_statements)

        if not allowed:
            reason = "missing_allow"
            raise PermissionDenied(
                action,
                resource,
                missing_permissions=[f"{action} on {resource}"],
            )

        reason = "allowed"
        return True
    except Exception as exc:
        if not reason:
            reason = exc.__class__.__name__
        _write_audit_log(
            request=request,
            principal=principal,
            action=action,
            resource=resource,
            context=context,
            allowed=False,
            reason=reason,
            matched_statements=matched_statements,
        )
        raise
    finally:
        if reason == "allowed":
            _write_audit_log(
                request=request,
                principal=principal,
                action=action,
                resource=resource,
                context=context,
                allowed=True,
                reason=reason,
                matched_statements=matched_statements,
            )


def get_principal(request):
    try:
        return request._django_iam_principal
    except AttributeError:
        pass

    user = getattr(request, "user", None)
    if not user or isinstance(user, AnonymousUser) or not user.is_authenticated:
        principal = None
    else:
        principal = (
            Principal.objects.select_related("user")
            .filter(principal_type=Principal.USER, user=user)
            .first()
        )

    request._django_iam_principal = principal
    return principal


def get_cumulative_policy(request):
    try:
        return request._django_iam_cumulative_policy
    except AttributeError:
        pass

    principal = get_principal(request)
    statements = []
    if principal:
        policies = (
            Policy.objects.filter(roles__principals=principal)
            .distinct()
            .values_list("document", flat=True)
        )
        for document in policies:
            statements.extend(document.get("Statements", []))

    cumulative_policy = {
        "Version": "0",
        "Statements": statements,
    }
    request._django_iam_cumulative_policy = cumulative_policy
    return cumulative_policy


def _action_matches(statement, action):
    statement_actions = statement.get("Actions", statement.get("Action", []))
    if isinstance(statement_actions, str):
        statement_actions = [statement_actions]

    return any(fnmatch.fnmatchcase(action, candidate) for candidate in statement_actions)


def _render_resource(template, context):
    if not isinstance(template, str):
        raise ValueError("Policy statement Resource must be a string.")

    missing = [
        match.group("key")
        for match in RESOURCE_TEMPLATE_RE.finditer(template)
        if match.group("key") not in context
    ]
    if missing:
        missing_keys = ", ".join(sorted(set(missing)))
        raise MissingContextValue(
            f"Policy resource '{template}' requires missing context value(s): {missing_keys}."
        )

    return RESOURCE_TEMPLATE_RE.sub(lambda match: str(context[match.group("key")]), template)


def _write_audit_log(
    request,
    principal,
    action,
    resource,
    context,
    allowed,
    reason,
    matched_statements,
):
    user = getattr(request, "user", None)
    if not user or isinstance(user, AnonymousUser) or not user.is_authenticated:
        user = None

    AuditLog.objects.create(
        principal=principal,
        user=user,
        action=action,
        resource=resource,
        context=context,
        allowed=allowed,
        reason=reason,
        matched_statements=matched_statements,
    )
