from dataclasses import dataclass, field

from django.conf import settings
from django.utils.module_loading import import_string

from .client import IAMServiceClient
from .exceptions import EnforcementDenied, IAMServiceError, MissingSessionToken


@dataclass(frozen=True)
class EnforcementOperation:
    mode: str
    resource: str
    action: str
    context: dict = field(default_factory=dict)


class RequestEnforcement:
    def __init__(self, request, client=None):
        self.request = request
        self.client = client or make_client()
        self.operations = []

    def read(self, object, action, context=None):
        operation = self._append("read", object, action, context)
        self._verify([operation])
        return True

    def write(self, object, action, context=None):
        self._append("write", object, action, context)
        self.verify()
        return True

    def verify(self):
        if not self.operations:
            return True
        self._verify(self.operations)
        return True

    def batch(self):
        return EnforcementBatch(self.request, client=self.client)

    def assume_role(self, principal_type, name, duration_seconds=None):
        token = get_session_token(self.request)
        if not token:
            raise MissingSessionToken("A bearer session token is required.")
        return self.client.assume_role(
            token,
            principal_type,
            name,
            duration_seconds=duration_seconds,
        )

    @property
    def reads(self):
        return [operation for operation in self.operations if operation.mode == "read"]

    @property
    def writes(self):
        return [operation for operation in self.operations if operation.mode == "write"]

    def _append(self, mode, resource, action, context):
        operation = EnforcementOperation(
            mode=mode,
            resource=resource,
            action=action,
            context=context or {},
        )
        self.operations.append(operation)
        return operation

    def _verify(self, operations):
        results = execute_operations(self.request, self.client, operations)
        failed_actions = failed_operation_actions(operations, results)
        if failed_actions:
            raise EnforcementDenied(failed_actions)


class EnforcementBatch:
    def __init__(self, request, client=None):
        self.request = request
        self.client = client or make_client()
        self.operations = []

    def read(self, object, action, context=None):
        self._append("read", object, action, context)
        return self

    def write(self, object, action, context=None):
        self._append("write", object, action, context)
        return self

    def execute(self):
        if not self.operations:
            return []
        return execute_operations(self.request, self.client, self.operations)

    def verify(self):
        results = self.execute()
        failed_actions = failed_operation_actions(self.operations, results)
        if failed_actions:
            raise EnforcementDenied(failed_actions)
        return True

    def _append(self, mode, resource, action, context):
        operation = EnforcementOperation(
            mode=mode,
            resource=resource,
            action=action,
            context=context or {},
        )
        self.operations.append(operation)
        return operation


def execute_operations(request, client, operations):
    token = get_session_token(request)
    if not token:
        raise MissingSessionToken("A bearer session token is required.")
    return client.enforce(token, operations)


def failed_operation_actions(operations, results):
    return [
        operation.action
        for operation, result in zip(operations, results)
        if not result.get("allowed")
    ]


def get_session_token(request):
    getter_path = getattr(settings, "IAM_CLIENT_SESSION_TOKEN_GETTER", None)
    if getter_path:
        return import_string(getter_path)(request)

    header = request.headers.get("Authorization", "")
    prefix = "Bearer "
    if header.startswith(prefix):
        return header[len(prefix) :].strip()

    return getattr(request, "iam_session_token", None)


def make_client():
    client_path = getattr(settings, "IAM_CLIENT_CLASS", None)
    if client_path:
        return import_string(client_path)()
    return IAMServiceClient()


def denied_response(failed_actions, status=403):
    from django.http import JsonResponse

    return JsonResponse(
        {
            "error": "permission_denied",
            "failed_actions": list(failed_actions),
        },
        status=status,
    )


def service_error_response(status=403):
    from django.http import JsonResponse

    return JsonResponse(
        {
            "error": "permission_denied",
            "failed_actions": [],
        },
        status=status,
    )


def exception_to_response(exc):
    if isinstance(exc, EnforcementDenied):
        return denied_response(exc.failed_actions)
    if isinstance(exc, (IAMServiceError, MissingSessionToken)):
        return service_error_response()
    return None
