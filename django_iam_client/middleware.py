from .enforcement import RequestEnforcement, exception_to_response
from .exceptions import EnforcementDenied, IAMServiceError, MissingSessionToken


class IAMEnforcementMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.enforce = RequestEnforcement(request)

        try:
            response = self.get_response(request)
        except (EnforcementDenied, IAMServiceError, MissingSessionToken) as exc:
            return exception_to_response(exc)

        try:
            request.enforce.verify()
        except (EnforcementDenied, IAMServiceError, MissingSessionToken) as exc:
            return exception_to_response(exc)

        return response
