from django.core.exceptions import PermissionDenied


class IAMClientError(Exception):
    """Base exception for IAM service client errors."""


class IAMServiceError(IAMClientError):
    """Raised when the IAM service cannot return a usable enforcement result."""


class MissingSessionToken(IAMClientError):
    """Raised when an enforcement call cannot find a user session token."""


class EnforcementDenied(PermissionDenied):
    """Raised when one or more accumulated enforcement operations are denied."""

    def __init__(self, failed_actions):
        self.failed_actions = _unique_actions(failed_actions)
        action_list = ", ".join(self.failed_actions) or "unknown"
        super().__init__(f"Permission denied for action(s): {action_list}.")


def _unique_actions(actions):
    seen = set()
    unique = []
    for action in actions:
        if action in seen:
            continue
        seen.add(action)
        unique.append(action)
    return unique
