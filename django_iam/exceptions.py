class IAMError(Exception):
    """Base exception for Django IAM enforcement errors."""


class MissingContextValue(IAMError):
    """Raised when a policy resource references a missing context value."""


class PermissionDenied(IAMError):
    """Raised when the active principal is not authorized for an action."""

    def __init__(self, action, resource, missing_permissions=None, denied_by=None):
        self.action = action
        self.resource = resource
        self.missing_permissions = missing_permissions or []
        self.denied_by = denied_by or []

        if self.denied_by:
            message = (
                f"Permission denied for action '{action}' on resource '{resource}': "
                "matched an explicit Deny statement."
            )
        else:
            missing = ", ".join(self.missing_permissions) or f"{action} on {resource}"
            message = (
                f"Permission denied for action '{action}' on resource '{resource}': "
                f"missing required permission(s): {missing}."
            )

        super().__init__(message)
