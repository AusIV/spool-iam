import json
import urllib.error
import urllib.request

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from .exceptions import IAMServiceError


DEFAULT_TIMEOUT_SECONDS = 5


class IAMServiceClient:
    def __init__(self, enforce_url=None, assume_role_url=None, timeout=None):
        base_url = getattr(settings, "IAM_CLIENT_BASE_URL", "").rstrip("/")
        self.enforce_url = enforce_url or getattr(settings, "IAM_CLIENT_ENFORCE_URL", None)
        if not self.enforce_url:
            if base_url:
                self.enforce_url = f"{base_url}/api/enforce/"

        self.assume_role_url = assume_role_url or getattr(
            settings,
            "IAM_CLIENT_ASSUME_ROLE_URL",
            None,
        )
        if not self.assume_role_url and base_url:
            self.assume_role_url = f"{base_url}/api/session/assume-role/"

        if not self.enforce_url and not self.assume_role_url:
            raise ImproperlyConfigured(
                "Configure IAM_CLIENT_BASE_URL, IAM_CLIENT_ENFORCE_URL, "
                "or IAM_CLIENT_ASSUME_ROLE_URL."
            )

        self.timeout = timeout
        if self.timeout is None:
            self.timeout = getattr(
                settings,
                "IAM_CLIENT_TIMEOUT_SECONDS",
                DEFAULT_TIMEOUT_SECONDS,
            )

    def enforce(self, token, operations):
        if not self.enforce_url:
            raise ImproperlyConfigured(
                "Configure IAM_CLIENT_ENFORCE_URL or IAM_CLIENT_BASE_URL."
            )

        body = json.dumps(
            {
                "checks": [
                    {
                        "object": operation.resource,
                        "action": operation.action,
                        "context": operation.context,
                    }
                    for operation in operations
                ]
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            self.enforce_url,
            data=body,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise IAMServiceError("IAM service rejected the enforcement request.") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise IAMServiceError("IAM service is unavailable.") from exc
        except json.JSONDecodeError as exc:
            raise IAMServiceError("IAM service returned invalid JSON.") from exc

        results = payload.get("results")
        if not isinstance(results, list):
            raise IAMServiceError("IAM service response did not include results.")
        if len(results) != len(operations):
            raise IAMServiceError("IAM service returned the wrong number of results.")

        return results

    def assume_role(self, token, principal_type, name, duration_seconds=None):
        if not self.assume_role_url:
            raise ImproperlyConfigured(
                "Configure IAM_CLIENT_ASSUME_ROLE_URL or IAM_CLIENT_BASE_URL."
            )

        payload = {
            "principal_type": principal_type,
            "name": name,
        }
        if duration_seconds is not None:
            payload["duration_seconds"] = duration_seconds

        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.assume_role_url,
            data=body,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                response_payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise IAMServiceError("IAM service rejected the assume-role request.") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise IAMServiceError("IAM service is unavailable.") from exc
        except json.JSONDecodeError as exc:
            raise IAMServiceError("IAM service returned invalid JSON.") from exc

        if not isinstance(response_payload.get("token"), str):
            raise IAMServiceError("IAM service response did not include a token.")
        if response_payload.get("token_type") != "Bearer":
            raise IAMServiceError("IAM service response did not include a bearer token.")

        return response_payload


def assume_role(token, principal_type, name, duration_seconds=None, client=None):
    client = client or IAMServiceClient()
    return client.assume_role(token, principal_type, name, duration_seconds)
