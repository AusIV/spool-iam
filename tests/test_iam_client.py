import json
import urllib.error
from unittest.mock import patch

from django.core.exceptions import ImproperlyConfigured
from django.http import JsonResponse
from django.test import RequestFactory, TestCase, override_settings

from django_iam_client.client import IAMServiceClient
from django_iam_client.enforcement import RequestEnforcement
from django_iam_client.exceptions import EnforcementDenied, IAMServiceError
from django_iam_client.middleware import IAMEnforcementMiddleware


FAKE_CALLS = []
FAKE_RESULTS = []
URLLIB_CALLS = []


class FakeIAMClient:
    def enforce(self, token, operations):
        FAKE_CALLS.append(
            {
                "token": token,
                "operations": [
                    {
                        "mode": operation.mode,
                        "object": operation.resource,
                        "action": operation.action,
                        "context": operation.context,
                    }
                    for operation in operations
                ],
            }
        )
        if FAKE_RESULTS:
            return FAKE_RESULTS.pop(0)
        return [{"allowed": True} for _ in operations]

    def assume_role(self, token, principal_type, name, duration_seconds=None):
        FAKE_CALLS.append(
            {
                "token": token,
                "principal_type": principal_type,
                "name": name,
                "duration_seconds": duration_seconds,
            }
        )
        return {
            "token": "assumed-token",
            "token_type": "Bearer",
            "expires_in": duration_seconds,
            "principal": {"principal_type": principal_type, "name": name},
        }


class FakeHTTPResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self):
        return self.payload


class IAMClientTests(TestCase):
    def setUp(self):
        FAKE_CALLS.clear()
        FAKE_RESULTS.clear()
        URLLIB_CALLS.clear()
        self.factory = RequestFactory()

    def _request(self):
        return self.factory.get("/", HTTP_AUTHORIZATION="Bearer session-token")

    def test_read_is_recorded_and_immediately_enforced(self):
        request = self._request()
        request.enforce = RequestEnforcement(request, client=FakeIAMClient())

        assert request.enforce.read(
            "comment:ProjectA:IssueB:UserC:0",
            "comment:View",
            {"principalName": "UserC"},
        )

        assert len(request.enforce.reads) == 1
        assert FAKE_CALLS == [
            {
                "token": "session-token",
                "operations": [
                    {
                        "mode": "read",
                        "object": "comment:ProjectA:IssueB:UserC:0",
                        "action": "comment:View",
                        "context": {"principalName": "UserC"},
                    }
                ],
            }
        ]

    def test_write_verifies_accumulated_operations(self):
        request = self._request()
        request.enforce = RequestEnforcement(request, client=FakeIAMClient())

        request.enforce.read("issue:ProjectA:IssueB", "issue:View")
        request.enforce.write("comment:ProjectA:IssueB:UserC:0", "comment:Create")

        assert FAKE_CALLS[-1]["operations"] == [
            {
                "mode": "read",
                "object": "issue:ProjectA:IssueB",
                "action": "issue:View",
                "context": {},
            },
            {
                "mode": "write",
                "object": "comment:ProjectA:IssueB:UserC:0",
                "action": "comment:Create",
                "context": {},
            },
        ]

    def test_denial_reports_failed_actions_only(self):
        request = self._request()
        request.enforce = RequestEnforcement(request, client=FakeIAMClient())
        FAKE_RESULTS.append([{"allowed": False, "reason": "missing_allow"}])

        with self.assertRaises(EnforcementDenied) as exc:
            request.enforce.read("private-object-id", "document:View")

        assert exc.exception.failed_actions == ["document:View"]
        assert "private-object-id" not in str(exc.exception)

    def test_user_batch_executes_independently_and_returns_ordered_results(self):
        request = self._request()
        request.enforce = RequestEnforcement(request, client=FakeIAMClient())
        FAKE_RESULTS.append(
            [
                {"allowed": True, "reason": "allowed"},
                {"allowed": False, "reason": "missing_allow"},
            ]
        )

        batch = request.enforce.batch()
        assert batch.read("issue:ProjectA:IssueA", "issue:View") is batch
        assert batch.read("issue:ProjectA:IssueB", "issue:View") is batch

        results = batch.execute()

        assert results == [
            {"allowed": True, "reason": "allowed"},
            {"allowed": False, "reason": "missing_allow"},
        ]
        assert request.enforce.operations == []
        assert FAKE_CALLS == [
            {
                "token": "session-token",
                "operations": [
                    {
                        "mode": "read",
                        "object": "issue:ProjectA:IssueA",
                        "action": "issue:View",
                        "context": {},
                    },
                    {
                        "mode": "read",
                        "object": "issue:ProjectA:IssueB",
                        "action": "issue:View",
                        "context": {},
                    },
                ],
            }
        ]

    def test_user_batch_verify_raises_for_denied_results(self):
        request = self._request()
        request.enforce = RequestEnforcement(request, client=FakeIAMClient())
        FAKE_RESULTS.append([{"allowed": False, "reason": "missing_allow"}])

        batch = request.enforce.batch()
        batch.write("comment:ProjectA:IssueB:UserC:0", "comment:Create")

        with self.assertRaises(EnforcementDenied) as exc:
            batch.verify()

        assert exc.exception.failed_actions == ["comment:Create"]

    def test_request_enforcement_assume_role_returns_assumed_token_payload(self):
        request = self._request()
        request.enforce = RequestEnforcement(request, client=FakeIAMClient())

        payload = request.enforce.assume_role("user", "Target", duration_seconds=900)

        assert payload["token"] == "assumed-token"
        assert payload["principal"] == {"principal_type": "user", "name": "Target"}
        assert request.enforce.operations == []
        assert FAKE_CALLS == [
            {
                "token": "session-token",
                "principal_type": "user",
                "name": "Target",
                "duration_seconds": 900,
            }
        ]

    @override_settings(IAM_CLIENT_CLASS="tests.test_iam_client.FakeIAMClient")
    def test_middleware_exit_verifies_accumulated_operations(self):
        def view(request):
            request.enforce.read("issue:ProjectA:IssueB", "issue:View")
            return JsonResponse({"ok": True})

        request = self._request()
        response = IAMEnforcementMiddleware(view)(request)

        assert response.status_code == 200
        assert len(FAKE_CALLS) == 2
        assert FAKE_CALLS[1]["operations"] == [
            {
                "mode": "read",
                "object": "issue:ProjectA:IssueB",
                "action": "issue:View",
                "context": {},
            }
        ]

    @override_settings(IAM_CLIENT_CLASS="tests.test_iam_client.FakeIAMClient")
    def test_middleware_returns_denial_without_request_details(self):
        FAKE_RESULTS.append([{"allowed": True}])
        FAKE_RESULTS.append([{"allowed": False, "reason": "missing_allow"}])

        def view(request):
            request.enforce.read("private-object-id", "document:View")
            return JsonResponse({"secret": "do-not-return"})

        request = self._request()
        response = IAMEnforcementMiddleware(view)(request)

        assert response.status_code == 403
        assert json.loads(response.content.decode("utf-8")) == {
            "error": "permission_denied",
            "failed_actions": ["document:View"],
        }

    @override_settings(IAM_CLIENT_CLASS="tests.test_iam_client.FakeIAMClient")
    def test_middleware_does_not_reverify_user_batch_operations(self):
        FAKE_RESULTS.append(
            [
                {"allowed": True, "reason": "allowed"},
                {"allowed": False, "reason": "missing_allow"},
            ]
        )

        def view(request):
            batch = request.enforce.batch()
            batch.read("issue:ProjectA:IssueA", "issue:View")
            batch.read("issue:ProjectA:IssueB", "issue:View")
            results = batch.execute()
            return JsonResponse({"visible": [result["allowed"] for result in results]})

        request = self._request()
        response = IAMEnforcementMiddleware(view)(request)

        assert response.status_code == 200
        assert json.loads(response.content.decode("utf-8")) == {
            "visible": [True, False],
        }
        assert len(FAKE_CALLS) == 1

    @override_settings(IAM_CLIENT_BASE_URL="https://iam.example.com")
    def test_client_derives_assume_role_url_from_base_url(self):
        client = IAMServiceClient()

        assert client.enforce_url == "https://iam.example.com/api/enforce/"
        assert client.assume_role_url == "https://iam.example.com/api/session/assume-role/"
        assert client.refresh_url == "https://iam.example.com/api/session/refresh/"

    @override_settings(
        IAM_CLIENT_BASE_URL="https://iam.example.com",
        IAM_CLIENT_ASSUME_ROLE_URL="https://iam.internal/assume/",
    )
    def test_client_allows_explicit_assume_role_url(self):
        client = IAMServiceClient()

        assert client.assume_role_url == "https://iam.internal/assume/"

    @override_settings(
        IAM_CLIENT_ENFORCE_URL="",
        IAM_CLIENT_ASSUME_ROLE_URL="https://iam.example.com/api/session/assume-role/",
    )
    def test_client_can_be_configured_for_assume_role_only(self):
        client = IAMServiceClient()

        with self.assertRaises(ImproperlyConfigured):
            client.enforce("session-token", [])

    def test_assume_role_posts_target_principal_and_returns_token_payload(self):
        response_payload = {
            "token": "assumed-token",
            "token_type": "Bearer",
            "expires_in": 900,
            "principal": {"principal_type": "user", "name": "Target"},
            "actor": {"principal_type": "user", "name": "Actor"},
        }

        def fake_urlopen(request, timeout):
            URLLIB_CALLS.append(
                {
                    "url": request.full_url,
                    "method": request.get_method(),
                    "headers": dict(request.header_items()),
                    "body": json.loads(request.data.decode("utf-8")),
                    "timeout": timeout,
                }
            )
            return FakeHTTPResponse(json.dumps(response_payload).encode("utf-8"))

        client = IAMServiceClient(
            assume_role_url="https://iam.example.com/api/session/assume-role/",
            timeout=7,
        )
        with patch("urllib.request.urlopen", fake_urlopen):
            payload = client.assume_role(
                "session-token",
                "user",
                "Target",
                duration_seconds=900,
            )

        assert payload == response_payload
        assert URLLIB_CALLS == [
            {
                "url": "https://iam.example.com/api/session/assume-role/",
                "method": "POST",
                "headers": {
                    "Authorization": "Bearer session-token",
                    "Content-type": "application/json",
                    "Accept": "application/json",
                },
                "body": {
                    "principal_type": "user",
                    "name": "Target",
                    "duration_seconds": 900,
                },
                "timeout": 7,
            }
        ]

    def test_assume_role_omits_duration_when_not_supplied(self):
        def fake_urlopen(request, timeout):
            URLLIB_CALLS.append(json.loads(request.data.decode("utf-8")))
            return FakeHTTPResponse(
                json.dumps({"token": "assumed-token", "token_type": "Bearer"}).encode(
                    "utf-8"
                )
            )

        client = IAMServiceClient(
            assume_role_url="https://iam.example.com/api/session/assume-role/"
        )
        with patch("urllib.request.urlopen", fake_urlopen):
            client.assume_role("session-token", "user", "Target")

        assert URLLIB_CALLS == [{"principal_type": "user", "name": "Target"}]

    def test_assume_role_rejects_malformed_response(self):
        def fake_urlopen(request, timeout):
            return FakeHTTPResponse(json.dumps({"token_type": "Bearer"}).encode("utf-8"))

        client = IAMServiceClient(
            assume_role_url="https://iam.example.com/api/session/assume-role/"
        )

        with patch("urllib.request.urlopen", fake_urlopen):
            with self.assertRaises(IAMServiceError):
                client.assume_role("session-token", "user", "Target")

    def test_assume_role_translates_http_errors(self):
        def fake_urlopen(request, timeout):
            raise urllib.error.HTTPError(
                request.full_url,
                403,
                "Forbidden",
                hdrs=None,
                fp=None,
            )

        client = IAMServiceClient(
            assume_role_url="https://iam.example.com/api/session/assume-role/"
        )

        with patch("urllib.request.urlopen", fake_urlopen):
            with self.assertRaises(IAMServiceError):
                client.assume_role("session-token", "user", "Target")

    def test_refresh_session_posts_refresh_token_and_returns_token_payload(self):
        response_payload = {
            "token": "session-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "next-refresh-token",
            "refresh_token_expires_at": "2026-06-26T12:00:00+00:00",
            "refreshes_remaining": 63,
        }

        def fake_urlopen(request, timeout):
            URLLIB_CALLS.append(
                {
                    "url": request.full_url,
                    "method": request.get_method(),
                    "headers": dict(request.header_items()),
                    "body": json.loads(request.data.decode("utf-8")),
                    "timeout": timeout,
                }
            )
            return FakeHTTPResponse(json.dumps(response_payload).encode("utf-8"))

        client = IAMServiceClient(
            refresh_url="https://iam.example.com/api/session/refresh/",
            timeout=7,
        )
        with patch("urllib.request.urlopen", fake_urlopen):
            payload = client.refresh_session("refresh-token")

        assert payload == response_payload
        assert URLLIB_CALLS == [
            {
                "url": "https://iam.example.com/api/session/refresh/",
                "method": "POST",
                "headers": {
                    "Content-type": "application/json",
                    "Accept": "application/json",
                },
                "body": {"refresh_token": "refresh-token"},
                "timeout": 7,
            }
        ]

    def test_refresh_session_rejects_malformed_response(self):
        def fake_urlopen(request, timeout):
            return FakeHTTPResponse(json.dumps({"token_type": "Bearer"}).encode("utf-8"))

        client = IAMServiceClient(
            refresh_url="https://iam.example.com/api/session/refresh/"
        )

        with patch("urllib.request.urlopen", fake_urlopen):
            with self.assertRaises(IAMServiceError):
                client.refresh_session("refresh-token")
