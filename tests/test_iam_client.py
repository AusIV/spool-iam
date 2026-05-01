import json

from django.http import JsonResponse
from django.test import RequestFactory, TestCase, override_settings

from django_iam_client.enforcement import RequestEnforcement
from django_iam_client.exceptions import EnforcementDenied
from django_iam_client.middleware import IAMEnforcementMiddleware


FAKE_CALLS = []
FAKE_RESULTS = []


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


class IAMClientTests(TestCase):
    def setUp(self):
        FAKE_CALLS.clear()
        FAKE_RESULTS.clear()
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
