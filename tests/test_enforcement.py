from types import SimpleNamespace

from django.contrib.auth import get_user_model
from django.test import TestCase

from django_iam.enforcement import enforce
from django_iam.exceptions import MissingContextValue, PermissionDenied
from django_iam.models import AuditLog, Policy, Principal, PrincipalRole, Role, RolePolicy


class EnforceTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="UserC")
        self.principal = Principal.objects.create(
            principal_type=Principal.USER,
            user=self.user,
            name="UserC",
        )
        self.role = Role.objects.create(name="issue-commenter")
        self.policy = Policy.objects.create(
            name="comments",
            document={
                "Version": "0",
                "Statements": [
                    {
                        "Actions": ["issue:Create", "issue:View", "comment:Create"],
                        "Effect": "Allow",
                        "Resource": "*",
                    },
                    {
                        "Actions": ["comment:Edit", "comment:Delete"],
                        "Effect": "Allow",
                        "Resource": "comment:*:{principalName}:*",
                    },
                    {
                        "Actions": ["issue:View"],
                        "Effect": "Deny",
                        "Resource": "issue:SecretAdminProject:*",
                    },
                ],
            },
        )
        RolePolicy.objects.create(role=self.role, policy=self.policy)
        PrincipalRole.objects.create(principal=self.principal, role=self.role)
        self.request = SimpleNamespace(user=self.user)

    def test_allows_matching_action_resource_and_context(self):
        assert enforce(
            self.request,
            "comment:ProjectA:IssueB:UserC:0",
            "comment:Edit",
            context={"principalName": "UserC"},
        )

        audit = AuditLog.objects.get()
        assert audit.allowed is True
        assert audit.reason == "allowed"

    def test_explicit_deny_overrides_allow(self):
        with self.assertRaises(PermissionDenied):
            enforce(self.request, "issue:SecretAdminProject:IssueQ", "issue:View")

        audit = AuditLog.objects.get()
        assert audit.allowed is False
        assert audit.reason == "explicit_deny"

    def test_missing_allow_reports_required_permission(self):
        with self.assertRaises(PermissionDenied) as exc:
            enforce(self.request, "comment:ProjectA:IssueB:UserD:0", "comment:Archive")

        assert "comment:Archive on comment:ProjectA:IssueB:UserD:0" in str(exc.exception)
        audit = AuditLog.objects.get()
        assert audit.allowed is False
        assert audit.reason == "missing_allow"

    def test_policy_is_cached_on_request(self):
        enforce(self.request, "issue:ProjectA:IssueB", "issue:View")

        RolePolicy.objects.filter(role=self.role).delete()

        assert enforce(self.request, "issue:ProjectA:IssueC", "issue:View")
        assert AuditLog.objects.count() == 2

    def test_missing_context_value_raises_clear_error(self):
        with self.assertRaises(MissingContextValue):
            enforce(self.request, "comment:ProjectA:IssueB:UserC:0", "comment:Edit")

        audit = AuditLog.objects.get()
        assert audit.allowed is False
        assert audit.reason == "MissingContextValue"
