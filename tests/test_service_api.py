import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase

from django_iam.models import AuditLog, Policy, Principal, PrincipalRole, Role, RolePolicy


class ServiceApiTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="UserC",
            password="password",
        )
        self.principal = Principal.objects.create(
            principal_type=Principal.USER,
            user=self.user,
            name="UserC",
        )
        role = Role.objects.create(name="issue-commenter")
        policy = Policy.objects.create(
            name="comments",
            document={
                "Version": "0",
                "Statements": [
                    {
                        "Actions": ["issue:View", "comment:Edit"],
                        "Effect": "Allow",
                        "Resource": "*",
                    },
                    {
                        "Actions": ["issue:View"],
                        "Effect": "Deny",
                        "Resource": "issue:SecretAdminProject:*",
                    },
                ],
            },
        )
        RolePolicy.objects.create(role=role, policy=policy)
        PrincipalRole.objects.create(principal=self.principal, role=role)

    def test_authenticate_issues_asymmetric_session_token(self):
        response = self.client.post(
            "/api/session/authenticate/",
            {"username": "UserC", "password": "password"},
            content_type="application/json",
        )

        assert response.status_code == 200
        token = response.json()["token"]
        payload = jwt.decode(
            token,
            settings.IAM_JWT_PUBLIC_KEY,
            algorithms=["RS256"],
            issuer="django-iam",
            options={"verify_aud": False},
        )
        assert payload["sub"] == str(self.user.pk)
        assert payload["typ"] == "session"

    def test_batch_enforce_returns_ordered_decisions(self):
        token = self.client.post(
            "/api/session/authenticate/",
            {"username": "UserC", "password": "password"},
            content_type="application/json",
        ).json()["token"]

        response = self.client.post(
            "/api/enforce/",
            {
                "token": token,
                "checks": [
                    {"object": "issue:ProjectA:IssueB", "action": "issue:View"},
                    {
                        "object": "issue:SecretAdminProject:IssueQ",
                        "action": "issue:View",
                    },
                    {
                        "object": "comment:ProjectA:IssueB:UserC:0",
                        "action": "comment:Archive",
                    },
                ],
            },
            content_type="application/json",
        )

        assert response.status_code == 200
        assert response.json()["results"] == [
            {"allowed": True, "reason": "allowed"},
            {
                "allowed": False,
                "reason": "explicit_deny",
                "error": (
                    "Permission denied for action 'issue:View' on resource "
                    "'issue:SecretAdminProject:IssueQ': matched an explicit Deny statement."
                ),
            },
            {
                "allowed": False,
                "reason": "missing_allow",
                "error": (
                    "Permission denied for action 'comment:Archive' on resource "
                    "'comment:ProjectA:IssueB:UserC:0': missing required permission(s): "
                    "comment:Archive on comment:ProjectA:IssueB:UserC:0."
                ),
            },
        ]
        assert AuditLog.objects.count() == 3

    def test_batch_enforce_accepts_authorization_header(self):
        token = self.client.post(
            "/api/session/authenticate/",
            {"username": "UserC", "password": "password"},
            content_type="application/json",
        ).json()["token"]

        response = self.client.post(
            "/api/enforce/",
            {"checks": [{"object": "issue:ProjectA:IssueB", "action": "issue:View"}]},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

        assert response.status_code == 200
        assert response.json()["results"] == [{"allowed": True, "reason": "allowed"}]

    def test_batch_enforce_rejects_invalid_token(self):
        response = self.client.post(
            "/api/enforce/",
            {"token": "not-a-token", "checks": []},
            content_type="application/json",
        )

        assert response.status_code == 401
        assert response.json()["error"] == "invalid_token"
