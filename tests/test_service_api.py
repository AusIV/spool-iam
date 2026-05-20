import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

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

    @override_settings(IAM_ASSUME_ROLE_MAX_TTL_SECONDS=900)
    def test_assume_role_issues_token_for_target_principal(self):
        target_user = get_user_model().objects.create_user(
            username="Target",
            password="password",
        )
        target_principal = Principal.objects.create(
            principal_type=Principal.USER,
            user=target_user,
            name="Target",
        )
        target_role = Role.objects.create(name="target-reader")
        target_policy = Policy.objects.create(
            name="target-reader",
            document={
                "Version": "0",
                "Statements": [
                    {
                        "Actions": ["document:View"],
                        "Effect": "Allow",
                        "Resource": "document:TargetOnly",
                    }
                ],
            },
        )
        RolePolicy.objects.create(role=target_role, policy=target_policy)
        PrincipalRole.objects.create(principal=target_principal, role=target_role)
        assume_role = Role.objects.create(name="target-assumer")
        assume_policy = Policy.objects.create(
            name="target-assumer",
            document={
                "Version": "0",
                "Statements": [
                    {
                        "Actions": ["iam:AssumeRole"],
                        "Effect": "Allow",
                        "Resource": "iam:principal:user:Target",
                    }
                ],
            },
        )
        RolePolicy.objects.create(role=assume_role, policy=assume_policy)
        PrincipalRole.objects.create(principal=self.principal, role=assume_role)
        token = self.client.post(
            "/api/session/authenticate/",
            {"username": "UserC", "password": "password"},
            content_type="application/json",
        ).json()["token"]

        response = self.client.post(
            "/api/session/assume-role/",
            {
                "principal_type": "user",
                "name": "Target",
                "duration_seconds": 300,
            },
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

        assert response.status_code == 200
        body = response.json()
        assert body["token_type"] == "Bearer"
        assert body["expires_in"] == 300
        assert body["principal"]["name"] == "Target"
        assert body["actor"]["name"] == "UserC"
        payload = jwt.decode(
            body["token"],
            settings.IAM_JWT_PUBLIC_KEY,
            algorithms=["RS256"],
            issuer="django-iam",
            options={"verify_aud": False},
        )
        assert payload["typ"] == "assumed_session"
        assert payload["sub"] == str(target_user.pk)
        assert payload["principal"] == {"type": "user", "name": "Target"}
        assert payload["actor"]["sub"] == str(self.user.pk)

        enforce_response = self.client.post(
            "/api/enforce/",
            {
                "checks": [
                    {"object": "document:TargetOnly", "action": "document:View"},
                    {"object": "issue:ProjectA:IssueB", "action": "issue:View"},
                ]
            },
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {body['token']}",
        )

        assert enforce_response.status_code == 200
        assert enforce_response.json()["results"] == [
            {"allowed": True, "reason": "allowed"},
            {
                "allowed": False,
                "reason": "missing_allow",
                "error": (
                    "Permission denied for action 'issue:View' on resource "
                    "'issue:ProjectA:IssueB': missing required permission(s): "
                    "issue:View on issue:ProjectA:IssueB."
                ),
            },
        ]
        assumed_audit = AuditLog.objects.filter(action="document:View").get()
        assert assumed_audit.principal == target_principal
        assert assumed_audit.user == target_user
        assert assumed_audit.actor_principal == self.principal
        assert assumed_audit.actor_user == self.user

    def test_assume_role_requires_policy_permission(self):
        target_user = get_user_model().objects.create_user(username="Target")
        Principal.objects.create(
            principal_type=Principal.USER,
            user=target_user,
            name="Target",
        )
        token = self.client.post(
            "/api/session/authenticate/",
            {"username": "UserC", "password": "password"},
            content_type="application/json",
        ).json()["token"]

        response = self.client.post(
            "/api/session/assume-role/",
            {"principal_type": "user", "name": "Target"},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

        assert response.status_code == 403
        assert response.json()["error"] == "permission_denied"

    @override_settings(IAM_ASSUME_ROLE_MAX_TTL_SECONDS=60)
    def test_assume_role_rejects_duration_above_cap(self):
        token = self.client.post(
            "/api/session/authenticate/",
            {"username": "UserC", "password": "password"},
            content_type="application/json",
        ).json()["token"]

        response = self.client.post(
            "/api/session/assume-role/",
            {
                "principal_type": "user",
                "name": "Target",
                "duration_seconds": 61,
            },
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

        assert response.status_code == 400
        assert response.json()["error"] == "invalid_duration"

    def test_assumed_token_cannot_assume_role_again(self):
        target_user = get_user_model().objects.create_user(username="Target")
        target_principal = Principal.objects.create(
            principal_type=Principal.USER,
            user=target_user,
            name="Target",
        )
        assume_role = Role.objects.create(name="target-assumer")
        assume_policy = Policy.objects.create(
            name="target-assumer",
            document={
                "Version": "0",
                "Statements": [
                    {
                        "Actions": ["iam:AssumeRole"],
                        "Effect": "Allow",
                        "Resource": "iam:principal:user:*",
                    }
                ],
            },
        )
        RolePolicy.objects.create(role=assume_role, policy=assume_policy)
        PrincipalRole.objects.create(principal=self.principal, role=assume_role)
        PrincipalRole.objects.create(principal=target_principal, role=assume_role)
        token = self.client.post(
            "/api/session/authenticate/",
            {"username": "UserC", "password": "password"},
            content_type="application/json",
        ).json()["token"]
        assumed_token = self.client.post(
            "/api/session/assume-role/",
            {"principal_type": "user", "name": "Target"},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        ).json()["token"]

        response = self.client.post(
            "/api/session/assume-role/",
            {"principal_type": "user", "name": "UserC"},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {assumed_token}",
        )

        assert response.status_code == 403
        assert response.json()["error"] == "assumed_token_not_allowed"
