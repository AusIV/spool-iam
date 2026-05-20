from django.contrib.auth import get_user_model
from django.test import TestCase

from django_iam.models import Policy, Principal, PrincipalRole, Role, RolePolicy


class ManagementApiTests(TestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_user(
            username="Admin",
            password="password",
        )
        self.admin_principal = Principal.objects.create(
            principal_type=Principal.USER,
            user=self.admin,
            name="Admin",
        )
        self.admin_role = Role.objects.create(name="iam-admin")
        self.admin_policy = Policy.objects.create(
            name="iam-admin",
            document={
                "Version": "0",
                "Statements": [
                    {"Actions": ["iam:*"], "Effect": "Allow", "Resource": "*"}
                ],
            },
        )
        RolePolicy.objects.create(role=self.admin_role, policy=self.admin_policy)
        PrincipalRole.objects.create(principal=self.admin_principal, role=self.admin_role)
        self.token = self._authenticate("Admin")

    def test_management_api_requires_session_token(self):
        response = self.client.get("/api/iam/users/")

        assert response.status_code == 401
        assert response.json()["error"] == "missing_token"

    def test_management_api_requires_iam_permission(self):
        user = get_user_model().objects.create_user(
            username="Limited",
            password="password",
        )
        Principal.objects.create(
            principal_type=Principal.USER,
            user=user,
            name="Limited",
        )
        token = self._authenticate("Limited")

        response = self.client.get(
            "/api/iam/users/",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

        assert response.status_code == 403
        assert response.json()["error"] == "permission_denied"

    def test_list_users_uses_explicit_userlist_resource(self):
        user = get_user_model().objects.create_user(
            username="UserLister",
            password="password",
        )
        principal = Principal.objects.create(
            principal_type=Principal.USER,
            user=user,
            name="UserLister",
        )
        role = Role.objects.create(name="user-lister")
        policy = Policy.objects.create(
            name="user-lister",
            document={
                "Version": "0",
                "Statements": [
                    {
                        "Actions": ["iam:ListUsers"],
                        "Effect": "Allow",
                        "Resource": "iam:userlist",
                    },
                    {
                        "Actions": ["iam:GetUser"],
                        "Effect": "Allow",
                        "Resource": "iam:user:*",
                    },
                ],
            },
        )
        RolePolicy.objects.create(role=role, policy=policy)
        PrincipalRole.objects.create(principal=principal, role=role)
        token = self._authenticate("UserLister")

        list_response = self.client.get(
            "/api/iam/users/",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        get_response = self.client.get(
            "/api/iam/users/Admin/",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

        assert list_response.status_code == 200
        assert get_response.status_code == 200

    def test_user_wildcard_resource_does_not_grant_user_list(self):
        user = get_user_model().objects.create_user(
            username="WildcardUserReader",
            password="password",
        )
        principal = Principal.objects.create(
            principal_type=Principal.USER,
            user=user,
            name="WildcardUserReader",
        )
        role = Role.objects.create(name="wildcard-user-reader")
        policy = Policy.objects.create(
            name="wildcard-user-reader",
            document={
                "Version": "0",
                "Statements": [
                    {
                        "Actions": ["iam:ListUsers", "iam:GetUser"],
                        "Effect": "Allow",
                        "Resource": "iam:user:*",
                    }
                ],
            },
        )
        RolePolicy.objects.create(role=role, policy=policy)
        PrincipalRole.objects.create(principal=principal, role=role)
        token = self._authenticate("WildcardUserReader")

        list_response = self.client.get(
            "/api/iam/users/",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        get_response = self.client.get(
            "/api/iam/users/Admin/",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

        assert list_response.status_code == 403
        assert get_response.status_code == 200

    def test_create_user_also_creates_matching_principal(self):
        response = self.client.post(
            "/api/iam/users/",
            {
                "username": "UserC",
                "password": "secret",
                "email": "userc@example.com",
                "first_name": "User",
                "last_name": "C",
            },
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )

        assert response.status_code == 201
        user = get_user_model().objects.get(username="UserC")
        principal = Principal.objects.get(principal_type=Principal.USER, name="UserC")
        assert principal.user == user
        assert user.email == "userc@example.com"
        assert user.check_password("secret")

    def test_update_user_does_not_allow_username_change(self):
        get_user_model().objects.create_user(username="UserC")

        response = self.client.patch(
            "/api/iam/users/UserC/",
            {"username": "Other"},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )

        assert response.status_code == 400
        assert response.json()["error"] == "invalid_user"

    def test_delete_user_cascades_to_matching_principal(self):
        user = get_user_model().objects.create_user(username="UserC")
        Principal.objects.create(
            principal_type=Principal.USER,
            user=user,
            name="UserC",
        )

        response = self.client.delete(
            "/api/iam/users/UserC/",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )

        assert response.status_code == 200
        assert not get_user_model().objects.filter(username="UserC").exists()
        assert not Principal.objects.filter(name="UserC").exists()

    def test_principal_crud(self):
        user = get_user_model().objects.create_user(username="UserC")

        create_response = self.client.post(
            "/api/iam/principals/",
            {"principal_type": "user", "name": "UserC"},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        assert create_response.status_code == 201

        get_response = self.client.get(
            "/api/iam/principals/user/UserC/",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        assert get_response.status_code == 200
        assert get_response.json()["principal"]["user"]["username"] == "UserC"

        list_response = self.client.get(
            "/api/iam/principals/",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        assert list_response.status_code == 200
        assert "UserC" in [
            principal["name"] for principal in list_response.json()["principals"]
        ]

        delete_response = self.client.delete(
            "/api/iam/principals/user/UserC/",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        assert delete_response.status_code == 200
        assert not Principal.objects.filter(principal_type="user", name="UserC").exists()
        assert get_user_model().objects.filter(username=user.username).exists()

    def test_service_principal_crud_without_user(self):
        create_response = self.client.post(
            "/api/iam/principals/",
            {"principal_type": "service", "name": "report-worker"},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        assert create_response.status_code == 201
        assert create_response.json()["principal"]["user"] is None

        principal = Principal.objects.get(
            principal_type=Principal.SERVICE,
            name="report-worker",
        )
        assert principal.user is None

        get_response = self.client.get(
            "/api/iam/principals/service/report-worker/",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        assert get_response.status_code == 200
        assert get_response.json()["principal"]["user"] is None

        update_response = self.client.patch(
            "/api/iam/principals/service/report-worker/",
            {},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        assert update_response.status_code == 200
        assert update_response.json()["principal"]["user"] is None

    def test_service_principal_rejects_user_linkage(self):
        user = get_user_model().objects.create_user(username="ServiceUser")

        create_response = self.client.post(
            "/api/iam/principals/",
            {
                "principal_type": "service",
                "name": "report-worker",
                "user_id": user.pk,
            },
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )

        assert create_response.status_code == 400
        assert create_response.json()["error"] == "invalid_principal"

    def test_role_crud(self):
        create_response = self.client.post(
            "/api/iam/roles/",
            {"name": "issue-commenter"},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        assert create_response.status_code == 201

        update_response = self.client.patch(
            "/api/iam/roles/issue-commenter/",
            {"name": "issue-editor"},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        assert update_response.status_code == 200
        assert update_response.json()["role"]["name"] == "issue-editor"

        list_response = self.client.get(
            "/api/iam/roles/",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        assert list_response.status_code == 200
        assert "issue-editor" in [role["name"] for role in list_response.json()["roles"]]

        delete_response = self.client.delete(
            "/api/iam/roles/issue-editor/",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        assert delete_response.status_code == 200
        assert not Role.objects.filter(name="issue-editor").exists()

    def test_policy_crud_validates_document_shape(self):
        invalid_response = self.client.post(
            "/api/iam/policies/",
            {"name": "bad", "document": {"Version": "0"}},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        assert invalid_response.status_code == 400
        assert invalid_response.json()["error"] == "invalid_policy"

        create_response = self.client.post(
            "/api/iam/policies/",
            {
                "name": "comments",
                "document": {
                    "Version": "0",
                    "Statements": [
                        {
                            "Actions": ["comment:Edit"],
                            "Effect": "Allow",
                            "Resource": "*",
                        }
                    ],
                },
            },
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        assert create_response.status_code == 201

        update_response = self.client.patch(
            "/api/iam/policies/comments/",
            {
                "document": {
                    "Version": "0",
                    "Statements": [
                        {
                            "Actions": ["comment:Delete"],
                            "Effect": "Allow",
                            "Resource": "*",
                        }
                    ],
                }
            },
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        assert update_response.status_code == 200
        assert update_response.json()["policy"]["document"]["Statements"][0][
            "Actions"
        ] == ["comment:Delete"]

        delete_response = self.client.delete(
            "/api/iam/policies/comments/",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        assert delete_response.status_code == 200
        assert not Policy.objects.filter(name="comments").exists()

    def test_principal_role_and_role_policy_links_are_idempotent(self):
        user = get_user_model().objects.create_user(username="UserC")
        principal = Principal.objects.create(
            principal_type=Principal.USER,
            user=user,
            name="UserC",
        )
        role = Role.objects.create(name="issue-commenter")
        policy = Policy.objects.create(
            name="comments",
            document={"Version": "0", "Statements": []},
        )

        assign_response = self.client.put(
            f"/api/iam/principals/user/{principal.name}/roles/{role.name}/",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        duplicate_assign_response = self.client.put(
            f"/api/iam/principals/user/{principal.name}/roles/{role.name}/",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        attach_response = self.client.put(
            f"/api/iam/roles/{role.name}/policies/{policy.name}/",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )

        assert assign_response.status_code == 201
        assert duplicate_assign_response.status_code == 201
        assert attach_response.status_code == 201
        assert PrincipalRole.objects.filter(principal=principal, role=role).count() == 1
        assert RolePolicy.objects.filter(role=role, policy=policy).count() == 1

        unassign_response = self.client.delete(
            f"/api/iam/principals/user/{principal.name}/roles/{role.name}/",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        duplicate_unassign_response = self.client.delete(
            f"/api/iam/principals/user/{principal.name}/roles/{role.name}/",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        detach_response = self.client.delete(
            f"/api/iam/roles/{role.name}/policies/{policy.name}/",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )

        assert unassign_response.status_code == 200
        assert duplicate_unassign_response.status_code == 200
        assert detach_response.status_code == 200

    def test_list_principals_by_role(self):
        role = Role.objects.create(name="issue-commenter")
        included_user = get_user_model().objects.create_user(username="Included")
        included_principal = Principal.objects.create(
            principal_type=Principal.USER,
            user=included_user,
            name="Included",
        )
        other_user = get_user_model().objects.create_user(username="Other")
        Principal.objects.create(
            principal_type=Principal.USER,
            user=other_user,
            name="Other",
        )
        PrincipalRole.objects.create(principal=included_principal, role=role)

        response = self.client.get(
            "/api/iam/roles/issue-commenter/principals/",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )

        assert response.status_code == 200
        assert response.json()["role"] == "issue-commenter"
        assert [principal["name"] for principal in response.json()["principals"]] == [
            "Included"
        ]

    def test_list_principals_by_role_requires_list_principals_scope(self):
        user = get_user_model().objects.create_user(
            username="ScopedRoleReader",
            password="password",
        )
        principal = Principal.objects.create(
            principal_type=Principal.USER,
            user=user,
            name="ScopedRoleReader",
        )
        role = Role.objects.create(name="scoped-role-reader")
        policy = Policy.objects.create(
            name="scoped-role-reader",
            document={
                "Version": "0",
                "Statements": [
                    {
                        "Actions": ["iam:ListPrincipals"],
                        "Effect": "Allow",
                        "Resource": "iam:role-principallist:allowed-role",
                    },
                    {
                        "Actions": ["iam:GetRole"],
                        "Effect": "Allow",
                        "Resource": "iam:role:denied-role",
                    }
                ],
            },
        )
        RolePolicy.objects.create(role=role, policy=policy)
        PrincipalRole.objects.create(principal=principal, role=role)
        Role.objects.create(name="allowed-role")
        Role.objects.create(name="denied-role")
        token = self._authenticate("ScopedRoleReader")

        allowed_response = self.client.get(
            "/api/iam/roles/allowed-role/principals/",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        denied_response = self.client.get(
            "/api/iam/roles/denied-role/principals/",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

        assert allowed_response.status_code == 200
        assert denied_response.status_code == 403

    def test_scoped_policy_can_limit_management_to_one_role(self):
        user = get_user_model().objects.create_user(
            username="RoleManager",
            password="password",
        )
        principal = Principal.objects.create(
            principal_type=Principal.USER,
            user=user,
            name="RoleManager",
        )
        role = Role.objects.create(name="limited-manager")
        policy = Policy.objects.create(
            name="limited-manager",
            document={
                "Version": "0",
                "Statements": [
                    {
                        "Actions": ["iam:GetRole"],
                        "Effect": "Allow",
                        "Resource": "iam:role:allowed-role",
                    }
                ],
            },
        )
        RolePolicy.objects.create(role=role, policy=policy)
        PrincipalRole.objects.create(principal=principal, role=role)
        Role.objects.create(name="allowed-role")
        Role.objects.create(name="denied-role")
        token = self._authenticate("RoleManager")

        allowed_response = self.client.get(
            "/api/iam/roles/allowed-role/",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        denied_response = self.client.get(
            "/api/iam/roles/denied-role/",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

        assert allowed_response.status_code == 200
        assert denied_response.status_code == 403

    def _authenticate(self, username):
        response = self.client.post(
            "/api/session/authenticate/",
            {"username": username, "password": "password"},
            content_type="application/json",
        )
        assert response.status_code == 200
        return response.json()["token"]
