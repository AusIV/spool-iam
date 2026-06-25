from django.urls import path

from . import views

urlpatterns = [
    path("api/session/authenticate/", views.authenticate_session, name="iam-authenticate"),
    path("api/session/refresh/", views.refresh_session_view, name="iam-refresh-session"),
    path("api/session/assume-role/", views.assume_role_session, name="iam-assume-role"),
    path("api/session/public-key/", views.public_key, name="iam-public-key"),
    path("api/enforce/", views.enforce_batch, name="iam-enforce"),
    path("api/iam/users/", views.manage_users, name="iam-manage-users"),
    path("api/iam/users/<str:username>/", views.manage_user, name="iam-manage-user"),
    path("api/iam/principals/", views.manage_principals, name="iam-manage-principals"),
    path(
        "api/iam/principals/<str:principal_type>/<str:name>/",
        views.manage_principal,
        name="iam-manage-principal",
    ),
    path("api/iam/roles/", views.manage_roles, name="iam-manage-roles"),
    path("api/iam/roles/<str:name>/", views.manage_role, name="iam-manage-role"),
    path(
        "api/iam/roles/<str:name>/principals/",
        views.manage_role_principals,
        name="iam-manage-role-principals",
    ),
    path("api/iam/policies/", views.manage_policies, name="iam-manage-policies"),
    path(
        "api/iam/policies/<str:name>/",
        views.manage_policy,
        name="iam-manage-policy",
    ),
    path(
        "api/iam/principals/<str:principal_type>/<str:name>/roles/<str:role_name>/",
        views.manage_principal_role,
        name="iam-manage-principal-role",
    ),
    path(
        "api/iam/roles/<str:role_name>/policies/<str:policy_name>/",
        views.manage_role_policy,
        name="iam-manage-role-policy",
    ),
]
