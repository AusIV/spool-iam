# django-iam

A Django application for AWS IAM-style policy enforcement.

Add the app to `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    # ...
    "django_iam",
]
```

Run migrations:

```bash
python manage.py migrate django_iam
```

Create `Principal` rows for users, assign principals to `Role` rows through `PrincipalRole`, and attach JSON `Policy` rows to roles through `RolePolicy`.

Use enforcement inside views or services:

```python
from django_iam.enforcement import enforce

enforce(
    request,
    "comment:ProjectA:IssueB:UserC:0",
    "comment:Edit",
    context={"principalName": "UserC"},
)
```

`enforce()` returns `True` when authorized. It raises `django_iam.exceptions.PermissionDenied` if no matching allow exists or if any explicit deny matches. It raises `django_iam.exceptions.MissingContextValue` when a matching action statement has a `Resource` template like `{principalName}` and that value is not supplied in `context`.

Every call writes an `AuditLog` row. The cumulative policy for the request principal is cached on the request object for the life of the request.
