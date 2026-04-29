# django-ltl-authorization

A Django application for LTL authorization with AWS IAM-style policy enforcement.

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

## Audit Log Export

Export unexported audit logs to a newline-delimited JSON file:

```bash
python manage.py export_audit_logs /secure/backups/iam-audit-logs.jsonl
```

The command writes unexported records to the file, then marks those records with
`exported_at` and `export_path`.

After confirming the exported file has been securely backed up, delete only
previously exported records:

```bash
python manage.py delete_exported_audit_logs
```

Preview the deletion count without deleting records:

```bash
python manage.py delete_exported_audit_logs --dry-run
```
