# django-ltl-authorization

A Django IAM service for LTL authorization with AWS IAM-style policy enforcement.

The package can still be installed as a Django app, but the repository now also
contains a runnable IAM service project. Applications authenticate users through
the IAM service, receive a minimal asymmetric JWT session token, and call the IAM
service to evaluate authorization checks instead of reading or writing IAM data
directly.

## Development Service

Create a virtual environment and install the project:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[test]"
```

Generate an RSA key pair for local JWT signing:

```bash
mkdir -p .local
openssl genrsa -out .local/iam-session.key 2048
openssl rsa -in .local/iam-session.key -pubout -out .local/iam-session.pub
export IAM_JWT_PRIVATE_KEY="$(cat .local/iam-session.key)"
export IAM_JWT_PUBLIC_KEY="$(cat .local/iam-session.pub)"
```

Run migrations and start the service:

```bash
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver 127.0.0.1:8000
```

The sample settings file is [iam_service/settings.py](iam_service/settings.py).
For production, set `DJANGO_SECRET_KEY`, database settings, allowed hosts, and
the JWT key settings through the environment. The private key should only be
available to the IAM service. Applications should use the public key from
configuration or from `GET /api/session/public-key/`.

## Service API

Authenticate with Django user credentials:

```bash
curl -s http://127.0.0.1:8000/api/session/authenticate/ \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password"}'
```

The response contains:

```json
{
  "token": "<jwt>",
  "token_type": "Bearer"
}
```

The JWT is signed with RS256 by default and contains only session metadata such
as issuer, subject user id, issued-at time, expiry, and token type. Applications
can verify it with the public key, but permission decisions should be made by the
IAM service.

Batch authorization checks:

```bash
curl -s http://127.0.0.1:8000/api/enforce/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <jwt>" \
  -d '{
    "checks": [
      {
        "object": "comment:ProjectA:IssueB:UserC:0",
        "action": "comment:Edit",
        "context": {"principalName": "UserC"}
      },
      {
        "object": "issue:SecretAdminProject:IssueQ",
        "action": "issue:View",
        "context": {}
      }
    ]
  }'
```

The response preserves request order:

```json
{
  "results": [
    {"allowed": true, "reason": "allowed"},
    {"allowed": false, "reason": "explicit_deny", "error": "..."}
  ]
}
```

Each check may use `object` or `resource`, plus `action` and optional `context`.
The endpoint also accepts `"token": "<jwt>"` in the JSON body when using an
Authorization header is inconvenient.

## Client Application

Applications that use the central IAM service can install the lightweight client
app and middleware instead of embedding the IAM database models.

```python
INSTALLED_APPS = [
    # ...
    "django_iam_client",
]

MIDDLEWARE = [
    # Authentication middleware should run before IAMEnforcementMiddleware.
    # ...
    "django_iam_client.middleware.IAMEnforcementMiddleware",
]

IAM_CLIENT_BASE_URL = "http://127.0.0.1:8000"
```

The middleware adds `request.enforce` for the lifetime of the request:

```python
def view(request):
    request.enforce.read(
        "comment:ProjectA:IssueB:UserC:0",
        "comment:View",
        {"principalName": "UserC"},
    )

    request.enforce.write(
        "comment:ProjectA:IssueB:UserC:1",
        "comment:Create",
        {"principalName": "UserC"},
    )
```

`read()` records the read operation and immediately verifies that operation with
the IAM service. `write()` records the write operation and verifies every
operation accumulated so far in a single batch call. When the response leaves the
middleware, any operations accumulated up to that point are verified again.

By default, the client forwards the incoming `Authorization: Bearer <jwt>` token
to the IAM service. Applications can set `request.iam_session_token` before
calling enforcement, or configure `IAM_CLIENT_SESSION_TOKEN_GETTER` with a dotted
function path that accepts `request` and returns the token. Use
`IAM_CLIENT_ENFORCE_URL` to point directly at the batch endpoint, or
`IAM_CLIENT_BASE_URL` to derive `/api/enforce/`.

If any enforcement fails, the middleware returns HTTP 403 with only the failed
action names:

```json
{
  "error": "permission_denied",
  "failed_actions": ["comment:Create"]
}
```

## IAM Data

Credential management uses Django's built-in user model. Authorization uses IAM
models:

1. Create Django users.
2. Create matching `Principal` rows for users.
3. Assign principals to `Role` rows through `PrincipalRole`.
4. Attach JSON `Policy` rows to roles through `RolePolicy`.

Example policy document:

```json
{
  "Version": "0",
  "Statements": [
    {
      "Actions": ["issue:View", "comment:Create"],
      "Effect": "Allow",
      "Resource": "*"
    },
    {
      "Actions": ["comment:Edit", "comment:Delete"],
      "Effect": "Allow",
      "Resource": "comment:*:*:{principalName}:*"
    }
  ]
}
```

## Embedded App Usage

If you still want to use the enforcement library inside another Django project,
add the app to `INSTALLED_APPS`:

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

## Tests

```bash
python -m pytest
```

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
