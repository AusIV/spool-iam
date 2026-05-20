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

## Docker

Build the IAM service image:

```bash
docker build -t django-iam-service .
```

Run the service with a SQLite database stored on a mounted volume:

```bash
docker run --rm -p 8000:8000 \
  -v iam-data:/data \
  -e DJANGO_SECRET_KEY="<random-secret>" \
  -e DJANGO_ALLOWED_HOSTS="localhost,127.0.0.1" \
  -e IAM_JWT_PRIVATE_KEY="$IAM_JWT_PRIVATE_KEY" \
  -e IAM_JWT_PUBLIC_KEY="$IAM_JWT_PUBLIC_KEY" \
  django-iam-service
```

The container runs `python manage.py migrate --noinput` before starting Gunicorn.
Create admin users or seed IAM data with one-off management commands against the
same volume:

```bash
docker run --rm -it -v iam-data:/data \
  -e DJANGO_SECRET_KEY="<random-secret>" \
  -e IAM_JWT_PRIVATE_KEY="$IAM_JWT_PRIVATE_KEY" \
  -e IAM_JWT_PUBLIC_KEY="$IAM_JWT_PUBLIC_KEY" \
  django-iam-service python manage.py createsuperuser
```

To use Postgres instead of SQLite, point Django at the Postgres backend and
provide the connection settings. The Docker image includes the `psycopg` driver.

```bash
docker run --rm -p 8000:8000 \
  -e DJANGO_SECRET_KEY="<random-secret>" \
  -e DJANGO_ALLOWED_HOSTS="iam.example.com" \
  -e DJANGO_DB_ENGINE="django.db.backends.postgresql" \
  -e DJANGO_DB_NAME="iam" \
  -e DJANGO_DB_USER="iam" \
  -e DJANGO_DB_PASSWORD="<database-password>" \
  -e DJANGO_DB_HOST="postgres.example.com" \
  -e DJANGO_DB_PORT="5432" \
  -e IAM_JWT_PRIVATE_KEY="$IAM_JWT_PRIVATE_KEY" \
  -e IAM_JWT_PUBLIC_KEY="$IAM_JWT_PUBLIC_KEY" \
  django-iam-service
```

Required environment variables for a usable deployment:

| Variable | Description |
| --- | --- |
| `DJANGO_SECRET_KEY` | Django signing secret. Set this to a unique high-entropy value. |
| `DJANGO_ALLOWED_HOSTS` | Comma-separated hostnames the service may answer for, such as `iam.example.com,localhost`. |
| `IAM_JWT_PRIVATE_KEY` | Private key used to sign session JWTs. Required by `/api/session/authenticate/`. |
| `IAM_JWT_PUBLIC_KEY` | Public key used to verify session JWTs. Required by `/api/enforce/` and `/api/session/public-key/`. |

Optional environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `PORT` | `8000` | Port Gunicorn binds inside the container. |
| `WEB_CONCURRENCY` | `2` | Number of Gunicorn worker processes. |
| `DJANGO_DEBUG` | `0` in Docker | Set to `1` only for local debugging. |
| `DJANGO_DB_ENGINE` | `django.db.backends.sqlite3` | Django database backend engine. |
| `DJANGO_DB_NAME` | `/data/db.sqlite3` in Docker | Database name or SQLite path. Mount `/data` to persist the default SQLite database. |
| `DJANGO_DB_USER` | unset | Database username. Required for Postgres unless your deployment uses another authentication method. |
| `DJANGO_DB_PASSWORD` | unset | Database password. Required for password-authenticated Postgres connections. |
| `DJANGO_DB_HOST` | unset | Database host. Set this for Postgres, for example `postgres.example.com`. |
| `DJANGO_DB_PORT` | unset | Database port. Use `5432` for the default Postgres port. |
| `IAM_JWT_ALGORITHM` | `RS256` | JWT signing algorithm. |
| `IAM_JWT_ISSUER` | `django-iam` | Expected token issuer. |
| `IAM_JWT_AUDIENCE` | unset | Optional JWT audience. |
| `IAM_JWT_KEY_ID` | unset | Optional JWT `kid` header value. |
| `IAM_JWT_TTL_SECONDS` | `3600` | Session token lifetime in seconds. |
| `IAM_ASSUME_ROLE_MAX_TTL_SECONDS` | `IAM_JWT_TTL_SECONDS` | Maximum lifetime for assumed-role tokens. |

Multiline JWT keys can be provided as normal multiline environment values or with
newlines escaped as `\n`; the service converts escaped newlines at startup.

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

Assume another principal after authenticating:

```bash
curl -s http://127.0.0.1:8000/api/session/assume-role/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <jwt>" \
  -d '{"principal_type":"user","name":"UserB","duration_seconds":900}'
```

The caller must be allowed to perform `iam:AssumeRole` on the target principal
resource, for example `iam:principal:user:UserB`. Assumed-role tokens use
`typ: "assumed_session"`, enforce permissions as the target principal, and carry
actor claims identifying the original caller. Assumed tokens cannot be used to
assume another principal.

The response contains:

```json
{
  "token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 900,
  "principal": {"id": 2, "principal_type": "user", "name": "UserB"},
  "actor": {"id": 1, "principal_type": "user", "name": "alice"}
}
```

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

Application developers and coding agents integrating ltl-IAM checks should use
the separate [client guide](CLIENT.md). It focuses on adding permission checks to
an ltl-IAM permissioned application without covering service operation.

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
For assumed-role tokens, audit rows keep `principal` and `user` as the effective
target identity and populate `actor_principal` and `actor_user` with the original
caller.

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
