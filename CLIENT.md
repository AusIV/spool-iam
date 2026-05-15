# ltl-IAM Client Guide

This guide is for a developer or coding agent adding ltl-IAM permission checks
to an application. It assumes the IAM service already exists and that the
application is given the service URL and a user session token.

Use the lightweight client package in application code. Do not read or write IAM
policy data from the application directly; ask the IAM service for authorization
decisions through the client middleware.

## Django Setup

Add the client app and middleware:

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

IAM_CLIENT_BASE_URL = "https://iam.example.com"
```

Use `IAM_CLIENT_ENFORCE_URL` instead of `IAM_CLIENT_BASE_URL` when the
application is given the full enforcement endpoint:

```python
IAM_CLIENT_ENFORCE_URL = "https://iam.example.com/api/enforce/"
```

Optional client settings:

| Setting | Default | Purpose |
| --- | --- | --- |
| `IAM_CLIENT_BASE_URL` | unset | Base IAM service URL. The client derives `/api/enforce/`. |
| `IAM_CLIENT_ENFORCE_URL` | unset | Full enforcement endpoint. Takes precedence over `IAM_CLIENT_BASE_URL`. |
| `IAM_CLIENT_TIMEOUT_SECONDS` | `5` | Timeout for IAM service calls. |
| `IAM_CLIENT_SESSION_TOKEN_GETTER` | unset | Dotted function path for custom token lookup. |
| `IAM_CLIENT_CLASS` | unset | Dotted class path for replacing the service client, usually in tests. |

## Session Token

By default, the client forwards the incoming `Authorization: Bearer <jwt>` token
from the request. If the token is available somewhere else, set
`request.iam_session_token` before making permission checks:

```python
def view(request):
    request.iam_session_token = request.session["iam_session_token"]
    request.enforce.read("issue:ProjectA:IssueB", "issue:View")
```

For application-wide custom lookup, configure a function that accepts `request`
and returns the token:

```python
IAM_CLIENT_SESSION_TOKEN_GETTER = "myapp.iam.get_session_token"
```

## Request Enforcement

The middleware adds `request.enforce` for the lifetime of each request.

Use `read()` before returning data the user must be allowed to see:

```python
def issue_detail(request, issue):
    request.enforce.read(
        issue.iam_resource,
        "issue:View",
        {"principalName": request.user.username},
    )
    return render(request, "issues/detail.html", {"issue": issue})
```

Use `write()` before mutating data:

```python
def create_comment(request, issue):
    request.enforce.read(issue.iam_resource, "issue:View")
    request.enforce.write(
        f"comment:{issue.project_id}:{issue.id}:{request.user.username}:new",
        "comment:Create",
        {"principalName": request.user.username},
    )
    # Perform the mutation only after enforcement succeeds.
```

`read()` records the operation and immediately verifies that read. `write()`
records the write and verifies every operation accumulated so far. When the
response leaves the middleware, accumulated operations are verified again.

If enforcement fails, the middleware returns HTTP 403 with only action names:

```json
{
  "error": "permission_denied",
  "failed_actions": ["comment:Create"]
}
```

## Filtering Lists

When building a list, use an explicit batch so denied items can be omitted
instead of failing the whole request. These checks are independent of the
request-level enforcement queue.

```python
def visible_issues(request, issues):
    batch = request.enforce.batch()
    for issue in issues:
        batch.read(
            issue.iam_resource,
            "issue:View",
            {"principalName": request.user.username},
        )

    results = batch.execute()
    return [
        issue
        for issue, result in zip(issues, results)
        if result["allowed"]
    ]
```

`batch.execute()` returns IAM decisions in request order and does not raise when
individual checks are denied. Use `batch.verify()` when every check in the batch
must be allowed.

## Resource And Action Names

Application code is responsible for passing the resource and action names that
match the policy model used by the organization. Common patterns are:

```python
issue_resource = f"issue:{project_id}:{issue_id}"
comment_resource = f"comment:{project_id}:{issue_id}:{author_name}:{comment_id}"
```

Use stable resource identifiers. Avoid using display names or mutable text unless
the policy model explicitly requires them.

Pass context values when policies use resource templates such as
`{principalName}`:

```python
request.enforce.read(
    comment_resource,
    "comment:View",
    {"principalName": request.user.username},
)
```

## Agent Checklist

When adding ltl-IAM checks to an application:

1. Confirm the app has `django_iam_client` installed and the middleware enabled.
2. Confirm the request has a session token available to the client.
3. Add `read()` checks before returning protected objects.
4. Add `write()` checks before mutations.
5. Use `request.enforce.batch().execute()` for list filtering.
6. Keep resource/action strings consistent with existing application patterns.
7. Do not expose denied object identifiers in error responses.
