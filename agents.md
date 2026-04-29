# Agent Notes

## Commit Messages

Write detailed, multi-line commit messages.

Use a concise imperative subject line, followed by a blank line and a body that explains:

- the primary behavior or feature added
- important implementation details or design choices
- tests or verification performed

Avoid one-line commits for non-trivial changes.

## Python Style

Avoid checking `hasattr()` immediately before `getattr()`. Prefer direct
attribute access with `try`/`except AttributeError` for that pattern.

Using `getattr(obj, name, default)` is fine when a default value is the intended
behavior.

Prefer normal attribute assignment, such as `request.variable = value`, over
`setattr()` when the attribute name is static.
