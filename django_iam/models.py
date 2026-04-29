from django.conf import settings
from django.db import models


class Policy(models.Model):
    name = models.CharField(max_length=150, unique=True)
    document = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        verbose_name_plural = "policies"

    def __str__(self):
        return self.name


class Role(models.Model):
    name = models.CharField(max_length=150, unique=True)
    policies = models.ManyToManyField(
        Policy,
        through="RolePolicy",
        related_name="roles",
        blank=True,
    )
    principals = models.ManyToManyField(
        "Principal",
        through="PrincipalRole",
        related_name="roles",
        blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class Principal(models.Model):
    USER = "user"

    PRINCIPAL_TYPE_CHOICES = [
        (USER, "User"),
    ]

    principal_type = models.CharField(
        max_length=50,
        choices=PRINCIPAL_TYPE_CHOICES,
        default=USER,
    )
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="iam_principal",
        null=True,
        blank=True,
    )
    name = models.CharField(max_length=150)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["principal_type", "name"],
                name="django_iam_unique_principal_type_name",
            ),
        ]
        ordering = ["principal_type", "name"]

    def __str__(self):
        return f"{self.principal_type}:{self.name}"


class RolePolicy(models.Model):
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    policy = models.ForeignKey(Policy, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["role", "policy"],
                name="django_iam_unique_role_policy",
            ),
        ]
        ordering = ["role__name", "policy__name"]

    def __str__(self):
        return f"{self.role} -> {self.policy}"


class PrincipalRole(models.Model):
    principal = models.ForeignKey(Principal, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["principal", "role"],
                name="django_iam_unique_principal_role",
            ),
        ]
        ordering = ["principal__name", "role__name"]

    def __str__(self):
        return f"{self.principal} -> {self.role}"


class AuditLog(models.Model):
    principal = models.ForeignKey(
        Principal,
        on_delete=models.SET_NULL,
        related_name="audit_logs",
        null=True,
        blank=True,
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="iam_audit_logs",
        null=True,
        blank=True,
    )
    action = models.CharField(max_length=255)
    resource = models.CharField(max_length=1024)
    context = models.JSONField(default=dict, blank=True)
    allowed = models.BooleanField()
    reason = models.TextField(blank=True)
    matched_statements = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    exported_at = models.DateTimeField(null=True, blank=True)
    export_path = models.CharField(max_length=1024, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        result = "allow" if self.allowed else "deny"
        return f"{result}: {self.action} {self.resource}"
