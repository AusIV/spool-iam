from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Policy",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=150, unique=True)),
                ("document", models.JSONField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name_plural": "policies",
                "ordering": ["name"],
            },
        ),
        migrations.CreateModel(
            name="Principal",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "principal_type",
                    models.CharField(choices=[("user", "User")], default="user", max_length=50),
                ),
                ("name", models.CharField(max_length=150)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "user",
                    models.OneToOneField(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="iam_principal",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["principal_type", "name"],
            },
        ),
        migrations.CreateModel(
            name="Role",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=150, unique=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "ordering": ["name"],
            },
        ),
        migrations.CreateModel(
            name="AuditLog",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("action", models.CharField(max_length=255)),
                ("resource", models.CharField(max_length=1024)),
                ("context", models.JSONField(blank=True, default=dict)),
                ("allowed", models.BooleanField()),
                ("reason", models.TextField(blank=True)),
                ("matched_statements", models.JSONField(blank=True, default=list)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "principal",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="audit_logs",
                        to="django_iam.principal",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="iam_audit_logs",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
        migrations.CreateModel(
            name="RolePolicy",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "policy",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="django_iam.policy"),
                ),
                (
                    "role",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="django_iam.role"),
                ),
            ],
            options={
                "ordering": ["role__name", "policy__name"],
            },
        ),
        migrations.CreateModel(
            name="PrincipalRole",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "principal",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="django_iam.principal"),
                ),
                (
                    "role",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="django_iam.role"),
                ),
            ],
            options={
                "ordering": ["principal__name", "role__name"],
            },
        ),
        migrations.AddField(
            model_name="role",
            name="policies",
            field=models.ManyToManyField(
                blank=True,
                related_name="roles",
                through="django_iam.RolePolicy",
                to="django_iam.policy",
            ),
        ),
        migrations.AddField(
            model_name="role",
            name="principals",
            field=models.ManyToManyField(
                blank=True,
                related_name="roles",
                through="django_iam.PrincipalRole",
                to="django_iam.principal",
            ),
        ),
        migrations.AddConstraint(
            model_name="principalrole",
            constraint=models.UniqueConstraint(
                fields=("principal", "role"),
                name="django_iam_unique_principal_role",
            ),
        ),
        migrations.AddConstraint(
            model_name="rolepolicy",
            constraint=models.UniqueConstraint(
                fields=("role", "policy"),
                name="django_iam_unique_role_policy",
            ),
        ),
        migrations.AddConstraint(
            model_name="principal",
            constraint=models.UniqueConstraint(
                fields=("principal_type", "name"),
                name="django_iam_unique_principal_type_name",
            ),
        ),
    ]
