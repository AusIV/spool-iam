from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("django_iam", "0003_auditlog_actor_provenance"),
    ]

    operations = [
        migrations.AlterField(
            model_name="principal",
            name="principal_type",
            field=models.CharField(
                choices=[("user", "User"), ("service", "Service")],
                default="user",
                max_length=50,
            ),
        ),
        migrations.AlterField(
            model_name="principal",
            name="user",
            field=models.OneToOneField(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="iam_principal",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
    ]
