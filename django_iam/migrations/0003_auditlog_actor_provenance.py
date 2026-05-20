from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("django_iam", "0002_auditlog_export_tracking"),
    ]

    operations = [
        migrations.AddField(
            model_name="auditlog",
            name="actor_principal",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="actor_audit_logs",
                to="django_iam.principal",
            ),
        ),
        migrations.AddField(
            model_name="auditlog",
            name="actor_user",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="iam_actor_audit_logs",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
    ]
