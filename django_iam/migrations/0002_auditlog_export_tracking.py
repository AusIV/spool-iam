from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("django_iam", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="auditlog",
            name="export_path",
            field=models.CharField(blank=True, max_length=1024),
        ),
        migrations.AddField(
            model_name="auditlog",
            name="exported_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
