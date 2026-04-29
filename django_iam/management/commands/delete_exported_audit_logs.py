from django.core.management.base import BaseCommand

from django_iam.models import AuditLog


class Command(BaseCommand):
    help = "Delete IAM audit logs that have already been exported."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report how many exported audit log rows would be deleted.",
        )

    def handle(self, *args, **options):
        exported_logs = AuditLog.objects.filter(exported_at__isnull=False)
        count = exported_logs.count()

        if options["dry_run"]:
            self.stdout.write(
                self.style.WARNING(
                    f"{count} exported audit log record(s) would be deleted."
                )
            )
            return

        deleted_count, _ = exported_logs.delete()
        self.stdout.write(
            self.style.SUCCESS(
                f"Deleted {deleted_count} previously exported audit log record(s)."
            )
        )
