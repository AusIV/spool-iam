import json

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from django_iam.models import AuditLog


class Command(BaseCommand):
    help = "Export unexported IAM audit logs to a newline-delimited JSON file."

    def add_arguments(self, parser):
        parser.add_argument("path", help="Destination file path for the audit log export.")
        parser.add_argument(
            "--batch-size",
            type=int,
            default=1000,
            help="Number of audit log rows to read at a time.",
        )

    def handle(self, *args, **options):
        path = options["path"]
        batch_size = options["batch_size"]
        if batch_size < 1:
            raise CommandError("--batch-size must be greater than zero.")

        rows = AuditLog.objects.filter(exported_at__isnull=True).order_by("created_at", "id")
        if not rows.exists():
            self.stdout.write(self.style.WARNING("No unexported audit log records found."))
            return

        exported_ids = []

        try:
            with open(path, "x", encoding="utf-8") as export_file:
                for audit_log in rows.iterator(chunk_size=batch_size):
                    export_file.write(json.dumps(_serialize_audit_log(audit_log), default=str))
                    export_file.write("\n")
                    exported_ids.append(audit_log.id)
        except FileExistsError as exc:
            raise CommandError(f"Export file already exists: {path}") from exc
        except OSError as exc:
            raise CommandError(f"Could not write audit log export to {path}: {exc}") from exc

        exported_at = timezone.now()
        with transaction.atomic():
            updated_count = AuditLog.objects.filter(
                id__in=exported_ids,
                exported_at__isnull=True,
            ).update(exported_at=exported_at, export_path=path)

        self.stdout.write(
            self.style.SUCCESS(
                f"Exported {updated_count} audit log record(s) to {path}."
            )
        )


def _serialize_audit_log(audit_log):
    user_id = None
    if audit_log.user_id is not None:
        user_id = audit_log.user_id

    principal_id = None
    if audit_log.principal_id is not None:
        principal_id = audit_log.principal_id

    return {
        "id": audit_log.id,
        "principal_id": principal_id,
        "user_id": user_id,
        "action": audit_log.action,
        "resource": audit_log.resource,
        "context": audit_log.context,
        "allowed": audit_log.allowed,
        "reason": audit_log.reason,
        "matched_statements": audit_log.matched_statements,
        "created_at": audit_log.created_at.isoformat(),
    }
