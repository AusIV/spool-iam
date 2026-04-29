import json
from pathlib import Path

from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from django_iam.models import AuditLog


class AuditLogCommandTests(TestCase):
    def test_export_writes_jsonl_and_marks_records_exported(self):
        first = AuditLog.objects.create(
            action="issue:View",
            resource="issue:ProjectA:Issue1",
            context={"project": "ProjectA"},
            allowed=True,
            reason="allowed",
            matched_statements=[{"Effect": "Allow"}],
        )
        second = AuditLog.objects.create(
            action="issue:Delete",
            resource="issue:ProjectA:Issue1",
            context={},
            allowed=False,
            reason="missing_allow",
            matched_statements=[],
        )
        export_path = Path(self._testMethodName).with_suffix(".jsonl")
        self.addCleanup(export_path.unlink, missing_ok=True)

        call_command("export_audit_logs", str(export_path))

        exported_rows = [
            json.loads(line)
            for line in export_path.read_text(encoding="utf-8").splitlines()
        ]
        assert [row["id"] for row in exported_rows] == [first.id, second.id]
        assert exported_rows[0]["context"] == {"project": "ProjectA"}

        first.refresh_from_db()
        second.refresh_from_db()
        assert first.exported_at is not None
        assert second.exported_at is not None
        assert first.export_path == str(export_path)
        assert second.export_path == str(export_path)

    def test_export_does_not_reexport_previously_exported_records(self):
        exported = AuditLog.objects.create(
            action="issue:View",
            resource="issue:ProjectA:Issue1",
            context={},
            allowed=True,
            reason="allowed",
            exported_at=timezone.now(),
            export_path="previous.jsonl",
        )
        pending = AuditLog.objects.create(
            action="comment:Create",
            resource="comment:ProjectA:Issue1:UserC:1",
            context={},
            allowed=True,
            reason="allowed",
        )
        export_path = Path(self._testMethodName).with_suffix(".jsonl")
        self.addCleanup(export_path.unlink, missing_ok=True)

        call_command("export_audit_logs", str(export_path))

        exported_rows = [
            json.loads(line)
            for line in export_path.read_text(encoding="utf-8").splitlines()
        ]
        assert [row["id"] for row in exported_rows] == [pending.id]

        exported.refresh_from_db()
        assert exported.export_path == "previous.jsonl"

    def test_delete_exported_audit_logs_leaves_unexported_records(self):
        AuditLog.objects.create(
            action="issue:View",
            resource="issue:ProjectA:Issue1",
            context={},
            allowed=True,
            reason="allowed",
            exported_at=timezone.now(),
            export_path="export.jsonl",
        )
        pending = AuditLog.objects.create(
            action="issue:View",
            resource="issue:ProjectA:Issue2",
            context={},
            allowed=True,
            reason="allowed",
        )

        call_command("delete_exported_audit_logs")

        assert list(AuditLog.objects.values_list("id", flat=True)) == [pending.id]

    def test_delete_exported_audit_logs_dry_run_does_not_delete(self):
        AuditLog.objects.create(
            action="issue:View",
            resource="issue:ProjectA:Issue1",
            context={},
            allowed=True,
            reason="allowed",
            exported_at=timezone.now(),
            export_path="export.jsonl",
        )

        call_command("delete_exported_audit_logs", "--dry-run")

        assert AuditLog.objects.count() == 1
