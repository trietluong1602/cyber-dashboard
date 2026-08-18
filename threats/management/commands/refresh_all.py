"""Run all ETL imports in sequence. Entry point for scheduled refreshes.

Intended to be triggered by an external scheduler (Windows Task Scheduler,
cron, etc.):

    python manage.py refresh_all

By default, NVD enrichment only fills in CVEs that don't have NVD data
yet (--only-missing). This is deliberate: import_nvd's default behavior is
to re-fetch NVD data for every CVE in the database, and NVD's public rate
limit (5 requests/30s without an API key) means a full pass over a
catalog with 1,000+ CVEs can take hours — far too slow to run on any
schedule shorter than that, and liable to stack overlapping runs if it
does. Existing enrichments rarely change once set, so incremental is the
right default for frequent scheduled runs; use --full for an occasional
full refresh of previously-enriched data.

Each underlying command (import_cisa, import_nvd) records its own ETLRun
row regardless of whether it's called directly or through this command, so
a partial failure here still leaves an accurate, auditable history — this
command's job is to run both in sequence and surface a combined non-zero
exit code if either failed, which is what the scheduler checks.
"""

from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Run import_cisa then import_nvd. Intended for scheduled/automated refreshes."

    def add_arguments(self, parser):
        parser.add_argument(
            "--full",
            action="store_true",
            help=(
                "Re-fetch NVD data for every CVE, not just ones missing "
                "enrichment. Slow on a large catalog — run occasionally, "
                "not on a frequent schedule."
            ),
        )

    def handle(self, *args, **options):
        failures = []

        self.stdout.write(self.style.MIGRATE_HEADING("Step 1/2: import_cisa"))
        try:
            call_command("import_cisa")
        except CommandError as exc:
            failures.append(("import_cisa", str(exc)))
            self.stdout.write(self.style.ERROR(f"import_cisa failed: {exc}"))

        self.stdout.write(self.style.MIGRATE_HEADING("Step 2/2: import_nvd"))
        try:
            if options["full"]:
                call_command("import_nvd")
            else:
                call_command("import_nvd", only_missing=True)
        except CommandError as exc:
            failures.append(("import_nvd", str(exc)))
            self.stdout.write(self.style.ERROR(f"import_nvd failed: {exc}"))

        if failures:
            summary = "; ".join(f"{name}: {msg}" for name, msg in failures)
            raise CommandError(f"refresh_all had {len(failures)} failure(s) — {summary}")

        self.stdout.write(self.style.SUCCESS("refresh_all completed successfully."))