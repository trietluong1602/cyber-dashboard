"""Import the CISA Known Exploited Vulnerabilities catalog."""

from django.core.management.base import BaseCommand, CommandError

from threats.models import ETLRun
from threats.services.cisa import (
    KEVExtractError,
    fetch_kev_catalog,
    transform_records,
)
from threats.services.loader import load_records


class Command(BaseCommand):
    help = "Fetch the CISA KEV catalog and upsert it into the database."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Extract and transform, but do not write to the database.",
        )
        parser.add_argument(
            "--show-errors",
            action="store_true",
            help="Print every skipped record instead of just the count.",
        )

    def handle(self, *args, **options):
        # Dry runs write nothing, so they aren't tracked as a real ETL
        # run — only actual database-affecting attempts get a history row.
        run = None if options["dry_run"] else ETLRun.objects.create(
            source=ETLRun.SOURCE_CISA
        )

        try:
            # Extract — nothing downstream can proceed if this fails.
            try:
                records, meta = fetch_kev_catalog()
            except KEVExtractError as exc:
                raise CommandError(f"Extract failed: {exc}") from exc

            self.stdout.write(
                f"Fetched {meta['record_count']} records "
                f"(catalog {meta['catalog_version']}, released {meta['date_released']})"
            )

            # Transform — per-record failures are collected, not raised.
            cleaned, errors = transform_records(records)

            if errors:
                self.stdout.write(
                    self.style.WARNING(f"Skipped {len(errors)} unusable record(s)")
                )
                if options["show_errors"]:
                    for index, message in errors:
                        self.stdout.write(f"  [{index}] {message}")

            if options["dry_run"]:
                self.stdout.write(
                    self.style.WARNING(
                        f"Dry run — {len(cleaned)} record(s) ready, nothing written."
                    )
                )
                return

            # Load
            result = load_records(cleaned)

            self.stdout.write(
                self.style.SUCCESS(
                    f"Loaded {result['total']}: "
                    f"{result['created']} created, {result['updated']} updated"
                )
            )

            run.mark_success(
                rows_extracted=meta["record_count"],
                rows_inserted=result["created"],
                rows_updated=result["updated"],
                rows_failed=len(errors),
            )
        except Exception as exc:
            if run is not None:
                run.mark_failed(str(exc))
            raise