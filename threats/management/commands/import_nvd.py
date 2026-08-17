"""Enrich existing Vulnerability records with NVD data (CVSS, severity, CWE)."""

import os

from django.core.management.base import BaseCommand, CommandError

from threats.models import Vulnerability
from threats.services.loader import load_enrichments
from threats.services.nvd import fetch_and_transform


class Command(BaseCommand):
    help = "Fetch NVD data for known CVE IDs and upsert it into NvdEnrichment."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Extract and transform, but do not write to the database.",
        )
        parser.add_argument(
            "--show-errors",
            action="store_true",
            help="Print every skipped CVE instead of just the count.",
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=None,
            help="Only process the first N CVE IDs (useful while testing).",
        )
        parser.add_argument(
            "--only-missing",
            action="store_true",
            help="Skip CVEs that already have an NvdEnrichment row.",
        )

    def handle(self, *args, **options):
        queryset = Vulnerability.objects.all().order_by("cve_id")

        if options["only_missing"]:
            queryset = queryset.filter(nvd__isnull=True)

        if options["limit"]:
            queryset = queryset[: options["limit"]]

        cve_ids = list(queryset.values_list("cve_id", flat=True))

        if not cve_ids:
            self.stdout.write("No CVE IDs to process.")
            return

        self.stdout.write(f"Fetching NVD data for {len(cve_ids)} CVE(s)...")

        api_key = os.getenv("NVD_API_KEY") or None

        # Extract + transform — per-CVE failures are collected, not raised.
        try:
            cleaned, errors = fetch_and_transform(cve_ids, api_key=api_key)
        except Exception as exc:  # unexpected, not a per-record NVD issue
            raise CommandError(f"NVD import failed: {exc}") from exc

        if errors:
            self.stdout.write(
                self.style.WARNING(f"Skipped {len(errors)} CVE(s)")
            )
            if options["show_errors"]:
                for cve_id, message in errors:
                    self.stdout.write(f"  [{cve_id}] {message}")

        if options["dry_run"]:
            self.stdout.write(
                self.style.WARNING(
                    f"Dry run — {len(cleaned)} record(s) ready, nothing written."
                )
            )
            return

        # Load
        result = load_enrichments(cleaned)

        self.stdout.write(
            self.style.SUCCESS(
                f"Loaded {result['total']}: "
                f"{result['created']} created, {result['updated']} updated "
                f"({result['nvd_only_created']} new Vulnerability rows created)"
            )
        )

        if errors:
            exit(1)