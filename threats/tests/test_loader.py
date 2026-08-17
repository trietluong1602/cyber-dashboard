"""Tests for the load stage: load_records (CISA) and load_enrichments (NVD)."""

from datetime import date

from django.test import TestCase

from threats.models import NvdEnrichment, Vulnerability
from threats.services.loader import load_enrichments, load_records


class LoadEnrichmentsTests(TestCase):
    def setUp(self):
        self.existing = Vulnerability.objects.create(
            cve_id="CVE-2026-8037",
            vendor="Progress",
            product="LoadMaster",
            vulnerability_name="Command Injection Vulnerability",
            date_added=date(2026, 8, 7),
            description="CISA's short description.",
            required_action="Apply mitigations.",
            known_ransomware_use=False,
        )

    def _row(self, **overrides):
        row = {
            "cve_id": "CVE-2026-8037",
            "nvd_description": "NVD's fuller description.",
            "cvss_score": 9.6,
            "severity": "CRITICAL",
            "cwe_id": "CWE-77",
            "published_date": date(2026, 6, 4),
            "modified_date": date(2026, 8, 10),
        }
        row.update(overrides)
        return row

    def test_enriches_an_existing_vulnerability(self):
        result = load_enrichments([self._row()])

        self.existing.refresh_from_db()
        self.assertEqual(result, {
            "created": 1, "updated": 0, "nvd_only_created": 0, "total": 1,
        })
        self.assertEqual(self.existing.nvd.cvss_score, 9.6)
        self.assertEqual(self.existing.nvd.severity, "CRITICAL")

    def test_does_not_touch_cisa_owned_fields(self):
        """Enriching a CVE must never overwrite its CISA-sourced data."""
        load_enrichments([self._row()])

        self.existing.refresh_from_db()
        self.assertEqual(self.existing.vendor, "Progress")
        self.assertEqual(self.existing.required_action, "Apply mitigations.")

    def test_rerunning_updates_not_duplicates(self):
        load_enrichments([self._row()])
        result = load_enrichments([self._row(cvss_score=9.8)])

        self.assertEqual(result["created"], 0)
        self.assertEqual(result["updated"], 1)
        self.assertEqual(NvdEnrichment.objects.count(), 1)
        self.assertEqual(NvdEnrichment.objects.first().cvss_score, 9.8)

    def test_nvd_only_cve_creates_bare_vulnerability(self):
        """A CVE with no CISA KEV row yet must still be enrichable."""
        row = self._row(cve_id="CVE-2026-99999")
        result = load_enrichments([row])

        self.assertEqual(result["nvd_only_created"], 1)
        vuln = Vulnerability.objects.get(cve_id="CVE-2026-99999")
        self.assertEqual(vuln.vendor, "")
        self.assertIsNone(vuln.date_added)
        self.assertEqual(vuln.nvd.severity, "CRITICAL")

    def test_empty_input_is_not_an_error(self):
        result = load_enrichments([])

        self.assertEqual(result, {
            "created": 0, "updated": 0, "nvd_only_created": 0, "total": 0,
        })