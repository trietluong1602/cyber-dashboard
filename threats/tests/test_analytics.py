"""Tests for the Checkpoint 3 analytics view."""

from datetime import date

from django.test import TestCase
from django.urls import reverse

from threats.models import NvdEnrichment, Vulnerability


class AnalyticsEmptyStateTests(TestCase):
    """No fixtures at all — the state before the first ETL run."""

    def test_loads_with_no_data(self):
        response = self.client.get(reverse("threats:vulnerability_analytics"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "threats/vulnerability_analytics.html")

    def test_counts_are_zero(self):
        response = self.client.get(reverse("threats:vulnerability_analytics"))

        self.assertEqual(response.context["total_count"], 0)
        self.assertEqual(response.context["known_exploited_count"], 0)
        self.assertEqual(response.context["severity_counts"], [])
        self.assertEqual(response.context["top_vendors"], [])
        self.assertEqual(response.context["top_cwes"], [])

    def test_cvss_stats_are_none_not_an_error(self):
        """Avg/median over an empty list must not raise ZeroDivisionError/StatisticsError."""
        response = self.client.get(reverse("threats:vulnerability_analytics"))

        self.assertIsNone(response.context["avg_cvss"])
        self.assertIsNone(response.context["median_cvss"])


class AnalyticsWithDataTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.cisco = Vulnerability.objects.create(
            cve_id="CVE-2026-20349",
            vendor="Cisco",
            product="Secure Firewall ASA",
            vulnerability_name="Heap Inspection Vulnerability",
            date_added=date(2026, 3, 10),
            description="A heap inspection vulnerability.",
            known_ransomware_use=False,
        )
        cls.log4j = Vulnerability.objects.create(
            cve_id="CVE-2021-44228",
            vendor="Apache",
            product="Log4j2",
            vulnerability_name="Remote Code Execution Vulnerability",
            date_added=date(2021, 12, 10),
            description="JNDI features do not protect against attacker-controlled input.",
            known_ransomware_use=True,
        )
        # A second Apache CVE so "top vendors" has something to rank.
        cls.apache_two = Vulnerability.objects.create(
            cve_id="CVE-2022-00001",
            vendor="Apache",
            product="HTTP Server",
            vulnerability_name="Sample Vulnerability",
            date_added=date(2022, 1, 5),
            description="Sample.",
            known_ransomware_use=False,
        )

        NvdEnrichment.objects.create(
            vulnerability=cls.cisco,
            cvss_score=7.5,
            severity="HIGH",
            cwe_id="CWE-77",
            modified_date=date(2026, 8, 1),
        )
        NvdEnrichment.objects.create(
            vulnerability=cls.log4j,
            cvss_score=10.0,
            severity="CRITICAL",
            cwe_id="NVD-CWE-noinfo",  # placeholder — must be excluded from top_cwes
            modified_date=date(2026, 7, 20),
        )

    def test_severity_counts(self):
        response = self.client.get(reverse("threats:vulnerability_analytics"))
        severities = {
            row["nvd__severity"]: row["count"]
            for row in response.context["severity_counts"]
        }

        self.assertEqual(severities.get("HIGH"), 1)
        self.assertEqual(severities.get("CRITICAL"), 1)

    def test_top_vendors_counts_and_orders(self):
        response = self.client.get(reverse("threats:vulnerability_analytics"))
        vendors = {row["vendor"]: row["count"] for row in response.context["top_vendors"]}

        self.assertEqual(vendors["Apache"], 2)
        self.assertEqual(vendors["Cisco"], 1)

    def test_cves_over_time_groups_by_month(self):
        response = self.client.get(reverse("threats:vulnerability_analytics"))
        months = {
            row["month"]: row["count"] for row in response.context["cves_over_time"]
        }

        self.assertEqual(months[date(2026, 3, 1)], 1)
        self.assertEqual(months[date(2021, 12, 1)], 1)
        self.assertEqual(months[date(2022, 1, 1)], 1)

    def test_ransomware_split(self):
        response = self.client.get(reverse("threats:vulnerability_analytics"))

        self.assertEqual(response.context["ransomware_known"], 1)
        self.assertEqual(response.context["ransomware_unknown"], 2)

    def test_placeholder_cwe_is_excluded(self):
        """NVD-CWE-noinfo must never appear in the top-weaknesses chart."""
        response = self.client.get(reverse("threats:vulnerability_analytics"))
        cwe_values = [row["nvd__cwe_id"] for row in response.context["top_cwes"]]

        self.assertIn("CWE-77", cwe_values)
        self.assertNotIn("NVD-CWE-noinfo", cwe_values)

    def test_avg_and_median_cvss(self):
        response = self.client.get(reverse("threats:vulnerability_analytics"))

        # scores: 7.5, 10.0 -> avg 8.75, median 8.75
        self.assertEqual(response.context["avg_cvss"], 8.75)
        self.assertEqual(response.context["median_cvss"], 8.75)

    def test_recently_modified_orders_newest_first(self):
        response = self.client.get(reverse("threats:vulnerability_analytics"))
        ordered_ids = [v.cve_id for v in response.context["recently_modified"]]

        self.assertEqual(ordered_ids[0], "CVE-2026-20349")  # modified 2026-08-01
        self.assertEqual(ordered_ids[1], "CVE-2021-44228")  # modified 2026-07-20

    def test_recently_modified_links_to_detail(self):
        response = self.client.get(reverse("threats:vulnerability_analytics"))
        expected_url = reverse("threats:vulnerability_detail", args=[self.cisco.cve_id])

        self.assertContains(response, f'href="{expected_url}"')