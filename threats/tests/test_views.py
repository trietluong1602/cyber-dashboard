"""Smoke and behaviour tests for the threats views."""

from datetime import date, timedelta

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from threats.models import NvdEnrichment, Vulnerability


class ViewTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        today = timezone.now().date()

        cls.recent = Vulnerability.objects.create(
            cve_id="CVE-2026-20349",
            vendor="Cisco",
            product="Secure Firewall ASA",
            vulnerability_name="Heap Inspection Vulnerability",
            date_added=today - timedelta(days=3),
            description="A heap inspection vulnerability.",
            required_action="Apply mitigations.",
            due_date=today + timedelta(days=7),
            known_ransomware_use=False,
        )
        cls.ransomware = Vulnerability.objects.create(
            cve_id="CVE-2021-44228",
            vendor="Apache",
            product="Log4j2",
            vulnerability_name="Remote Code Execution Vulnerability",
            date_added=date(2021, 12, 10),
            description="JNDI features do not protect against attacker-controlled input.",
            required_action="Apply updates per vendor instructions.",
            due_date=date(2021, 12, 24),
            known_ransomware_use=True,
        )


class DashboardViewTests(ViewTestCase):
    def test_loads(self):
        response = self.client.get(reverse("threats:dashboard"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "threats/dashboard.html")

    def test_counts_are_correct(self):
        response = self.client.get(reverse("threats:dashboard"))

        self.assertEqual(response.context["total_count"], 2)
        self.assertEqual(response.context["ransomware_count"], 1)
        self.assertEqual(response.context["recent_count"], 1)

    def test_last_imported_is_populated(self):
        response = self.client.get(reverse("threats:dashboard"))

        self.assertIsNotNone(response.context["last_imported"])


class DashboardEmptyStateTests(TestCase):
    """No fixtures at all — the state before the first ETL run."""

    def test_loads_with_no_data(self):
        response = self.client.get(reverse("threats:dashboard"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["total_count"], 0)
        self.assertIsNone(response.context["last_imported"])


class VulnerabilityListTests(ViewTestCase):
    def test_loads(self):
        response = self.client.get(reverse("threats:vulnerability_list"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "threats/vulnerability_list.html")

    def test_shows_all_by_default(self):
        response = self.client.get(reverse("threats:vulnerability_list"))

        self.assertEqual(response.context["total_count"], 2)

    def test_newest_first(self):
        response = self.client.get(reverse("threats:vulnerability_list"))
        rows = list(response.context["page_obj"])

        self.assertEqual(rows[0], self.recent)

    def test_search_matches_vendor(self):
        response = self.client.get(reverse("threats:vulnerability_list"), {"q": "cisco"})

        self.assertEqual(response.context["total_count"], 1)
        self.assertContains(response, "CVE-2026-20349")

    def test_search_matches_product(self):
        response = self.client.get(reverse("threats:vulnerability_list"), {"q": "log4j"})

        self.assertEqual(response.context["total_count"], 1)

    def test_search_matches_cve_id(self):
        response = self.client.get(reverse("threats:vulnerability_list"), {"q": "44228"})

        self.assertEqual(response.context["total_count"], 1)

    def test_search_is_case_insensitive(self):
        response = self.client.get(reverse("threats:vulnerability_list"), {"q": "CISCO"})

        self.assertEqual(response.context["total_count"], 1)

    def test_blank_search_returns_everything(self):
        response = self.client.get(reverse("threats:vulnerability_list"), {"q": "   "})

        self.assertEqual(response.context["total_count"], 2)

    def test_search_with_no_matches(self):
        response = self.client.get(reverse("threats:vulnerability_list"), {"q": "zzzznothing"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["total_count"], 0)

    def test_ransomware_filter(self):
        response = self.client.get(reverse("threats:vulnerability_list"), {"ransomware": "known"})

        self.assertEqual(response.context["total_count"], 1)
        self.assertContains(response, "CVE-2021-44228")

    def test_querystring_excludes_page(self):
        """Pagination links must carry the search but set their own page."""
        response = self.client.get(
            reverse("threats:vulnerability_list"), {"q": "cisco", "page": "1"}
        )
        querystring = response.context["querystring"]

        self.assertIn("q=cisco", querystring)
        self.assertNotIn("page=", querystring)

    def test_invalid_page_does_not_error(self):
        for value in ["0", "-1", "abc", "99999"]:
            with self.subTest(page=value):
                response = self.client.get(reverse("threats:vulnerability_list"), {"page": value})
                self.assertEqual(response.status_code, 200)

    # --- NVD-related search behavior ---

    def test_search_matches_nvd_description_for_nvd_only_cve(self):
        """A CVE known only through NVD has no vendor/product/name to match on."""
        nvd_only = Vulnerability.objects.create(
            cve_id="CVE-2026-99999",
            vendor="",
            product="",
            vulnerability_name="",
            description="",
        )
        NvdEnrichment.objects.create(
            vulnerability=nvd_only,
            nvd_description="A rare buffer overflow in ExampleWidget.",
            severity="HIGH",
        )

        response = self.client.get(
            reverse("threats:vulnerability_list"), {"q": "ExampleWidget"}
        )

        self.assertEqual(response.context["total_count"], 1)
        self.assertContains(response, "CVE-2026-99999")

    def test_search_matches_cwe(self):
        NvdEnrichment.objects.create(vulnerability=self.recent, cwe_id="CWE-77")

        response = self.client.get(reverse("threats:vulnerability_list"), {"q": "CWE-77"})

        self.assertEqual(response.context["total_count"], 1)
        self.assertContains(response, "CVE-2026-20349")

    def test_search_does_not_return_duplicate_rows(self):
        """Matching on multiple Q branches must not duplicate a row in the results."""
        NvdEnrichment.objects.create(
            vulnerability=self.recent, cwe_id="CWE-77", nvd_description="Cisco heap issue"
        )

        response = self.client.get(reverse("threats:vulnerability_list"), {"q": "cisco"})

        self.assertEqual(response.context["total_count"], 1)

    # --- Sorting ---

    def test_default_sort_is_newest_first(self):
        response = self.client.get(reverse("threats:vulnerability_list"))

        self.assertEqual(response.context["sort"], "-date_added")

    def test_sort_by_vendor(self):
        response = self.client.get(
            reverse("threats:vulnerability_list"), {"sort": "vendor"}
        )
        rows = list(response.context["page_obj"])

        self.assertEqual(response.context["sort"], "vendor")
        self.assertEqual(rows[0], self.ransomware)  # "Apache" before "Cisco"

    def test_sort_by_cve_id(self):
        response = self.client.get(
            reverse("threats:vulnerability_list"), {"sort": "cve_id"}
        )
        rows = list(response.context["page_obj"])

        self.assertEqual(rows[0].cve_id, "CVE-2021-44228")

    def test_invalid_sort_falls_back_to_default(self):
        """Sort must be a whitelisted value — never a raw pass-through into order_by()."""
        response = self.client.get(
            reverse("threats:vulnerability_list"), {"sort": "'; DROP TABLE threats_vulnerability;"}
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["sort"], "-date_added")

    def test_sort_options_available_in_context(self):
        response = self.client.get(reverse("threats:vulnerability_list"))

        self.assertIn("-date_added", response.context["sort_options"])
        self.assertIn("vendor", response.context["sort_options"])


class VulnerabilityDetailTests(ViewTestCase):
    def test_loads(self):
        url = reverse("threats:vulnerability_detail", args=[self.recent.cve_id])
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "threats/vulnerability_detail.html")

    def test_shows_the_long_fields(self):
        url = reverse("threats:vulnerability_detail", args=[self.ransomware.cve_id])
        response = self.client.get(url)

        self.assertContains(response, "JNDI features")
        self.assertContains(response, "Apply updates per vendor instructions")

    def test_unknown_cve_returns_404(self):
        url = reverse("threats:vulnerability_detail", args=["CVE-9999-99999"])
        response = self.client.get(url)

        self.assertEqual(response.status_code, 404)

    def test_lowercase_cve_returns_404(self):
        """Documents the exact-match lookup — change this if you switch to iexact."""
        url = reverse("threats:vulnerability_detail", args=["cve-2026-20349"])
        response = self.client.get(url)

        self.assertEqual(response.status_code, 404)

    def test_list_links_to_detail(self):
        response = self.client.get(reverse("threats:vulnerability_list"))
        expected = reverse("threats:vulnerability_detail", args=[self.recent.cve_id])

        self.assertContains(response, f'href="{expected}"')

    def test_shows_nvd_enrichment_when_present(self):
        NvdEnrichment.objects.create(
            vulnerability=self.recent,
            cvss_score=9.6,
            severity="CRITICAL",
            cwe_id="CWE-77",
        )
        url = reverse("threats:vulnerability_detail", args=[self.recent.cve_id])
        response = self.client.get(url)

        self.assertContains(response, "9.6")
        self.assertContains(response, "CWE-77")

    def test_shows_fallback_when_not_enriched(self):
        url = reverse("threats:vulnerability_detail", args=[self.recent.cve_id])
        response = self.client.get(url)

        self.assertContains(response, "has not yet been enriched")