"""Tests for ETLRun tracking, the refresh_all scheduler entry point, and
the dashboard/etl-status views that surface run history."""

from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.models import User

from threats.models import ETLRun
from threats.services.cisa import KEVExtractError


class ETLRunModelTests(TestCase):
    def test_mark_success_sets_fields(self):
        run = ETLRun.objects.create(source=ETLRun.SOURCE_CISA)

        run.mark_success(rows_extracted=10, rows_inserted=6, rows_updated=3, rows_failed=1)

        self.assertEqual(run.status, ETLRun.STATUS_SUCCESS)
        self.assertIsNotNone(run.finished_at)
        self.assertEqual(run.rows_extracted, 10)
        self.assertEqual(run.rows_inserted, 6)
        self.assertEqual(run.rows_updated, 3)
        self.assertEqual(run.rows_failed, 1)

    def test_mark_failed_sets_fields_and_truncates_long_errors(self):
        run = ETLRun.objects.create(source=ETLRun.SOURCE_NVD)

        run.mark_failed("boom " * 2000, rows_extracted=5, rows_failed=5)

        self.assertEqual(run.status, ETLRun.STATUS_FAILED)
        self.assertIsNotNone(run.finished_at)
        self.assertLessEqual(len(run.error_message), 5000)


class ImportCisaETLRunTests(TestCase):
    def test_success_records_etl_run(self):
        with patch(
            "threats.management.commands.import_cisa.fetch_kev_catalog"
        ) as mock_fetch, patch(
            "threats.management.commands.import_cisa.transform_records"
        ) as mock_transform, patch(
            "threats.management.commands.import_cisa.load_records"
        ) as mock_load:
            mock_fetch.return_value = (
                [{"cveID": "CVE-2026-00001"}],
                {"record_count": 1, "catalog_version": "1.0", "date_released": "2026-08-01"},
            )
            mock_transform.return_value = ([{"cve_id": "CVE-2026-00001"}], [])
            mock_load.return_value = {"created": 1, "updated": 0, "total": 1}

            call_command("import_cisa")

        run = ETLRun.objects.get(source=ETLRun.SOURCE_CISA)
        self.assertEqual(run.status, ETLRun.STATUS_SUCCESS)
        self.assertEqual(run.rows_extracted, 1)
        self.assertEqual(run.rows_inserted, 1)
        self.assertEqual(run.rows_updated, 0)
        self.assertEqual(run.rows_failed, 0)

    def test_extract_failure_marks_run_failed_and_raises(self):
        with patch(
            "threats.management.commands.import_cisa.fetch_kev_catalog"
        ) as mock_fetch:
            mock_fetch.side_effect = KEVExtractError("feed unreachable")

            with self.assertRaises(CommandError):
                call_command("import_cisa")

        run = ETLRun.objects.get(source=ETLRun.SOURCE_CISA)
        self.assertEqual(run.status, ETLRun.STATUS_FAILED)
        self.assertIn("feed unreachable", run.error_message)

    def test_dry_run_does_not_create_etl_run(self):
        with patch(
            "threats.management.commands.import_cisa.fetch_kev_catalog"
        ) as mock_fetch, patch(
            "threats.management.commands.import_cisa.transform_records"
        ) as mock_transform:
            mock_fetch.return_value = (
                [{"cveID": "CVE-2026-00001"}],
                {"record_count": 1, "catalog_version": "1.0", "date_released": "2026-08-01"},
            )
            mock_transform.return_value = ([{"cve_id": "CVE-2026-00001"}], [])

            call_command("import_cisa", "--dry-run")

        self.assertEqual(ETLRun.objects.count(), 0)


class ImportNvdETLRunTests(TestCase):
    def test_success_with_skipped_cves_still_completes(self):
        """Regression test: this used to call exit(1) whenever any CVE was
        skipped, which would kill the process — including when chained
        from refresh_all. It should now complete normally and just record
        the skip count on the ETLRun row."""
        from threats.models import Vulnerability

        Vulnerability.objects.create(
            cve_id="CVE-2026-00001",
            vendor="Acme",
            product="Widget",
            vulnerability_name="Sample",
            description="Sample.",
        )

        with patch(
            "threats.management.commands.import_nvd.fetch_and_transform"
        ) as mock_fetch, patch(
            "threats.management.commands.import_nvd.load_enrichments"
        ) as mock_load:
            mock_fetch.return_value = (
                [],
                [("CVE-2026-00001", "NVD lookup failed")],
            )
            mock_load.return_value = {"created": 0, "updated": 0, "nvd_only_created": 0, "total": 0}

            # Must not raise, must not call sys.exit.
            call_command("import_nvd")

        run = ETLRun.objects.get(source=ETLRun.SOURCE_NVD)
        self.assertEqual(run.status, ETLRun.STATUS_SUCCESS)
        self.assertEqual(run.rows_failed, 1)

    def test_no_cve_ids_still_marks_success(self):
        call_command("import_nvd")

        run = ETLRun.objects.get(source=ETLRun.SOURCE_NVD)
        self.assertEqual(run.status, ETLRun.STATUS_SUCCESS)
        self.assertEqual(run.rows_extracted, 0)


class RefreshAllCommandTests(TestCase):
    def test_both_succeed_and_nvd_defaults_to_only_missing(self):
        with patch(
            "threats.management.commands.refresh_all.call_command"
        ) as mock_call:
            mock_call.return_value = None

            call_command("refresh_all")

            self.assertEqual(mock_call.call_count, 2)
            first_call, second_call = mock_call.call_args_list
            self.assertEqual(first_call.args[0], "import_cisa")
            self.assertEqual(second_call.args[0], "import_nvd")
            self.assertTrue(second_call.kwargs.get("only_missing"))

    def test_full_flag_requests_complete_nvd_refresh(self):
        with patch(
            "threats.management.commands.refresh_all.call_command"
        ) as mock_call:
            mock_call.return_value = None

            call_command("refresh_all", "--full")

            second_call = mock_call.call_args_list[1]
            self.assertEqual(second_call.args[0], "import_nvd")
            self.assertNotIn("only_missing", second_call.kwargs)

    def test_one_failure_still_runs_the_other_and_raises(self):
        def side_effect(name, *args, **kwargs):
            if name == "import_cisa":
                raise CommandError("CISA feed down")
            return None

        with patch(
            "threats.management.commands.refresh_all.call_command",
            side_effect=side_effect,
        ) as mock_call:
            with self.assertRaises(CommandError):
                call_command("refresh_all")

            called_names = [c.args[0] for c in mock_call.call_args_list]
            self.assertIn("import_nvd", called_names)


class DashboardETLStatusContextTests(TestCase):
    def test_latest_run_per_source_is_independent(self):
        older_cisa = ETLRun.objects.create(source=ETLRun.SOURCE_CISA)
        older_cisa.mark_success()

        newer_cisa = ETLRun.objects.create(source=ETLRun.SOURCE_CISA)
        newer_cisa.mark_failed("timeout")

        nvd_run = ETLRun.objects.create(source=ETLRun.SOURCE_NVD)
        nvd_run.mark_success()

        response = self.client.get(reverse("threats:dashboard"))

        self.assertEqual(response.context["latest_cisa_run"].pk, newer_cisa.pk)
        self.assertEqual(response.context["latest_cisa_run"].status, ETLRun.STATUS_FAILED)
        self.assertEqual(response.context["latest_nvd_run"].pk, nvd_run.pk)
        self.assertEqual(response.context["latest_nvd_run"].status, ETLRun.STATUS_SUCCESS)

    def test_no_runs_yet(self):
        response = self.client.get(reverse("threats:dashboard"))

        self.assertIsNone(response.context["latest_cisa_run"])
        self.assertIsNone(response.context["latest_nvd_run"])


class EtlStatusViewTests(TestCase):
    def test_loads_and_lists_runs(self):
        run = ETLRun.objects.create(source=ETLRun.SOURCE_CISA)
        run.mark_success(rows_extracted=5, rows_inserted=5)

        response = self.client.get(reverse("threats:etl_status"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "threats/etl_status.html")
        self.assertContains(response, "CISA KEV")

    def test_loads_with_no_runs(self):
        response = self.client.get(reverse("threats:etl_status"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No ETL runs recorded yet")

    def test_refresh_button_hidden_from_anonymous_visitors(self):
        response = self.client.get(reverse("threats:etl_status"))

        self.assertNotContains(response, "Refresh data now")

    def test_refresh_button_visible_to_staff(self):
        User.objects.create_user("admin", password="pw", is_staff=True)
        self.client.login(username="admin", password="pw")

        response = self.client.get(reverse("threats:etl_status"))

        self.assertContains(response, "Refresh data now")


class TriggerRefreshViewTests(TestCase):
    def setUp(self):
        self.staff_user = User.objects.create_user(
            "admin", password="pw", is_staff=True
        )
        self.regular_user = User.objects.create_user(
            "analyst", password="pw", is_staff=False
        )

    def test_anonymous_user_redirected_to_login(self):
        response = self.client.post(reverse("threats:trigger_refresh"))

        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

    def test_non_staff_user_cannot_trigger(self):
        self.client.login(username="analyst", password="pw")

        response = self.client.post(reverse("threats:trigger_refresh"))

        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

    def test_get_request_not_allowed(self):
        self.client.login(username="admin", password="pw")

        response = self.client.get(reverse("threats:trigger_refresh"))

        self.assertEqual(response.status_code, 405)

    def test_staff_post_starts_background_refresh_and_redirects(self):
        self.client.login(username="admin", password="pw")

        with patch("threats.views.threading.Thread") as mock_thread_cls:
            mock_thread = mock_thread_cls.return_value

            response = self.client.post(reverse("threats:trigger_refresh"))

            mock_thread_cls.assert_called_once()
            _, kwargs = mock_thread_cls.call_args
            self.assertTrue(kwargs.get("daemon"))
            mock_thread.start.assert_called_once()

        self.assertRedirects(response, reverse("threats:etl_status"))