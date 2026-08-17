"""Tests for the NVD transform stage."""

from datetime import date

from django.test import SimpleTestCase

from threats.services.nvd import (
    NVDTransformError,
    transform_record,
)

# Shaped like a real NVD API response for one CVE — trimmed to the fields
# transform_record actually reads, but keeping the nesting NVD really uses.
SAMPLE_RECORD = {
    "id": "CVE-2026-8037",
    "published": "2026-06-04T13:15:10.123",
    "lastModified": "2026-08-10T09:22:41.000",
    "descriptions": [
        {
            "lang": "en",
            "value": (
                "OS Command Injection Remote Code Execution Vulnerability in "
                "API in Progress ADC Products allows an un-authenticated "
                "attacker to execute arbitrary commands on the LoadMaster "
                "appliance by exploiting unsanitized input in multiple "
                "command endpoints"
            ),
        },
        {
            "lang": "es",
            "value": "Vulnerabilidad de inyeccion de comandos del sistema operativo.",
        },
    ],
    "metrics": {
        "cvssMetricV31": [
            {
                "baseSeverity": "CRITICAL",
                "cvssData": {
                    "baseScore": 9.6,
                    "baseSeverity": "CRITICAL",
                },
            }
        ],
        "cvssMetricV2": [
            {
                "baseSeverity": "HIGH",
                "cvssData": {"baseScore": 8.3},
            }
        ],
    },
    "weaknesses": [
        {
            "description": [
                {"lang": "en", "value": "CWE-77"},
            ]
        }
    ],
}


def make_record(**overrides):
    """A copy of the sample record with specific top-level keys changed or removed.

    Passing a value of None removes the key entirely, so tests can model
    a field NVD omitted rather than one it sent as empty.
    """
    record = dict(SAMPLE_RECORD)
    for key, value in overrides.items():
        if value is None:
            record.pop(key, None)
        else:
            record[key] = value
    return record


class TransformRecordTests(SimpleTestCase):
    """transform_record: one raw NVD `cve` dict in, model field values out."""

    def test_maps_source_keys_to_model_fields(self):
        row = transform_record(SAMPLE_RECORD)

        self.assertEqual(row["cve_id"], "CVE-2026-8037")
        self.assertIn("Command Injection", row["nvd_description"])
        self.assertEqual(row["cwe_id"], "CWE-77")

    def test_returns_only_model_field_names(self):
        row = transform_record(SAMPLE_RECORD)

        self.assertEqual(
            set(row),
            {
                "cve_id",
                "nvd_description",
                "cvss_score",
                "severity",
                "cwe_id",
                "published_date",
                "modified_date",
            },
        )

    def test_dates_become_date_objects(self):
        row = transform_record(SAMPLE_RECORD)

        self.assertEqual(row["published_date"], date(2026, 6, 4))
        self.assertEqual(row["modified_date"], date(2026, 8, 10))
        self.assertIsInstance(row["published_date"], date)

    def test_description_picks_english_only(self):
        row = transform_record(SAMPLE_RECORD)

        self.assertNotIn("Vulnerabilidad", row["nvd_description"])

    def test_cvss_prefers_v31_over_v2(self):
        """NVD may publish several CVSS versions; the newest one wins."""
        row = transform_record(SAMPLE_RECORD)

        self.assertEqual(row["cvss_score"], 9.6)
        self.assertEqual(row["severity"], "CRITICAL")

    def test_cvss_falls_back_to_v2_when_v31_missing(self):
        record = make_record(metrics={"cvssMetricV2": SAMPLE_RECORD["metrics"]["cvssMetricV2"]})
        row = transform_record(record)

        self.assertEqual(row["cvss_score"], 8.3)
        self.assertEqual(row["severity"], "HIGH")

    def test_missing_metrics_gives_none_score_and_severity(self):
        record = make_record(metrics={})
        row = transform_record(record)

        self.assertIsNone(row["cvss_score"])
        self.assertEqual(row["severity"], "")

    def test_missing_weaknesses_gives_empty_cwe(self):
        record = make_record(weaknesses=[])
        row = transform_record(record)

        self.assertEqual(row["cwe_id"], "")

    def test_missing_weaknesses_key_entirely(self):
        record = make_record(weaknesses=None)
        row = transform_record(record)

        self.assertEqual(row["cwe_id"], "")

    def test_missing_published_date_becomes_none(self):
        record = make_record(published=None)
        row = transform_record(record)

        self.assertIsNone(row["published_date"])

    def test_unparseable_date_becomes_none_not_a_crash(self):
        """A date NVD can't format shouldn't fail the whole enrichment."""
        record = make_record(lastModified="not-a-date")
        row = transform_record(record)

        self.assertIsNone(row["modified_date"])

    def test_missing_descriptions_gives_empty_string(self):
        record = make_record(descriptions=[])
        row = transform_record(record)

        self.assertEqual(row["nvd_description"], "")

    def test_missing_cve_id_raises(self):
        with self.assertRaises(NVDTransformError):
            transform_record(make_record(id=None))

    def test_blank_cve_id_raises(self):
        with self.assertRaises(NVDTransformError):
            transform_record(make_record(id="   "))