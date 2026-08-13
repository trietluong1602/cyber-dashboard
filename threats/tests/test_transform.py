"""Tests for the CISA KEV transform stage."""

from datetime import date

from django.test import SimpleTestCase

from threats.services.cisa import (
    KEVTransformError,
    transform_record,
    transform_records,
)

# Copied verbatim from the CISA feed, trailing whitespace and all.
SAMPLE_RECORD = {
    "cveID": "CVE-2026-20349",
    "vendorProject": "Cisco",
    "product": (
        "Secure Firewall Adaptive Security Appliance (ASA) and "
        "Secure Firewall Threat Defense (FTD) "
    ),
    "vulnerabilityName": (
        "Cisco Secure Firewall Adaptive Security Appliance (ASA) and "
        "Secure Firewall Threat Defense (FTD) Heap Inspection Vulnerability"
    ),
    "dateAdded": "2026-08-11",
    "shortDescription": (
        "Cisco Secure Firewall Adaptive Security Appliance (ASA) and Secure "
        "Firewall Threat Defense (FTD) contain a heap inspection vulnerability "
        "that could allow an unauthenticated, remote attacker to cause the "
        "device to reload unexpectedly, resulting in a denial of service (DoS) "
        "condition."
    ),
    "requiredAction": (
        "Apply mitigations in accordance with vendor instructions, ensuring "
        "compliance with CISA\u2019s BOD 26-04 guidance."
    ),
    "dueDate": "2026-08-14",
    "knownRansomwareCampaignUse": "Unknown",
    "notes": "https://nvd.nist.gov/vuln/detail/CVE-2026-20349",
    "cwes": ["CWE-244"],
}


def make_record(**overrides):
    """A copy of the sample record with specific keys changed or removed.

    Passing a value of None removes the key entirely, so tests can model
    a field the feed omitted rather than one it sent as empty.
    """
    record = dict(SAMPLE_RECORD)
    for key, value in overrides.items():
        if value is None:
            record.pop(key, None)
        else:
            record[key] = value
    return record


class TransformRecordTests(SimpleTestCase):
    """transform_record: one raw dict in, model field values out."""

    def test_maps_source_keys_to_model_fields(self):
        row = transform_record(SAMPLE_RECORD)

        self.assertEqual(row["cve_id"], "CVE-2026-20349")
        self.assertEqual(row["vendor"], "Cisco")
        self.assertIn("Heap Inspection", row["vulnerability_name"])
        self.assertIn("denial of service", row["description"])
        self.assertIn("Apply mitigations", row["required_action"])

    def test_returns_only_model_field_names(self):
        row = transform_record(SAMPLE_RECORD)

        self.assertEqual(
            set(row),
            {
                "cve_id",
                "vendor",
                "product",
                "vulnerability_name",
                "date_added",
                "description",
                "required_action",
                "due_date",
                "known_ransomware_use",
            },
        )

    def test_dates_become_date_objects(self):
        row = transform_record(SAMPLE_RECORD)

        self.assertEqual(row["date_added"], date(2026, 8, 11))
        self.assertEqual(row["due_date"], date(2026, 8, 14))
        self.assertIsInstance(row["date_added"], date)

    def test_strips_trailing_whitespace_from_source(self):
        row = transform_record(SAMPLE_RECORD)

        self.assertFalse(row["product"].endswith(" "))
        self.assertTrue(row["product"].startswith("Secure Firewall"))

    def test_ransomware_known_is_true(self):
        row = transform_record(make_record(knownRansomwareCampaignUse="Known"))

        self.assertIs(row["known_ransomware_use"], True)

    def test_ransomware_unknown_is_false(self):
        row = transform_record(SAMPLE_RECORD)

        self.assertIs(row["known_ransomware_use"], False)

    def test_ransomware_unexpected_value_is_false(self):
        """A new value from CISA must not be read as confirmed ransomware use."""
        row = transform_record(make_record(knownRansomwareCampaignUse="Suspected"))

        self.assertIs(row["known_ransomware_use"], False)

    def test_missing_due_date_becomes_none(self):
        row = transform_record(make_record(dueDate=None))

        self.assertIsNone(row["due_date"])

    def test_blank_due_date_becomes_none(self):
        row = transform_record(make_record(dueDate="   "))

        self.assertIsNone(row["due_date"])

    def test_missing_cve_id_raises(self):
        with self.assertRaises(KEVTransformError):
            transform_record(make_record(cveID=None))

    def test_missing_date_added_raises(self):
        with self.assertRaises(KEVTransformError):
            transform_record(make_record(dateAdded=None))

    def test_unparseable_date_added_raises(self):
        with self.assertRaises(KEVTransformError):
            transform_record(make_record(dateAdded="08/11/2026"))

    def test_unparseable_due_date_raises(self):
        with self.assertRaises(KEVTransformError):
            transform_record(make_record(dueDate="not a date"))

    def test_error_message_identifies_the_record(self):
        """A skip message with no CVE ID in it is not actionable."""
        with self.assertRaises(KEVTransformError) as ctx:
            transform_record(make_record(dueDate="not a date"))

        self.assertIn("CVE-2026-20349", str(ctx.exception))


class TransformRecordsTests(SimpleTestCase):
    """transform_records: a list in, cleaned rows plus collected errors out."""

    def test_valid_records_all_pass_through(self):
        records = [
            SAMPLE_RECORD,
            make_record(cveID="CVE-2026-00001"),
        ]

        cleaned, errors = transform_records(records)

        self.assertEqual(len(cleaned), 2)
        self.assertEqual(errors, [])

    def test_bad_record_is_collected_not_raised(self):
        records = [
            SAMPLE_RECORD,
            make_record(cveID="CVE-2026-00002", dateAdded="nonsense"),
            make_record(cveID="CVE-2026-00003"),
        ]

        cleaned, errors = transform_records(records)

        self.assertEqual(len(cleaned), 2)
        self.assertEqual(len(errors), 1)

    def test_error_carries_the_index_of_the_bad_record(self):
        records = [
            SAMPLE_RECORD,
            make_record(cveID="CVE-2026-00002", dateAdded="nonsense"),
        ]

        cleaned, errors = transform_records(records)
        index, message = errors[0]

        self.assertEqual(index, 1)
        self.assertIn("CVE-2026-00002", message)

    def test_duplicate_cve_keeps_first_and_reports_second(self):
        records = [
            SAMPLE_RECORD,
            make_record(vendor="Contradictory duplicate"),
        ]

        cleaned, errors = transform_records(records)

        self.assertEqual(len(cleaned), 1)
        self.assertEqual(cleaned[0]["vendor"], "Cisco")
        self.assertIn("duplicate", errors[0][1])

    def test_cve_ids_in_output_are_unique(self):
        """The loader's upsert depends on this, so assert it directly."""
        records = [SAMPLE_RECORD, SAMPLE_RECORD, make_record(cveID="CVE-2026-00004")]

        cleaned, _ = transform_records(records)
        cve_ids = [row["cve_id"] for row in cleaned]

        self.assertEqual(len(cve_ids), len(set(cve_ids)))

    def test_empty_input_is_not_an_error(self):
        cleaned, errors = transform_records([])

        self.assertEqual(cleaned, [])
        self.assertEqual(errors, [])