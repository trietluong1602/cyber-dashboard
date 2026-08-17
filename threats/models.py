from django.db import models


class Vulnerability(models.Model):
    cve_id = models.CharField(max_length=25, unique=True)
    vendor = models.CharField(max_length=255)
    product = models.CharField(max_length=255)
    vulnerability_name = models.CharField(max_length=255)
    description = models.TextField()

    # KEV-specific fields — no longer required, because a Vulnerability
    # row can now originate from NVD alone (import_nvd creates a bare
    # Vulnerability if one doesn't already exist for that CVE).
    date_added = models.DateField(null=True, blank=True)
    required_action = models.TextField(null=True, blank=True)
    due_date = models.DateField(null=True, blank=True)
    known_ransomware_use = models.BooleanField(null=True, blank=True)
    source_updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.cve_id} - {self.vulnerability_name}"


class NvdEnrichment(models.Model):
    """NVD's contribution for a CVE: CVSS, severity, CWE, richer dates/text.

    One row per Vulnerability. Kept separate from Vulnerability itself so
    that an ETL refresh from one source never touches data owned by the
    other — a CISA re-import can't blow away CVSS data, and vice versa.
    """
    vulnerability = models.OneToOneField(
        Vulnerability,
        on_delete=models.CASCADE,
        related_name="nvd",
    )

    nvd_description = models.TextField(blank=True)
    cvss_score = models.FloatField(null=True, blank=True)
    severity = models.CharField(max_length=16, blank=True)
    cwe_id = models.CharField(max_length=32, blank=True)

    published_date = models.DateField(null=True, blank=True)
    modified_date = models.DateField(null=True, blank=True)

    source_updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"NVD data for {self.vulnerability.cve_id}"