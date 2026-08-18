from django.db import models
from django.utils import timezone


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


class ETLRun(models.Model):
    """A record of one run of one ETL job (CISA import or NVD import).

    Kept separate per source rather than one combined "last refresh"
    timestamp, so a failed NVD run doesn't hide the fact that CISA still
    refreshed successfully, and so a run history is auditable over time
    rather than only ever showing the single most recent attempt.
    """

    SOURCE_CISA = "cisa"
    SOURCE_NVD = "nvd"
    SOURCE_CHOICES = [
        (SOURCE_CISA, "CISA KEV"),
        (SOURCE_NVD, "NVD Enrichment"),
    ]

    STATUS_RUNNING = "running"
    STATUS_SUCCESS = "success"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = [
        (STATUS_RUNNING, "Running"),
        (STATUS_SUCCESS, "Success"),
        (STATUS_FAILED, "Failed"),
    ]

    source = models.CharField(max_length=16, choices=SOURCE_CHOICES)
    status = models.CharField(
        max_length=16, choices=STATUS_CHOICES, default=STATUS_RUNNING
    )
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    rows_extracted = models.PositiveIntegerField(default=0)
    rows_inserted = models.PositiveIntegerField(default=0)
    rows_updated = models.PositiveIntegerField(default=0)
    rows_failed = models.PositiveIntegerField(default=0)

    error_message = models.TextField(blank=True)

    class Meta:
        ordering = ["-started_at"]

    def __str__(self):
        return f"{self.get_source_display()} run at {self.started_at:%Y-%m-%d %H:%M} ({self.status})"

    def mark_success(self, *, rows_extracted=0, rows_inserted=0, rows_updated=0, rows_failed=0):
        self.status = self.STATUS_SUCCESS
        self.finished_at = timezone.now()
        self.rows_extracted = rows_extracted
        self.rows_inserted = rows_inserted
        self.rows_updated = rows_updated
        self.rows_failed = rows_failed
        self.save()

    def mark_failed(self, error_message, *, rows_extracted=0, rows_failed=0):
        self.status = self.STATUS_FAILED
        self.finished_at = timezone.now()
        self.rows_extracted = rows_extracted
        self.rows_failed = rows_failed
        self.error_message = str(error_message)[:5000]
        self.save()