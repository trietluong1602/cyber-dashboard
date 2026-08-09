from django.db import models

# Create your models here.
class Vulnerability(models.Model):
    cve_id = models.CharField(max_length=25, unique=True)
    vendor = models.CharField(max_length=255)
    product = models.CharField(max_length=255)
    vulnerability_name = models.CharField(max_length=255)
    date_added = models.DateField()
    description = models.TextField()
    required_action = models.TextField()
    due_date = models.DateField(null=True, blank=True)
    known_ransomware_use = models.BooleanField(default=False)
    source_updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.cve_id} - {self.vuln_name}"