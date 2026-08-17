from django.contrib import admin
from threats.models import NvdEnrichment, Vulnerability

# Register your models here.
@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('cve_id', 'vendor', 'product', 'vulnerability_name', 'date_added', 'due_date', 'known_ransomware_use', 'source_updated_at')
    search_fields = ('cve_id', 'vendor', 'product', 'vulnerability_name', 'date_added', 'due_date', 'known_ransomware_use', 'source_updated_at')
    list_filter = ('cve_id', 'vendor', 'product', 'vulnerability_name', 'date_added', 'due_date', 'known_ransomware_use', 'source_updated_at')


@admin.register(NvdEnrichment)
class NvdEnrichmentAdmin(admin.ModelAdmin):
    list_display = ('vulnerability', 'cvss_score', 'severity', 'cwe_id', 'published_date', 'source_updated_at')
    search_fields = ('vulnerability__cve_id', 'cwe_id')
    list_filter = ('severity', 'cwe_id')