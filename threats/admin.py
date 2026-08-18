from django.contrib import admin
from threats.models import ETLRun, NvdEnrichment, Vulnerability

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


@admin.register(ETLRun)
class ETLRunAdmin(admin.ModelAdmin):
    list_display = ('source', 'status', 'started_at', 'finished_at', 'rows_extracted', 'rows_inserted', 'rows_updated', 'rows_failed')
    list_filter = ('source', 'status')
    ordering = ('-started_at',)
    readonly_fields = [f.name for f in ETLRun._meta.fields]

    def has_add_permission(self, request):
        # ETLRun rows are only ever created by the ETL commands themselves.
        return False