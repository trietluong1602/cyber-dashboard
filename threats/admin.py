from django.contrib import admin
from threats.models import Vulnerability

# Register your models here.
@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('cve_id', 'vendor', 'product', 'vuln_name', 'date_added')
    search_fields = ('cve_id', 'vendor', 'product', 'vuln_name')
    list_filter = ('vendor', 'product', 'known_ransomware_use', 'date_added', 'source_updated_at')