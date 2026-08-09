from django.contrib import admin
from threats.models import Vulnerability

# Register your models here.
@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('cve_id', 'vendor', 'product', 'vulnerability_name', 'date_added', 'due_date', 'known_ransomware_use', 'source_updated_at')
    search_fields = ('cve_id', 'vendor', 'product', 'vulnerability_name', 'date_added', 'due_date', 'known_ransomware_use', 'source_updated_at')
    list_filter = ('cve_id', 'vendor', 'product', 'vulnerability_name', 'date_added', 'due_date', 'known_ransomware_use', 'source_updated_at')