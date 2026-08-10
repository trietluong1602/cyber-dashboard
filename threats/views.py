from datetime import timedelta

from django.db.models import Max
from django.shortcuts import render
from django.utils import timezone

from .models import Vulnerability


def dashboard(request):
    today = timezone.now().date()
    thirty_days_ago = today - timedelta(days=30)

    freshness = Vulnerability.objects.aggregate(
        last_imported=Max("source_updated_at"),
    )

    context = {
        "total_count": Vulnerability.objects.count(),
        "ransomware_count": Vulnerability.objects.filter(
            known_ransomware_use=True
        ).count(),
        "recent_count": Vulnerability.objects.filter(
            date_added__gte=thirty_days_ago
        ).count(),
        "last_imported": freshness["last_imported"],
    }
    return render(request, "threats/dashboard.html", context)