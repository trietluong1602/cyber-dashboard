from datetime import timedelta

from django.core.paginator import Paginator
from django.db.models import Max, Q
from django.shortcuts import render, get_object_or_404
from django.utils import timezone

from .models import Vulnerability

PAGE_SIZE = 25

# Maps the ?sort= query value to the actual order_by() arguments.
# Whitelisted rather than accepting raw field names from the querystring,
# so a request can't sort on an arbitrary/expensive field.
SORT_OPTIONS = {
    "-date_added": "Date added (newest)",
    "date_added": "Date added (oldest)",
    "vendor": "Vendor (A-Z)",
    "cve_id": "CVE ID",
    "due_date": "Due date",
    "-nvd__cvss_score": "Severity (highest first)",
}
DEFAULT_SORT = "-date_added"


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


def vulnerability_list(request):
    query = request.GET.get("q", "").strip()
    ransomware = request.GET.get("ransomware", "")
    sort = request.GET.get("sort", DEFAULT_SORT)
    if sort not in SORT_OPTIONS:
        sort = DEFAULT_SORT

    queryset = Vulnerability.objects.select_related("nvd").order_by(sort, "cve_id")

    if query:
        # Vendor/product/name/description cover CISA KEV records. A CVE
        # known only through NVD (no KEV entry) has none of those filled
        # in, so it can only be found through NVD's own description or
        # CWE classification — matched here too so it isn't invisible.
        queryset = queryset.filter(
            Q(cve_id__icontains=query)
            | Q(vendor__icontains=query)
            | Q(product__icontains=query)
            | Q(vulnerability_name__icontains=query)
            | Q(nvd__nvd_description__icontains=query)
            | Q(nvd__cwe_id__icontains=query)
        ).distinct()

    if ransomware == "known":
        queryset = queryset.filter(known_ransomware_use=True)

    total_count = queryset.count()

    paginator = Paginator(queryset, PAGE_SIZE)
    page_obj = paginator.get_page(request.GET.get("page"))

    params = request.GET.copy()
    params.pop("page", None)
    querystring = params.urlencode()

    context = {
        "page_obj": page_obj,
        "total_count": total_count,
        "query": query,
        "ransomware": ransomware,
        "sort": sort,
        "sort_options": SORT_OPTIONS,
        "querystring": querystring,
    }
    return render(request, "threats/vulnerability_list.html", context)


def vulnerability_detail(request, cve_id):
    vulnerability = get_object_or_404(
        Vulnerability.objects.select_related("nvd"), cve_id=cve_id
    )
    return render(request, "threats/vulnerability_detail.html", {"vulnerability": vulnerability})