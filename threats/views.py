import threading
from datetime import timedelta
from statistics import median

from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.core.management import call_command
from django.core.paginator import Paginator
from django.db.models import Avg, Count, Max, Q
from django.db.models.functions import TruncMonth
from django.shortcuts import redirect, render, get_object_or_404
from django.utils import timezone
from django.views.decorators.http import require_POST

from .models import ETLRun, Vulnerability

# NVD's placeholders for "no CWE could be determined" — excluded from the
# top-weaknesses chart so it reflects real categories, not "unknown".
CWE_PLACEHOLDER_VALUES = ["NVD-CWE-noinfo", "NVD-CWE-Other"]

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
    due_soon_cutoff = today + timedelta(days=7)

    freshness = Vulnerability.objects.aggregate(
        last_imported=Max("source_updated_at"),
    )

    overdue_count = Vulnerability.objects.filter(
        due_date__isnull=False, due_date__lt=today
    ).count()
    due_soon_count = Vulnerability.objects.filter(
        due_date__gte=today, due_date__lte=due_soon_cutoff
    ).count()

    recent_vulnerabilities = (
        Vulnerability.objects.filter(date_added__isnull=False)
        .select_related("nvd")
        .order_by("-date_added")[:8]
    )

    top_vendors = (
        Vulnerability.objects.exclude(vendor="")
        .values("vendor")
        .annotate(count=Count("id"))
        .order_by("-count")[:8]
    )

    # Most recent run of each source, so a failed NVD run is visible even
    # if CISA's most recent run succeeded (and vice versa) — ordering by
    # `-started_at` alone would only show whichever ran last.
    latest_runs = {
        run.source: run
        for run in ETLRun.objects.order_by("source", "-started_at").distinct("source")
    }

    context = {
        "total_count": Vulnerability.objects.count(),
        "ransomware_count": Vulnerability.objects.filter(
            known_ransomware_use=True
        ).count(),
        "recent_count": Vulnerability.objects.filter(
            date_added__gte=thirty_days_ago
        ).count(),
        "overdue_count": overdue_count,
        "due_soon_count": due_soon_count,
        "last_imported": freshness["last_imported"],
        "recent_vulnerabilities": recent_vulnerabilities,
        "top_vendors": list(top_vendors),
        "latest_cisa_run": latest_runs.get(ETLRun.SOURCE_CISA),
        "latest_nvd_run": latest_runs.get(ETLRun.SOURCE_NVD),
    }
    return render(request, "threats/dashboard.html", context)


def etl_status(request):
    """Full ETL run history — the detail behind the dashboard's summary."""
    runs = ETLRun.objects.all()[:50]
    return render(request, "threats/etl_status.html", {"runs": runs})

def _run_refresh_in_background():
    """Runs on a background thread so the triggering request returns
    immediately instead of blocking on however long the ETL takes.

    Errors are intentionally swallowed here — refresh_all already records
    a failed ETLRun row per source with the real error message, which is
    what /etl-status/ shows. There's no request left to report back to by
    the time this thread finishes, so raising here would only crash a
    background thread no one is watching.
    """
    try:
        call_command("refresh_all")
    except Exception:
        pass


@staff_member_required
@require_POST
def trigger_refresh(request):
    """Manually kick off refresh_all from the browser.

    Gated to staff accounts: this is a stand-in for the real Checkpoint 4
    accounts system, which doesn't exist yet. An unauthenticated
    "run the ETL now" button on a public site would let anyone trigger
    outbound API calls on demand, so it's restricted to Django's existing
    admin auth in the meantime rather than left open.
    """
    thread = threading.Thread(target=_run_refresh_in_background, daemon=True)
    thread.start()
    messages.success(
        request,
        "Refresh started in the background. This page won't update live — "
        "reload in a minute or two to see the result.",
    )
    return redirect("threats:etl_status")


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


def analytics(request):
    # Severity distribution — bucket by NVD severity label.
    severity_counts = (
        Vulnerability.objects.filter(nvd__severity__gt="")
        .values("nvd__severity")
        .annotate(count=Count("id"))
        .order_by("-count")
    )

    # Top vendors — most-represented vendors in the catalog.
    top_vendors = (
        Vulnerability.objects.exclude(vendor="")
        .values("vendor")
        .annotate(count=Count("id"))
        .order_by("-count")[:10]
    )

    # CVEs over time — grouped by month added.
    cves_over_time = (
        Vulnerability.objects.filter(date_added__isnull=False)
        .annotate(month=TruncMonth("date_added"))
        .values("month")
        .annotate(count=Count("id"))
        .order_by("month")
    )

    # Known exploited vs. broader CVEs.
    total_count = Vulnerability.objects.count()
    known_exploited_count = Vulnerability.objects.filter(
        date_added__isnull=False
    ).count()

    # Ransomware association among known exploited vulnerabilities.
    ransomware_known = Vulnerability.objects.filter(
        known_ransomware_use=True
    ).count()
    ransomware_unknown = Vulnerability.objects.filter(
        date_added__isnull=False
    ).exclude(known_ransomware_use=True).count()

    # Top CWEs — real weakness categories only (placeholders excluded).
    top_cwes = (
        Vulnerability.objects.filter(nvd__cwe_id__gt="")
        .exclude(nvd__cwe_id__in=CWE_PLACEHOLDER_VALUES)
        .values("nvd__cwe_id")
        .annotate(count=Count("id"))
        .order_by("-count")[:10]
    )

    # Average / median CVSS. Median isn't a builtin Django aggregate,
    # so we pull the raw scores and compute it in Python — fine at
    # this dataset size, and keeps the query portable across DBs.
    cvss_scores = list(
        Vulnerability.objects.filter(nvd__cvss_score__isnull=False)
        .values_list("nvd__cvss_score", flat=True)
    )
    avg_cvss = round(sum(cvss_scores) / len(cvss_scores), 2) if cvss_scores else None
    median_cvss = round(median(cvss_scores), 2) if cvss_scores else None

    # Recently modified CVEs (per NVD's modified_date), most recent first.
    recently_modified = (
        Vulnerability.objects.filter(nvd__modified_date__isnull=False)
        .select_related("nvd")
        .order_by("-nvd__modified_date")[:10]
    )

    context = {
        "severity_counts": list(severity_counts),
        "top_vendors": list(top_vendors),
        "cves_over_time": list(cves_over_time),
        "total_count": total_count,
        "known_exploited_count": known_exploited_count,
        "ransomware_known": ransomware_known,
        "ransomware_unknown": ransomware_unknown,
        "top_cwes": list(top_cwes),
        "avg_cvss": avg_cvss,
        "median_cvss": median_cvss,
        "recently_modified": recently_modified,
    }
    return render(request, "threats/vulnerability_analytics.html", context)