from django.urls import path
from . import views

app_name = "threats"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("vulnerabilities/", views.vulnerability_list, name="vulnerability_list"),
    path("vulnerabilities/<slug:cve_id>/", views.vulnerability_detail, name="vulnerability_detail"),
    path("analytics/", views.analytics, name="vulnerability_analytics"),
    path("etl-status/", views.etl_status, name="etl_status"),
    path("etl-status/refresh/", views.trigger_refresh, name="trigger_refresh"),
]