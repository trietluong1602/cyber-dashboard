from django.urls import path
from . import views

app_name = "threats"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("vulnerabilities/", views.vulnerability_list, name="vulnerability_list"),
    path("vulnerabilities/<slug:cve_id>/", views.vulnerability_detail, name="vulnerability_detail"),
]