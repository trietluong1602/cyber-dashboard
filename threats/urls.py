from django.urls import path
from . import views

app_name = "threats"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
]