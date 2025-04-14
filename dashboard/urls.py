from django.urls import path
from . import views

urlpatterns = [
    path('', views.home_view, name='home'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('graphs/', views.graphs_view, name='graphs'),
    path('anomalies/', views.anomalies_view, name='anomalies'),
    path('traffic/', views.traffic_view, name='traffic'),
    path('reports/daily/', views.daily_report_view, name='daily_report'),
    path('reports/weekly/', views.weekly_report_view, name='weekly_report'),
    path('reports/monthly/', views.monthly_report_view, name='monthly_report'),
    path('settings/general/', views.settings_view, name='settings'),
    path('settings/user/', views.user_settings_view, name='user_settings'),
]