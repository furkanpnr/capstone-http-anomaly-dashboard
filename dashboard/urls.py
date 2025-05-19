from django.urls import path
from . import views

urlpatterns = [
    path('', views.home_view, name='home'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('dashboard/graphs/', views.graphs_view, name='graphs'),
    path('dashboard/anomalies/', views.anomalies_view, name='anomalies'),
    path('dashboard/traffic/', views.traffic_view, name='traffic'),
    path('dashboard/reports/daily/', views.daily_report_view, name='daily_report'),
    path('dashboard/reports/weekly/', views.weekly_report_view, name='weekly_report'),
    path('dashboard/reports/monthly/', views.monthly_report_view, name='monthly_report'),
    path('dashboard/settings/general/', views.settings_view, name='settings'),
    path('dashboard/settings/user/', views.user_settings_view, name='user_settings'),
    path('dashboard/settings/user/', views.user_settings_view, name='user_settings'),
    path('dashboard/settings/user/update-profile/', views.update_profile, name='update_profile'),
    path('dashboard/settings/user/change-password/', views.change_password, name='change_password'),
    path('dashboard/anomalies/<int:anomaly_id>/', views.anomaly_detail, name='anomaly_detail'),
    path('dashboard/logout/', views.logout_view, name='logout'),
    path('dashboard/login/', views.login_view, name='login'),
]