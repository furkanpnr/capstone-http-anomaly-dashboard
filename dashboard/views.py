from django.shortcuts import render, HttpResponse

# Create your views here.


def home_view(request):
    return render(request, 'dashboard/home.html')

def dashboard_view(request):
    context = {
        'active_menu': 'dashboard'
    }
    return render(request, 'dashboard/dashboard.html', context)

# Anomali Grafikleri
def graphs_view(request):
    context = {
        'active_menu': 'graphs'
    }
    return render(request, 'dashboard/graphs.html', context)

# Tespit Edilen Anomaliler
def anomalies_view(request):
    context = {
        'active_menu': 'anomalies'
    }
    return render(request, 'dashboard/anomalies.html', context)

# HTTP Trafiği
def traffic_view(request):
    context = {
        'active_menu': 'traffic'
    }
    return render(request, 'dashboard/traffic.html', context)

# Günlük Rapor
def daily_report_view(request):
    context = {
        'active_menu': 'daily_report'
    }
    return render(request, 'dashboard/reports/daily_report.html', context)

# Haftalık Rapor
def weekly_report_view(request):
    context = {
        'active_menu': 'weekly_report'
    }
    return render(request, 'dashboard/reports/weekly_report.html', context)

# Aylık Rapor
def monthly_report_view(request):
    context = {
        'active_menu': 'monthly_report'
    }
    return render(request, 'dashboard/reports/monthly_report.html', context)

# Genel Ayarlar
def settings_view(request):
    context = {
        'active_menu': 'settings'
    }
    return render(request, 'dashboard/settings/general.html', context)

# Kullanıcı Ayarları
def user_settings_view(request):
    context = {
        'active_menu': 'user_settings'
    }
    return render(request, 'dashboard/settings/user.html', context)
