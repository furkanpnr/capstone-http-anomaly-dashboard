from django.shortcuts import render, HttpResponse

# Create your views here.


def home(request):
    return render(request, 'base.html')

def dashboard_view(request):
    context = {
        'active_menu': 'dashboard'
    }
    return render(request, 'dashboard/dashboard.html', context)
