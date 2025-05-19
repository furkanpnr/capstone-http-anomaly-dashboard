import logging
from django.shortcuts import render, HttpResponse, redirect
from django.http import JsonResponse
from django.conf import settings
from django.contrib import messages
from django.utils import timezone
import os
from datetime import datetime, timedelta, time
from django.contrib.auth import update_session_auth_hash, login as auth_login, logout as auth_logout
from django.contrib.auth.forms import PasswordChangeForm, AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.db.models.functions import TruncHour
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db import models

from .models import ModelConfig, HttpLog, RiskLevel, AttackType
from .modules.ml_log_analyzer import MLLogAnalyzer

logger = logging.getLogger(__name__)

# Global analyzer instance
global_analyzer = None

def initialize_analyzer():
    """Initialize the global analyzer if ModelConfig exists"""
    global global_analyzer
    
    try:
        if ModelConfig.objects.filter(enabled=True).exists() and global_analyzer is None:
            try:
                print("[*] Initializing ML Log Analyzer...")
                global_analyzer = MLLogAnalyzer()
                
                log_file = os.getenv('HTTP_LOG_PATH')
                if not log_file:
                    log_file = os.path.join(settings.BASE_DIR, 'dashboard', 'data', 'http_log.txt')
                print(f"[*] Log file path: {log_file}")
                
                # Check if log file exists
                if not os.path.exists(log_file):
                    print(f"[-] WARNING: Log file not found at {log_file}")
                    logger.warning(f"Log file not found at {log_file}")
                    # Create empty file if not exists
                    with open(log_file, 'a') as f:
                        pass
                    print(f"[+] Created empty log file at {log_file}")
                
                global_analyzer.start_monitoring(log_file)
                print("[+] Log analyzer initialized successfully")
            except Exception as e:
                logger.error(f"Error initializing analyzer: {e}")
                print(f"[-] Error initializing analyzer: {e}")
    except Exception as e:
        logger.error(f"Error checking ModelConfig: {e}")
        print(f"[-] Database error: {e}")

def home_view(request):
    # Initialize analyzer if not already running
    initialize_analyzer()
    return render(request, 'dashboard/home.html')

@login_required
def dashboard_view(request):
    """View for the main dashboard page with real-time analytics"""
    
    # Initialize analyzer if not already running
    initialize_analyzer()
    
    # Get the last 24 hours timestamp
    last_24_hours = timezone.now() - timedelta(hours=24)
    
    # Get total statistics
    total_logs = HttpLog.objects.count()
    anomaly_logs = HttpLog.objects.exclude(label=AttackType.NORMAL).count()
    high_risk_logs = HttpLog.objects.filter(risk_level=RiskLevel.HIGH).count()
    
    # Calculate percentages for security status
    if total_logs > 0:
        normal_percentage = (total_logs - anomaly_logs) / total_logs * 100
        suspicious_percentage = anomaly_logs / total_logs * 100
    else:
        normal_percentage = 100
        suspicious_percentage = 0
    
    # Get hourly request data for the line chart
    hourly_requests = HttpLog.objects.filter(
        timestamp__gte=last_24_hours
    ).annotate(
        hour=TruncHour('timestamp')
    ).values('hour').annotate(
        count=Count('id')
    ).order_by('hour')
    
    # Prepare hourly data for the chart
    hours_data = {hour: 0 for hour in range(24)}
    for entry in hourly_requests:
        hour = entry['hour'].hour
        hours_data[hour] = entry['count']
    
    # Get attack type distribution for the bar chart
    attack_distribution = HttpLog.objects.exclude(
        label=AttackType.NORMAL
    ).filter(
        timestamp__gte=last_24_hours
    ).values('label').annotate(
        count=Count('id')
    ).order_by('-count')

    # Ensure all attack types are represented
    attack_types = {
        AttackType.SQLI: 0,
        AttackType.XSS: 0,
        AttackType.COMMAND_INJECTION: 0,
        AttackType.PATH_TRAVERSAL: 0
    }
    
    # Fill in actual counts
    for attack in attack_distribution:
        if attack['label'] in attack_types:
            attack_types[attack['label']] = attack['count']
    
    # Convert to ordered lists for the chart
    attack_labels = []
    attack_counts = []
    for attack_type, count in attack_types.items():
        attack_labels.append(dict(AttackType.choices)[attack_type])
        attack_counts.append(count)
    
    # Get recent anomaly records - limit to 5
    recent_anomalies = HttpLog.objects.exclude(
        label=AttackType.NORMAL
    ).order_by('-timestamp')[:5]
    
    # Determine current threat level
    high_risk_count = HttpLog.objects.filter(
        timestamp__gte=last_24_hours,
        risk_level=RiskLevel.HIGH
    ).count()
    
    medium_risk_count = HttpLog.objects.filter(
        timestamp__gte=last_24_hours,
        risk_level=RiskLevel.MEDIUM
    ).count()
    
    if high_risk_count > 0:
        threat_level = "High Level Threat"
        threat_icon_class = "text-danger"
    elif medium_risk_count > 0:
        threat_level = "Medium Level Threat"
        threat_icon_class = "text-warning"
    else:
        threat_level = "Low Level Threat"
        threat_icon_class = "text-success"
    
    context = {
        'active_menu': 'dashboard',
        # Chart data
        'hourly_requests': list(hours_data.values()),
        'attack_distribution': {
            'labels': attack_labels,
            'data': attack_counts
        },
        # Statistics
        'total_logs': total_logs,
        'anomaly_logs': anomaly_logs,
        'high_risk_logs': high_risk_logs,
        # Security status
        'normal_percentage': round(normal_percentage, 1),
        'suspicious_percentage': round(suspicious_percentage, 1),
        'threat_level': threat_level,
        'threat_icon_class': threat_icon_class,
        # Recent anomalies
        'recent_anomalies': recent_anomalies,
    }
    
    return render(request, 'dashboard/dashboard.html', context)

def settings_view(request):
    """View for model configuration settings"""
    try:
        # Get current config or create default
        config = ModelConfig.objects.filter(enabled=True).first()
        if not config:
            config = ModelConfig(
                model_name="BERT Anomaly Detector",
                version="1.0",
                trained_at=timezone.now(),
                scan_interval_seconds=60,
                batch_size=50,
                enabled=False,
                max_risk_level_to_alert=RiskLevel.HIGH
            )
        
        if request.method == 'POST':
            try:
                # Parse numeric values
                try:
                    config.scan_interval_seconds = int(request.POST.get('scan_interval_seconds'))
                    config.batch_size = int(request.POST.get('batch_size'))
                except (TypeError, ValueError) as e:
                    messages.error(request, 'Scan interval and batch size must be numeric values.')
                    raise e
                
                # Handle checkbox value
                config.enabled = request.POST.get('enabled') == 'on'
                
                # Email and risk level
                config.alert_email = request.POST.get('alert_email', '')
                config.max_risk_level_to_alert = request.POST.get('max_risk_level_to_alert', RiskLevel.HIGH)
                
                # Validate values
                if config.scan_interval_seconds < 1:
                    messages.error(request, 'Scan interval must be at least 1 second.')
                    raise ValueError('Invalid scan interval')
                
                if config.batch_size < 1:
                    messages.error(request, 'Batch size must be at least 1.')
                    raise ValueError('Invalid batch size')
                
                # Save config
                config.save()
                
                # Restart analyzer if enabled
                global global_analyzer
                if config.enabled:
                    if global_analyzer:
                        global_analyzer.stop_monitoring()
                    initialize_analyzer()
                elif global_analyzer:
                    global_analyzer.stop_monitoring()
                    global_analyzer = None
                
                messages.success(request, 'Settings saved successfully!')
                return redirect('settings')
                
            except Exception as e:
                logger.error(f"Error saving settings: {str(e)}")
                if not messages.get_messages(request):
                    messages.error(request, f'An error occurred while saving settings: {str(e)}')
    except Exception as e:
        logger.error(f"Error in settings view: {str(e)}")
        messages.error(request, f'An error occurred: {str(e)}')
    
    context = {
        'active_menu': 'settings',
        'config': config,
        'risk_levels': RiskLevel.choices
    }
    return render(request, 'dashboard/settings/general.html', context)

def graphs_view(request):
    """View for detailed graphs and analytics"""
    # Get the last 24 hours timestamp
    last_24_hours = timezone.now() - timedelta(hours=24)
    
    # HTTP Method Distribution
    method_counts = HttpLog.objects.values('method').annotate(
        count=Count('id')
    ).order_by('-count')
    
    method_data = {
        'GET': 0, 'POST': 0, 'PUT': 0, 'DELETE': 0, 'OPTIONS': 0
    }
    for item in method_counts:
        if item['method'] in method_data:
            method_data[item['method']] = item['count']
    
    # Status Code Distribution
    status_ranges = {
        '2xx Success': (200, 299),
        '3xx Redirect': (300, 399),
        '4xx Client Error': (400, 499),
        '5xx Server Error': (500, 599)
    }
    
    status_data = {name: 0 for name in status_ranges.keys()}
    for name, (start, end) in status_ranges.items():
        count = HttpLog.objects.filter(
            status_code__gte=start,
            status_code__lte=end
        ).count()
        status_data[name] = count
    
    # Risk Level Distribution
    risk_counts = HttpLog.objects.values('risk_level').annotate(
        count=Count('id')
    ).order_by('risk_level')
    
    risk_data = {
        'High': 0, 'Medium': 0, 'Low': 0, 'Normal': 0
    }
    for item in risk_counts:
        level = dict(RiskLevel.choices)[item['risk_level']]
        risk_data[level] = item['count']
    
    # Top Attack Sources (IP addresses with most anomalies)
    source_distribution = HttpLog.objects.exclude(
        label=AttackType.NORMAL
    ).values('ip').annotate(
        count=Count('id')
    ).order_by('-count')[:5]
    
    context = {
        'active_menu': 'graphs',
        'method_distribution': {
            'data': list(method_data.values())
        },
        'status_distribution': {
            'data': list(status_data.values())
        },
        'risk_distribution': {
            'data': list(risk_data.values())
        },
        'source_distribution': {
            'labels': [item['ip'] for item in source_distribution],
            'data': [item['count'] for item in source_distribution]
        }
    }
    return render(request, 'dashboard/graphs.html', context)

def anomalies_view(request):
    """View for anomaly records with pagination"""
    # Sıralama için GET parametresini kontrol et
    sort_by = request.GET.get('sort', '-timestamp')  # Varsayılan olarak en yeni tarih
    
    # Sayfada gösterilecek kayıt sayısı için GET parametresini kontrol et
    records_per_page = int(request.GET.get('records', 10))  # Varsayılan olarak 10 kayıt
    
    # Get all anomalies except normal logs
    anomalies = HttpLog.objects.exclude(
        label=AttackType.NORMAL
    ).order_by(sort_by)
    
    # Pagination
    page_number = request.GET.get('page', 1)
    paginator = Paginator(anomalies, records_per_page)  # Belirtilen sayıda anomali göster
    page_obj = paginator.get_page(page_number)
    
    # Calculate page range for pagination
    page_range = get_pagination_range(paginator, page_obj.number, 5)
    
    # En son tespit edilen 3 anomali
    latest_anomalies = HttpLog.objects.exclude(
        label=AttackType.NORMAL
    ).order_by('-scanned_at')[:3]
    
    context = {
        'active_menu': 'anomalies',
        'page_obj': page_obj,
        'page_range': page_range,
        'latest_anomalies': latest_anomalies,
        'current_sort': sort_by,
        'current_records': records_per_page
    }
    return render(request, 'dashboard/anomalies.html', context)

def get_pagination_range(paginator, current_page, range_size=5):
    """Helper function to get pagination range"""
    start = max(current_page - range_size // 2, 1)
    end = min(start + range_size - 1, paginator.num_pages)
    
    if end - start + 1 < range_size and start > 1:
        start = max(end - range_size + 1, 1)
    
    return range(start, end + 1)

def traffic_view(request):
    """View for HTTP traffic logs with filtering and pagination"""
    # Filtreleme parametrelerini al
    method = request.GET.get('method', '')
    status_code = request.GET.get('status_code', '')
    ip = request.GET.get('ip', '')
    url = request.GET.get('url', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    
    # Temel sorgu
    logs = HttpLog.objects.all()
    
    # Filtreleri uygula
    if method:
        logs = logs.filter(method=method)
    if status_code:
        logs = logs.filter(status_code=status_code)
    if ip:
        logs = logs.filter(ip__icontains=ip)
    if url:
        logs = logs.filter(url__icontains=url)
    if date_from:
        try:
            date_from = datetime.strptime(date_from, '%Y-%m-%d').date()
            logs = logs.filter(timestamp__date__gte=date_from)
        except ValueError:
            pass
    if date_to:
        try:
            date_to = datetime.strptime(date_to, '%Y-%m-%d').date()
            logs = logs.filter(timestamp__date__lte=date_to)
        except ValueError:
            pass
    
    # Sıralama
    logs = logs.order_by('-timestamp')
    
    # Pagination
    page_number = request.GET.get('page', 1)
    paginator = Paginator(logs, 10)  # Her sayfada 10 kayıt
    
    try:
        page_obj = paginator.get_page(page_number)
    except EmptyPage:
        page_obj = paginator.page(paginator.num_pages)
    
    # Pagination aralığını hesapla
    page_range = get_pagination_range(paginator, page_obj.number, 5)
    
    # Unique değerleri al (filtre seçenekleri için)
    unique_methods = HttpLog.objects.values_list('method', flat=True).distinct()
    unique_status_codes = HttpLog.objects.values_list('status_code', flat=True).distinct()
    
    context = {
        'active_menu': 'traffic',
        'page_obj': page_obj,
        'page_range': page_range,
        'unique_methods': unique_methods,
        'unique_status_codes': unique_status_codes,
        # Mevcut filtre değerlerini context'e ekle
        'filters': {
            'method': method,
            'status_code': status_code,
            'ip': ip,
            'url': url,
            'date_from': date_from,
            'date_to': date_to,
        }
    }
    return render(request, 'dashboard/traffic.html', context)

def daily_report_view(request):
    """View for daily report with detailed HTTP traffic and anomaly analysis"""
    # Initialize analyzer if not already running
    initialize_analyzer()
    
    # Selected date or default to today
    selected_date = request.GET.get('date', timezone.now().date())
    if isinstance(selected_date, str):
        try:
            selected_date = datetime.strptime(selected_date, '%Y-%m-%d').date()
        except ValueError:
            selected_date = timezone.now().date()

    # Get logs for the selected day
    start_of_day = timezone.make_aware(datetime.combine(selected_date, time.min))
    end_of_day = timezone.make_aware(datetime.combine(selected_date, time.max))
    
    # Debug print
    print(f"[*] Fetching logs for date: {selected_date}")
    print(f"[*] Time range: {start_of_day} to {end_of_day}")
    
    daily_logs = HttpLog.objects.filter(
        timestamp__range=(start_of_day, end_of_day)
    )
    
    # Debug print
    log_count = daily_logs.count()
    print(f"[*] Found {log_count} logs for the selected date")

    # Basic statistics
    total_requests = daily_logs.count()
    anomaly_logs = daily_logs.exclude(label=AttackType.NORMAL).count()
    anomaly_rate = round((anomaly_logs / total_requests * 100), 1) if total_requests > 0 else 0
    normal_rate = round(100 - anomaly_rate, 1)

    # Hourly traffic distribution
    hourly_traffic = daily_logs.annotate(
        hour=TruncHour('timestamp')
    ).values('hour').annotate(
        total=Count('id'),
        anomalies=Count('id', filter=~models.Q(label=AttackType.NORMAL))
    ).order_by('hour')

    # Convert hourly data to JSON format
    hourly_data = []
    for hour in range(24):
        current_hour = timezone.make_aware(datetime.combine(selected_date, time(hour=hour)))
        hour_data = next(
            (item for item in hourly_traffic if item['hour'].hour == hour),
            {'hour': current_hour, 'total': 0, 'anomalies': 0}
        )
        hourly_data.append({
            'hour': hour_data['hour'].strftime('%H:00'),
            'total': hour_data['total'],
            'anomalies': hour_data['anomalies'],
            'normal': hour_data['total'] - hour_data['anomalies']
        })

    # Risk level distribution
    risk_distribution = daily_logs.values('risk_level').annotate(
        count=Count('id')
    ).order_by('risk_level')

    risk_data = {
        RiskLevel.HIGH: 0,
        RiskLevel.MEDIUM: 0,
        RiskLevel.LOW: 0,
        RiskLevel.NORMAL: 0
    }
    
    for item in risk_distribution:
        risk_data[item['risk_level']] = item['count']

    # Attack type distribution
    attack_distribution = daily_logs.exclude(
        label=AttackType.NORMAL
    ).values('label').annotate(
        count=Count('id')
    ).order_by('-count')

    attack_data = []
    for attack in attack_distribution:
        attack_data.append({
            'label': dict(AttackType.choices)[attack['label']],
            'count': attack['count']
        })

    # HTTP Method distribution
    method_distribution = daily_logs.values('method').annotate(
        count=Count('id')
    ).order_by('-count')

    # Status code distribution
    status_ranges = {
        '2xx Success': (200, 299),
        '3xx Redirect': (300, 399),
        '4xx Client Error': (400, 499),
        '5xx Server Error': (500, 599)
    }

    status_data = []
    for name, (start, end) in status_ranges.items():
        count = daily_logs.filter(
            status_code__gte=start,
            status_code__lte=end
        ).count()
        if count > 0:
            status_data.append({
                'label': name,
                'count': count
            })

    # Most targeted URLs
    top_urls = daily_logs.exclude(
        label=AttackType.NORMAL
    ).values('url').annotate(
        total=Count('id')
    ).order_by('-total')[:5]

    # Top attacking IPs
    top_ips = daily_logs.exclude(
        label=AttackType.NORMAL
    ).values('ip').annotate(
        total=Count('id')
    ).order_by('-total')[:5]

    context = {
        'active_menu': 'daily_report',
        'selected_date': selected_date,
        # Basic metrics
        'total_requests': total_requests,
        'anomaly_logs': anomaly_logs,
        'anomaly_rate': anomaly_rate,
        'normal_rate': normal_rate,
        # Chart data
        'hourly_data': hourly_data,
        'risk_data': [
            {'label': dict(RiskLevel.choices)[level], 'count': count}
            for level, count in risk_data.items()
        ],
        'attack_data': attack_data,
        'method_data': list(method_distribution),
        'status_data': status_data,
        # Table data
        'top_urls': top_urls,
        'top_ips': top_ips
    }

    # Report format check
    report_format = request.GET.get('format', 'html')
    if report_format == 'pdf':
        # PDF report generation
        return render_pdf_report(request, 'daily', context)
    elif report_format == 'csv':
        # CSV report generation
        return export_csv_report(request, 'daily', daily_logs)
    elif report_format == 'json':
        # JSON report generation
        return JsonResponse(context)

    return render(request, 'dashboard/reports/daily_report.html', context)

def weekly_report_view(request):
    """Haftalık rapor görünümü - Detaylı HTTP trafiği ve anomali analizi"""
    # Varsayılan olarak bu hafta
    today = timezone.now().date()
    default_week_start = today - timedelta(days=today.weekday())
    default_week_end = default_week_start + timedelta(days=6)

    # Seçilen hafta
    selected_week = request.GET.get('week', '')
    print(f"Seçilen hafta değeri: {selected_week}")

    week_start = default_week_start
    week_end = default_week_end

    if selected_week:
        try:
            # ISO hafta formatını parse et (örn: 2024-W18)
            year, week = selected_week.split('-W')
            year, week = int(year), int(week)
            
            # Seçilen haftanın başlangıç gününü bul
            # %V kullanarak ISO hafta numarasını doğru şekilde işle
            first_day = f"{year}-01-01"
            first_day_date = datetime.strptime(first_day, '%Y-%m-%d')
            
            # ISO hafta 1'in başlangıç gününü bul
            iso_start = first_day_date - timedelta(days=first_day_date.weekday())
            # Seçilen haftanın başlangıç gününü hesapla
            week_start = iso_start + timedelta(weeks=week-1)
            week_end = week_start + timedelta(days=6)
            
            # datetime'dan date'e çevir
            week_start = week_start.date()
            week_end = week_end.date()
            
            print(f"Hesaplanan tarihler - Başlangıç: {week_start}, Bitiş: {week_end}")
            
        except (ValueError, TypeError) as e:
            print(f"Hata oluştu: {e}")
            week_start = default_week_start
            week_end = default_week_end
            print(f"Varsayılan tarihlere dönüldü - Başlangıç: {week_start}, Bitiş: {week_end}")

    # Haftalık log kayıtları
    weekly_logs = HttpLog.objects.filter(
        timestamp__date__range=[week_start, week_end]
    )

    print(f"Bulunan log sayısı: {weekly_logs.count()}")

    # Temel istatistikler
    total_requests = weekly_logs.count()
    anomaly_logs = weekly_logs.exclude(label=AttackType.NORMAL).count()
    anomaly_rate = round((anomaly_logs / total_requests * 100), 1) if total_requests > 0 else 0
    normal_rate = round(100 - anomaly_rate, 1)

    # Günlük trafik ve anomali trendi
    daily_stats = []
    daily_trend_data = []
    
    for i in range(7):
        current_date = week_start + timedelta(days=i)
        daily_logs = weekly_logs.filter(timestamp__date=current_date)
        
        # Günlük toplam ve anomali sayıları
        daily_total = daily_logs.count()
        daily_anomalies = daily_logs.exclude(label=AttackType.NORMAL)
        anomaly_count = daily_anomalies.count()
        
        # En yaygın anomali türü
        most_common = daily_anomalies.values('label').annotate(
            count=Count('id')
        ).order_by('-count').first()

        # Risk seviyesi dağılımı
        high_risk = daily_anomalies.filter(risk_level=RiskLevel.HIGH).count()
        medium_risk = daily_anomalies.filter(risk_level=RiskLevel.MEDIUM).count()

        # Risk durumu belirleme
        if high_risk > 0:
            status = {'level': 'danger', 'text': 'High Risk'}
        elif medium_risk > 0:
            status = {'level': 'warning', 'text': 'Medium Risk'}
        else:
            status = {'level': 'success', 'text': 'Low Risk'}

        # Günlük istatistikleri kaydet
        daily_stats.append({
            'date': current_date,
            'total_requests': daily_total,
            'anomalies': anomaly_count,
            'rate': round((anomaly_count / daily_total * 100), 1) if daily_total > 0 else 0,
            'most_common_anomaly': dict(AttackType.choices)[most_common['label']] if most_common else 'N/A',
            'status': status
        })

        # Trend verisi için
        daily_trend_data.append({
            'date': current_date.strftime('%A'),
            'total': daily_total,
            'anomalies': anomaly_count,
            'normal': daily_total - anomaly_count
        })

    # Risk seviyesi dağılımı
    risk_distribution = weekly_logs.values('risk_level').annotate(
        count=Count('id')
    ).order_by('risk_level')

    risk_data = {
        RiskLevel.HIGH: 0,
        RiskLevel.MEDIUM: 0,
        RiskLevel.LOW: 0,
        RiskLevel.NORMAL: 0
    }
    
    for item in risk_distribution:
        risk_data[item['risk_level']] = item['count']

    # Anomali türleri dağılımı
    attack_distribution = weekly_logs.exclude(
        label=AttackType.NORMAL
    ).values('label').annotate(
        count=Count('id')
    ).order_by('-count')

    attack_data = []
    for attack in attack_distribution:
        attack_data.append({
            'label': dict(AttackType.choices)[attack['label']],
            'count': attack['count']
        })

    # En çok hedeflenen URL'ler
    top_urls = weekly_logs.exclude(
        label=AttackType.NORMAL
    ).values('url').annotate(
        total=Count('id')
    ).order_by('-total')[:5]

    # En çok anomali üreten IP'ler
    top_ips = weekly_logs.exclude(
        label=AttackType.NORMAL
    ).values('ip').annotate(
        total=Count('id')
    ).order_by('-total')[:5]

    # ISO hafta numarasını hesapla
    iso_year, iso_week, _ = week_start.isocalendar()
    week_value = f"{iso_year}-W{str(iso_week).zfill(2)}"

    context = {
        'active_menu': 'weekly_report',
        'week_start': week_start,
        'week_end': week_end,
        'week_value': week_value,  # Input için ISO hafta değeri
        # Temel metrikler
        'total_requests': total_requests,
        'anomaly_logs': anomaly_logs,
        'anomaly_rate': anomaly_rate,
        'normal_rate': normal_rate,
        # Chart verileri
        'daily_trend': daily_trend_data,
        'risk_data': [
            {'label': dict(RiskLevel.choices)[level], 'count': count}
            for level, count in risk_data.items()
        ],
        'attack_data': attack_data,
        # Tablo verileri
        'daily_stats': daily_stats,
        'top_urls': top_urls,
        'top_ips': top_ips
    }

    return render(request, 'dashboard/reports/weekly_report.html', context)

def monthly_report_view(request):
    """Aylık rapor görünümü"""
    # Seçilen ay veya varsayılan olarak bu ay
    today = timezone.now().date()
    month_start = today.replace(day=1)
    next_month = month_start.replace(month=month_start.month % 12 + 1, year=month_start.year + month_start.month // 12)
    month_end = next_month - timedelta(days=1)

    selected_month = request.GET.get('month', '')
    if selected_month:
        try:
            year, month = selected_month.split('-')
            month_start = datetime(int(year), int(month), 1).date()
            if month == '12':
                next_month = datetime(int(year) + 1, 1, 1).date()
            else:
                next_month = datetime(int(year), int(month) + 1, 1).date()
            month_end = next_month - timedelta(days=1)
        except ValueError:
            pass

    # Aylık log kayıtları
    monthly_logs = HttpLog.objects.filter(
        timestamp__date__range=[month_start, month_end]
    )

    # Temel istatistikler
    total_requests = monthly_logs.count()
    anomaly_logs = monthly_logs.exclude(label=AttackType.NORMAL).count()
    anomaly_rate = (anomaly_logs / total_requests * 100) if total_requests > 0 else 0
    normal_rate = 100 - anomaly_rate

    # Risk seviyesi dağılımı
    risk_distribution = monthly_logs.values('risk_level').annotate(
        count=Count('id')
    ).order_by('risk_level')

    risk_data = []
    for risk in risk_distribution:
        risk_data.append({
            'label': dict(RiskLevel.choices)[risk['risk_level']],
            'count': risk['count']
        })

    # En çok hedeflenen endpoint'ler
    targeted_endpoints = monthly_logs.exclude(
        label=AttackType.NORMAL
    ).values('url').annotate(
        anomaly_count=Count('id')
    ).order_by('-anomaly_count')[:5]

    # Toplam anomali sayısı
    total_anomalies = sum(endpoint['anomaly_count'] for endpoint in targeted_endpoints)
    
    # Yüzdeleri hesapla
    for endpoint in targeted_endpoints:
        endpoint['rate'] = round((endpoint['anomaly_count'] / total_anomalies * 100), 1) if total_anomalies > 0 else 0

    # En çok saldıran IP'ler
    attacking_ips = monthly_logs.exclude(
        label=AttackType.NORMAL
    ).values('ip').annotate(
        anomaly_count=Count('id')
    ).order_by('-anomaly_count')[:5]

    # Günlük trafik ve anomali trendi
    daily_trend = []
    current_date = month_start
    
    while current_date <= month_end:
        daily_logs = monthly_logs.filter(timestamp__date=current_date)
        daily_total = daily_logs.count()
        daily_anomalies = daily_logs.exclude(label=AttackType.NORMAL).count()
        
        daily_trend.append({
            'date': current_date.strftime('%Y-%m-%d'),
            'total': daily_total,
            'anomalies': daily_anomalies,
            'normal': daily_total - daily_anomalies
        })
        
        current_date += timedelta(days=1)

    context = {
        'active_menu': 'monthly_report',
        'month_start': month_start,
        'month_end': month_end,
        'total_requests': total_requests,
        'anomaly_logs': anomaly_logs,
        'anomaly_rate': round(anomaly_rate, 1),
        'normal_rate': round(normal_rate, 1),
        'risk_data': risk_data,
        'targeted_endpoints': list(targeted_endpoints),
        'attacking_ips': list(attacking_ips),
        'daily_trend': daily_trend
    }
    return render(request, 'dashboard/reports/monthly_report.html', context)

@login_required
def user_settings_view(request):
    """Kullanıcı ayarları sayfasını görüntüler"""
    context = {
        'active_menu': 'user_settings',
        'user': request.user
    }
    return render(request, 'dashboard/settings/user.html', context)

@login_required
def update_profile(request):
    """Updates user profile information"""
    if request.method == 'POST':
        user = request.user
        user.first_name = request.POST.get('first_name', '')
        user.last_name = request.POST.get('last_name', '')
        
        try:
            user.save()
            messages.success(request, 'Profile information updated successfully.')
        except Exception as e:
            messages.error(request, f'An error occurred while updating profile: {str(e)}')
    
    return redirect('user_settings')

@login_required
def change_password(request):
    """Changes user password"""
    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        
        # Password validation
        if not request.user.check_password(current_password):
            messages.error(request, 'Current password is incorrect.')
            return redirect('user_settings')
        
        # New password check
        if new_password != confirm_password:
            messages.error(request, 'New passwords do not match.')
            return redirect('user_settings')
        
        # Password complexity check
        if len(new_password) < 8:
            messages.error(request, 'Password must be at least 8 characters long.')
            return redirect('user_settings')
        
        # Change password
        try:
            request.user.set_password(new_password)
            request.user.save()
            update_session_auth_hash(request, request.user)  # Keeps the session active
            messages.success(request, 'Password changed successfully.')
        except Exception as e:
            messages.error(request, f'An error occurred while changing password: {str(e)}')
        
    return redirect('user_settings')

def anomaly_detail(request, anomaly_id):
    """API endpoint for anomaly details"""
    try:
        # Get anomaly record
        anomaly = HttpLog.objects.get(id=anomaly_id)
        
        # Format the data
        data = {
            'id': anomaly.id,
            'timestamp': anomaly.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'ip': anomaly.ip,
            'method': anomaly.method,
            'url': anomaly.url,
            'status_code': anomaly.status_code,
            'label': anomaly.get_label_display(),  # Get display name for label
            'risk_level': anomaly.get_risk_level_display(),  # Get display name for risk level
            'user_agent': anomaly.user_agent,
            'referrer': anomaly.referrer,
            'raw_log': anomaly.raw_log
        }
        
        return JsonResponse(data)
        
    except HttpLog.DoesNotExist:
        return JsonResponse({
            'error': 'Anomaly record not found'
        }, status=404)
        
    except Exception as e:
        logger.error(f"Error in anomaly_detail: {str(e)}")
        return JsonResponse({
            'error': 'An error occurred while fetching anomaly details'
        }, status=500)

def login_view(request):
    """Kullanıcı giriş sayfası"""
    if request.user.is_authenticated:
        return redirect('dashboard')
        
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            auth_login(request, form.get_user())
            messages.success(request, 'Başarıyla giriş yaptınız.')
            return redirect('dashboard')
        else:
            messages.error(request, 'Kullanıcı adı veya şifre hatalı.')
    
    return render(request, 'dashboard/auth/login.html')

def logout_view(request):
    """Kullanıcı çıkış işlemi"""
    auth_logout(request)
    messages.success(request, 'Başarıyla çıkış yaptınız.')
    return redirect('home')
