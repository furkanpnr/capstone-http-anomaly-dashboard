import os
from django.core.management.base import BaseCommand
from django.conf import settings
from dashboard.modules.ml_log_analyzer import MLLogAnalyzer

class Command(BaseCommand):
    help = 'HTTP loglarını izler ve anomali tespiti yapar'

    def add_arguments(self, parser):
        parser.add_argument(
            '--log-file',
            type=str,
            help='İzlenecek log dosyasının yolu',
            default=os.path.join(settings.BASE_DIR, 'dashboard', 'data', 'http_log.txt')
        )

    def handle(self, *args, **options):
        log_file = options['log_file']
        
        if not os.path.exists(log_file):
            self.stderr.write(self.style.ERROR(f'Log dosyası bulunamadı: {log_file}'))
            return

        self.stdout.write(self.style.SUCCESS(f'Log izleme başlatılıyor: {log_file}'))
        
        try:
            analyzer = MLLogAnalyzer()
            analyzer.start_monitoring(log_file)
            
            # Ctrl+C ile durdurulana kadar çalış
            try:
                while True:
                    input()
            except KeyboardInterrupt:
                analyzer.stop_monitoring()
                self.stdout.write(self.style.SUCCESS('Log izleme durduruldu'))
                
        except Exception as e:
            self.stderr.write(self.style.ERROR(f'Hata oluştu: {str(e)}')) 