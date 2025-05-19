import os
import logging
import threading
import time
from typing import List, Dict, Any
from datetime import datetime

from django.conf import settings
from transformers import BertTokenizer, BertForSequenceClassification
import torch

from dashboard.models import ModelConfig, HttpLog, AttackType, RiskLevel
from dashboard.modules.log_reader import HTTPLogReader

# Consumers modülünü import et
try:
    from dashboard.consumers import send_anomaly_alert
    CHANNELS_AVAILABLE = True
except ImportError:
    CHANNELS_AVAILABLE = False
    print("Django Channels yüklenmemiş. Gerçek zamanlı bildirimler devre dışı.")

logger = logging.getLogger(__name__)

class MLLogAnalyzer:
    """
    A class that analyzes HTTP logs using a BERT model and saves results to the database.
    Works according to the settings in the ModelConfig table.
    """

    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.log_reader = None
        self.config = None
        self.stop_monitoring = threading.Event()
        self._monitoring_thread = None
        self.total_logs_processed = 0

        # Load BERT model
        self._load_model()

    def _load_model(self):
        """Loads the BERT model from the specified path"""
        try:
            # Use the dynamic path from settings
            model_path = settings.ML_MODEL_PATH
            model_name = os.path.basename(model_path)
            
            print(f"\n[*] Loading ML model: {model_path}")
            logger.info(f"Loading ML model from: {model_path}")
            
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Model directory not found at: {model_path}")
            
            self.tokenizer = BertTokenizer.from_pretrained(model_path)
            self.model = BertForSequenceClassification.from_pretrained(model_path)
            self.model.eval()  # Set to evaluation mode
            print(f"[+] {model_name} model loaded successfully!")
            logger.info(f"{model_name} model loaded successfully")
        except Exception as e:
            print(f"[-] Model loading error: {str(e)}")
            logger.error(f"Error loading model: {str(e)}")
            raise

    def _predict_log(self, log_data: Dict[str, Any]) -> tuple[str, str]:
        """
        Makes a prediction for a single log entry.

        Args:
            log_data: Dictionary containing log data

        Returns:
            tuple[str, str]: (attack_type, risk_level)
        """
        try:
            # Combine log data for prediction
            log_text = f"{log_data['url']} [SEP] {log_data['referrer']}"

            # Tokenize
            inputs = self.tokenizer(
                log_text,
                truncation=True,
                padding=True,
                return_tensors="pt"
            )

            # Make prediction
            with torch.no_grad():
                outputs = self.model(**inputs)
                predicted_class = torch.argmax(outputs.logits, dim=1).item()

            # Determine attack type
            attack_types = list(AttackType.choices)
            predicted_label = attack_types[predicted_class][0]

            # Determine risk level based on confidence
            attack_risk_map = {
                AttackType.SQLI: RiskLevel.HIGH,
                AttackType.COMMAND_INJECTION: RiskLevel.HIGH,
                AttackType.PATH_TRAVERSAL: RiskLevel.HIGH,
                AttackType.XSS: RiskLevel.MEDIUM,
            }

            if predicted_label == AttackType.NORMAL:
                risk_level = RiskLevel.NORMAL
            else:
                risk_level = attack_risk_map.get(predicted_label, RiskLevel.LOW)

            return predicted_label, risk_level

        except Exception as e:
            print(f"[-] Tahmin hatası: {str(e)}")
            logger.error(f"Error making prediction: {str(e)}")
            return AttackType.NORMAL, RiskLevel.LOW

    def _save_to_db(self, log_data: Dict[str, Any], label: str, risk_level: str):
        """Saves log data to the database"""
        try:
            # Veritabanına kaydet
            http_log = HttpLog.objects.create(
                ip=log_data['ip'],
                timestamp=log_data['timestamp'],
                method=log_data['method'],
                url=log_data['url'],
                protocol=log_data['protocol'],
                status_code=log_data['status'],
                size=log_data['size'],
                referrer=log_data['referrer'],
                user_agent=log_data['user_agent'],
                raw_log=log_data['raw'],
                label=label,
                risk_level=risk_level
            )
            
            print("\n=== Log Kaydı ===")
            print(f"URL      : {log_data['url']}")
            print(f"Referrer : {log_data['referrer']}")
            print(f"Label    : {label}")
            print(f"Risk     : {risk_level}")
            print("================\n")
            
            # Eğer anomali tespit edildiyse gerçek zamanlı bildirim gönder
            if label != AttackType.NORMAL and CHANNELS_AVAILABLE:
                # Ekranda gösterilecek bilgileri hazırla
                # str() ile çevirerek __proxy__ nesnelerini serialize edilebilir hale getir
                choices_dict = dict(AttackType.choices)
                attack_type_display = str(choices_dict[label])
                
                choices_dict = dict(RiskLevel.choices)
                risk_level_display = str(choices_dict[risk_level])
                
                # Bildirim verilerini oluştur
                alert_data = {
                    'id': http_log.id,
                    'timestamp': http_log.timestamp.strftime('%H:%M:%S'),
                    'ip': http_log.ip,
                    'url': http_log.url,
                    'attack_type': attack_type_display,
                    'risk_level': risk_level_display
                }
                
                # Websocket üzerinden bildirim gönder
                try:
                    send_anomaly_alert(alert_data)
                    print(f"[+] Gerçek zamanlı bildirim gönderildi: {attack_type_display}")
                except Exception as alert_error:
                    print(f"[-] Bildirim gönderme hatası: {str(alert_error)}")
            
        except Exception as e:
            print(f"[-] Veritabanı kayıt hatası: {str(e)}")
            logger.error(f"Error saving to database: {str(e)}")

    def process_logs(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Processes a list of logs and saves them to the database.
        Also returns the processed results for immediate use.

        Args:
            logs: List of logs to process

        Returns:
            List[Dict[str, Any]]: List of processed logs with predictions
        """
        results = []
        print(f"\n[*] Processing {len(logs)} logs...")
        
        for log in logs:
            label, risk_level = self._predict_log(log)
            self._save_to_db(log, label, risk_level)
            
            # Add prediction results to the log data
            log['predicted_label'] = label
            log['risk_level'] = risk_level
            results.append(log)
            
            self.total_logs_processed += 1
            
        print(f"[+] Total logs processed: {self.total_logs_processed}")
        return results

    def manual_scan(self, log_path: str, num_lines: int = 100) -> List[Dict[str, Any]]:
        """
        Performs a manual scan of the last N lines of the log file.
        This method is designed for on-demand scanning from the dashboard.

        Args:
            log_path: Path to the log file
            num_lines: Number of lines to scan (default: 100)

        Returns:
            List[Dict[str, Any]]: List of processed logs with predictions
        """
        try:
            print(f"\n[*] Starting manual scan - Last {num_lines} lines...")
            temp_reader = HTTPLogReader(log_path)
            lines = temp_reader.read_last_n_lines(num_lines)
            if not lines:
                print("[-] No logs found to read")
                return []
                
            parsed_logs = temp_reader.parse_logs(lines)
            return self.process_logs(parsed_logs)
            
        except Exception as e:
            print(f"[-] Manual scan error: {str(e)}")
            logger.error(f"Error during manual scan: {str(e)}")
            return []

    def start_monitoring(self, log_path: str):
        """
        Gerçek zamanlı log izlemeyi başlatır.

        Args:
            log_path: İzlenecek log dosyasının yolu
        """
        try:
            print("\n[*] Gerçek zamanlı log izleme başlatılıyor...")
            # Aktif config'i al
            self.config = ModelConfig.objects.filter(enabled=True).first()
            if not self.config:
                print("[-] Aktif ModelConfig bulunamadı!")
                logger.error("No active ModelConfig found")
                return

            # Log reader'ı başlat
            self.log_reader = HTTPLogReader(log_path)
            
            # İzlemeyi başlat
            self.stop_monitoring.clear()
            
            def process_new_logs(new_lines: List[str]):
                """Yeni logları işleyecek callback fonksiyonu"""
                try:
                    # Config'i yenile
                    self.config.refresh_from_db()
                    
                    if not self.config.enabled:
                        print("[-] İzleme devre dışı bırakıldı")
                        logger.info("Monitoring disabled")
                        self.stop_monitoring.set()
                        return

                    # Yeni logları işle
                    parsed_logs = self.log_reader.parse_logs(new_lines)
                    if parsed_logs:
                        print(f"\n[*] {len(parsed_logs)} yeni log bulundu")
                        self.process_logs(parsed_logs)

                except Exception as e:
                    print(f"[-] Log işleme hatası: {str(e)}")
                    logger.error(f"Error processing logs: {str(e)}")

            # Gerçek zamanlı izlemeyi başlat
            self.log_reader.watch(interval=1.0, callback=process_new_logs)
            
            print(f"[+] Gerçek zamanlı log izleme başlatıldı: {log_path}")
            logger.info(f"Real-time log monitoring started: {log_path}")
            
        except Exception as e:
            print(f"[-] İzleme başlatma hatası: {str(e)}")
            logger.error(f"Error starting monitoring: {str(e)}")

    def stop_monitoring(self):
        """Log izlemeyi durdurur"""
        try:
            if self.log_reader:
                print("\n[*] Log izleme durduruluyor...")
                self.stop_monitoring.set()
                self.log_reader.stop_watching()
                print("[+] Log izleme durduruldu")
                logger.info("Log monitoring stopped")
        except Exception as e:
            print(f"[-] İzleme durdurma hatası: {str(e)}")
            logger.error(f"Error stopping monitoring: {str(e)}") 