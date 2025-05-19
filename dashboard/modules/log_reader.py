import os
import time
from typing import List, Generator, Optional, Dict, Any
import json
import threading
import logging
from datetime import datetime
from functools import lru_cache
from http_anomaly_detector.settings import LOG_TYPE
from urllib.parse import unquote, urlparse

logger = logging.getLogger(__name__)


class HTTPLogReader:
    """
    HTTP log okuyucu sınıfı.

    Bu sınıf, HTTP log dosyalarını okuma, izleme ve analiz etme işlevselliği sağlar.
    Performans için optimize edilmiştir ve çeşitli okuma modlarını destekler.
    """

    def __init__(self, log_path: str, encoding: str = 'utf-8', max_cache_size: int = 1000):
        """
        HTTPLogReader sınıfını başlatır.

        Args:
            log_path (str): Log dosyasının tam yolu
            encoding (str, optional): Log dosyasının encoding türü. Varsayılan: 'utf-8'
            max_cache_size (int, optional): LRU önbellek boyutu. Varsayılan: 1000

        Raises:
            FileNotFoundError: Log dosyası bulunamazsa
        """
        self.log_path = os.path.abspath(log_path)
        self.encoding = encoding
        self.max_cache_size = max_cache_size
        self._stop_watching = threading.Event()

        # Dosya kontrolü
        if not os.path.exists(self.log_path):
            raise FileNotFoundError(f"Log dosyası bulunamadı: {self.log_path}")

        # İzleme thread'i için referans
        self._watch_thread = None

    def read_all(self) -> List[str]:
        """
        Log dosyasındaki tüm satırları okur ve döndürür.

        Returns:
            List[str]: Log satırlarının listesi
        """
        try:
            with open(self.log_path, 'r', encoding=self.encoding) as file:
                return file.readlines()
        except Exception as e:
            logger.error(f"Log okunurken hata oluştu: {str(e)}")
            return []

    def read_from_position(self, position: int) -> List[str]:
        """
        Belirtilen byte pozisyonundan itibaren log dosyasını okur.

        Args:
            position (int): Okumaya başlanacak byte pozisyonu

        Returns:
            List[str]: Belirtilen pozisyondan itibaren okunan log satırları
        """
        try:
            with open(self.log_path, 'r', encoding=self.encoding) as file:
                file.seek(position)
                return file.readlines()
        except Exception as e:
            logger.error(f"Belirtilen pozisyondan okuma yapılırken hata oluştu: {str(e)}")
            return []

    def read_from_line(self, line_number: int) -> List[str]:
        """
        Belirtilen satır numarasından itibaren log dosyasını okur.

        Args:
            line_number (int): Okumaya başlanacak satır numarası (1'den başlar)

        Returns:
            List[str]: Belirtilen satırdan itibaren okunan log satırları
        """
        if line_number < 1:
            raise ValueError("Satır numarası en az 1 olmalıdır")

        try:
            with open(self.log_path, 'r', encoding=self.encoding) as file:
                # İlk n-1 satırı atla
                for _ in range(line_number - 1):
                    next(file, None)

                # Kalan satırları oku
                return file.readlines()
        except Exception as e:
            logger.error(f"Belirtilen satırdan okuma yapılırken hata oluştu: {str(e)}")
            return []

    def read_last_n_lines(self, n: int) -> List[str]:
        """
        Dosyanın son n satırını okur.

        Bu metod, büyük dosyalar için optimize edilmiştir.

        Args:
            n (int): Okunacak son satır sayısı

        Returns:
            List[str]: Son n satırın listesi
        """
        try:
            # Dosya küçükse veya n büyükse tüm dosyayı oku
            file_size = os.path.getsize(self.log_path)
            if file_size < 1024 * 1024 * 10:  # 10MB'dan küçükse
                with open(self.log_path, 'r', encoding=self.encoding) as file:
                    lines = file.readlines()
                    return lines[-n:] if len(lines) >= n else lines

            # Büyük dosyalar için sondan okuma stratejisi
            with open(self.log_path, 'rb') as file:
                # Başlangıçta dosyanın sonuna git
                file.seek(0, os.SEEK_END)
                size = file.tell()

                # Son n satırı bulmak için geriye doğru oku
                lines = []
                position = size - 1
                line_count = 0

                while position >= 0 and line_count < n:
                    file.seek(position)
                    char = file.read(1)

                    if char == b'\n' and position != size - 1:
                        line_count += 1
                        if line_count == n:
                            break

                    position -= 1

                # Bulunan pozisyondan itibaren satırları oku
                if position < 0:
                    file.seek(0)
                else:
                    file.seek(position + 1)

                # Satırları UTF-8 olarak dönüştür
                result = file.read().decode(self.encoding).splitlines(True)
                return result

        except Exception as e:
            logger.error(f"Son {n} satır okunurken hata oluştu: {str(e)}")
            return []

    def watch(self, interval: float = 1.0, callback=None):
        """
        Log dosyasını belirli aralıklarla izler ve yeni satırları okur.

        Args:
            interval (float, optional): Kontrol aralığı (saniye). Varsayılan: 1.0
            callback (callable, optional): Her yeni satır için çağrılacak fonksiyon.
                                          callback(new_lines) şeklinde çağrılacaktır.

        Note:
            Bu metod bir threaded işlemdir ve arka planda çalışır.
            Durdurulana kadar devam eder.
        """
        if self._watch_thread and self._watch_thread.is_alive():
            logger.warning("Zaten bir izleme işlemi çalışıyor")
            return

        self._stop_watching.clear()
        self._watch_thread = threading.Thread(
            target=self._watch_log_file,
            args=(interval, callback),
            daemon=True
        )
        self._watch_thread.start()

    def _watch_log_file(self, interval: float, callback):
        """
        Log dosyasını sürekli izleyen iç metod.

        Args:
            interval (float): Kontrol aralığı (saniye)
            callback (callable): Her yeni satır için çağrılacak fonksiyon
        """
        try:
            with open(self.log_path, 'r', encoding=self.encoding) as file:
                # Dosyanın sonuna git
                file.seek(0, os.SEEK_END)

                while not self._stop_watching.is_set():
                    # Yeni satırları kontrol et
                    new_lines = []
                    while True:
                        line = file.readline()
                        if not line:
                            break
                        new_lines.append(line)

                    # Yeni satır varsa callback'i çağır
                    if new_lines and callback:
                        try:
                            callback(new_lines)
                        except Exception as e:
                            logger.error(f"Callback çağrılırken hata oluştu: {str(e)}")

                    # Belirtilen aralık kadar bekle
                    time.sleep(interval)

                    # Dosya yeniden oluşturulduysa (rotasyon gibi durumlarda)
                    if not os.path.exists(self.log_path):
                        logger.warning("Log dosyası bulunamadı, bekleniyor...")
                        while not os.path.exists(self.log_path) and not self._stop_watching.is_set():
                            time.sleep(interval)

                        # Dosya tekrar oluşturulduysa, yeni dosyayı aç
                        if not self._stop_watching.is_set():
                            file.close()
                            file = open(self.log_path, 'r', encoding=self.encoding)
                            file.seek(0)
        except Exception as e:
            logger.error(f"Log dosyası izlenirken hata oluştu: {str(e)}")

    def stop_watching(self):
        """
        Log dosyasını izleme işlemini durdurur.
        """
        if self._watch_thread and self._watch_thread.is_alive():
            self._stop_watching.set()
            self._watch_thread.join(timeout=5.0)
            logger.info("Log izleme işlemi durduruldu")

    @lru_cache(maxsize=100)
    def parse_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        HTTP log satırını ayrıştırır ve sözlük olarak döndürür.

        Bu metod önbelleklenmiştir ve tekrarlanan aynı log satırları için hızlı yanıt verir.

        Args:
            line (str): Ayrıştırılacak log satırı

        Returns:
            Optional[Dict[str, Any]]: Ayrıştırılmış log bilgisi veya None (ayrıştırılamazsa)
        """
        line = line.strip()
        if not line:
            return None

        try:
            import re

            apache_pattern = re.compile(
                r'(?P<ip>\S+) - - \[(?P<timestamp>[^\]]+)\] '
                r'"(?P<method>\S+)\s(?P<url>\S+)\s(?P<protocol>[^"]+)" '
                r'(?P<status>\d{3}) (?P<size>\d+) '
                r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
            )

            nginx_pattern = re.compile(
                r'\[(?P<timestamp>[^\]]+)\]\s+-\s+'
                r'(?P<status1>\d{3})\s+(?P<status2>\d{3})\s+-\s+'
                r'(?P<method>\S+)\s+(?P<protocol>\S+)\s+(?P<host>\S+)\s+'
                r'"(?P<url>[^"]+)"\s+'
                r'\[Client (?P<client_ip>[^\]]+)\]\s+'
                r'\[Length (?P<length>\d+)\]\s+'
                r'\[Gzip (?P<gzip>[^\]]+)\]\s+'
                r'\[Sent-to (?P<sent_to>[^\]]+)\]\s+'
                r'"(?P<user_agent>[^"]+)"\s+'
                r'"(?P<referrer>[^"]*)"'
            )

            # LOG_TYPE'e göre regex seç
            if LOG_TYPE == 'nginx':
                match = nginx_pattern.match(line)
                if match:
                    g = match.groupdict()
                    timestamp = datetime.strptime(g['timestamp'], "%d/%b/%Y:%H:%M:%S %z")
                    decoded_url = unquote(g['url'])
                    ref_domain = unquote(g['referrer']) if g['referrer'] != "-" else ""

                    return {
                        "ip": g['client_ip'],
                        "timestamp": timestamp,
                        "method": g['method'],
                        "url": decoded_url,
                        "protocol": g['protocol'],
                        "status": int(g['status1']),
                        "size": int(g['length']),
                        "referrer": ref_domain,
                        "user_agent": g['user_agent'],
                        "raw": line,
                    }

            elif LOG_TYPE == 'apache':
                match = apache_pattern.match(line)
                if match:
                    g = match.groupdict()
                    timestamp = datetime.strptime(g['timestamp'], "%d/%b/%Y:%H:%M:%S %z")
                    decoded_url = unquote(g['url'])
                    ref_domain = unquote(g['referrer']) if g['referrer'] != "-" else ""

                    return {
                        "ip": g['ip'],
                        "timestamp": timestamp,
                        "method": g['method'],
                        "url": decoded_url,
                        "protocol": g['protocol'],
                        "status": int(g['status']),
                        "size": int(g['size']),
                        "referrer": ref_domain,
                        "user_agent": g['user_agent'],
                        "raw": line,
                    }

            # JSON formatındaki log satırları için
            try:
                data = json.loads(line)
                return data
            except json.JSONDecodeError:
                pass

            # Basit ayrıştırılamayan log için en azından ham veriyi döndür
            return {"raw": line, "parsed": False}

        except Exception as e:
            logger.debug(f"Log satırı ayrıştırılamadı: {str(e)}, satır: {line[:100]}")
            return {"raw": line, "parsed": False, "error": str(e)}

    def parse_logs(self, lines: List[str]) -> List[Dict[str, Any]]:
        """
        Log satırlarını toplu olarak ayrıştırır.

        Args:
            lines (List[str]): Ayrıştırılacak log satırları

        Returns:
            List[Dict[str, Any]]: Ayrıştırılmış log bilgileri
        """
        result = []
        for line in lines:
            parsed = self.parse_log_line(line)
            if parsed:
                result.append(parsed)
        return result

    def get_file_info(self) -> Dict[str, Any]:
        """
        Log dosyası hakkında bilgi döndürür.

        Returns:
            Dict[str, Any]: Dosya boyutu, son değiştirilme zamanı gibi bilgiler
        """
        try:
            stats = os.stat(self.log_path)
            return {
                "path": self.log_path,
                "size": stats.st_size,
                "size_human": self._human_readable_size(stats.st_size),
                "modified": datetime.fromtimestamp(stats.st_mtime),
                "created": datetime.fromtimestamp(stats.st_ctime),
                "exists": True
            }
        except FileNotFoundError:
            return {
                "path": self.log_path,
                "exists": False
            }
        except Exception as e:
            logger.error(f"Dosya bilgisi alınırken hata oluştu: {str(e)}")
            return {
                "path": self.log_path,
                "error": str(e)
            }

    @staticmethod
    def _human_readable_size(size: int) -> str:
        """
        Byte cinsinden boyutu insan okunabilir formata dönüştürür.

        Args:
            size (int): Byte cinsinden boyut

        Returns:
            str: İnsan okunabilir boyut (örn: '2.5 MB')
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0 or unit == 'TB':
                break
            size /= 1024.0
        return f"{size:.2f} {unit}"

    def __del__(self):
        """
        Sınıf temizlenirken izleme işlemini durdur.
        """
        self.stop_watching()