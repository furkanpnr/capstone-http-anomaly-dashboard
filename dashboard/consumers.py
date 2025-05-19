import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
import logging

logger = logging.getLogger(__name__)

class AnomalyConsumer(AsyncWebsocketConsumer):
    """
    Gerçek zamanlı anomali bildirimlerini yöneten websocket consumer
    """
    
    async def connect(self):
        """Websocket bağlantısı kurulduğunda çalışan metod"""
        # Anomali bildirim grubuna katıl
        await self.channel_layer.group_add(
            "anomaly_alerts",
            self.channel_name
        )
        await self.accept()
        logger.info(f"Yeni websocket bağlantısı kuruldu: {self.channel_name}")
    
    async def disconnect(self, close_code):
        """Bağlantı koptuğunda çalışan metod"""
        # Gruptan ayrıl
        await self.channel_layer.group_discard(
            "anomaly_alerts",
            self.channel_name
        )
        logger.info(f"Websocket bağlantısı kapatıldı: {self.channel_name}")

    async def receive(self, text_data):
        """
        Clienttan mesaj alındığında çalışan metod (bu uygulamada kullanılmıyor)
        """
        pass

    async def anomaly_alert(self, event):
        """
        Bir anomali tespit edildiğinde bu metod çağrılacak
        """
        # Alert bilgilerini al
        alert_data = event['data']
        
        # Client'a gönder
        await self.send(text_data=json.dumps(alert_data))

def send_anomaly_alert(data):
    """
    ML Analyzer'dan anomali tespit edildiğinde bildirim göndermek için kullanılacak yardımcı fonksiyon
    """
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        "anomaly_alerts",
        {
            "type": "anomaly_alert",
            "data": data
        }
    ) 