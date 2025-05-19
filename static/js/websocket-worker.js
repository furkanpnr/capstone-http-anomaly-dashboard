// WebSocket Worker Script
// Bu worker, tüm sekmelerde/sayfalarda paylaşılan tek bir WebSocket bağlantısı sağlar

// Bağlantı tutan değişkenler
let socket = null;
let connections = [];
let reconnectTimer = null;
let isConnecting = false;

// WebSocket URL'i oluşturma fonksiyonu
function getWebSocketUrl() {
    const wsProtocol = self.location.protocol === 'https:' ? 'wss://' : 'ws://';
    const host = self.location.host;
    return `${wsProtocol}${host}/ws/anomaly_alerts/`;
}

// WebSocket bağlantısını kurma fonksiyonu
function connectWebSocket() {
    if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
        console.log("[Worker] WebSocket zaten bağlı veya bağlanıyor");
        return;
    }
    
    if (isConnecting) {
        console.log("[Worker] Bağlantı zaten başlatıldı");
        return;
    }
    
    isConnecting = true;
    
    try {
        const wsUrl = getWebSocketUrl();
        console.log(`[Worker] WebSocket bağlantısı kuruluyor: ${wsUrl}`);
        
        socket = new WebSocket(wsUrl);
        
        socket.onopen = function(e) {
            console.log("[Worker] WebSocket bağlantısı kuruldu");
            isConnecting = false;
            
            // Tüm bağlantılara bildir
            broadcastToAll({
                type: "connection_status",
                status: "connected"
            });
            
            // Yeniden bağlanma zamanlayıcısını temizle
            if (reconnectTimer) {
                clearTimeout(reconnectTimer);
                reconnectTimer = null;
            }
        };
        
        socket.onmessage = function(e) {
            try {
                const data = JSON.parse(e.data);
                console.log("[Worker] WebSocket mesajı alındı:", data);
                
                // Mesajı tüm bağlantılara ilet
                broadcastToAll({
                    type: "anomaly_alert",
                    data: data
                });
            } catch (error) {
                console.error("[Worker] WebSocket mesaj işleme hatası:", error);
            }
        };
        
        socket.onerror = function(e) {
            console.error("[Worker] WebSocket hatası:", e);
            isConnecting = false;
            
            // Tüm bağlantılara bildir
            broadcastToAll({
                type: "connection_status",
                status: "error",
                message: "Bağlantı hatası oluştu"
            });
        };
        
        socket.onclose = function(e) {
            console.log("[Worker] WebSocket bağlantısı kapandı. Yeniden bağlanılacak...");
            isConnecting = false;
            
            // Tüm bağlantılara bildir
            broadcastToAll({
                type: "connection_status",
                status: "disconnected"
            });
            
            // 3 saniye sonra yeniden bağlan
            if (!reconnectTimer) {
                reconnectTimer = setTimeout(connectWebSocket, 3000);
            }
        };
        
    } catch (error) {
        console.error("[Worker] WebSocket bağlantı hatası:", error);
        isConnecting = false;
        
        // 3 saniye sonra yeniden bağlan
        if (!reconnectTimer) {
            reconnectTimer = setTimeout(connectWebSocket, 3000);
        }
    }
}

// Tüm bağlantılara mesaj gönderme
function broadcastToAll(message) {
    connections.forEach(function(connection) {
        try {
            connection.postMessage(message);
        } catch (e) {
            console.error("[Worker] Broadcast hatası:", e);
        }
    });
}

// SharedWorker connection event
self.addEventListener('connect', function(e) {
    const port = e.ports[0];
    connections.push(port);
    
    console.log("[Worker] Yeni bağlantı eklendi, toplam:", connections.length);
    
    // Mesaj alındığında
    port.addEventListener('message', function(e) {
        const message = e.data;
        
        if (message.type === "connect") {
            // Bağlantı isteği
            if (!socket || socket.readyState !== WebSocket.OPEN) {
                connectWebSocket();
            } else {
                // Zaten bağlıysa durum bilgisi gönder
                port.postMessage({
                    type: "connection_status",
                    status: "connected"
                });
            }
        }
    });
    
    // Port'u başlat
    port.start();
    
    // Bağlantıyı kur
    if (!socket || socket.readyState !== WebSocket.OPEN) {
        connectWebSocket();
    }
    
    // Bağlantının düzgün temizlenmesi için
    port.addEventListener('close', function() {
        const index = connections.indexOf(port);
        if (index > -1) {
            connections.splice(index, 1);
            console.log("[Worker] Bağlantı kapatıldı, kalan:", connections.length);
        }
        
        // Eğer hiç bağlantı kalmadıysa WebSocket'i kapat
        if (connections.length === 0 && socket) {
            console.log("[Worker] Tüm bağlantılar kapandı, WebSocket kapatılıyor");
            socket.close();
            socket = null;
        }
    });
}); 