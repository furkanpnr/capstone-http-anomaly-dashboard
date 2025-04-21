document.addEventListener('DOMContentLoaded', function() {
    // Ana grafikleri oluştur
    createTrafficCharts();
    createStatusCharts();
    createMethodCharts();
    createResponseTimeCharts();
    
    // Tema değiştiriciyi etkinleştir
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', toggleTheme);
    }
    
    // Tarih ve saat bilgisini güncelle
    updateDateTime();
    setInterval(updateDateTime, 60000); // Her dakika güncelle
});

// Grafikleri oluştur
function createTrafficCharts() {
    const trafficCtx = document.getElementById('trafficChart');
    if (!trafficCtx) return;
    
    // Saatlik etiketleri al
    const labels = getHourlyLabels();
    
    // Trafik verileri
    const data = {
        labels: labels,
        datasets: [
            {
                label: 'Normal Trafik',
                data: generateRandomData(24, 100, 500),
                borderColor: chartColors.primary,
                backgroundColor: chartColors.primaryTransparent,
                borderWidth: 2,
                fill: true,
                tension: 0.4
            },
            {
                label: 'Anormal Trafik',
                data: generateRandomData(24, 5, 50),
                borderColor: chartColors.danger,
                backgroundColor: chartColors.dangerTransparent,
                borderWidth: 2,
                fill: true,
                tension: 0.4
            }
        ]
    };
    
    // Çizgi grafiği oluştur
    createLineChart(trafficCtx, data, {
        showGrid: true,
        ticksColor: getComputedStyle(document.documentElement).getPropertyValue('--text-color').trim(),
        title: 'Günlük Trafik Analizi'
    });
}

function createStatusCharts() {
    const statusCtx = document.getElementById('statusChart');
    if (!statusCtx) return;
    
    // HTTP Durum kodları için veri
    const data = {
        labels: ['2xx', '3xx', '4xx', '5xx'],
        datasets: [{
            label: 'HTTP Durum Kodları',
            data: [65, 15, 12, 8],
            backgroundColor: [
                chartColors.success,
                chartColors.info,
                chartColors.warning,
                chartColors.danger
            ],
            borderColor: [
                chartColors.success,
                chartColors.info,
                chartColors.warning,
                chartColors.danger
            ],
            borderWidth: 1
        }]
    };
    
    // Pasta grafiği oluştur
    createDoughnutChart(statusCtx, data, {
        title: 'HTTP Durum Kodları Dağılımı'
    });
}

function createMethodCharts() {
    const methodCtx = document.getElementById('methodChart');
    if (!methodCtx) return;
    
    // HTTP Metod verileri
    const data = {
        labels: ['GET', 'POST', 'PUT', 'DELETE', 'OTHER'],
        datasets: [{
            label: 'HTTP Metodları',
            data: [55, 25, 10, 5, 5],
            backgroundColor: [
                chartColors.primary,
                chartColors.success,
                chartColors.warning,
                chartColors.danger,
                chartColors.secondary
            ],
            borderColor: [
                chartColors.primary,
                chartColors.success,
                chartColors.warning,
                chartColors.danger,
                chartColors.secondary
            ],
            borderWidth: 1
        }]
    };
    
    // Pasta grafiği oluştur
    createDoughnutChart(methodCtx, data, {
        title: 'HTTP Metodları Dağılımı'
    });
}

function createResponseTimeCharts() {
    const responseTimeCtx = document.getElementById('responseTimeChart');
    if (!responseTimeCtx) return;
    
    // Saatlik etiketleri al
    const labels = getHourlyLabels();
    
    // Yanıt süresi verileri
    const data = {
        labels: labels,
        datasets: [{
            label: 'Ortalama Yanıt Süresi (ms)',
            data: generateRandomData(24, 50, 500),
            backgroundColor: chartColors.info,
            borderColor: chartColors.info,
            borderWidth: 1
        }]
    };
    
    // Çubuk grafiği oluştur
    createBarChart(responseTimeCtx, data, {
        showGrid: true,
        ticksColor: getComputedStyle(document.documentElement).getPropertyValue('--text-color').trim(),
        title: 'Ortalama Yanıt Süresi'
    });
}

// Tema değiştirici
function toggleTheme() {
    document.body.classList.toggle('dark-theme');
    
    // Tema tercihini kaydet
    const isDarkTheme = document.body.classList.contains('dark-theme');
    localStorage.setItem('darkTheme', isDarkTheme);
    
    // Tema değişikliği olayını tetikle
    document.dispatchEvent(new Event('themeChanged'));
}

// Tarih ve saat bilgisi güncelleyici
function updateDateTime() {
    const dateTimeElement = document.getElementById('current-date-time');
    if (!dateTimeElement) return;
    
    const now = new Date();
    const options = { 
        weekday: 'long', 
        year: 'numeric', 
        month: 'long', 
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    };
    
    dateTimeElement.textContent = now.toLocaleDateString('tr-TR', options);
} 