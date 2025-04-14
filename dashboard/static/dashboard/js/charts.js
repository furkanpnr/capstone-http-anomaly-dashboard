/**
 * Ortak grafik fonksiyonları
 */

// Grafik renkleri
const chartColors = {
    primary: getComputedStyle(document.documentElement).getPropertyValue('--primary-color').trim(),
    secondary: getComputedStyle(document.documentElement).getPropertyValue('--secondary-color').trim(),
    info: getComputedStyle(document.documentElement).getPropertyValue('--info-color').trim(),
    success: getComputedStyle(document.documentElement).getPropertyValue('--success-color').trim(),
    warning: getComputedStyle(document.documentElement).getPropertyValue('--warning-color').trim(),
    danger: getComputedStyle(document.documentElement).getPropertyValue('--danger-color').trim(),
    
    // Yarı saydam renkler
    primaryTransparent: hexToRGBA(getComputedStyle(document.documentElement).getPropertyValue('--primary-color').trim(), 0.2),
    secondaryTransparent: hexToRGBA(getComputedStyle(document.documentElement).getPropertyValue('--secondary-color').trim(), 0.2),
    infoTransparent: hexToRGBA(getComputedStyle(document.documentElement).getPropertyValue('--info-color').trim(), 0.2),
    successTransparent: hexToRGBA(getComputedStyle(document.documentElement).getPropertyValue('--success-color').trim(), 0.2),
    warningTransparent: hexToRGBA(getComputedStyle(document.documentElement).getPropertyValue('--warning-color').trim(), 0.2),
    dangerTransparent: hexToRGBA(getComputedStyle(document.documentElement).getPropertyValue('--danger-color').trim(), 0.2),
};

// HEX renk kodunu RGBA'ya dönüştürme
function hexToRGBA(hex, alpha = 1) {
    // # işareti varsa kaldır
    hex = hex.replace('#', '');
    
    // Kısa gösterim ise (örn: #fff) uzun gösterime dönüştür
    if (hex.length === 3) {
        hex = hex.split('').map(char => char + char).join('');
    }
    
    // Hex'i RGB'ye dönüştür
    const r = parseInt(hex.substring(0, 2), 16);
    const g = parseInt(hex.substring(2, 4), 16);
    const b = parseInt(hex.substring(4, 6), 16);
    
    // RGBA değerini döndür
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

// Varsayılan çizgi grafik oluşturma fonksiyonu
function createLineChart(ctx, labels, data, options = {}) {
    const defaultOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                display: false
            }
        },
        scales: {
            x: {
                grid: {
                    display: false
                },
                ticks: {
                    color: '#d1d5db'
                }
            },
            y: {
                grid: {
                    color: 'rgba(255, 255, 255, 0.05)'
                },
                ticks: {
                    color: '#d1d5db'
                },
                beginAtZero: true
            }
        }
    };

    const mergedOptions = { ...defaultOptions, ...options };
    
    return new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: options.label || 'Veri',
                data: data,
                borderColor: options.borderColor || chartColors.primary,
                backgroundColor: options.backgroundColor || chartColors.chartBg,
                fill: true,
                tension: 0.4,
                borderWidth: 2,
                pointRadius: options.pointRadius !== undefined ? options.pointRadius : 0,
                pointHoverRadius: 4
            }]
        },
        options: mergedOptions
    });
}

// Varsayılan çubuk grafik oluşturma fonksiyonu
function createBarChart(ctx, labels, data, options = {}) {
    const defaultOptions = {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            x: {
                grid: {
                    display: false
                },
                ticks: {
                    color: '#d1d5db'
                }
            },
            y: {
                grid: {
                    color: 'rgba(255, 255, 255, 0.05)'
                },
                ticks: {
                    color: '#d1d5db'
                },
                beginAtZero: true
            }
        }
    };

    const mergedOptions = { ...defaultOptions, ...options };

    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: options.label || 'Veri',
                data: data,
                backgroundColor: options.backgroundColor || chartColors.primary,
                borderWidth: 0
            }]
        },
        options: mergedOptions
    });
}

// Pasta/Donut grafik oluşturma fonksiyonu
function createDoughnutChart(ctx, labels, data, options = {}) {
    const defaultOptions = {
        responsive: true,
        maintainAspectRatio: false,
        cutout: options.cutout !== undefined ? options.cutout : '60%'
    };

    const mergedOptions = { ...defaultOptions, ...options };
    
    const defaultColors = [
        chartColors.danger,
        chartColors.orange,
        chartColors.primary,
        chartColors.purple,
        chartColors.success,
        chartColors.gray
    ];

    return new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: options.backgroundColor || defaultColors
            }]
        },
        options: mergedOptions
    });
}

// 24 saatlik zaman dilimleri için etiketler oluştur
function getHourlyLabels() {
    return Array.from({length: 24}, (_, i) => `${i}:00`);
}

// Rastgele veri oluştur
function generateRandomData(count, min = 0, max = 100) {
    return Array.from({length: count}, () => Math.floor(Math.random() * (max - min + 1)) + min);
}

// Tema değiştiğinde grafikleri güncelleme
document.addEventListener('themeChanged', function() {
    // Renkleri güncelle
    Object.keys(chartColors).forEach(key => {
        if (key.includes('Transparent')) {
            const baseKey = key.replace('Transparent', '');
            chartColors[key] = hexToRGBA(getComputedStyle(document.documentElement).getPropertyValue(`--${baseKey.toLowerCase()}-color`).trim(), 0.2);
        } else {
            chartColors[key] = getComputedStyle(document.documentElement).getPropertyValue(`--${key.toLowerCase()}-color`).trim();
        }
    });
    
    // Sayfadaki tüm grafikleri güncelle
    Chart.instances.forEach(chart => {
        chart.update();
    });
}); 