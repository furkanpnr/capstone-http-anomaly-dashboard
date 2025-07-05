document.addEventListener('DOMContentLoaded', function() {
    // Sidebar toggle
    const sidebarCollapseBtn = document.getElementById('sidebarCollapseBtn');
    const sidebar = document.getElementById('sidebar');
    const mainContent = document.querySelector('.main-content');
    
    function toggleSidebar() {
        sidebar.classList.toggle('hidden');
        sidebarCollapseBtn.classList.toggle('active');
        
        // Mobil cihazları algıla
        const isMobile = window.innerWidth < 768;
        
        // Eğer mobil değilse içerik genişliğini ayarla
        if (!isMobile) {
            mainContent.classList.toggle('full-width');
        }
        
        // Sidebar durumunu localStorage'a kaydet
        if (sidebar.classList.contains('hidden')) {
            localStorage.setItem('sidebarState', 'hidden');
        } else {
            localStorage.setItem('sidebarState', 'visible');
        }
    }
    
    // Sidebar toggle tıklaması
    if (sidebarCollapseBtn) {
        sidebarCollapseBtn.addEventListener('click', function(e) {
            e.preventDefault();
            toggleSidebar();
        });
    }
    
    // Önceki sidebar durumunu yükle (sadece masaüstünde)
    if (window.innerWidth >= 768) {
        const sidebarState = localStorage.getItem('sidebarState');
        if (sidebarState === 'visible') {
            sidebar.classList.remove('hidden');
            sidebarCollapseBtn.classList.add('active');
        } else if (sidebarState === 'hidden') {
            sidebar.classList.add('hidden');
            mainContent.classList.add('full-width');
            sidebarCollapseBtn.classList.remove('active');
        }
    }
    
    // Ekran boyutu değiştiğinde
    window.addEventListener('resize', function() {
        const isMobile = window.innerWidth < 768;
        
        // Mobil cihaz ve sidebar açıksa, içerik alanını tam genişlik yap
        if (isMobile && !sidebar.classList.contains('hidden')) {
            mainContent.classList.add('full-width');
        } 
        // Masaüstünde ve sidebar kapalıysa, içerik alanı tam genişlik olmalı
        else if (!isMobile && sidebar.classList.contains('hidden')) {
            mainContent.classList.add('full-width');
        }
        // Masaüstünde ve sidebar açıksa, içerik alanını daralt
        else if (!isMobile && !sidebar.classList.contains('hidden')) {
            mainContent.classList.remove('full-width');
        }
    });
    
    // Mobil cihazlarda, sidebar dışına tıklandığında sidebar'ı kapat
    document.addEventListener('click', function(event) {
        const isMobile = window.innerWidth < 768;
        if (isMobile && 
            !sidebar.classList.contains('hidden') && 
            !sidebar.contains(event.target) && 
            event.target !== sidebarCollapseBtn &&
            !sidebarCollapseBtn.contains(event.target)) {
            sidebar.classList.add('hidden');
        }
    });
}); 