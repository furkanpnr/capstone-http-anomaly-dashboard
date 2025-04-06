document.addEventListener('DOMContentLoaded', function() {
    const sidebar = document.getElementById('sidebar');
    const mainContent = document.querySelector('.main-content');
    const sidebarCollapseBtn = document.getElementById('sidebarCollapseBtn');
    
    // Toggle butonu için tıklama olayı
    sidebarCollapseBtn.addEventListener('click', function() {
        sidebar.classList.toggle('hidden');
        mainContent.classList.toggle('full-width');
        sidebarCollapseBtn.classList.toggle('active');
        
        // Kullanıcı tercihini kaydet
        if (sidebar.classList.contains('hidden')) {
            localStorage.setItem('sidebarState', 'hidden');
        } else {
            localStorage.setItem('sidebarState', 'visible');
        }
    });
    
    // Sayfa yüklendiğinde kullanıcının tercihini hatırla
    const sidebarState = localStorage.getItem('sidebarState');
    if (sidebarState === 'hidden') {
        sidebar.classList.add('hidden');
        mainContent.classList.add('full-width');
        sidebarCollapseBtn.classList.add('active');
    }
}); 