document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM yüklendi');
    
    const sidebar = document.getElementById('sidebar');
    const sidebarBtn = document.getElementById('sidebarCollapseBtn');
    
    console.log('Sidebar:', sidebar);
    console.log('SidebarBtn:', sidebarBtn);

    if (sidebarBtn) {
        sidebarBtn.addEventListener('click', function() {
            console.log('Sidebar butonu tıklandı');
            sidebar.classList.toggle('hidden');
            sidebarBtn.classList.toggle('active');
            console.log('Sidebar sınıfları:', sidebar.classList);
        });
    }
}); 