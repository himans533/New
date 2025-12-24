// UI Enhancements: toasts, modal helpers, theme toggle, accessible focus
(function(){
    // Toast system
    function showToast(message, type='info', timeout=3500){
        const el = document.createElement('div');
        el.className = `toast ${type}`;
        el.textContent = message;
        document.body.appendChild(el);
        setTimeout(()=> el.classList.add('visible'), 10);
        const remove = ()=>{ el.remove(); }
        setTimeout(remove, timeout);
    }

    // Modal helpers: open by id, close by id
    function openModal(id){
        const m = document.getElementById(id);
        if(!m) return;
        m.classList.add('show');
        const focusable = m.querySelector('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
        if(focusable) focusable.focus();
    }
    function closeModal(id){
        const m = document.getElementById(id);
        if(!m) return;
        m.classList.remove('show');
    }

    // Theme toggle: persist to localStorage
    function toggleTheme(){
        document.documentElement.classList.toggle('dark-theme');
        const isDark = document.documentElement.classList.contains('dark-theme');
        localStorage.setItem('theme_dark', isDark? '1':'0');
        updateThemeButton();
    }
    function updateThemeButton(){
        const btn = document.getElementById('themeToggleBtn');
        if(!btn) return;
        btn.textContent = document.documentElement.classList.contains('dark-theme') ? '☀️' : '🌙';
    }

    // On load, restore theme
    document.addEventListener('DOMContentLoaded', ()=>{
        try{
            const dark = localStorage.getItem('theme_dark');
            if(dark === '1') document.documentElement.classList.add('dark-theme');
            updateThemeButton();
            const btn = document.getElementById('themeToggleBtn');
            if(btn) btn.addEventListener('click', toggleTheme);
        }catch(e){/* ignore */}
    });

    // Expose helpers globally without overwriting existing names
    window.UIEnhancements = window.UIEnhancements || {};
    window.UIEnhancements.showToast = showToast;
    window.UIEnhancements.openModal = openModal;
    window.UIEnhancements.closeModal = closeModal;
    window.UIEnhancements.toggleTheme = toggleTheme;
})();
