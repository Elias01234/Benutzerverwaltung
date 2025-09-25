(function(){
  const STORAGE_KEY = 'app.theme';
  const root = document.documentElement; // <html>
  function systemPref(){
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  function applyTheme(t){
    if(t === 'dark') { root.setAttribute('data-theme','dark'); }
    else { root.removeAttribute('data-theme'); }
  }
  function loadTheme(){
    const saved = localStorage.getItem(STORAGE_KEY);
    return saved === 'dark' || saved === 'light' ? saved : systemPref();
  }
  function saveTheme(t){ localStorage.setItem(STORAGE_KEY, t); }
  function toggleTheme(){
    const current = root.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
    const next = current === 'dark' ? 'light' : 'dark';
    applyTheme(next); saveTheme(next); updateToggleIcon(next);
  }
  function updateToggleIcon(theme){
    const btn = document.getElementById('themeToggleBtn');
    if(!btn) return;
    btn.innerHTML = theme === 'dark'
      ? '<i class="bi bi-sun"></i>'
      : '<i class="bi bi-moon"></i>';
    btn.setAttribute('aria-label', theme === 'dark' ? 'Helles Design aktivieren' : 'Dunkles Design aktivieren');
  }
  // Init
  const initial = loadTheme();
  applyTheme(initial);
  document.addEventListener('DOMContentLoaded', function(){
    // Falls Button existiert
    const btn = document.getElementById('themeToggleBtn');
    if(btn){ btn.addEventListener('click', toggleTheme); updateToggleIcon(initial); }
  });
  // Reagieren auf Systemwechsel (optional)
  if(window.matchMedia){
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function(e){
      const saved = localStorage.getItem(STORAGE_KEY);
      if(!saved){ applyTheme(e.matches ? 'dark' : 'light'); updateToggleIcon(e.matches ? 'dark':'light'); }
    });
  }
})();