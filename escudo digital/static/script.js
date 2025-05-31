// Função para alternar o modo de alto contraste
function toggleHighContrast() {
    const body = document.body;
    const currentTheme = body.getAttribute('data-theme');
    
    if (currentTheme === 'high-contrast') {
        body.removeAttribute('data-theme');
        localStorage.setItem('theme', 'default');
    } else {
        body.setAttribute('data-theme', 'high-contrast');
        localStorage.setItem('theme', 'high-contrast');
    }
}

// Função para carregar a preferência de tema salva
function loadThemePreference() {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'high-contrast') {
        document.body.setAttribute('data-theme', 'high-contrast');
    }
}

// Adicionar botão de alto contraste
function addContrastButton() {
    const button = document.createElement('button');
    button.className = 'contrast-toggle';
    button.innerHTML = '<i class="fas fa-adjust"></i>';
    button.setAttribute('aria-label', 'Alternar alto contraste');
    button.onclick = toggleHighContrast;
    document.body.appendChild(button);
}

// Inicializar quando o documento estiver carregado
document.addEventListener('DOMContentLoaded', () => {
    loadThemePreference();
    addContrastButton();
}); 