// Função para expandir/colapsar o menu de acessibilidade
function toggleAccessibilityMenu() {
    const options = document.getElementById('acessibilidade-options');
    if (options) {
        options.classList.toggle('active');
        console.log('Menu de acessibilidade toggled');
    } else {
        console.error('Elemento acessibilidade-options não encontrado!');
    }
}

// Função para aplicar o modo alto contraste
function toggleHighContrast() {
    const body = document.body;
    if (body) {
        body.classList.toggle('modo-alto-contraste');
        const isHighContrast = body.classList.contains('modo-alto-contraste');
        localStorage.setItem('highContrast', isHighContrast);
        console.log('Modo alto contraste toggled. Estado:', isHighContrast);
    } else {
        console.error('Elemento body não encontrado!');
    }
}

// Função para aumentar a fonte
function increaseFontSize() {
    let fontSize = parseFloat(window.getComputedStyle(document.body).fontSize);
    fontSize = Math.min(fontSize + 2, 20); // Limite máximo de 20px
    document.body.style.fontSize = `${fontSize}px`;
    localStorage.setItem('fontSize', fontSize);
    console.log('Fonte aumentada para:', fontSize, 'px');
}

// Função para diminuir a fonte
function decreaseFontSize() {
    let fontSize = parseFloat(window.getComputedStyle(document.body).fontSize);
    fontSize = Math.max(fontSize - 2, 12); // Limite mínimo de 12px
    document.body.style.fontSize = `${fontSize}px`;
    localStorage.setItem('fontSize', fontSize);
    console.log('Fonte diminuída para:', fontSize, 'px');
}

// Carrega as preferências ao iniciar a página
document.addEventListener('DOMContentLoaded', () => {
    // Carrega o modo alto contraste
    const highContrast = localStorage.getItem('highContrast') === 'true';
    if (highContrast) {
        document.body.classList.add('modo-alto-contraste');
        console.log('Modo alto contraste carregado do localStorage');
    }

    // Carrega o tamanho da fonte
    const savedFontSize = localStorage.getItem('fontSize');
    if (savedFontSize) {
        document.body.style.fontSize = `${savedFontSize}px`;
        console.log('Tamanho da fonte carregado:', savedFontSize, 'px');
    }

    // Adiciona eventos aos botões
    const accessibilityBtn = document.getElementById('acessibilidade-btn');
    const highContrastBtn = document.getElementById('alto-contraste-btn');
    const increaseFontBtn = document.getElementById('aumentar-fonte-btn');
    const decreaseFontBtn = document.getElementById('diminuir-fonte-btn');

    if (accessibilityBtn) {
        accessibilityBtn.addEventListener('click', toggleAccessibilityMenu);
    } else {
        console.error('Botão acessibilidade-btn não encontrado!');
    }
    if (highContrastBtn) {
        highContrastBtn.addEventListener('click', toggleHighContrast);
    } else {
        console.error('Botão alto-contraste-btn não encontrado!');
    }
    if (increaseFontBtn) {
        increaseFontBtn.addEventListener('click', increaseFontSize);
    } else {
        console.error('Botão aumentar-fonte-btn não encontrado!');
    }
    if (decreaseFontBtn) {
        decreaseFontBtn.addEventListener('click', decreaseFontSize);
    } else {
        console.error('Botão diminuir-fonte-btn não encontrado!');
    }
});