(function() {
  'use strict';
  
  function fixContentHeight() {
    const contentWrapper = document.querySelector('.content-wrapper');
    const content = document.querySelector('.main-container .content');
    
    if (!contentWrapper || !content) {
      return;
    }
    
    // Aguardar o conteúdo carregar completamente
    setTimeout(() => {
      // Obter a altura real do conteúdo (com scale aplicado)
      const contentHeight = content.scrollHeight;
      // Calcular a altura visual (80% devido ao scale 0.8)
      const visualHeight = contentHeight * 0.8;
      // Ajustar o wrapper para cortar o espaço extra
      contentWrapper.style.height = visualHeight + 'px';
      contentWrapper.style.overflow = 'hidden';
    }, 100);
    
    // Recalcular quando imagens ou outros recursos carregarem
    window.addEventListener('load', () => {
      setTimeout(() => {
        const contentHeight = content.scrollHeight;
        const visualHeight = contentHeight * 0.8;
        contentWrapper.style.height = visualHeight + 'px';
      }, 200);
    });
  }
  
  // Executar quando o DOM estiver pronto
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', fixContentHeight);
  } else {
    fixContentHeight();
  }
})();

