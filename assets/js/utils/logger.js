// assets/js/utils/logger.js
// Logger centralizado - sempre disponível (garantia de que nunca falha)
(function() {
  'use strict';
  
  // Garantir que Logger sempre exista, mesmo antes deste script carregar
  if (!window.Logger) {
    // Logger mínimo de emergência (caso script não carregue)
    window.Logger = {
      log: function() {},
      warn: function() {},
      error: function() {
        // Último recurso: tentar console se disponível
        if (typeof console !== 'undefined' && console.error) {
          console.error.apply(console, arguments);
        }
      }
    };
  }
  
  const isDev = window.location.hostname === 'localhost' || 
                window.location.hostname === '127.0.0.1' ||
                window.location.hostname.includes('.local');
  
  // Substituir pelo Logger completo
  window.Logger = {
    log: function(...args) {
      if (isDev && typeof console !== 'undefined' && console.log) {
        console.log(...args);
      }
      // Em produção, não faz nada (silencioso)
    },
    
    warn: function(...args) {
      if (isDev && typeof console !== 'undefined' && console.warn) {
        console.warn(...args);
      }
      // Em produção, não faz nada
    },
    
    error: function(...args) {
      // Erros SEMPRE logados (mesmo em produção)
      if (typeof console !== 'undefined' && console.error) {
        console.error(...args);
      }
    }
  };
})();
