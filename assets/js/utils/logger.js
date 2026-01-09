// assets/js/utils/logger.js
// FALLBACK TOTAL: Se algo der errado, usa console normal
(function() {
  'use strict';
  
  const isDev = window.location.hostname === 'localhost' || 
                window.location.hostname === '127.0.0.1' ||
                window.location.hostname.includes('.local');
  
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
