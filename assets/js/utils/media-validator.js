// assets/js/utils/media-validator.js
(function() {
  'use strict';
  
  window.validateMediaFile = function(filePath, type) {
    // Se validação falhar, retorna true mesmo assim (não bloqueia)
    // Apenas loga warning em dev
    if (!filePath || typeof filePath !== 'string') {
      if (window.Logger) {
        window.Logger.warn('MediaValidator: filePath inválido');
      }
      return true; // NÃO BLOQUEIA - permite tentar carregar
    }
    
    const validExtensions = {
      audio: ['.m4a', '.mp3', '.ogg', '.wav'],
      video: ['.mp4', '.webm', '.ogg']
    };
    
    const extensions = validExtensions[type] || [...validExtensions.audio, ...validExtensions.video];
    const hasValidExtension = extensions.some(ext => 
      filePath.toLowerCase().endsWith(ext)
    );
    
    if (!hasValidExtension && window.Logger) {
      window.Logger.warn('MediaValidator: extensão não reconhecida, mas permitindo:', filePath);
    }
    
    return true; // SEMPRE retorna true - nunca bloqueia
  };
})();
