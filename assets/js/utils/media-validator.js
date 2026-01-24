// assets/js/utils/media-validator.js
(function() {
  'use strict';
  
  const isDev = window.location.hostname === 'localhost' || 
                window.location.hostname === '127.0.0.1' ||
                window.location.hostname.includes('.local');
  
  window.validateMediaFile = function(filePath, type) {
    // Em dev, validação é permissiva para facilitar testes
    // Em produção, bloqueia extensões inválidas
    if (!filePath || typeof filePath !== 'string') {
      window.Logger?.warn('MediaValidator: filePath inválido');
      return isDev; // Em produção, bloquear para evitar erro
    }
    
    const validExtensions = {
      audio: ['.m4a', '.mp3', '.ogg', '.wav'],
      video: ['.mp4', '.webm', '.ogg']
    };
    
    const extensions = validExtensions[type] || [...validExtensions.audio, ...validExtensions.video];
    const hasValidExtension = extensions.some(ext => 
      filePath.toLowerCase().endsWith(ext)
    );
    
    if (!hasValidExtension) {
      window.Logger?.warn('MediaValidator: extensão não reconhecida, mas permitindo:', filePath);
    }
    
    return hasValidExtension || isDev;
  };
})();
