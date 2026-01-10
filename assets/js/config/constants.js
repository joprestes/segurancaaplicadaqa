// assets/js/config/constants.js
// Constantes centralizadas do projeto
(function() {
  'use strict';
  
  const Constants = {
    MEDIA_PLAYER: {
      DEBOUNCE_SAVE_PROGRESS: 250, // ms
      PRELOAD_METADATA: 'metadata',
      DEFAULT_PLAYBACK_RATE: 1.0,
      DEFAULT_VOLUME: 100
    },
    
    ANALYTICS: {
      MIN_TIME_ON_PAGE: 5, // seconds
      SCROLL_THRESHOLDS: [25, 50, 75, 100]
    },
    
    STORAGE_KEYS: {
      COURSE_PROGRESS: 'course-progress',
      VIDEO_GLOBAL_STATE: 'video-global-state',
      PODCAST_GLOBAL_STATE: 'podcast-global-state' // Para limpeza durante migração
    }
  };
  
  // Disponibilizar globalmente
  window.Constants = Constants;
})();
