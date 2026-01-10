// assets/js/utils/storage-migration.js
// Utilitário para limpar dados antigos de podcast do storage
(function() {
  'use strict';
  
  class StorageMigration {
    /**
     * Limpa todos os dados relacionados a podcast do storage
     * Seguro para executar múltiplas vezes - não quebra se não houver dados
     */
    static cleanPodcastData() {
      try {
        // Limpar sessionStorage
        sessionStorage.removeItem('podcast-global-state');
        
        // Limpar localStorage de podcasts individuais
        const keys = Object.keys(localStorage);
        keys.forEach(key => {
          if (key.startsWith('podcast-')) {
            localStorage.removeItem(key);
          }
        });
        
        // Limpar podcasts do course-progress
        const progressKey = (window.Constants && window.Constants.STORAGE_KEYS && window.Constants.STORAGE_KEYS.COURSE_PROGRESS) || 'course-progress';
        let progress = null;
        
        if (window.StorageSafe && typeof window.StorageSafe.getItem === 'function') {
          progress = window.StorageSafe.getItem(progressKey);
        } else {
          try {
            const progressJson = localStorage.getItem(progressKey);
            progress = progressJson ? JSON.parse(progressJson) : null;
          } catch (e) {
            window.Logger?.error('Erro ao ler progresso durante limpeza de podcast:', e);
            progress = null;
          }
        }
        
        if (progress && progress.podcasts) {
          delete progress.podcasts;
          
          // Salvar progresso limpo
          if (window.StorageSafe && typeof window.StorageSafe.setItem === 'function') {
            window.StorageSafe.setItem(progressKey, progress);
          } else {
            try {
              localStorage.setItem(progressKey, JSON.stringify(progress));
            } catch (e) {
              window.Logger?.error('Erro ao salvar progresso limpo:', e);
            }
          }
          
          window.Logger?.log('Dados de podcast removidos do progresso do curso');
        }
        
        window.Logger?.log('Limpeza de dados de podcast concluída');
      } catch (e) {
        window.Logger?.error('Erro ao limpar dados de podcast:', e);
      }
    }
  }
  
  // Disponibilizar globalmente
  window.StorageMigration = StorageMigration;
  
  // Executar limpeza automaticamente quando o script carregar
  // Apenas uma vez para evitar remover dados múltiplas vezes
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      StorageMigration.cleanPodcastData();
    });
  } else {
    StorageMigration.cleanPodcastData();
  }
})();
