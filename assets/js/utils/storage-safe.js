// assets/js/utils/storage-safe.js
// Wrapper seguro para localStorage/sessionStorage com tratamento de erros robusto
(function() {
  'use strict';
  
  class StorageSafe {
    /**
     * Salva item no localStorage com tratamento de QuotaExceededError
     * @param {string} key - Chave do item
     * @param {*} value - Valor a ser salvo (será convertido para JSON)
     * @returns {boolean} - true se salvou com sucesso, false caso contrário
     */
    static setItem(key, value) {
      try {
        localStorage.setItem(key, JSON.stringify(value));
        return true;
      } catch (e) {
        if (e.name === 'QuotaExceededError') {
          if (window.Logger) {
            window.Logger.error('LocalStorage cheio. Tentando limpar dados antigos...');
          }
          // Tentar limpar dados antigos
          const cleaned = this.cleanOldData();
          if (cleaned) {
            // Tentar novamente uma vez após limpeza
            try {
              localStorage.setItem(key, JSON.stringify(value));
              if (window.Logger) {
                window.Logger.log('Item salvo após limpeza de dados antigos');
              }
              return true;
            } catch (e2) {
              if (window.Logger) {
                window.Logger.error('Não foi possível salvar após limpeza:', e2);
              }
              if (window.Toast) {
                window.Toast.error(
                  'Não foi possível salvar progresso. Espaço de armazenamento cheio.',
                  'Armazenamento Cheio',
                  7000
                );
              }
              return false;
            }
          } else {
            if (window.Logger) {
              window.Logger.error('Não foi possível limpar dados antigos');
            }
            if (window.Toast) {
              window.Toast.error(
                'Espaço de armazenamento cheio. Alguns dados podem não ser salvos.',
                'Armazenamento Cheio',
                7000
              );
            }
            return false;
          }
        } else if (e.name === 'SecurityError') {
          if (window.Logger) {
            window.Logger.error('Erro de segurança ao acessar localStorage:', e);
          }
          return false;
        } else {
          if (window.Logger) {
            window.Logger.error('Erro ao salvar no localStorage:', e);
          }
          return false;
        }
      }
    }
    
    /**
     * Lê item do localStorage com tratamento de erros
     * @param {string} key - Chave do item
     * @returns {*} - Valor parseado ou null se não existir ou erro
     */
    static getItem(key) {
      try {
        const item = localStorage.getItem(key);
        if (item === null) {
          return null;
        }
        return JSON.parse(item);
      } catch (e) {
        if (window.Logger) {
          window.Logger.error('Erro ao ler do localStorage:', e);
        }
        // Tentar remover item corrompido
        try {
          localStorage.removeItem(key);
        } catch (e2) {
          // Ignorar erro ao remover
        }
        return null;
      }
    }
    
    /**
     * Remove item do localStorage com tratamento de erros
     * @param {string} key - Chave do item
     * @returns {boolean} - true se removeu com sucesso
     */
    static removeItem(key) {
      try {
        localStorage.removeItem(key);
        return true;
      } catch (e) {
        if (window.Logger) {
          window.Logger.error('Erro ao remover do localStorage:', e);
        }
        return false;
      }
    }
    
    /**
     * Salva item no sessionStorage com tratamento de erros
     * @param {string} key - Chave do item
     * @param {*} value - Valor a ser salvo
     * @returns {boolean} - true se salvou com sucesso
     */
    static setSessionItem(key, value) {
      try {
        sessionStorage.setItem(key, JSON.stringify(value));
        return true;
      } catch (e) {
        if (window.Logger) {
          window.Logger.error('Erro ao salvar no sessionStorage:', e);
        }
        return false;
      }
    }
    
    /**
     * Lê item do sessionStorage com tratamento de erros
     * @param {string} key - Chave do item
     * @returns {*} - Valor parseado ou null
     */
    static getSessionItem(key) {
      try {
        const item = sessionStorage.getItem(key);
        if (item === null) {
          return null;
        }
        return JSON.parse(item);
      } catch (e) {
        if (window.Logger) {
          window.Logger.error('Erro ao ler do sessionStorage:', e);
        }
        try {
          sessionStorage.removeItem(key);
        } catch (e2) {
          // Ignorar erro ao remover
        }
        return null;
      }
    }
    
    /**
     * Remove item do sessionStorage
     * @param {string} key - Chave do item
     * @returns {boolean} - true se removeu com sucesso
     */
    static removeSessionItem(key) {
      try {
        sessionStorage.removeItem(key);
        return true;
      } catch (e) {
        if (window.Logger) {
          window.Logger.error('Erro ao remover do sessionStorage:', e);
        }
        return false;
      }
    }
    
    /**
     * Limpa dados antigos do localStorage (progresso com mais de 30 dias)
     * @returns {boolean} - true se limpou algo, false caso contrário
     */
    static cleanOldData() {
      try {
        const keys = Object.keys(localStorage);
        const now = Date.now();
        const thirtyDaysInMs = 30 * 24 * 60 * 60 * 1000;
        let cleaned = false;
        
        keys.forEach(key => {
          // Limpar apenas keys relacionadas ao progresso do curso
          if (key.startsWith('video-') || key.startsWith('podcast-')) {
            try {
              const item = localStorage.getItem(key);
              if (item) {
                const data = JSON.parse(item);
                // Se tem timestamp e é mais antigo que 30 dias, remover
                if (data.timestamp && (now - data.timestamp) > thirtyDaysInMs) {
                  localStorage.removeItem(key);
                  cleaned = true;
                }
              }
            } catch (e) {
              // Item corrompido, remover
              localStorage.removeItem(key);
              cleaned = true;
            }
          }
        });
        
        // Também limpar course-progress antigo se necessário
        const progressKey = (window.Constants && window.Constants.STORAGE_KEYS && window.Constants.STORAGE_KEYS.COURSE_PROGRESS) || 'course-progress';
        const progress = this.getItem(progressKey);
        if (progress && progress.timestamp) {
          if ((now - progress.timestamp) > thirtyDaysInMs) {
            // Não remover completamente, mas limpar quizzes antigos
            if (progress.quizzes) {
              const oldQuizzes = Object.keys(progress.quizzes).filter(quizId => {
                const quiz = progress.quizzes[quizId];
                if (quiz.completed_at) {
                  const completedDate = new Date(quiz.completed_at).getTime();
                  return (now - completedDate) > thirtyDaysInMs;
                }
                return false;
              });
              oldQuizzes.forEach(quizId => {
                delete progress.quizzes[quizId];
                cleaned = true;
              });
              if (cleaned) {
                this.setItem(progressKey, progress);
              }
            }
          }
        }
        
        return cleaned;
      } catch (e) {
        if (window.Logger) {
          window.Logger.error('Erro ao limpar dados antigos:', e);
        }
        return false;
      }
    }
  }
  
  // Disponibilizar globalmente
  window.StorageSafe = StorageSafe;
})();
