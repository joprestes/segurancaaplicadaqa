/**
 * Skeleton Loader - Vanilla JavaScript
 * 
 * Sistema simples de skeleton screens para estados de carregamento
 * 100% vanilla JS - sem dependências
 * 
 * Uso:
 *   SkeletonLoader.show(containerElement);
 *   SkeletonLoader.hide(containerElement);
 */

(function() {
  'use strict';
  
  // ============================================
  // Skeleton Loader Functions
  // ============================================
  
  /**
   * Cria um skeleton loader padrão
   * @param {HTMLElement} container - Container onde o skeleton será inserido
   * @returns {HTMLElement} Elemento skeleton criado
   */
  function createSkeletonLoader(container) {
    if (!container) return null;
    
    const skeleton = document.createElement('div');
    skeleton.className = 'skeleton-loader';
    skeleton.innerHTML = `
      <div class="skeleton-text skeleton-text--title"></div>
      <div class="skeleton-text skeleton-text--line"></div>
      <div class="skeleton-text skeleton-text--line"></div>
      <div class="skeleton-text skeleton-text--short"></div>
    `;
    
    return skeleton;
  }
  
  /**
   * Mostra skeleton loader no container
   * @param {HTMLElement} container - Container onde mostrar o skeleton
   */
  function showSkeleton(container) {
    if (!container) return;
    
    // Verificar se já existe skeleton
    const existing = container.querySelector('.skeleton-loader');
    if (existing) return;
    
    const skeleton = createSkeletonLoader(container);
    if (skeleton) {
      container.appendChild(skeleton);
    }
  }
  
  /**
   * Esconde skeleton loader do container
   * @param {HTMLElement} container - Container onde esconder o skeleton
   */
  function hideSkeleton(container) {
    if (!container) return;
    
    const skeleton = container.querySelector('.skeleton-loader');
    if (skeleton) {
      skeleton.style.opacity = '0';
      skeleton.style.transition = 'opacity 0.3s ease';
      
      setTimeout(function() {
        if (skeleton.parentNode) {
          skeleton.parentNode.removeChild(skeleton);
        }
      }, 300);
    }
  }
  
  // ============================================
  // Auto-hide quando página carregar
  // ============================================
  function autoHideOnLoad() {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', function() {
        document.querySelectorAll('.skeleton-loader').forEach(function(el) {
          if (el.parentElement) {
            hideSkeleton(el.parentElement);
          }
        });
      });
    } else {
      // DOM já carregado
      document.querySelectorAll('.skeleton-loader').forEach(function(el) {
        if (el.parentElement) {
          hideSkeleton(el.parentElement);
        }
      });
    }
  }
  
  // Inicializar auto-hide
  autoHideOnLoad();
  
  // ============================================
  // Exportar API pública
  // ============================================
  window.SkeletonLoader = {
    show: showSkeleton,
    hide: hideSkeleton,
    create: createSkeletonLoader
  };
})();
