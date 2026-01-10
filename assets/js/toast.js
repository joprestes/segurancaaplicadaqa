/**
 * Toast Notifications - Vanilla JavaScript
 * 
 * Sistema simples de notificações toast
 * 100% vanilla JS - sem dependências
 * 
 * Uso:
 *   window.toast.show({
 *     type: 'success',
 *     title: 'Sucesso!',
 *     message: 'Operação realizada com sucesso',
 *     duration: 5000
 *   });
 */

(function() {
  'use strict';
  
  // ============================================
  // Toast Constructor
  // ============================================
  function Toast() {
    this.container = null;
    this.init();
  }
  
  // ============================================
  // Initialize
  // ============================================
  Toast.prototype.init = function() {
    // Verificar se já existe container
    if (document.getElementById('toast-container')) {
      this.container = document.getElementById('toast-container');
      return;
    }
    
    this.container = document.createElement('div');
    this.container.id = 'toast-container';
    this.container.className = 'toast-container';
    this.container.setAttribute('aria-live', 'polite');
    this.container.setAttribute('aria-atomic', 'true');
    document.body.appendChild(this.container);
  };
  
  // ============================================
  // Show Toast
  // ============================================
  Toast.prototype.show = function(options) {
    if (!this.container) {
      this.init();
    }
    
    var type = options.type || 'info';
    var title = options.title || '';
    var message = options.message || '';
    var duration = options.duration !== undefined ? options.duration : 5000;
    
    // Validar tipo
    var validTypes = ['success', 'error', 'warning', 'info'];
    if (validTypes.indexOf(type) === -1) {
      type = 'info';
    }
    
    // Criar elemento toast
    var toast = document.createElement('div');
    toast.className = 'toast toast--' + type;
    
    // Se não tiver título, usar classe message-only
    if (!title) {
      toast.className += ' toast--message-only';
    }
    
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    
    // Construir conteúdo
    var content = '<div class="toast__content">';
    if (title) {
      content += '<div class="toast__title">' + this.escapeHtml(title) + '</div>';
    }
    if (message) {
      content += '<div class="toast__message">' + this.escapeHtml(message) + '</div>';
    }
    content += '</div>';
    
    toast.innerHTML = content;
    
    // Adicionar ao container
    this.container.appendChild(toast);
    
    // Auto hide
    if (duration > 0) {
      var self = this;
      setTimeout(function() {
        self.hide(toast);
      }, duration);
    }
    
    return toast;
  };
  
  // ============================================
  // Hide Toast
  // ============================================
  Toast.prototype.hide = function(toast) {
    if (!toast) return;
    
    // Adicionar classe de fade out
    toast.classList.add('toast--fade-out');
    
    // Remover após animação
    setTimeout(function() {
      if (toast.parentNode) {
        toast.parentNode.removeChild(toast);
      }
    }, 300);
  };
  
  // ============================================
  // Escape HTML
  // ============================================
  Toast.prototype.escapeHtml = function(text) {
    var div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  };
  
  // ============================================
  // Convenience Methods
  // ============================================
  Toast.prototype.success = function(message, title, duration) {
    return this.show({
      type: 'success',
      title: title || 'Sucesso!',
      message: message,
      duration: duration
    });
  };
  
  Toast.prototype.error = function(message, title, duration) {
    return this.show({
      type: 'error',
      title: title || 'Erro',
      message: message,
      duration: duration
    });
  };
  
  Toast.prototype.warning = function(message, title, duration) {
    return this.show({
      type: 'warning',
      title: title || 'Atenção',
      message: message,
      duration: duration
    });
  };
  
  Toast.prototype.info = function(message, title, duration) {
    return this.show({
      type: 'info',
      title: title || 'Informação',
      message: message,
      duration: duration
    });
  };
  
  // ============================================
  // Global Instance
  // ============================================
  const toastInstance = new Toast();
  window.toast = toastInstance;
  // Alias para consistência com outros módulos (window.Toast)
  window.Toast = {
    show: function(options) {
      return toastInstance.show(options);
    },
    success: function(message, title, duration) {
      return toastInstance.success(message, title, duration);
    },
    error: function(message, title, duration) {
      return toastInstance.error(message, title, duration);
    },
    warning: function(message, title, duration) {
      return toastInstance.warning(message, title, duration);
    },
    info: function(message, title, duration) {
      return toastInstance.info(message, title, duration);
    }
  };
})();
