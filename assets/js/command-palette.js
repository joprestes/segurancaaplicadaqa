/**
 * Command Palette - Vanilla JavaScript
 * 
 * Sistema de busca rápida estilo VS Code
 * Atalho: Cmd/Ctrl + K
 * 100% vanilla JS - sem dependências
 */

(function() {
  'use strict';
  
  // ============================================
  // Command Palette Constructor
  // ============================================
  function CommandPalette() {
    this.isOpen = false;
    this.data = [];
    this.results = [];
    this.selectedIndex = 0;
    
    this.init();
  }
  
  // ============================================
  // Initialize
  // ============================================
  CommandPalette.prototype.init = function() {
    this.createHTML();
    this.loadData();
    this.bindEvents();
  };
  
  // ============================================
  // Create HTML Structure
  // ============================================
  CommandPalette.prototype.createHTML = function() {
    // Verificar se já existe
    if (document.getElementById('command-palette')) return;
    
    var palette = document.createElement('div');
    palette.id = 'command-palette';
    palette.className = 'command-palette';
    palette.setAttribute('aria-hidden', 'true');
    palette.setAttribute('role', 'dialog');
    palette.setAttribute('aria-label', 'Command Palette');
    palette.innerHTML = 
      '<div class="command-palette__backdrop" id="palette-backdrop"></div>' +
      '<div class="command-palette__container">' +
        '<div class="command-palette__header">' +
          '<input type="text" id="palette-input" class="command-palette__input" ' +
                 'placeholder="Buscar módulos, lições..." autocomplete="off" ' +
                 'aria-label="Buscar">' +
          '<kbd>' + (navigator.platform.indexOf('Mac') > -1 ? '⌘' : 'Ctrl') + ' K</kbd>' +
        '</div>' +
        '<div class="command-palette__results" id="palette-results" role="listbox"></div>' +
      '</div>';
    
    document.body.appendChild(palette);
    
    this.palette = palette;
    this.input = document.getElementById('palette-input');
    this.resultsContainer = document.getElementById('palette-results');
    this.backdrop = document.getElementById('palette-backdrop');
  };
  
  // ============================================
  // Load Data
  // ============================================
  CommandPalette.prototype.loadData = function() {
    // Usar dados já disponíveis em window.siteData
    if (!window.siteData) {
      this.data = [];
      return;
    }
    
    var modules = window.siteData.modules || [];
    var lessons = window.siteData.lessons || [];
    
    this.data = [];
    
    // Adicionar módulos
    for (var i = 0; i < modules.length; i++) {
      var module = modules[i];
      this.data.push({
        type: 'module',
        title: module.title || module.name || 'Módulo sem título',
        url: module.url || '/modules/' + (module.slug || module.id || '')
      });
    }
    
    // Adicionar lições
    for (var j = 0; j < lessons.length; j++) {
      var lesson = lessons[j];
      this.data.push({
        type: 'lesson',
        title: lesson.title || lesson.name || 'Lição sem título',
        url: lesson.url || '#'
      });
    }
  };
  
  // ============================================
  // Bind Events
  // ============================================
  CommandPalette.prototype.bindEvents = function() {
    var self = this;
    
    // Cmd/Ctrl + K
    document.addEventListener('keydown', function(e) {
      // Não abrir se estiver digitando em input/textarea
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
        // Mas permitir Cmd+K mesmo em inputs
        if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
          e.preventDefault();
          self.toggle();
        }
        return;
      }
      
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        self.toggle();
      }
      
      if (e.key === 'Escape' && self.isOpen) {
        self.close();
      }
    });
    
    // Backdrop click
    if (this.backdrop) {
      this.backdrop.addEventListener('click', function() {
        self.close();
      });
    }
    
    // Input search
    if (this.input) {
      this.input.addEventListener('input', function(e) {
        self.search(e.target.value);
      });
      
      // Keyboard navigation
      this.input.addEventListener('keydown', function(e) {
        if (e.key === 'ArrowDown') {
          e.preventDefault();
          self.selectNext();
        } else if (e.key === 'ArrowUp') {
          e.preventDefault();
          self.selectPrevious();
        } else if (e.key === 'Enter') {
          e.preventDefault();
          self.selectCurrent();
        }
      });
    }
  };
  
  // ============================================
  // Toggle
  // ============================================
  CommandPalette.prototype.toggle = function() {
    if (this.isOpen) {
      this.close();
    } else {
      this.open();
    }
  };
  
  // ============================================
  // Open
  // ============================================
  CommandPalette.prototype.open = function() {
    this.isOpen = true;
    if (this.palette) {
      this.palette.setAttribute('aria-hidden', 'false');
    }
    if (this.input) {
      this.input.focus();
      this.input.value = '';
    }
    document.body.style.overflow = 'hidden';
    this.renderEmpty();
  };
  
  // ============================================
  // Close
  // ============================================
  CommandPalette.prototype.close = function() {
    this.isOpen = false;
    if (this.palette) {
      this.palette.setAttribute('aria-hidden', 'true');
    }
    if (this.input) {
      this.input.value = '';
      this.input.blur();
    }
    this.results = [];
    this.selectedIndex = 0;
    document.body.style.overflow = '';
    this.renderEmpty();
  };
  
  // ============================================
  // Search
  // ============================================
  CommandPalette.prototype.search = function(query) {
    if (!query || !query.trim()) {
      this.renderEmpty();
      return;
    }
    
    var lowerQuery = query.toLowerCase().trim();
    this.results = [];
    this.selectedIndex = 0;
    
    for (var i = 0; i < this.data.length; i++) {
      var item = this.data[i];
      if (item.title.toLowerCase().indexOf(lowerQuery) !== -1) {
        this.results.push(item);
      }
    }
    
    this.render();
  };
  
  // ============================================
  // Render Results
  // ============================================
  CommandPalette.prototype.render = function() {
    if (!this.resultsContainer) return;
    
    if (this.results.length === 0) {
      this.resultsContainer.innerHTML = 
        '<div class="command-palette__empty">Nenhum resultado encontrado</div>';
      return;
    }
    
    var html = '';
    for (var i = 0; i < this.results.length; i++) {
      var item = this.results[i];
      var selected = i === this.selectedIndex ? 'is-selected' : '';
      var typeLabel = item.type === 'module' ? 'Módulo' : 'Lição';
      
      html += '<div class="command-palette__item ' + selected + '" ' +
              'data-url="' + this.escapeHtml(item.url) + '" ' +
              'role="option" ' +
              (i === this.selectedIndex ? 'aria-selected="true"' : '') +
              '>' +
              '<div class="command-palette__item-title">' + 
              this.escapeHtml(item.title) + 
              '</div>' +
              '<div class="command-palette__item-type">' + typeLabel + '</div>' +
              '</div>';
    }
    
    this.resultsContainer.innerHTML = html;
    
    // Click events
    var items = this.resultsContainer.querySelectorAll('.command-palette__item');
    var self = this;
    for (var j = 0; j < items.length; j++) {
      items[j].addEventListener('click', function() {
        var url = this.dataset.url;
        if (url && url !== '#') {
          window.location.href = url;
        }
      });
    }
    
    // Scroll selected into view
    if (items[this.selectedIndex]) {
      items[this.selectedIndex].scrollIntoView({ block: 'nearest' });
    }
  };
  
  // ============================================
  // Render Empty
  // ============================================
  CommandPalette.prototype.renderEmpty = function() {
    if (this.resultsContainer) {
      this.resultsContainer.innerHTML = 
        '<div class="command-palette__empty">Digite para buscar módulos e lições...</div>';
    }
  };
  
  // ============================================
  // Select Next
  // ============================================
  CommandPalette.prototype.selectNext = function() {
    if (this.results.length === 0) return;
    this.selectedIndex = (this.selectedIndex + 1) % this.results.length;
    this.render();
  };
  
  // ============================================
  // Select Previous
  // ============================================
  CommandPalette.prototype.selectPrevious = function() {
    if (this.results.length === 0) return;
    this.selectedIndex = this.selectedIndex === 0 ? 
      this.results.length - 1 : 
      this.selectedIndex - 1;
    this.render();
  };
  
  // ============================================
  // Select Current
  // ============================================
  CommandPalette.prototype.selectCurrent = function() {
    if (this.results.length === 0) return;
    var selected = this.results[this.selectedIndex];
    if (selected && selected.url && selected.url !== '#') {
      window.location.href = selected.url;
    }
  };
  
  // ============================================
  // Escape HTML
  // ============================================
  CommandPalette.prototype.escapeHtml = function(text) {
    var div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  };
  
  // ============================================
  // Initialize when DOM is ready
  // ============================================
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
      new CommandPalette();
    });
  } else {
    new CommandPalette();
  }
})();
