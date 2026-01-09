/**
 * Module Gate - Intercepta acesso ao próximo módulo e mostra resumo do módulo anterior
 */
class ModuleGate {
  constructor() {
    this.init();
  }

  init() {
    // Verificar se estamos tentando acessar um módulo
    this.checkModuleAccess();
    
    // Interceptar cliques em links de módulos
    this.interceptModuleLinks();
  }

  checkModuleAccess() {
    // Verificar se há um parâmetro na URL indicando que devemos mostrar resumo
    const urlParams = new URLSearchParams(window.location.search);
    const showSummary = urlParams.get('summary');
    const previousModule = urlParams.get('previous_module');

    if (showSummary === 'true' && previousModule) {
      // Redirecionar para página de resumo do módulo anterior
      this.showModuleSummary(previousModule);
      return;
    }

    // Verificar se estamos acessando um módulo que não é o primeiro
    const currentPath = window.location.pathname;
    const moduleMatch = currentPath.match(/\/modules\/([^\/]+)/);
    
    if (moduleMatch) {
      const moduleSlug = moduleMatch[1];
      const currentModule = this.getModuleBySlug(moduleSlug);
      
      if (currentModule && currentModule.order > 1) {
        // Verificar se módulo anterior está completo
        const previousModule = this.getPreviousModule(currentModule);
        if (previousModule && !this.isModuleComplete(previousModule.id)) {
          // Redirecionar para resumo do módulo anterior
          this.redirectToSummary(previousModule.id);
        }
      }
    }
  }

  interceptModuleLinks() {
    // Interceptar cliques em links de módulos na navegação
    document.addEventListener('click', (e) => {
      const link = e.target.closest('a[href*="/modules/"]');
      if (!link) return;

      const href = link.getAttribute('href');
      const moduleMatch = href.match(/\/modules\/([^\/]+)/);
      
      if (moduleMatch) {
        const moduleSlug = moduleMatch[1];
        const targetModule = this.getModuleBySlug(moduleSlug);
        
        if (targetModule && targetModule.order > 1) {
          // Verificar se módulo anterior está completo
          const previousModule = this.getPreviousModule(targetModule);
          if (previousModule && !this.isModuleComplete(previousModule.id)) {
            e.preventDefault();
            this.redirectToSummary(previousModule.id, targetModule.slug);
          }
        }
      }
    });
  }

  getModuleBySlug(slug) {
    if (!window.siteData || !window.siteData.modules) return null;
    return window.siteData.modules.find(m => m.slug === slug);
  }

  getPreviousModule(currentModule) {
    if (!window.siteData || !window.siteData.modules) return null;
    const currentIndex = window.siteData.modules.findIndex(m => m.id === currentModule.id);
    if (currentIndex > 0) {
      return window.siteData.modules[currentIndex - 1];
    }
    return null;
  }

  isModuleComplete(moduleId) {
    // Verificar se todos os quizzes do módulo foram completados
    const saved = localStorage.getItem('course-progress');
    if (!saved) return false;

    try {
      const progress = JSON.parse(saved);
      if (!progress.quizzes) return false;

      const module = window.siteData.modules.find(m => m.id === moduleId);
      if (!module || !module.lessons) return false;

      // Verificar se todos os quizzes das lições foram completados
      const completedQuizzes = module.lessons.filter(lessonId => {
        return progress.quizzes[lessonId] && progress.quizzes[lessonId].score !== undefined;
      });

      return completedQuizzes.length === module.lessons.length;
    } catch (e) {
      console.error('Error checking module completion:', e);
      return false;
    }
  }

  redirectToSummary(moduleId, nextModuleSlug = null) {
    // Redirecionar para página de resumo
    const module = window.siteData.modules.find(m => m.id === moduleId);
    if (!module) return;

    let url = `/modules/${module.slug}/summary/`;
    if (nextModuleSlug) {
      url += `?next_module=${nextModuleSlug}`;
    }
    
    window.location.href = url;
  }

  showModuleSummary(moduleId) {
    // Esta função será chamada quando a página de resumo carregar
    // O ModuleSummary já cuida disso
  }
}

document.addEventListener('DOMContentLoaded', () => {
  new ModuleGate();
});
