class ModuleSummary {
  constructor() {
    this.moduleId = null;
    this.moduleData = null;
    this.quizResults = {};
    this.init();
  }

  init() {
    const container = document.getElementById('module-summary-container');
    if (!container) return;

    this.moduleId = container.dataset.moduleId;
    
    // Mostrar skeleton loader durante carregamento
    this.showSkeletonLoader();
    
    // Simular pequeno delay para melhor UX (opcional)
    setTimeout(() => {
      this.loadModuleData();
      this.loadQuizResults();
      this.calculateStats();
      this.renderQuizCards();
      this.setupActions();
      
      // Esconder skeleton loader
      this.hideSkeletonLoader();
    }, 300);
  }
  
  showSkeletonLoader() {
    const statsContainer = document.querySelector('.module-summary-stats');
    const badgeContainer = document.getElementById('classification-badge');
    const gridContainer = document.getElementById('quiz-results-grid');
    
    if (statsContainer && window.SkeletonLoader) {
      window.SkeletonLoader.show(statsContainer);
    }
    
    if (badgeContainer && window.SkeletonLoader) {
      window.SkeletonLoader.show(badgeContainer);
    }
    
    if (gridContainer && window.SkeletonLoader) {
      window.SkeletonLoader.show(gridContainer);
    }
  }
  
  hideSkeletonLoader() {
    const statsContainer = document.querySelector('.module-summary-stats');
    const badgeContainer = document.getElementById('classification-badge');
    const gridContainer = document.getElementById('quiz-results-grid');
    
    if (statsContainer && window.SkeletonLoader) {
      window.SkeletonLoader.hide(statsContainer);
    }
    
    if (badgeContainer && window.SkeletonLoader) {
      window.SkeletonLoader.hide(badgeContainer);
    }
    
    if (gridContainer && window.SkeletonLoader) {
      window.SkeletonLoader.hide(gridContainer);
    }
  }

  loadModuleData() {
    // Carregar dados do módulo do siteData ou construir a partir da página
    if (window.siteData && window.siteData.modules) {
      this.moduleData = window.siteData.modules.find(m => m.id === this.moduleId);
    }
    
    // Se não encontrou, tentar construir a partir da página atual
    if (!this.moduleData) {
      // Buscar lições do módulo através dos links na página
      const lessonLinks = document.querySelectorAll('.lessons-list a');
      const lessons = [];
      lessonLinks.forEach(link => {
        const href = link.getAttribute('href');
        if (href) {
          // Extrair lesson_id do href ou usar um padrão
          const match = href.match(/lessons\/([^\/]+)/);
          if (match) {
            // Tentar encontrar o lesson_id correspondente
            const slug = match[1];
            if (window.siteData && window.siteData.lessons) {
              const lesson = window.siteData.lessons.find(l => l.slug === slug);
              if (lesson) {
                lessons.push(lesson.id);
              }
            }
          }
        }
      });
      
      this.moduleData = {
        id: this.moduleId,
        lessons: lessons
      };
    }
  }

  loadQuizResults() {
    // Carregar resultados dos quizzes do localStorage
    const saved = localStorage.getItem('course-progress');
    if (!saved) return;

    try {
      const progress = JSON.parse(saved);
      if (!progress.quizzes) return;

      // Filtrar apenas quizzes deste módulo
      if (this.moduleData && this.moduleData.lessons) {
        this.moduleData.lessons.forEach(lessonId => {
          if (progress.quizzes[lessonId]) {
            this.quizResults[lessonId] = progress.quizzes[lessonId];
          }
        });
      }
    } catch (e) {
      console.error('Error loading quiz results:', e);
    }
  }

  calculateStats() {
    const quizIds = Object.keys(this.quizResults);
    const completedCount = quizIds.length;
    const totalLessons = this.moduleData ? this.moduleData.lessons.length : 0;

    if (completedCount === 0) {
      // Mostrar empty state será feito em renderQuizCards
      // Apenas atualizar stats básicas
      const avgScoreEl = document.getElementById('average-score');
      const completedEl = document.getElementById('completed-quizzes');
      const classificationEl = document.getElementById('classification-title');
      
      if (avgScoreEl) avgScoreEl.textContent = '-';
      if (completedEl) completedEl.textContent = `0/${totalLessons}`;
      if (classificationEl) classificationEl.textContent = 'N/A';
      
      // Atualizar badge de classificação para mostrar empty state
      const badge = document.getElementById('classification-badge');
      const badgeName = document.getElementById('classification-name');
      const badgeDesc = document.getElementById('classification-description');
      
      if (badge && badgeName && badgeDesc) {
        badge.className = 'classification-badge classification-apprentice';
        badgeName.textContent = 'Ainda não há resultados';
        badgeDesc.textContent = 'Complete os quizzes das aulas para ver seu desempenho e descobrir sua classificação!';
      }
      
      return;
    }

    // Calcular média
    let totalScore = 0;
    quizIds.forEach(lessonId => {
      const result = this.quizResults[lessonId];
      if (result && result.score !== undefined) {
        totalScore += result.score;
      }
    });

    const averageScore = Math.round(totalScore / completedCount);
    
    // Atualizar estatísticas
    document.getElementById('average-score').textContent = `${averageScore}%`;
    document.getElementById('completed-quizzes').textContent = `${completedCount}/${totalLessons}`;

    // Determinar classificação
    const classification = this.getClassification(averageScore);
    document.getElementById('classification-title').textContent = classification.title;
    document.getElementById('classification-name').textContent = classification.name;
    document.getElementById('classification-description').textContent = classification.description;
    document.getElementById('badge-icon').textContent = classification.icon;

    // Aplicar classe de classificação
    const badge = document.getElementById('classification-badge');
    badge.className = `classification-badge ${classification.class}`;

    // Botão de continuar sempre aparece na página de resumo
    // (esta página só é acessada quando necessário)
  }

  getClassification(score) {
    if (score >= 90) {
      return {
        name: '🛡️ Mestre da Segurança',
        title: 'Mestre da Segurança',
        description: 'Excelente! Você demonstrou domínio completo dos conceitos. Está pronto para desafios avançados!',
        icon: '🛡️',
        class: 'classification-master'
      };
    } else if (score >= 80) {
      return {
        name: '🔒 Especialista em Segurança',
        title: 'Especialista em Segurança',
        description: 'Muito bom! Você tem um conhecimento sólido. Continue praticando para alcançar a maestria!',
        icon: '🔒',
        class: 'classification-expert'
      };
    } else if (score >= 70) {
      return {
        name: '🔐 Analista de Segurança',
        title: 'Analista de Segurança',
        description: 'Bom trabalho! Você entendeu os conceitos principais. Revise os tópicos com menor pontuação.',
        icon: '🔐',
        class: 'classification-analyst'
      };
    } else if (score >= 60) {
      return {
        name: '🛡️ Guardião em Formação',
        title: 'Guardião em Formação',
        description: 'Você está no caminho certo! Revise o conteúdo e refaça os quizzes para melhorar seu desempenho.',
        icon: '🛡️',
        class: 'classification-guardian'
      };
    } else {
      return {
        name: '🔍 Aprendiz de Segurança',
        title: 'Aprendiz de Segurança',
        description: 'Continue estudando! Revise as aulas e pratique mais. Cada quiz é uma oportunidade de aprender.',
        icon: '🔍',
        class: 'classification-apprentice'
      };
    }
  }

  renderQuizCards() {
    const grid = document.getElementById('quiz-results-grid');
    if (!grid) return;

    if (Object.keys(this.quizResults).length === 0) {
      // Usar empty-state component
      grid.innerHTML = this.createEmptyState();
      return;
    }

    // Ordenar por ordem das lições
    const sortedLessons = this.moduleData ? this.moduleData.lessons : Object.keys(this.quizResults);
    
    // Adicionar animação fadeInUp aos cards
    grid.innerHTML = sortedLessons.map((lessonId, index) => {
      const result = this.quizResults[lessonId];
      let cardHtml = '';
      
      if (!result) {
        // Quiz não completado
        const lesson = this.getLessonData(lessonId);
        cardHtml = this.createIncompleteCard(lessonId, lesson);
      } else {
        cardHtml = this.createQuizCard(lessonId, result);
      }
      
      // Adicionar classe de animação com delay progressivo
      return cardHtml.replace('<div class="quiz-result-card', 
        `<div class="quiz-result-card animate-fadeInUp" style="animation-delay: ${index * 0.1}s"`);
    }).join('');
  }

  getLessonData(lessonId) {
    if (window.siteData && window.siteData.lessons) {
      return window.siteData.lessons.find(l => l.id === lessonId);
    }
    return null;
  }

  createQuizCard(lessonId, result) {
    const lesson = this.getLessonData(lessonId);
    const lessonTitle = lesson ? lesson.title : `Aula ${lessonId}`;
    const score = result.score || 0;
    const classification = result.classification || 'N/A';
    const completedAt = result.completed_at ? new Date(result.completed_at).toLocaleDateString('pt-BR') : '';

    // Determinar cor baseada na pontuação
    let scoreClass = 'score-low';
    if (score >= 90) scoreClass = 'score-excellent';
    else if (score >= 80) scoreClass = 'score-good';
    else if (score >= 70) scoreClass = 'score-medium';
    else if (score >= 60) scoreClass = 'score-ok';

    return `
      <div class="quiz-result-card completed">
        <div class="card-header">
          <h3>${lessonTitle}</h3>
          <span class="card-status completed">✅ Completo</span>
        </div>
        <div class="card-body">
          <div class="score-display ${scoreClass}">
            <div class="score-value">${score}%</div>
            <div class="score-label">Pontuação</div>
          </div>
          <div class="card-details">
            <div class="detail-item">
              <span class="detail-label">Classificação:</span>
              <span class="detail-value">${classification}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Completado em:</span>
              <span class="detail-value">${completedAt}</span>
            </div>
          </div>
        </div>
        <div class="card-footer">
          <a href="${this.getLessonUrl(lessonId)}" class="btn-link">Refazer Quiz</a>
        </div>
      </div>
    `;
  }

  createIncompleteCard(lessonId, lesson) {
    const lessonTitle = lesson ? lesson.title : `Aula ${lessonId}`;
    return `
      <div class="quiz-result-card incomplete">
        <div class="card-header">
          <h3>${lessonTitle}</h3>
          <span class="card-status incomplete">⏳ Pendente</span>
        </div>
        <div class="card-body">
          <div class="score-display score-pending">
            <div class="score-value">-</div>
            <div class="score-label">Não iniciado</div>
          </div>
          <div class="card-details">
            <p class="pending-message">Complete a aula e faça o quiz para ver seu resultado aqui!</p>
          </div>
        </div>
        <div class="card-footer">
          <a href="${this.getLessonUrl(lessonId)}" class="btn-link">Ir para Aula</a>
        </div>
      </div>
    `;
  }

  getLessonUrl(lessonId) {
    // Construir URL da lição baseado no módulo
    if (!this.moduleData) return '#';
    
    const lesson = this.getLessonData(lessonId);
    if (!lesson) return '#';

    // Tentar construir URL relativa
    const moduleSlug = this.moduleData.slug || this.moduleId.replace('module-', '');
    const lessonSlug = lesson.slug || lessonId.replace('lesson-', '');
    
    return `/modules/${moduleSlug}/lessons/${lessonSlug}/`;
  }

  createEmptyState() {
    // Construir URL da primeira lição do módulo para ação
    let actionUrl = '/';
    if (this.moduleData && this.moduleData.lessons && this.moduleData.lessons.length > 0) {
      const firstLessonId = this.moduleData.lessons[0];
      actionUrl = this.getLessonUrl(firstLessonId);
    }
    
    return `
      <div class="empty-state empty-state--inline" style="grid-column: 1 / -1; width: 100%;">
        <div class="empty-state__icon">🎯</div>
        <h3 class="empty-state__title">Nenhum quiz completado ainda</h3>
        <p class="empty-state__description">Complete os quizzes das aulas para ver seus resultados e descobrir sua classificação como profissional de segurança!</p>
        <div class="empty-state__action">
          <a href="${actionUrl}" class="btn btn-primary" style="background: var(--color-primary); color: var(--color-text-inverse); padding: 0.75rem 1.5rem; border-radius: 6px; text-decoration: none; display: inline-block; font-weight: 600; transition: all 0.2s ease;">Começar a Estudar →</a>
        </div>
      </div>
    `;
  }
  
  showNoResults() {
    document.getElementById('average-score').textContent = '-';
    document.getElementById('completed-quizzes').textContent = '0/0';
    document.getElementById('classification-title').textContent = 'N/A';
    document.getElementById('classification-name').textContent = 'Ainda não há resultados';
    document.getElementById('classification-description').textContent = 'Complete os quizzes das aulas para ver seu desempenho aqui!';
  }

  setupActions() {
    const continueBtn = document.getElementById('continue-next-module');
    const reviewBtn = document.getElementById('review-module');

    if (continueBtn) {
      continueBtn.addEventListener('click', () => {
        // Verificar se há próximo módulo especificado na URL
        const urlParams = new URLSearchParams(window.location.search);
        const nextModuleSlug = urlParams.get('next_module');
        
        if (nextModuleSlug) {
          // Navegar para o módulo especificado
          window.location.href = `/modules/${nextModuleSlug}/`;
        } else {
          // Navegar para próximo módulo ou página inicial
          const nextModule = this.getNextModule();
          if (nextModule) {
            window.location.href = `/modules/${nextModule.slug}/`;
          } else {
            window.location.href = '/';
          }
        }
      });
    }

    if (reviewBtn) {
      reviewBtn.addEventListener('click', () => {
        // Voltar para primeira lição do módulo
        if (this.moduleData && this.moduleData.lessons && this.moduleData.lessons.length > 0) {
          const firstLessonId = this.moduleData.lessons[0];
          const url = this.getLessonUrl(firstLessonId);
          window.location.href = url;
        }
      });
    }
  }

  getNextModule() {
    if (!window.siteData || !window.siteData.modules) return null;
    
    const currentIndex = window.siteData.modules.findIndex(m => m.id === this.moduleId);
    if (currentIndex >= 0 && currentIndex < window.siteData.modules.length - 1) {
      return window.siteData.modules[currentIndex + 1];
    }
    return null;
  }
}

document.addEventListener('DOMContentLoaded', () => {
  new ModuleSummary();
});
