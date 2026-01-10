class QuizManager {
  constructor() {
    this.getThemeColor = (varName, fallback) => {
      try {
        const value = getComputedStyle(document.documentElement).getPropertyValue(varName);
        return value && value.trim() !== '' ? value.trim() : fallback;
      } catch (_e) {
        return fallback;
      }
    };

    this.quizData = null;
    this.currentQuestion = 0;
    this.answers = [];
    this.score = 0;
    this.classifications = {
      'Detetive Iniciante': {
        min: 0,
        max: 60,
        icon: '🔍',
        color: this.getThemeColor('--color-primary', '#4A90E2'),
        message: 'Você está começando sua jornada na investigação de vulnerabilidades. Continue estudando e logo será um grande detetive de segurança!',
        badge: 'badge-novice'
      },
      'Inspector': {
        min: 61,
        max: 75,
        icon: '🕵️',
        color: this.getThemeColor('--color-success', '#50C878'),
        message: 'Você demonstrou conhecimento sólido. Está no caminho certo para se tornar um grande detetive de segurança!',
        badge: 'badge-inspector'
      },
      'Detetive Experiente': {
        min: 76,
        max: 90,
        icon: '🔎',
        color: this.getThemeColor('--color-warning', '#FF8C00'),
        message: 'Excelente! Você tem olho clínico para identificar vulnerabilidades. Um verdadeiro investigador de segurança!',
        badge: 'badge-expert'
      },
      'QA Sherlock': {
        min: 91,
        max: 100,
        icon: '🕵️‍♂️',
        color: this.getThemeColor('--color-primary', '#FFD700'),
        message: 'Elementar, meu caro Watson! Você dominou completamente este tema. Um verdadeiro gênio da segurança em QA!',
        badge: 'badge-sherlock',
        special: true
      }
    };
    
    this.init();
  }
  
  init() {
    const quizContainer = document.getElementById('quiz-container');
    if (!quizContainer) return;
    
    const lessonId = quizContainer.dataset.lessonId;
    const quizDataElement = document.getElementById('quiz-data');
    
    if (!quizDataElement) {
      window.Logger?.warn('Quiz data not found');
      return;
    }
    
    try {
      const dataText = quizDataElement.textContent.trim();
      if (!dataText || dataText === 'null' || dataText === '') {
        quizContainer.classList.add('hidden');
        return;
      }
      
      const data = JSON.parse(dataText);
      if (!data || !data.questions || data.questions.length === 0) {
        quizContainer.classList.add('hidden');
        return;
      }
      
      this.quizData = data;
      this.renderQuestion();
    } catch (e) {
      window.Logger?.error('Error parsing quiz data:', e);
      quizContainer.classList.add('hidden');
    }
  }
  
  renderQuestion() {
    if (!this.quizData || !this.quizData.questions) return;
    
    const question = this.quizData.questions[this.currentQuestion];
    if (!question) {
      this.showResults();
      return;
    }
    
    const quizContent = document.getElementById('quiz-content');
    if (!quizContent) return;
    
    // Atualizar progresso
    this.updateProgress();
    
    // Renderizar pergunta
    quizContent.innerHTML = `
      <div class="question-card">
        <div class="question-header">
          <span class="question-number">Pergunta ${this.currentQuestion + 1}</span>
          <h3 class="question-text" id="question-${this.currentQuestion}">${this.escapeHtml(question.question)}</h3>
        </div>
        <div class="options-container" id="options-container" role="radiogroup" aria-labelledby="question-${this.currentQuestion}">
          ${question.options.map((option, index) => `
            <button class="option-button" 
                    data-testid="quiz-option-${index}"
                    data-option-index="${index}"
                    data-correct="${index === question.correct}"
                    role="radio"
                    aria-checked="false"
                    aria-label="Opção ${String.fromCharCode(65 + index)}: ${this.escapeHtml(option)}"
                    tabindex="${index === 0 ? '0' : '-1'}">
              <span class="option-letter" aria-hidden="true">${String.fromCharCode(65 + index)}</span>
              <span class="option-text">${this.escapeHtml(option)}</span>
            </button>
          `).join('')}
        </div>
        <div class="explanation hidden" id="explanation" data-testid="quiz-explanation" role="region" aria-live="polite" aria-atomic="true" aria-hidden="true">
          <div class="explanation-content">
            <strong>Explicação:</strong>
            <p>${this.escapeHtml(question.explanation)}</p>
          </div>
          <button class="next-question-button" id="next-question-btn" data-testid="quiz-next-btn" aria-label="${this.currentQuestion < this.quizData.questions.length - 1 ? 'Ir para próxima pergunta' : 'Ver resultado final do quiz'}">
            ${this.currentQuestion < this.quizData.questions.length - 1 ? 'Próxima Pergunta →' : 'Ver Resultado Final'}
          </button>
        </div>
      </div>
    `;
    
    // Garantir que explicação está oculta inicialmente
    const explanationEl = document.getElementById('explanation');
    if (explanationEl) {
      explanationEl.classList.add('hidden');
      explanationEl.style.display = 'none';
      explanationEl.setAttribute('aria-hidden', 'true');
    }
    
    // Adicionar event listeners
    this.setupOptionButtons();
  }
  
  setupOptionButtons() {
    const options = document.querySelectorAll('.option-button');
    const explanation = document.getElementById('explanation');
    const nextBtn = document.getElementById('next-question-btn');
    
    options.forEach((button, index) => {
      // Click handler
      const handleAnswer = () => {
        if (button.classList.contains('answered')) return;
        
        const isCorrect = button.dataset.correct === 'true';
        const optionIndex = parseInt(button.dataset.optionIndex, 10);
        if (isNaN(optionIndex) || optionIndex < 0) {
          window.Logger?.warn('Índice de opção inválido:', button.dataset.optionIndex);
          return;
        }
        
        // Marcar todas as opções como respondidas
        options.forEach(opt => {
          opt.classList.add('answered');
          opt.disabled = true;
          opt.setAttribute('aria-checked', opt === button ? 'true' : 'false');
          opt.setAttribute('tabindex', '-1'); // Remover do tab order após resposta
          
          if (opt.dataset.correct === 'true') {
            opt.classList.add('correct');
            const currentLabel = opt.getAttribute('aria-label') || '';
            opt.setAttribute('aria-label', currentLabel.replace(' (Resposta correta)', '').replace(' (Resposta incorreta)', '') + ' (Resposta correta)');
          } else if (opt === button && !isCorrect) {
            opt.classList.add('incorrect');
            const currentLabel = opt.getAttribute('aria-label') || '';
            opt.setAttribute('aria-label', currentLabel.replace(' (Resposta correta)', '').replace(' (Resposta incorreta)', '') + ' (Resposta incorreta)');
          }
        });
        
        // Focar no botão "Próxima Pergunta" após resposta
        if (nextBtn) {
          nextBtn.focus();
        }
        
        // Salvar resposta
        this.answers.push({
          questionId: this.quizData.questions[this.currentQuestion].id,
          selected: optionIndex,
          correct: isCorrect
        });
        
        // Mostrar explicação APENAS após resposta ser selecionada
        if (explanation) {
          explanation.classList.remove('hidden');
          explanation.style.display = ''; // Remove style inline para permitir que CSS funcione
          explanation.setAttribute('aria-hidden', 'false');
          // Scroll suave para a explicação após um pequeno delay para melhor UX
          setTimeout(() => {
            explanation.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
          }, 100);
        }
      };
      
      button.addEventListener('click', handleAnswer);
      
      // Keyboard navigation (1-4 keys for options A-D)
      button.addEventListener('keydown', (e) => {
        if (e.key >= '1' && e.key <= '4') {
          const keyIndex = parseInt(e.key, 10) - 1;
          if (!isNaN(keyIndex) && keyIndex >= 0 && options[keyIndex]) {
            e.preventDefault();
            options[keyIndex].focus();
            options[keyIndex].click();
          }
        } else if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          handleAnswer();
        }
      });
      
      // Nota: Atributos ARIA (role="radio", aria-checked, tabindex) já são definidos no template string
      // aria-checked é atualizado dinamicamente quando resposta é selecionada em handleAnswer()
    });
    
    // Botão próxima pergunta
    if (nextBtn) {
      const handleNext = () => {
        this.currentQuestion++;
        if (this.currentQuestion < this.quizData.questions.length) {
          this.renderQuestion();
          // Não forçar scroll; manter a posição atual evita pular para o footer
        } else {
          this.showResults();
        }
      };
      
      nextBtn.addEventListener('click', handleNext);
      
      // Suporte a Enter no botão
      nextBtn.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          handleNext();
        }
      });
    }
  }
  
  updateProgress() {
    const progressFill = document.getElementById('quiz-progress-fill');
    const currentQuestionNum = document.getElementById('current-question-num');
    
    if (progressFill) {
      const progress = ((this.currentQuestion + 1) / this.quizData.questions.length) * 100;
      progressFill.style.width = `${progress}%`;
    }
    
    if (currentQuestionNum) {
      currentQuestionNum.textContent = this.currentQuestion + 1;
    }
  }
  
  calculateScore() {
    const correctAnswers = this.answers.filter(a => a.correct).length;
    const totalQuestions = this.quizData.questions.length;
    this.score = Math.round((correctAnswers / totalQuestions) * 100);
    return this.score;
  }
  
  getClassification(score) {
    for (const [name, config] of Object.entries(this.classifications)) {
      if (score >= config.min && score <= config.max) {
        return { name, ...config };
      }
    }
    return this.classifications['Detetive Iniciante'];
  }
  
  showResults() {
    const score = this.calculateScore();
    const classification = this.getClassification(score);
    const quizContent = document.getElementById('quiz-content');
    const quizResults = document.getElementById('quiz-results');
    
    if (!quizContent || !quizResults) return;
    
    // Esconder conteúdo do quiz
    quizContent.classList.add('hidden');
    
    // Mostrar resultados
    quizResults.classList.remove('hidden');
    quizResults.innerHTML = `
      <div class="results-card ${classification.badge}">
        <div class="results-header">
          <div class="classification-icon ${classification.special ? 'special' : ''}">${classification.icon}</div>
          <h2 class="classification-title">Você é um ${classification.name}!</h2>
          <div class="score-display">
            <span class="score-number">${score}</span>
            <span class="score-label">pontos</span>
          </div>
        </div>
        <div class="results-message">
          <p>${classification.message}</p>
        </div>
        <div class="results-details">
          <div class="detail-item">
            <span class="detail-label">Acertos:</span>
            <span class="detail-value">${this.answers.filter(a => a.correct).length} de ${this.quizData.questions.length}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Taxa de acerto:</span>
            <span class="detail-value">${score}%</span>
          </div>
        </div>
        <button class="retry-quiz-button" id="retry-quiz-btn" data-testid="quiz-retry-btn">
          🔄 Refazer Quiz
        </button>
      </div>
    `;
    
    // Scroll para resultados
    quizResults.scrollIntoView({ behavior: 'smooth', block: 'start' });
    
    // Adicionar animação especial para QA Sherlock
    if (classification.special) {
      quizResults.classList.add('sherlock-special');
    }
    
    // Salvar resultado no progress tracker
    this.saveResult(score, classification.name);
    
    // Event listener para refazer quiz
    const retryBtn = document.getElementById('retry-quiz-btn');
    if (retryBtn) {
      retryBtn.addEventListener('click', () => {
        this.resetQuiz();
      });
    }
  }
  
  saveResult(score, classification) {
    const quizContainer = document.getElementById('quiz-container');
    if (!quizContainer) return;
    
    const lessonId = quizContainer.dataset.lessonId;
    
    if (window.progressTracker && typeof window.progressTracker.saveQuizResult === 'function') {
      window.progressTracker.saveQuizResult(lessonId, score, classification, this.answers);
    } else {
      // Fallback: salvar usando StorageSafe se disponível, senão localStorage direto
      const progressKey = (window.Constants && window.Constants.STORAGE_KEYS && window.Constants.STORAGE_KEYS.COURSE_PROGRESS) || 'course-progress';
      let progress = {};
      
      if (window.StorageSafe && typeof window.StorageSafe.getItem === 'function') {
        progress = window.StorageSafe.getItem(progressKey) || {};
      } else {
        try {
          const saved = localStorage.getItem(progressKey);
          progress = saved ? JSON.parse(saved) : {};
        } catch (e) {
          window.Logger?.error('Error parsing progress:', e);
          progress = {};
        }
      }
      
      if (!progress.quizzes) progress.quizzes = {};
      progress.quizzes[lessonId] = {
        score: score,
        classification: classification,
        completed_at: new Date().toISOString(),
        answers: this.answers
      };
      
      // Salvar usando StorageSafe se disponível
      if (window.StorageSafe && typeof window.StorageSafe.setItem === 'function') {
        window.StorageSafe.setItem(progressKey, progress);
      } else {
        try {
          localStorage.setItem(progressKey, JSON.stringify(progress));
        } catch (e) {
          window.Logger?.error('Error saving quiz result:', e);
        }
      }
    }
  }
  
  resetQuiz() {
    this.currentQuestion = 0;
    this.answers = [];
    this.score = 0;
    
    const quizContent = document.getElementById('quiz-content');
    const quizResults = document.getElementById('quiz-results');
    
    if (quizContent) quizContent.classList.remove('hidden');
    if (quizResults) {
      quizResults.classList.add('hidden');
      quizResults.classList.remove('sherlock-special');
    }
    
    this.renderQuestion();
  }
  
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
}

// Inicializar quando DOM estiver pronto
document.addEventListener('DOMContentLoaded', () => {
  const quizContainer = document.getElementById('quiz-container');
  if (quizContainer) {
    window.quizManager = new QuizManager();
  }
});
