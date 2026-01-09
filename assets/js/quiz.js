class QuizManager {
  constructor() {
    this.quizData = null;
    this.currentQuestion = 0;
    this.answers = [];
    this.score = 0;
    this.classifications = {
      'Detetive Iniciante': {
        min: 0,
        max: 60,
        icon: '🔍',
        color: '#4A90E2',
        message: 'Você está começando sua jornada na investigação de vulnerabilidades. Continue estudando e logo será um grande detetive de segurança!',
        badge: 'badge-novice'
      },
      'Inspector': {
        min: 61,
        max: 75,
        icon: '🕵️',
        color: '#50C878',
        message: 'Você demonstrou conhecimento sólido. Está no caminho certo para se tornar um grande detetive de segurança!',
        badge: 'badge-inspector'
      },
      'Detetive Experiente': {
        min: 76,
        max: 90,
        icon: '🔎',
        color: '#FF8C00',
        message: 'Excelente! Você tem olho clínico para identificar vulnerabilidades. Um verdadeiro investigador de segurança!',
        badge: 'badge-expert'
      },
      'QA Sherlock': {
        min: 91,
        max: 100,
        icon: '🕵️‍♂️',
        color: '#FFD700',
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
      console.warn('Quiz data not found');
      return;
    }
    
    try {
      const dataText = quizDataElement.textContent.trim();
      if (!dataText || dataText === 'null' || dataText === '') {
        quizContainer.style.display = 'none';
        return;
      }
      
      const data = JSON.parse(dataText);
      if (!data || !data.questions || data.questions.length === 0) {
        quizContainer.style.display = 'none';
        return;
      }
      
      this.quizData = data;
      this.renderQuestion();
    } catch (e) {
      console.error('Error parsing quiz data:', e);
      quizContainer.style.display = 'none';
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
          <h3 class="question-text">${this.escapeHtml(question.question)}</h3>
        </div>
        <div class="options-container" id="options-container">
          ${question.options.map((option, index) => `
            <button class="option-button" 
                    data-option-index="${index}"
                    data-correct="${index === question.correct}"
                    aria-label="Opção ${index + 1}: ${this.escapeHtml(option)}">
              <span class="option-letter">${String.fromCharCode(65 + index)}</span>
              <span class="option-text">${this.escapeHtml(option)}</span>
            </button>
          `).join('')}
        </div>
        <div class="explanation" id="explanation" style="display: none;">
          <div class="explanation-content">
            <strong>Explicação:</strong>
            <p>${this.escapeHtml(question.explanation)}</p>
          </div>
          <button class="next-question-button" id="next-question-btn">
            ${this.currentQuestion < this.quizData.questions.length - 1 ? 'Próxima Pergunta →' : 'Ver Resultado Final'}
          </button>
        </div>
      </div>
    `;
    
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
        const optionIndex = parseInt(button.dataset.optionIndex);
        
        // Marcar todas as opções como respondidas
        options.forEach(opt => {
          opt.classList.add('answered');
          opt.disabled = true;
          opt.setAttribute('aria-checked', opt === button ? 'true' : 'false');
          
          if (opt.dataset.correct === 'true') {
            opt.classList.add('correct');
            opt.setAttribute('aria-label', opt.getAttribute('aria-label') + ' (Resposta correta)');
          } else if (opt === button && !isCorrect) {
            opt.classList.add('incorrect');
            opt.setAttribute('aria-label', opt.getAttribute('aria-label') + ' (Resposta incorreta)');
          }
        });
        
        // Salvar resposta
        this.answers.push({
          questionId: this.quizData.questions[this.currentQuestion].id,
          selected: optionIndex,
          correct: isCorrect
        });
        
        // Mostrar explicação
        if (explanation) {
          explanation.style.display = 'block';
          explanation.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
      };
      
      button.addEventListener('click', handleAnswer);
      
      // Keyboard navigation (1-4 keys for options A-D)
      button.addEventListener('keydown', (e) => {
        if (e.key >= '1' && e.key <= '4') {
          const keyIndex = parseInt(e.key) - 1;
          if (options[keyIndex]) {
            e.preventDefault();
            options[keyIndex].focus();
            options[keyIndex].click();
          }
        } else if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          handleAnswer();
        }
      });
      
      // Acessibilidade: ARIA labels
      button.setAttribute('role', 'radio');
      button.setAttribute('aria-checked', 'false');
      button.setAttribute('tabindex', '0');
    });
    
    // Botão próxima pergunta
    if (nextBtn) {
      const handleNext = () => {
        this.currentQuestion++;
        if (this.currentQuestion < this.quizData.questions.length) {
          this.renderQuestion();
          // Scroll para o topo da nova pergunta
          document.getElementById('quiz-content')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
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
    quizContent.style.display = 'none';
    
    // Mostrar resultados
    quizResults.style.display = 'block';
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
        <button class="retry-quiz-button" id="retry-quiz-btn">
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
      // Fallback: salvar diretamente no localStorage
      const saved = localStorage.getItem('course-progress');
      let progress = {};
      
      if (saved) {
        try {
          progress = JSON.parse(saved);
        } catch (e) {
          console.error('Error parsing progress:', e);
        }
      }
      
      if (!progress.quizzes) progress.quizzes = {};
      progress.quizzes[lessonId] = {
        score: score,
        classification: classification,
        completed_at: new Date().toISOString(),
        answers: this.answers
      };
      
      localStorage.setItem('course-progress', JSON.stringify(progress));
    }
  }
  
  resetQuiz() {
    this.currentQuestion = 0;
    this.answers = [];
    this.score = 0;
    
    const quizContent = document.getElementById('quiz-content');
    const quizResults = document.getElementById('quiz-results');
    
    if (quizContent) quizContent.style.display = 'block';
    if (quizResults) {
      quizResults.style.display = 'none';
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
