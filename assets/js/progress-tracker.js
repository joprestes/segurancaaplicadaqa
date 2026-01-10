class ProgressTracker {
  constructor() {
    // Limpar dados antigos de podcast se existir utilitário de migração
    if (window.StorageMigration && typeof window.StorageMigration.cleanPodcastData === 'function') {
      window.StorageMigration.cleanPodcastData();
    }
    this.progress = this.loadProgress();
    this.init();
  }
  
  init() {
    this.updateDisplay();
    this.setupLessonCompletion();
  }
  
  loadProgress() {
    const progressKey = (window.Constants && window.Constants.STORAGE_KEYS && window.Constants.STORAGE_KEYS.COURSE_PROGRESS) || 'course-progress';
    
    // Usar StorageSafe se disponível, senão fallback para localStorage direto
    let saved = null;
    if (window.StorageSafe && typeof window.StorageSafe.getItem === 'function') {
      saved = window.StorageSafe.getItem(progressKey);
    } else {
      try {
        const item = localStorage.getItem(progressKey);
        saved = item ? JSON.parse(item) : null;
      } catch (e) {
        window.Logger?.error('Erro ao carregar progresso:', e);
        saved = null;
      }
    }
    
    if (saved) {
      // Remover podcasts do progresso se existir (limpeza de dados antigos)
      if (saved.podcasts) {
        delete saved.podcasts;
        // Salvar progresso limpo
        this.saveProgress();
      }
      return saved;
    }
    
    return {
      lessons: {},
      exercises: {}
    };
  }
  
  saveProgress() {
    const progressKey = (window.Constants && window.Constants.STORAGE_KEYS && window.Constants.STORAGE_KEYS.COURSE_PROGRESS) || 'course-progress';
    
    // Usar StorageSafe se disponível
    if (window.StorageSafe && typeof window.StorageSafe.setItem === 'function') {
      const success = window.StorageSafe.setItem(progressKey, this.progress);
      if (!success) {
        window.Logger?.warn('Não foi possível salvar progresso no localStorage');
      }
    } else {
      // Fallback para localStorage direto
      try {
        localStorage.setItem(progressKey, JSON.stringify(this.progress));
      } catch (e) {
        window.Logger?.error('Erro ao salvar progresso:', e);
      }
    }
  }
  
  markLessonComplete(lessonId, moduleId) {
    if (!this.progress.lessons) this.progress.lessons = {};
    this.progress.lessons[lessonId] = {
      completed: true,
      completed_at: new Date().toISOString()
    };
    this.saveProgress();
    this.updateDisplay();
    
    this.trackEvent('lesson_complete', {
      lesson_id: lessonId,
      module_id: moduleId,
      completion_time: new Date().toISOString()
    });
  }
  
  markExerciseComplete(exerciseId, lessonId) {
    if (!this.progress.exercises) this.progress.exercises = {};
    this.progress.exercises[exerciseId] = {
      completed: true,
      completed_at: new Date().toISOString()
    };
    this.saveProgress();
    this.updateDisplay();
    
    this.trackEvent('exercise_complete', {
      exercise_id: exerciseId,
      lesson_id: lessonId
    });
  }
  
  updateModuleProgress(moduleId) {
    const module = window.siteData?.modules?.find(m => m.id === moduleId);
    if (!module) return;
    
    const moduleLessons = window.siteData?.lessons?.filter(l => l.module === moduleId) || [];
    const completedLessons = moduleLessons.filter(l => 
      this.progress.lessons?.[l.id]?.completed
    ).length;
    
    const progressPercentage = moduleLessons.length > 0 
      ? Math.round((completedLessons / moduleLessons.length) * 100)
      : 0;
    
    this.trackEvent('module_progress', {
      module_id: moduleId,
      progress_percentage: progressPercentage,
      lessons_completed: completedLessons
    });
  }
  
  calculateOverallProgress() {
    const allLessons = window.siteData?.lessons || [];
    if (allLessons.length === 0) return 0;
    
    const completedLessons = allLessons.filter(l => 
      this.progress.lessons?.[l.id]?.completed
    ).length;
    
    return Math.round((completedLessons / allLessons.length) * 100);
  }
  
  updateDisplay() {
    const overallProgress = this.calculateOverallProgress();
    const progressFill = document.getElementById('overall-progress-fill');
    const progressText = document.getElementById('overall-progress-text');
    const tracker = document.getElementById('progress-tracker');
    
    if (progressFill) {
      progressFill.style.width = `${overallProgress}%`;
    }
    
    if (progressText) {
      progressText.textContent = `${overallProgress}%`;
    }
    
    if (tracker) {
      if (overallProgress > 0) {
        tracker.classList.remove('hidden');
      } else {
        tracker.classList.add('hidden');
      }
    }
  }
  
  setupLessonCompletion() {
    const completeButtons = document.querySelectorAll('.mark-lesson-complete');
    completeButtons.forEach(button => {
      button.addEventListener('click', () => {
        const lessonId = button.dataset.lessonId;
        const moduleId = button.dataset.moduleId;
        if (lessonId && moduleId) {
          this.markLessonComplete(lessonId, moduleId);
          this.updateModuleProgress(moduleId);
          button.textContent = '✓ Concluída';
          button.disabled = true;
        }
      });
    });
  }
  
  saveQuizResult(lessonId, score, classification, answers) {
    if (!this.progress.quizzes) this.progress.quizzes = {};
    this.progress.quizzes[lessonId] = {
      score: score,
      classification: classification,
      completed_at: new Date().toISOString(),
      answers: answers
    };
    this.saveProgress();
    this.updateDisplay();
    
    this.trackEvent('quiz_complete', {
      lesson_id: lessonId,
      score: score,
      classification: classification
    });
  }
  
  trackEvent(eventName, parameters) {
    if (typeof gtag !== 'undefined') {
      gtag('event', eventName, parameters);
    }
  }
}

document.addEventListener('DOMContentLoaded', () => {
  window.progressTracker = new ProgressTracker();
});

