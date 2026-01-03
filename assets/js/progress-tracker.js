class ProgressTracker {
  constructor() {
    this.progress = this.loadProgress();
    this.init();
  }
  
  init() {
    this.updateDisplay();
    this.setupLessonCompletion();
  }
  
  loadProgress() {
    const saved = localStorage.getItem('course-progress');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch (e) {
        console.error('Erro ao carregar progresso:', e);
      }
    }
    return {
      lessons: {},
      exercises: {},
      podcasts: {}
    };
  }
  
  saveProgress() {
    localStorage.setItem('course-progress', JSON.stringify(this.progress));
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
    
    if (tracker && overallProgress > 0) {
      tracker.style.display = 'block';
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
  
  trackEvent(eventName, parameters) {
    if (typeof gtag !== 'undefined') {
      gtag('event', eventName, parameters);
    }
  }
}

document.addEventListener('DOMContentLoaded', () => {
  window.progressTracker = new ProgressTracker();
});

