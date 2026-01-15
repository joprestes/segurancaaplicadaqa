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
    // #region agent log
    fetch('http://127.0.0.1:7242/ingest/59658d78-532f-46f1-95b3-b0fe827c7eaa',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'progress-tracker.js:setupLessonCompletion',message:'setupLessonCompletion iniciado',data:{progressLessons:this.progress.lessons,progressLessonsKeys:Object.keys(this.progress.lessons||{})},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'A'})}).catch(()=>{});
    // #endregion
    
    const completeButtons = document.querySelectorAll('.mark-lesson-complete');
    
    // #region agent log
    fetch('http://127.0.0.1:7242/ingest/59658d78-532f-46f1-95b3-b0fe827c7eaa',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'progress-tracker.js:setupLessonCompletion',message:'Botões encontrados',data:{buttonsCount:completeButtons.length,buttons:Array.from(completeButtons).map(b=>({lessonId:b.dataset.lessonId,moduleId:b.dataset.moduleId,disabled:b.disabled,text:b.textContent}))},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'A'})}).catch(()=>{});
    // #endregion
    
    completeButtons.forEach(button => {
      const lessonId = button.dataset.lessonId;
      const moduleId = button.dataset.moduleId;
      
      // #region agent log
      fetch('http://127.0.0.1:7242/ingest/59658d78-532f-46f1-95b3-b0fe827c7eaa',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'progress-tracker.js:setupLessonCompletion:forEach',message:'Verificando botão',data:{lessonId:lessonId,moduleId:moduleId,isCompleted:!!(this.progress.lessons?.[lessonId]?.completed),progressData:this.progress.lessons?.[lessonId]},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'A'})}).catch(()=>{});
      // #endregion
      
      // Verificar se a aula já está completa e restaurar estado do botão
      if (lessonId && this.progress.lessons?.[lessonId]?.completed) {
        // #region agent log
        fetch('http://127.0.0.1:7242/ingest/59658d78-532f-46f1-95b3-b0fe827c7eaa',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'progress-tracker.js:setupLessonCompletion:restore',message:'Restaurando estado do botão',data:{lessonId:lessonId,wasCompleted:true},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'A'})}).catch(()=>{});
        // #endregion
        button.textContent = '✓ Concluída';
        button.disabled = true;
      }
      
      button.addEventListener('click', () => {
        // #region agent log
        fetch('http://127.0.0.1:7242/ingest/59658d78-532f-46f1-95b3-b0fe827c7eaa',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'progress-tracker.js:setupLessonCompletion:click',message:'Botão clicado',data:{lessonId:lessonId,moduleId:moduleId},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'B'})}).catch(()=>{});
        // #endregion
        
        if (lessonId && moduleId) {
          this.markLessonComplete(lessonId, moduleId);
          
          // #region agent log
          fetch('http://127.0.0.1:7242/ingest/59658d78-532f-46f1-95b3-b0fe827c7eaa',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'progress-tracker.js:setupLessonCompletion:afterMark',message:'Após markLessonComplete',data:{lessonId:lessonId,savedProgress:this.progress.lessons?.[lessonId],localStorageCheck:localStorage.getItem('course-progress')?JSON.parse(localStorage.getItem('course-progress')).lessons?.[lessonId]:null},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'B'})}).catch(()=>{});
          // #endregion
          
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

