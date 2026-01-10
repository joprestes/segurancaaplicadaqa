class GlobalVideoManager {
  constructor() {
    this.currentPlayer = null;
    this.currentVideo = null;
    this.currentConfig = null;
    this.isPlaying = false;
    this.init();
  }

  init() {
    if (typeof window.globalVideoManager === 'undefined') {
      window.globalVideoManager = this;
    }
    return window.globalVideoManager;
  }

  static getInstance() {
    if (!window.globalVideoManager) {
      window.globalVideoManager = new GlobalVideoManager();
    }
    return window.globalVideoManager;
  }

  setPlayer(player, video, config) {
    if (this.currentPlayer && this.currentPlayer !== player) {
      this.currentPlayer.pause();
      this.currentPlayer.isPlaying = false;
      this.currentPlayer.updateUI();
    }
    this.currentPlayer = player;
    this.currentVideo = video;
    this.currentConfig = config;
    this.isPlaying = player ? player.isPlaying : false;
  }

  getCurrentPlayer() {
    return this.currentPlayer;
  }

  getCurrentConfig() {
    return this.currentConfig;
  }

  pauseCurrent() {
    if (this.currentPlayer) {
      this.currentPlayer.pause();
    }
  }
}

class VideoPlayer {
  constructor(config) {
    this.manager = GlobalVideoManager.getInstance();
    this.config = config;
    this.lessonId = config.lessonId;
    this.videoFile = config.videoFile;
    this.videoTitle = config.videoTitle || null;
    this.videoDescription = config.videoDescription || null;
    this.videoThumbnail = config.videoThumbnail || null;
    this.currentTime = 0;
    this.duration = 0;
    this.isPlaying = false;
    this.playbackRate = 1.0;
    
    this.video = document.getElementById('video-element');
    
    if (this.video) {
      if (this.video.src && this.video.src !== '' && this.video.src !== window.location.href) {
        this.videoFile = this.video.src;
        if (window.Logger) {
          window.Logger.log('Usando src do HTML:', this.videoFile);
        } else {
          console.log('Usando src do HTML:', this.videoFile);
        }
      } else if (this.videoFile && (!this.video.src || this.video.src === '' || this.video.src === window.location.href)) {
        if (window.Logger) {
          window.Logger.log('Definindo src do JavaScript:', this.videoFile);
        } else {
          console.log('Definindo src do JavaScript:', this.videoFile);
        }
        // Validação não-bloqueante (apenas logging)
        if (typeof window.validateMediaFile === 'function') {
          window.validateMediaFile(this.videoFile, 'video');
        }
        this.video.src = this.videoFile;
        this.video.load();
      }
      this.manager.setPlayer(this, this.video, config);
    } else {
      const currentPlayer = this.manager.getCurrentPlayer();
      if (currentPlayer && currentPlayer.video && currentPlayer.video.src) {
        this.video = currentPlayer.video;
        this.videoFile = currentPlayer.videoFile;
        this.videoTitle = currentPlayer.videoTitle;
        this.videoDescription = currentPlayer.videoDescription;
        this.videoThumbnail = currentPlayer.videoThumbnail;
        this.lessonId = currentPlayer.lessonId;
        this.currentTime = currentPlayer.currentTime;
        this.duration = currentPlayer.duration;
        this.isPlaying = currentPlayer.isPlaying;
        this.playbackRate = currentPlayer.playbackRate;
        this.manager.setPlayer(this, this.video, currentPlayer.config);
      } else {
        const globalState = sessionStorage.getItem('video-global-state');
        if (globalState) {
          try {
            const state = JSON.parse(globalState);
            if (state.videoFile && this.video) {
              if (this.video.src && this.video.src !== '') {
                this.videoFile = this.video.src;
              } else {
                this.video.src = state.videoFile;
                this.video.load();
                this.videoFile = state.videoFile;
              }
              this.videoTitle = state.videoTitle || null;
              this.videoDescription = state.videoDescription || null;
              this.videoThumbnail = state.videoThumbnail || null;
              this.currentTime = state.currentTime || 0;
              this.duration = state.duration || 0;
              this.isPlaying = false;
              this.playbackRate = state.playbackRate || 1.0;
              this.manager.setPlayer(this, this.video, {
                videoFile: this.videoFile,
                lessonId: state.lessonId,
                videoTitle: state.videoTitle,
                videoDescription: state.videoDescription,
                videoThumbnail: state.videoThumbnail
              });
            }
          } catch (e) {
            if (window.Logger) {
              window.Logger.error('Erro ao recuperar estado global:', e);
            } else {
              console.error('Erro ao recuperar estado global:', e);
            }
            this.video = null;
          }
        } else {
          this.video = null;
        }
      }
    }
    
    this.initElements();
    this.bindEvents();
    this.loadProgress();
    this.updateUI();
    this.updateInfo();
    
    if (this.video && this.video.src && this.isPlaying) {
      this.video.play().catch((error) => {
        if (window.Logger) {
          window.Logger.warn('Erro ao retomar reprodução:', error);
        } else {
          console.warn('Erro ao retomar reprodução:', error);
        }
        this.isPlaying = false;
        this.updateUI();
      });
    }
  }
  
  initElements() {
    this.videoElement = document.getElementById('video-element');
    this.currentTimeDisplay = document.getElementById('video-current-time');
    this.durationDisplay = document.getElementById('video-duration');
    this.speedSelect = document.getElementById('video-speed');
    this.volumeControl = document.getElementById('video-volume');
    this.indicator = document.getElementById('video-indicator');
    this.videoInfo = document.querySelector('.video-info');
    this.videoTitleEl = document.querySelector('.video-info h3');
    this.videoDescriptionEl = document.querySelector('.video-description');
  }
  
  bindEvents() {
    if (!this.video) {
      const globalState = sessionStorage.getItem('video-global-state');
      if (globalState) {
        try {
          const state = JSON.parse(globalState);
          if (state.isPlaying) {
            this.isPlaying = false;
            this.updateUI();
          }
        } catch (e) {}
      }
      return;
    }

    if (!this.video.src) {
      return;
    }

    this.video.addEventListener('loadedmetadata', () => {
      this.duration = this.video.duration;
      this.updateDurationDisplay();
    });
    
    // Debounce apenas em saveProgress, não em updateProgress visual
    const debouncedSave = typeof window.debounce === 'function' 
      ? window.debounce(() => this.saveProgress(), 250)
      : () => this.saveProgress();
    
    this.video.addEventListener('timeupdate', () => {
      this.currentTime = this.video.currentTime;
      this.updateProgress();  // Visual - SEMPRE (sem debounce)
      debouncedSave();         // Storage - com debounce (se disponível)
    });
    
    this.video.addEventListener('play', () => {
      this.isPlaying = true;
      this.manager.isPlaying = true;
      this.updateUI();
      this.showIndicator();
      this.trackEvent('video_play', {
        lesson_id: this.lessonId,
        video_title: this.videoTitle,
        current_time: this.currentTime
      });
    });
    
    this.video.addEventListener('pause', () => {
      this.isPlaying = false;
      this.manager.isPlaying = false;
      this.updateUI();
      this.hideIndicator();
      const progressPercentage = this.duration > 0 ? (this.currentTime / this.duration) * 100 : 0;
      this.trackEvent('video_pause', {
        lesson_id: this.lessonId,
        progress_percentage: Math.round(progressPercentage)
      });
    });
    
    this.video.addEventListener('ended', () => {
      this.isPlaying = false;
      this.updateUI();
      this.markAsWatched();
      sessionStorage.removeItem('video-global-state');
      this.trackEvent('video_complete', {
        lesson_id: this.lessonId,
        duration: this.duration,
        total_time: this.duration
      });
    });
    
    this.video.addEventListener('error', (e) => {
      if (window.Logger) {
        window.Logger.error('Erro ao carregar vídeo:', e);
        if (this.video.error) {
          window.Logger.error('Código de erro do vídeo:', this.video.error.code);
          window.Logger.error('Mensagem:', this.video.error.message);
          window.Logger.error('URL tentada:', this.video.src);
          window.Logger.error('URL esperada:', this.videoFile);
        }
      } else {
        console.error('Erro ao carregar vídeo:', e);
        if (this.video.error) {
          console.error('Código de erro do vídeo:', this.video.error.code);
          console.error('Mensagem:', this.video.error.message);
          console.error('URL tentada:', this.video.src);
          console.error('URL esperada:', this.videoFile);
        }
      }
      if (this.videoFile) {
        this.handleError();
      }
    });
    
    this.video.addEventListener('loadstart', () => {
      if (window.Logger) {
        window.Logger.log('Iniciando carregamento do vídeo:', this.video.src || this.videoFile);
      } else {
        console.log('Iniciando carregamento do vídeo:', this.video.src || this.videoFile);
      }
    });
    
    this.video.addEventListener('canplay', () => {
      if (window.Logger) {
        window.Logger.log('Vídeo pode ser reproduzido:', this.video.src);
      } else {
        console.log('Vídeo pode ser reproduzido:', this.video.src);
      }
    });
    
    this.video.addEventListener('loadeddata', () => {
      if (window.Logger) {
        window.Logger.log('Dados do vídeo carregados');
      } else {
        console.log('Dados do vídeo carregados');
      }
      if (this.video.readyState >= 2) {
        this.duration = this.video.duration;
        this.updateDurationDisplay();
      }
    });
    
    this.speedSelect?.addEventListener('change', (e) => this.setSpeed(e.target.value));
    this.volumeControl?.addEventListener('input', (e) => this.setVolume(e.target.value));
    
    document.addEventListener('visibilitychange', () => {
      if (document.hidden && this.isPlaying) {
        this.showIndicator();
      }
    });

    if (this.video && this.video.readyState >= 2) {
      this.duration = this.video.duration;
      this.updateDurationDisplay();
    }
  }
  
  setSpeed(speed) {
    if (!this.video || !this.video.src) return;
    
    const oldSpeed = this.playbackRate;
    this.playbackRate = parseFloat(speed);
    this.video.playbackRate = this.playbackRate;
    this.trackEvent('video_speed_change', {
      old_speed: oldSpeed,
      new_speed: this.playbackRate
    });
  }
  
  setVolume(volume) {
    if (!this.video || !this.video.src) return;
    
    this.video.volume = parseFloat(volume) / 100;
  }
  
  updateProgress() {
    if (this.duration > 0) {
      const percentage = (this.currentTime / this.duration) * 100;
      this.updateCurrentTimeDisplay();
    }
  }
  
  updateCurrentTimeDisplay() {
    const minutes = Math.floor(this.currentTime / 60);
    const seconds = Math.floor(this.currentTime % 60);
    if (this.currentTimeDisplay) {
      this.currentTimeDisplay.textContent = 
        `${minutes}:${seconds.toString().padStart(2, '0')}`;
    }
  }
  
  updateDurationDisplay() {
    const minutes = Math.floor(this.duration / 60);
    const seconds = Math.floor(this.duration % 60);
    if (this.durationDisplay) {
      this.durationDisplay.textContent = 
        `${minutes}:${seconds.toString().padStart(2, '0')}`;
    }
  }

  updateInfo() {
    if (this.videoTitleEl) {
      if (this.videoTitle) {
        this.videoTitleEl.textContent = this.videoTitle;
      } else if (this.videoTitleEl.id === 'video-title-placeholder') {
        const globalState = sessionStorage.getItem('video-global-state');
        if (globalState) {
          try {
            const state = JSON.parse(globalState);
            if (state.videoTitle) {
              this.videoTitleEl.textContent = state.videoTitle;
              this.videoTitle = state.videoTitle;
            }
          } catch (e) {
            this.videoTitleEl.textContent = 'Nenhum vídeo disponível';
          }
        } else {
          this.videoTitleEl.textContent = 'Nenhum vídeo disponível';
        }
      }
    }
    if (this.videoDescriptionEl) {
      if (this.videoDescription) {
        this.videoDescriptionEl.textContent = this.videoDescription;
      } else if (this.videoDescriptionEl.id === 'video-description-placeholder') {
        const globalState = sessionStorage.getItem('video-global-state');
        if (globalState) {
          try {
            const state = JSON.parse(globalState);
            if (state.videoDescription) {
              this.videoDescriptionEl.textContent = state.videoDescription;
              this.videoDescription = state.videoDescription;
            }
          } catch (e) {
            this.videoDescriptionEl.textContent = '';
          }
        }
      }
    }
  }
  
  updateUI() {
    if (this.video && this.video.paused) {
      this.isPlaying = false;
    } else if (this.video && !this.video.paused) {
      this.isPlaying = true;
    }
  }
  
  pause() {
    if (!this.video || !this.video.src) return;
    
    this.video.pause();
    this.isPlaying = false;
    this.manager.isPlaying = false;
    this.updateUI();
    this.hideIndicator();
  }
  
  saveProgress() {
    if (!this.video || !this.video.src) return;
    
    const progress = {
      currentTime: this.currentTime,
      duration: this.duration,
      playbackRate: this.playbackRate,
      timestamp: Date.now(),
      videoFile: this.videoFile,
      lessonId: this.lessonId,
      videoTitle: this.videoTitle,
      videoDescription: this.videoDescription,
      videoThumbnail: this.videoThumbnail,
      isPlaying: this.isPlaying
    };
    sessionStorage.setItem('video-global-state', JSON.stringify(progress));
    if (this.videoFile) {
      localStorage.setItem(`video-${this.lessonId}`, JSON.stringify(progress));
    }
  }
  
  loadProgress() {
    if (this.videoFile && this.video && this.video.src) {
      const saved = localStorage.getItem(`video-${this.lessonId}`);
      if (saved) {
        try {
          const progress = JSON.parse(saved);
          if (progress.currentTime !== undefined && progress.duration) {
            this.video.currentTime = progress.currentTime;
            this.currentTime = progress.currentTime;
            this.duration = progress.duration;
            this.playbackRate = progress.playbackRate || 1.0;
            this.video.playbackRate = this.playbackRate;
            if (this.speedSelect) {
              this.speedSelect.value = this.playbackRate.toString();
            }
            this.updateCurrentTimeDisplay();
            this.updateDurationDisplay();
            this.updateProgress();
          }
        } catch (e) {
          if (window.Logger) {
            window.Logger.error('Erro ao carregar progresso:', e);
          } else {
            console.error('Erro ao carregar progresso:', e);
          }
        }
      }
    } else if (this.video && this.video.src) {
      const globalState = sessionStorage.getItem('video-global-state');
      if (globalState) {
        try {
          const progress = JSON.parse(globalState);
          if (progress.videoFile && progress.currentTime !== undefined) {
            this.currentTime = progress.currentTime;
            this.duration = progress.duration || 0;
            this.playbackRate = progress.playbackRate || 1.0;
            this.isPlaying = progress.isPlaying || false;
            
            if (this.video && this.video.src) {
              this.video.currentTime = this.currentTime;
              this.video.playbackRate = this.playbackRate;
            }
            
            if (this.speedSelect) {
              this.speedSelect.value = this.playbackRate.toString();
            }
            
            this.updateCurrentTimeDisplay();
            this.updateDurationDisplay();
            this.updateProgress();
            this.updateUI();
          }
        } catch (e) {
          if (window.Logger) {
            window.Logger.error('Erro ao carregar estado global:', e);
          } else {
            console.error('Erro ao carregar estado global:', e);
          }
        }
      }
    }
  }
  
  markAsWatched() {
    const progress = JSON.parse(
      localStorage.getItem('course-progress') || '{}'
    );
    if (!progress.videos) progress.videos = {};
    progress.videos[this.lessonId] = {
      watched: true,
      progress: 100,
      completed_at: new Date().toISOString()
    };
    localStorage.setItem('course-progress', JSON.stringify(progress));
  }
  
  showIndicator() {
    if (this.indicator) {
      this.indicator.classList.add('active');
    }
  }
  
  hideIndicator() {
    if (this.indicator) {
      this.indicator.classList.remove('active');
    }
  }
  
  handleError() {
    if (this.videoFile) {
      alert('Erro ao carregar o vídeo. Verifique sua conexão e tente novamente.');
    }
  }
  
  trackEvent(eventName, parameters) {
    if (typeof gtag !== 'undefined') {
      gtag('event', eventName, parameters);
    }
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const videoData = document.getElementById('video-data');
  const lessonData = document.getElementById('lesson-data');
  
  let config = null;
  
  if (videoData) {
    try {
      config = JSON.parse(videoData.textContent);
    } catch (e) {
      if (window.Logger) {
        window.Logger.error('Erro ao parsear dados do vídeo:', e);
      } else {
        console.error('Erro ao parsear dados do vídeo:', e);
      }
    }
  } else if (lessonData) {
    try {
      const lesson = JSON.parse(lessonData.textContent);
      config = {
        lessonId: lesson.lesson_id,
        videoFile: null,
        videoTitle: null,
        videoDescription: null
      };
    } catch (e) {
      if (window.Logger) {
        window.Logger.error('Erro ao parsear dados da lição:', e);
      } else {
        console.error('Erro ao parsear dados da lição:', e);
      }
    }
  }
  
  if (config) {
    // Se já existe instância válida, reutilizar
    if (window.videoPlayer && 
        window.videoPlayer instanceof VideoPlayer &&
        window.videoPlayer.lessonId === config.lessonId) {
      // Reutilizar instância existente
      if (window.Logger) {
        window.Logger.log('Reutilizando instância existente de VideoPlayer');
      }
    } else {
      // Criar nova instância
      window.videoPlayer = new VideoPlayer(config);
    }
  }
});

