class GlobalPodcastManager {
  constructor() {
    this.currentPlayer = null;
    this.currentAudio = null;
    this.currentConfig = null;
    this.isPlaying = false;
    this.init();
  }

  init() {
    if (typeof window.globalPodcastManager === 'undefined') {
      window.globalPodcastManager = this;
    }
    return window.globalPodcastManager;
  }

  static getInstance() {
    if (!window.globalPodcastManager) {
      window.globalPodcastManager = new GlobalPodcastManager();
    }
    return window.globalPodcastManager;
  }

  setPlayer(player, audio, config) {
    if (this.currentPlayer && this.currentPlayer !== player) {
      this.currentPlayer.pause();
      this.currentPlayer.isPlaying = false;
      this.currentPlayer.updateUI();
    }
    this.currentPlayer = player;
    this.currentAudio = audio;
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

class PodcastPlayer {
  constructor(config) {
    this.manager = GlobalPodcastManager.getInstance();
    this.config = config;
    this.lessonId = config.lessonId;
    this.audioFile = config.audioFile;
    this.podcastFile = config.podcastFile || config.audioFile;
    this.podcastTitle = config.podcastTitle || null;
    this.podcastDescription = config.podcastDescription || null;
    this.podcastImage = config.podcastImage || null;
    this.currentTime = 0;
    this.duration = 0;
    this.isPlaying = false;
    this.playbackRate = 1.0;
    
    if (this.audioFile) {
      this.audio = new Audio();
      this.audio.src = this.audioFile;
      this.manager.setPlayer(this, this.audio, config);
    } else {
      const currentPlayer = this.manager.getCurrentPlayer();
      if (currentPlayer && currentPlayer.audio && currentPlayer.audio.src) {
        this.audio = currentPlayer.audio;
        this.audioFile = currentPlayer.audioFile;
        this.podcastFile = currentPlayer.podcastFile || currentPlayer.audioFile;
        this.podcastTitle = currentPlayer.podcastTitle;
        this.podcastDescription = currentPlayer.podcastDescription;
        this.podcastImage = currentPlayer.podcastImage;
        this.lessonId = currentPlayer.lessonId;
        this.currentTime = currentPlayer.currentTime;
        this.duration = currentPlayer.duration;
        this.isPlaying = currentPlayer.isPlaying;
        this.playbackRate = currentPlayer.playbackRate;
        this.manager.setPlayer(this, this.audio, currentPlayer.config);
      } else {
        const globalState = sessionStorage.getItem('podcast-global-state');
        if (globalState) {
          try {
            const state = JSON.parse(globalState);
            if (state.audioFile) {
              this.audio = new Audio();
              this.audio.src = state.audioFile;
              this.audioFile = state.audioFile;
              this.podcastFile = state.podcastFile || state.audioFile;
              this.podcastTitle = state.podcastTitle || null;
              this.podcastDescription = state.podcastDescription || null;
              this.podcastImage = state.podcastImage || null;
              this.currentTime = state.currentTime || 0;
              this.duration = state.duration || 0;
              this.isPlaying = false;
              this.playbackRate = state.playbackRate || 1.0;
              this.manager.setPlayer(this, this.audio, {
                audioFile: state.audioFile,
                podcastFile: state.podcastFile || state.audioFile,
                lessonId: state.lessonId,
                podcastTitle: state.podcastTitle,
                podcastDescription: state.podcastDescription,
                podcastImage: state.podcastImage
              });
            }
          } catch (e) {
            console.error('Erro ao recuperar estado global:', e);
            this.audio = null;
          }
        } else {
          this.audio = null;
        }
      }
    }
    
    this.initElements();
    this.bindEvents();
    this.loadProgress();
    this.updateUI();
    this.updateInfo();
    
    if (this.audio && this.audio.src && this.isPlaying) {
      this.audio.play().catch((error) => {
        console.warn('Erro ao retomar reprodução:', error);
        this.isPlaying = false;
        this.updateUI();
      });
    }
    
    this.initScrollHandler();
  }
  
  initElements() {
    this.playButton = document.getElementById('podcast-play');
    this.pauseButton = document.getElementById('podcast-pause');
    this.progressBar = document.getElementById('podcast-progress');
    this.progressFill = document.getElementById('podcast-progress-fill');
    this.currentTimeDisplay = document.getElementById('podcast-current-time');
    this.durationDisplay = document.getElementById('podcast-duration');
    this.speedSelect = document.getElementById('podcast-speed');
    this.volumeControl = document.getElementById('podcast-volume');
    this.indicator = document.getElementById('podcast-indicator');
    this.podcastInfo = document.querySelector('.podcast-info');
    this.podcastTitleEl = document.querySelector('.podcast-info h3');
    this.podcastDescriptionEl = document.querySelector('.podcast-description');
    this.podcastBannerContainer = document.getElementById('podcast-banner-container');
    this.podcastBannerImage = document.getElementById('podcast-banner-image');
    this.podcastBannerPlaceholder = document.getElementById('podcast-banner-placeholder');
    this.podcastBannerImagePlaceholder = document.getElementById('podcast-banner-image-placeholder');
    this.lastScrollY = window.scrollY;
    this.initImageZoom();
  }
  
  bindEvents() {
    if (!this.audio || !this.audio.src) {
      const globalState = sessionStorage.getItem('podcast-global-state');
      if (globalState) {
        try {
          const state = JSON.parse(globalState);
          if (state.isPlaying) {
            this.isPlaying = false;
            this.updateUI();
          }
        } catch (e) {}
      }
      this.playButton?.addEventListener('click', () => {
        const globalState = sessionStorage.getItem('podcast-global-state');
        if (globalState) {
          try {
            const state = JSON.parse(globalState);
            if (state.audioFile) {
              const lessonUrl = this.findLessonUrlByPodcast(state.audioFile);
              if (lessonUrl) {
                window.location.href = lessonUrl;
              }
            }
          } catch (e) {}
        }
      });
      if (this.pauseButton) {
        this.pauseButton.style.display = 'none';
      }
      if (this.progressBar) {
        this.progressBar.style.opacity = '0.5';
      }
      return;
    }

    this.audio.addEventListener('loadedmetadata', () => {
      this.duration = this.audio.duration;
      this.updateDurationDisplay();
    });
    
    this.audio.addEventListener('timeupdate', () => {
      this.currentTime = this.audio.currentTime;
      this.updateProgress();
      this.saveProgress();
    });
    
    this.audio.addEventListener('ended', () => {
      this.isPlaying = false;
      this.updateUI();
      this.markAsListened();
      sessionStorage.removeItem('podcast-global-state');
      this.trackEvent('podcast_complete', {
        lesson_id: this.lessonId,
        duration: this.duration,
        total_time: this.duration
      });
    });
    
    this.audio.addEventListener('error', (e) => {
      if (this.audioFile) {
        console.error('Erro ao carregar áudio:', e);
        this.handleError();
      } else {
        const globalState = sessionStorage.getItem('podcast-global-state');
        if (!globalState) {
          this.audio = null;
          this.updateUI();
        }
      }
    });
    
    this.playButton?.addEventListener('click', () => this.play());
    this.pauseButton?.addEventListener('click', () => this.pause());
    this.progressBar?.addEventListener('click', (e) => this.seek(e));
    this.speedSelect?.addEventListener('change', (e) => this.setSpeed(e.target.value));
    this.volumeControl?.addEventListener('input', (e) => this.setVolume(e.target.value));
    
    document.addEventListener('visibilitychange', () => {
      if (document.hidden && this.isPlaying) {
        this.showIndicator();
      }
    });

    if (this.audio && this.audio.readyState >= 2) {
      this.duration = this.audio.duration;
      this.updateDurationDisplay();
    }
    
    this.initScrollHandler();
  }
  
  initScrollHandler() {
  }
  
  initImageZoom() {
    const images = [
      this.podcastBannerImage,
      this.podcastBannerImagePlaceholder
    ].filter(img => img !== null);
    
    if (images.length === 0) return;
    
    let zoomModal = document.getElementById('image-zoom-modal');
    if (!zoomModal) {
      zoomModal = document.createElement('div');
      zoomModal.id = 'image-zoom-modal';
      zoomModal.className = 'image-zoom-modal';
      const zoomedImg = document.createElement('img');
      zoomedImg.className = 'zoomed-image';
      zoomModal.appendChild(zoomedImg);
      document.body.appendChild(zoomModal);
      
      zoomModal.addEventListener('click', (e) => {
        if (e.target === zoomModal || e.target === zoomedImg) {
          zoomModal.classList.remove('active');
          document.body.style.overflow = '';
        }
      });
      
      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && zoomModal.classList.contains('active')) {
          zoomModal.classList.remove('active');
          document.body.style.overflow = '';
        }
      });
    }
    
    const zoomedImg = zoomModal.querySelector('.zoomed-image');
    
    images.forEach(img => {
      img.addEventListener('click', () => {
        zoomedImg.src = img.src;
        zoomedImg.alt = img.alt || 'Imagem ampliada';
        zoomModal.classList.add('active');
        document.body.style.overflow = 'hidden';
      });
    });
  }

  findLessonUrlByPodcast(audioFile) {
    const lessons = document.querySelectorAll('a[href*="/lessons/"]');
    for (let link of lessons) {
      const href = link.getAttribute('href');
      if (href && href.includes('/lessons/')) {
        return href;
      }
    }
    return '/angular/';
  }
  
  play() {
    if (!this.audio || !this.audio.src) {
      const globalState = sessionStorage.getItem('podcast-global-state');
      if (globalState) {
        try {
          const state = JSON.parse(globalState);
          if (state.audioFile) {
            const lessonUrl = this.findLessonUrlByPodcast(state.audioFile);
            if (lessonUrl && lessonUrl !== window.location.pathname) {
              window.location.href = lessonUrl;
              return;
            }
          }
        } catch (e) {
          console.warn('Não foi possível recuperar estado do podcast');
        }
      } else {
        console.info('Nenhum podcast disponível para esta aula');
      }
      return;
    }
    
    if (this.audioFile) {
      this.manager.pauseCurrent();
    }
    
    this.manager.setPlayer(this, this.audio, this.config);
    
    this.audio.play().then(() => {
      this.isPlaying = true;
      this.manager.isPlaying = true;
      this.updateUI();
      this.showIndicator();
      this.saveProgress();
      this.trackEvent('podcast_play', {
        lesson_id: this.lessonId,
        podcast_title: this.podcastTitle,
        current_time: this.currentTime
      });
    }).catch(error => {
      console.error('Erro ao reproduzir:', error);
      this.handleError();
    });
  }
  
  pause() {
    if (!this.audio.src) return;
    
    this.audio.pause();
    this.isPlaying = false;
    this.manager.isPlaying = false;
    this.updateUI();
    this.hideIndicator();
    const progressPercentage = this.duration > 0 ? (this.currentTime / this.duration) * 100 : 0;
    this.trackEvent('podcast_pause', {
      lesson_id: this.lessonId,
      progress_percentage: Math.round(progressPercentage)
    });
  }
  
  seek(event) {
    if (!this.audio.src) return;
    
    const rect = this.progressBar.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const percentage = x / rect.width;
    const newTime = percentage * this.duration;
    this.audio.currentTime = newTime;
  }
  
  setSpeed(speed) {
    if (!this.audio.src) return;
    
    const oldSpeed = this.playbackRate;
    this.playbackRate = parseFloat(speed);
    this.audio.playbackRate = this.playbackRate;
    this.trackEvent('podcast_speed_change', {
      old_speed: oldSpeed,
      new_speed: this.playbackRate
    });
  }
  
  setVolume(volume) {
    if (!this.audio.src) return;
    
    this.audio.volume = parseFloat(volume) / 100;
  }
  
  updateProgress() {
    if (this.duration > 0) {
      const percentage = (this.currentTime / this.duration) * 100;
      if (this.progressFill) {
        this.progressFill.style.width = `${percentage}%`;
      }
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

  getLessonsForPodcast(podcastFile) {
    const lessonsData = document.getElementById('lessons-data');
    if (!lessonsData) return [];
    
    if (!podcastFile) return [];
    
    try {
      const lessons = JSON.parse(lessonsData.textContent);
      const normalizedFile = podcastFile.replace(/^\/angular\//, '').replace(/^assets\//, 'assets/');
      return lessons.filter(lesson => {
        const lessonFile = lesson.podcastFile.replace(/^\/angular\//, '').replace(/^assets\//, 'assets/');
        return lessonFile === normalizedFile || lessonFile === podcastFile || lesson.podcastFile === podcastFile;
      });
    } catch (e) {
      console.error('Erro ao buscar aulas do podcast:', e);
      return [];
    }
  }

  formatPodcastTitle(title, podcastFile) {
    if (!podcastFile) return title;
    
    const lessons = this.getLessonsForPodcast(podcastFile);
    if (lessons.length <= 1) return title;
    
    const lessonNumbers = lessons
      .sort((a, b) => {
        const moduleA = a.module.replace('module-', '');
        const orderA = a.order;
        const moduleB = b.module.replace('module-', '');
        const orderB = b.order;
        if (moduleA !== moduleB) return moduleA.localeCompare(moduleB);
        return orderA - orderB;
      })
      .map(lesson => {
        const moduleNum = lesson.module.replace('module-', '');
        return `${moduleNum}.${lesson.order}`;
      });
    
    const lessonsText = lessonNumbers.length === 2 
      ? `Aulas ${lessonNumbers[0]} e ${lessonNumbers[1]}`
      : `Aulas ${lessonNumbers.slice(0, -1).join(', ')} e ${lessonNumbers[lessonNumbers.length - 1]}`;
    
    return `${title} (${lessonsText})`;
  }

  updateInfo() {
    if (this.podcastTitleEl) {
      if (this.podcastTitle) {
        const podcastFile = this.config.podcastFile || this.audioFile;
        const formattedTitle = this.formatPodcastTitle(this.podcastTitle, podcastFile);
        this.podcastTitleEl.textContent = formattedTitle;
      } else if (this.podcastTitleEl.id === 'podcast-title-placeholder') {
        const globalState = sessionStorage.getItem('podcast-global-state');
        if (globalState) {
          try {
            const state = JSON.parse(globalState);
            if (state.podcastTitle) {
              const podcastFile = state.podcastFile || state.audioFile;
              const formattedTitle = this.formatPodcastTitle(state.podcastTitle, podcastFile);
              this.podcastTitleEl.textContent = formattedTitle;
              this.podcastTitle = state.podcastTitle;
              this.podcastFile = podcastFile;
            }
          } catch (e) {
            this.podcastTitleEl.textContent = 'Nenhum podcast disponível';
          }
        } else {
          this.podcastTitleEl.textContent = 'Nenhum podcast disponível';
        }
      }
    }
    if (this.podcastDescriptionEl) {
      if (this.podcastDescription) {
        this.podcastDescriptionEl.textContent = this.podcastDescription;
      } else if (this.podcastDescriptionEl.id === 'podcast-description-placeholder') {
        const globalState = sessionStorage.getItem('podcast-global-state');
        if (globalState) {
          try {
            const state = JSON.parse(globalState);
            if (state.podcastDescription) {
              this.podcastDescriptionEl.textContent = state.podcastDescription;
              this.podcastDescription = state.podcastDescription;
            }
          } catch (e) {
            this.podcastDescriptionEl.textContent = '';
          }
        }
      }
    }
    if (this.podcastBannerImage || this.podcastBannerImagePlaceholder) {
      const imgEl = this.podcastBannerImage || this.podcastBannerImagePlaceholder;
      const containerEl = this.podcastBannerContainer || this.podcastBannerPlaceholder;
      
      if (this.podcastImage) {
        imgEl.src = this.podcastImage;
        imgEl.alt = this.podcastTitle || 'Podcast';
        if (containerEl) {
          containerEl.style.display = 'block';
        }
        if (this.podcastBannerContainer) {
          this.podcastBannerContainer.classList.remove('hidden');
        }
        this.initImageZoom();
      } else {
        const globalState = sessionStorage.getItem('podcast-global-state');
        if (globalState) {
          try {
            const state = JSON.parse(globalState);
            if (state.podcastImage) {
              imgEl.src = state.podcastImage;
              imgEl.alt = state.podcastTitle || 'Podcast';
              this.podcastImage = state.podcastImage;
              if (containerEl) {
                containerEl.style.display = 'block';
              }
              if (this.podcastBannerContainer) {
                this.podcastBannerContainer.classList.remove('hidden');
              }
              this.initImageZoom();
            } else if (containerEl) {
              containerEl.style.display = 'none';
            }
          } catch (e) {
            if (containerEl) {
              containerEl.style.display = 'none';
            }
          }
        } else if (containerEl) {
          containerEl.style.display = 'none';
        }
      }
    }
    
    if (this.podcastImage || (this.podcastBannerImage && this.podcastBannerImage.src)) {
      this.initImageZoom();
    }
  }
  
  updateUI() {
    if (!this.playButton || !this.pauseButton) return;
    
    if (this.isPlaying) {
      this.playButton.style.display = 'none';
      this.pauseButton.style.display = 'block';
    } else {
      this.playButton.style.display = 'block';
      this.pauseButton.style.display = 'none';
    }
  }
  
  saveProgress() {
    if (!this.audio || !this.audio.src) return;
    
    const progress = {
      currentTime: this.currentTime,
      duration: this.duration,
      playbackRate: this.playbackRate,
      timestamp: Date.now(),
      audioFile: this.audioFile,
      podcastFile: this.podcastFile || this.audioFile,
      lessonId: this.lessonId,
      podcastTitle: this.podcastTitle,
      podcastDescription: this.podcastDescription,
      podcastImage: this.podcastImage,
      isPlaying: this.isPlaying
    };
    sessionStorage.setItem('podcast-global-state', JSON.stringify(progress));
    if (this.audioFile) {
      localStorage.setItem(`podcast-${this.lessonId}`, JSON.stringify(progress));
    }
  }
  
  loadProgress() {
    if (this.audioFile && this.audio && this.audio.src) {
      const saved = localStorage.getItem(`podcast-${this.lessonId}`);
      if (saved) {
        try {
          const progress = JSON.parse(saved);
          if (progress.currentTime !== undefined && progress.duration) {
            this.audio.currentTime = progress.currentTime;
            this.currentTime = progress.currentTime;
            this.duration = progress.duration;
            this.playbackRate = progress.playbackRate || 1.0;
            this.audio.playbackRate = this.playbackRate;
            if (this.speedSelect) {
              this.speedSelect.value = this.playbackRate.toString();
            }
            this.updateCurrentTimeDisplay();
            this.updateDurationDisplay();
            this.updateProgress();
          }
        } catch (e) {
          console.error('Erro ao carregar progresso:', e);
        }
      }
    } else if (this.audio && this.audio.src) {
      const globalState = sessionStorage.getItem('podcast-global-state');
      if (globalState) {
        try {
          const progress = JSON.parse(globalState);
          if (progress.audioFile && progress.currentTime !== undefined) {
            this.currentTime = progress.currentTime;
            this.duration = progress.duration || 0;
            this.playbackRate = progress.playbackRate || 1.0;
            this.isPlaying = progress.isPlaying || false;
            
            if (this.audio && this.audio.src) {
              this.audio.currentTime = this.currentTime;
              this.audio.playbackRate = this.playbackRate;
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
          console.error('Erro ao carregar estado global:', e);
        }
      }
    } else if (!this.audioFile && !this.audio) {
      const globalState = sessionStorage.getItem('podcast-global-state');
      if (globalState) {
        try {
          const progress = JSON.parse(globalState);
          if (progress.audioFile) {
            this.currentTime = progress.currentTime || 0;
            this.duration = progress.duration || 0;
            this.playbackRate = progress.playbackRate || 1.0;
            this.isPlaying = false;
            
            if (this.speedSelect) {
              this.speedSelect.value = this.playbackRate.toString();
            }
            
            this.updateCurrentTimeDisplay();
            this.updateDurationDisplay();
            this.updateProgress();
            this.updateUI();
          }
        } catch (e) {
          console.warn('Não há podcast global disponível');
        }
      }
    }
  }
  
  markAsListened() {
    const progress = JSON.parse(
      localStorage.getItem('course-progress') || '{}'
    );
    if (!progress.podcasts) progress.podcasts = {};
    progress.podcasts[this.lessonId] = {
      listened: true,
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
    if (this.progressFill) {
      this.progressFill.style.background = '#f44336';
    }
    if (this.audioFile) {
      alert('Erro ao carregar o podcast. Verifique sua conexão e tente novamente.');
    }
  }
  
  trackEvent(eventName, parameters) {
    if (typeof gtag !== 'undefined') {
      gtag('event', eventName, parameters);
    }
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const podcastData = document.getElementById('podcast-data');
  const lessonData = document.getElementById('lesson-data');
  
  let config = null;
  
  if (podcastData) {
    try {
      config = JSON.parse(podcastData.textContent);
    } catch (e) {
      console.error('Erro ao parsear dados do podcast:', e);
    }
  } else if (lessonData) {
    try {
      const lesson = JSON.parse(lessonData.textContent);
      config = {
        lessonId: lesson.lesson_id,
        audioFile: null,
        podcastTitle: null,
        podcastDescription: null
      };
    } catch (e) {
      console.error('Erro ao parsear dados da lição:', e);
    }
  }
  
  if (config) {
    window.podcastPlayer = new PodcastPlayer(config);
  }
});
