class PodcastPlayer {
  constructor(config) {
    this.audio = new Audio();
    this.audio.src = config.audioFile;
    this.lessonId = config.lessonId;
    this.podcastTitle = config.podcastTitle;
    this.currentTime = 0;
    this.duration = 0;
    this.isPlaying = false;
    this.playbackRate = 1.0;
    
    this.initElements();
    this.bindEvents();
    this.loadProgress();
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
  }
  
  bindEvents() {
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
      this.trackEvent('podcast_complete', {
        lesson_id: this.lessonId,
        duration: this.duration,
        total_time: this.duration
      });
    });
    
    this.audio.addEventListener('error', (e) => {
      console.error('Erro ao carregar áudio:', e);
      this.handleError();
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
  }
  
  play() {
    this.audio.play().then(() => {
      this.isPlaying = true;
      this.updateUI();
      this.showIndicator();
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
    this.audio.pause();
    this.isPlaying = false;
    this.updateUI();
    this.hideIndicator();
    const progressPercentage = this.duration > 0 ? (this.currentTime / this.duration) * 100 : 0;
    this.trackEvent('podcast_pause', {
      lesson_id: this.lessonId,
      progress_percentage: Math.round(progressPercentage)
    });
  }
  
  seek(event) {
    const rect = this.progressBar.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const percentage = x / rect.width;
    const newTime = percentage * this.duration;
    this.audio.currentTime = newTime;
  }
  
  setSpeed(speed) {
    const oldSpeed = this.playbackRate;
    this.playbackRate = parseFloat(speed);
    this.audio.playbackRate = this.playbackRate;
    this.trackEvent('podcast_speed_change', {
      old_speed: oldSpeed,
      new_speed: this.playbackRate
    });
  }
  
  setVolume(volume) {
    this.audio.volume = parseFloat(volume) / 100;
  }
  
  updateProgress() {
    if (this.duration > 0) {
      const percentage = (this.currentTime / this.duration) * 100;
      this.progressFill.style.width = `${percentage}%`;
      this.updateCurrentTimeDisplay();
    }
  }
  
  updateCurrentTimeDisplay() {
    const minutes = Math.floor(this.currentTime / 60);
    const seconds = Math.floor(this.currentTime % 60);
    this.currentTimeDisplay.textContent = 
      `${minutes}:${seconds.toString().padStart(2, '0')}`;
  }
  
  updateDurationDisplay() {
    const minutes = Math.floor(this.duration / 60);
    const seconds = Math.floor(this.duration % 60);
    this.durationDisplay.textContent = 
      `${minutes}:${seconds.toString().padStart(2, '0')}`;
  }
  
  updateUI() {
    if (this.isPlaying) {
      this.playButton.style.display = 'none';
      this.pauseButton.style.display = 'block';
    } else {
      this.playButton.style.display = 'block';
      this.pauseButton.style.display = 'none';
    }
  }
  
  saveProgress() {
    const progress = {
      currentTime: this.currentTime,
      duration: this.duration,
      playbackRate: this.playbackRate,
      timestamp: Date.now()
    };
    localStorage.setItem(`podcast-${this.lessonId}`, JSON.stringify(progress));
  }
  
  loadProgress() {
    const saved = localStorage.getItem(`podcast-${this.lessonId}`);
    if (saved) {
      try {
        const progress = JSON.parse(saved);
        if (progress.currentTime && progress.duration) {
          this.audio.currentTime = progress.currentTime;
          this.playbackRate = progress.playbackRate || 1.0;
          this.audio.playbackRate = this.playbackRate;
          if (this.speedSelect) {
            this.speedSelect.value = this.playbackRate.toString();
          }
        }
      } catch (e) {
        console.error('Erro ao carregar progresso:', e);
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
    alert('Erro ao carregar o podcast. Verifique sua conexão e tente novamente.');
  }
  
  trackEvent(eventName, parameters) {
    if (typeof gtag !== 'undefined') {
      gtag('event', eventName, parameters);
    }
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const podcastData = document.getElementById('podcast-data');
  if (podcastData) {
    try {
      const config = JSON.parse(podcastData.textContent);
      window.podcastPlayer = new PodcastPlayer(config);
    } catch (e) {
      console.error('Erro ao inicializar player:', e);
    }
  }
});

