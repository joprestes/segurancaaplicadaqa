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
    const defaultPlaybackRate = (window.Constants && window.Constants.MEDIA_PLAYER && window.Constants.MEDIA_PLAYER.DEFAULT_PLAYBACK_RATE) || 1.0;
    const restoreDelayMs = (window.Constants && window.Constants.MEDIA_PLAYER && window.Constants.MEDIA_PLAYER.RESTORE_DELAY_MS) || 500;
    this.playbackRate = defaultPlaybackRate;
    this.restoreDelayMs = restoreDelayMs;
    
    this.video = document.getElementById('video-element');
    
    if (this.video) {
      if (this.video.src && this.video.src !== '' && this.video.src !== window.location.href) {
        this.videoFile = this.video.src;
        window.Logger?.log('Usando src do HTML:', this.videoFile);
      } else if (this.videoFile && (!this.video.src || this.video.src === '' || this.video.src === window.location.href)) {
        window.Logger?.log('Definindo src do JavaScript:', this.videoFile);
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
        const videoStateKey = (window.Constants && window.Constants.STORAGE_KEYS && window.Constants.STORAGE_KEYS.VIDEO_GLOBAL_STATE) || 'video-global-state';
        const defaultPlaybackRate = (window.Constants && window.Constants.MEDIA_PLAYER && window.Constants.MEDIA_PLAYER.DEFAULT_PLAYBACK_RATE) || 1.0;
        
        let globalState = null;
        if (window.StorageSafe && typeof window.StorageSafe.getSessionItem === 'function') {
          globalState = window.StorageSafe.getSessionItem(videoStateKey);
        } else {
          try {
            const item = sessionStorage.getItem(videoStateKey);
            globalState = item ? JSON.parse(item) : null;
          } catch (e) {
            window.Logger?.error('Erro ao recuperar estado global do vídeo:', e);
            globalState = null;
          }
        }
        
        if (globalState && globalState.videoFile && this.video) {
          if (this.video.src && this.video.src !== '') {
            this.videoFile = this.video.src;
          } else {
            this.video.src = globalState.videoFile;
            this.video.load();
            this.videoFile = globalState.videoFile;
          }
          this.videoTitle = globalState.videoTitle || null;
          this.videoDescription = globalState.videoDescription || null;
          this.videoThumbnail = globalState.videoThumbnail || null;
          this.currentTime = globalState.currentTime || 0;
          this.duration = globalState.duration || 0;
          this.isPlaying = false;
          this.playbackRate = globalState.playbackRate || defaultPlaybackRate;
          this.manager.setPlayer(this, this.video, {
            videoFile: this.videoFile,
            lessonId: globalState.lessonId,
            videoTitle: globalState.videoTitle,
            videoDescription: globalState.videoDescription,
            videoThumbnail: globalState.videoThumbnail
          });
        } else {
          this.video = null;
        }
      }
    }
    
    this.initElements();
    this.bindEvents();
    // Carregar progresso ANTES de definir currentTime
    // Isso garante que temos o valor salvo, mas não vamos aplicar até o vídeo estar pronto
    this.loadProgress();
    this.updateUI();
    this.updateInfo();
    
    // NÃO tentar reproduzir automaticamente - deixar usuário controlar
    // Se houver progresso salvo, será restaurado quando vídeo estiver pronto (loadedmetadata/canplay)
    // Isso evita problemas de autoplay bloqueado e buffer insuficiente
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
      const videoStateKey = (window.Constants && window.Constants.STORAGE_KEYS && window.Constants.STORAGE_KEYS.VIDEO_GLOBAL_STATE) || 'video-global-state';
      let globalState = null;
      
      if (window.StorageSafe && typeof window.StorageSafe.getSessionItem === 'function') {
        globalState = window.StorageSafe.getSessionItem(videoStateKey);
      } else {
        try {
          const item = sessionStorage.getItem(videoStateKey);
          globalState = item ? JSON.parse(item) : null;
        } catch (e) {
          window.Logger?.warn('Erro ao parsear estado global do vídeo ao inicializar:', e);
        }
      }
      
      if (globalState && globalState.isPlaying) {
        this.isPlaying = false;
        this.updateUI();
      }
      return;
    }

    if (!this.video.src) {
      return;
    }

    this.video.addEventListener('loadedmetadata', () => {
      this.duration = this.video.duration;
      this.updateDurationDisplay();
      // NÃO restaurar currentTime aqui - pode causar problemas de buffer
      // A restauração será feita apenas quando usuário clicar para reproduzir (evento 'play')
    });
    
    // Debounce apenas em saveProgress, não em updateProgress visual
    const debounceDelay = (window.Constants && window.Constants.MEDIA_PLAYER && window.Constants.MEDIA_PLAYER.DEBOUNCE_SAVE_PROGRESS) || 250;
    const debouncedSave = typeof window.debounce === 'function' 
      ? window.debounce(() => this.saveProgress(), debounceDelay)
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
      
      // Restaurar posição salva quando usuário clica para reproduzir pela primeira vez
      // Aguardar um pequeno delay para garantir que vídeo tem alguns dados carregados
      if (this.currentTime > 0 && this.video.duration && this.currentTime < this.video.duration) {
        // Verificar se currentTime do vídeo está diferente do salvo (vídeo começa em 0)
        if (Math.abs(this.video.currentTime - this.currentTime) > 1) {
          // Usar requestAnimationFrame para garantir que vídeo começou a carregar dados
          requestAnimationFrame(() => {
            if (this.video && this.video.readyState >= 2) {
              // readyState >= 2 significa que vídeo tem dados do frame atual
              // Tentar restaurar posição
              try {
                this.video.currentTime = this.currentTime;
                window.Logger?.log(`Progresso restaurado: ${this.currentTime.toFixed(2)}s`);
              } catch (error) {
                window.Logger?.warn('Erro ao restaurar progresso do vídeo:', error);
                // Se falhar, vídeo vai continuar do início - não é crítico
              }
            } else {
              // Se vídeo ainda não tem dados suficientes, aguardar um pouco mais
              setTimeout(() => {
                if (this.video && this.video.readyState >= 2 && this.isPlaying) {
                  try {
                    this.video.currentTime = this.currentTime;
                    window.Logger?.log(`Progresso restaurado (delay): ${this.currentTime.toFixed(2)}s`);
                  } catch (error) {
                    window.Logger?.warn('Erro ao restaurar progresso do vídeo (tentativa 2):', error);
                  }
                }
              }, this.restoreDelayMs);
            }
          });
        }
      }
      
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
      const videoStateKey = (window.Constants && window.Constants.STORAGE_KEYS && window.Constants.STORAGE_KEYS.VIDEO_GLOBAL_STATE) || 'video-global-state';
      if (window.StorageSafe && typeof window.StorageSafe.removeSessionItem === 'function') {
        window.StorageSafe.removeSessionItem(videoStateKey);
      } else {
        try {
          sessionStorage.removeItem(videoStateKey);
        } catch (e) {
          window.Logger?.warn('Erro ao remover estado global do vídeo:', e);
        }
      }
      this.trackEvent('video_complete', {
        lesson_id: this.lessonId,
        duration: this.duration,
        total_time: this.duration
      });
    });
    
    this.video.addEventListener('error', (e) => {
      window.Logger?.error('Erro ao carregar vídeo:', e);
      if (this.video.error) {
        window.Logger?.error('Código de erro do vídeo:', this.video.error.code);
        window.Logger?.error('Mensagem:', this.video.error.message);
        window.Logger?.error('URL tentada:', this.video.src);
        window.Logger?.error('URL esperada:', this.videoFile);
      }
      if (this.videoFile) {
        this.handleError();
      }
    });
    
    this.video.addEventListener('loadstart', () => {
      window.Logger?.log('Iniciando carregamento do vídeo:', this.video.src || this.videoFile);
    });
    
    this.video.addEventListener('canplay', () => {
      window.Logger?.log('Vídeo pode ser reproduzido:', this.video.src);
      // Não restaurar currentTime aqui - esperar evento 'play' do usuário
      // Isso evita que o vídeo tente pular para um ponto antes de ter buffer suficiente
    });
    
    this.video.addEventListener('canplaythrough', () => {
      window.Logger?.log('Vídeo pode ser reproduzido até o fim sem pausar para buffer');
      // Vídeo tem buffer suficiente, mas ainda não vamos restaurar currentTime
      // Vai ser restaurado quando usuário clicar para reproduzir
    });
    
    this.video.addEventListener('waiting', () => {
      window.Logger?.log('Vídeo aguardando dados (buffering)...');
      // Não pausar automaticamente - deixar vídeo tentar continuar
      // O navegador vai pausar temporariamente se necessário, mas vai retomar quando tiver dados
    });
    
    this.video.addEventListener('stalled', () => {
      window.Logger?.warn('Vídeo estagnado (download interrompido)');
      // Não fazer nada - o navegador vai tentar recuperar automaticamente
    });
    
    this.video.addEventListener('suspend', () => {
      window.Logger?.log('Download do vídeo suspenso (mas não necessariamente parou)');
      // Não fazer nada - download pode continuar em background
    });
    
    this.video.addEventListener('loadeddata', () => {
      window.Logger?.log('Dados do vídeo carregados');
      if (this.video.readyState >= 2) {
        this.duration = this.video.duration;
        this.updateDurationDisplay();
        // NÃO restaurar currentTime aqui - esperar usuário clicar para reproduzir
        // Isso evita problemas de buffer e vídeo parando
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
    
    const parsedSpeed = parseFloat(speed);
    if (isNaN(parsedSpeed) || parsedSpeed <= 0) {
      window.Logger?.warn('Velocidade inválida:', speed);
      return;
    }
    
    const oldSpeed = this.playbackRate;
    this.playbackRate = parsedSpeed;
    this.video.playbackRate = this.playbackRate;
    this.trackEvent('video_speed_change', {
      old_speed: oldSpeed,
      new_speed: this.playbackRate
    });
  }
  
  setVolume(volume) {
    if (!this.video || !this.video.src) return;
    
    const parsedVolume = parseFloat(volume);
    if (isNaN(parsedVolume) || parsedVolume < 0 || parsedVolume > 100) {
      window.Logger?.warn('Volume inválido:', volume);
      return;
    }
    
    this.video.volume = parsedVolume / 100;
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
        const videoStateKey = (window.Constants && window.Constants.STORAGE_KEYS && window.Constants.STORAGE_KEYS.VIDEO_GLOBAL_STATE) || 'video-global-state';
        let globalState = null;
        
        if (window.StorageSafe && typeof window.StorageSafe.getSessionItem === 'function') {
          globalState = window.StorageSafe.getSessionItem(videoStateKey);
        } else {
          try {
            const item = sessionStorage.getItem(videoStateKey);
            globalState = item ? JSON.parse(item) : null;
          } catch (e) {
            window.Logger?.warn('Erro ao parsear estado global do vídeo em updateInfo:', e);
            globalState = null;
          }
        }
        
        if (globalState && globalState.videoTitle) {
          this.videoTitleEl.textContent = globalState.videoTitle;
          this.videoTitle = globalState.videoTitle;
        } else {
          this.videoTitleEl.textContent = 'Nenhum vídeo disponível';
        }
      }
    }
    if (this.videoDescriptionEl) {
      if (this.videoDescription) {
        this.videoDescriptionEl.textContent = this.videoDescription;
      } else if (this.videoDescriptionEl.id === 'video-description-placeholder') {
        const videoStateKey = (window.Constants && window.Constants.STORAGE_KEYS && window.Constants.STORAGE_KEYS.VIDEO_GLOBAL_STATE) || 'video-global-state';
        let globalState = null;
        
        if (window.StorageSafe && typeof window.StorageSafe.getSessionItem === 'function') {
          globalState = window.StorageSafe.getSessionItem(videoStateKey);
        } else {
          try {
            const item = sessionStorage.getItem(videoStateKey);
            globalState = item ? JSON.parse(item) : null;
          } catch (e) {
            window.Logger?.warn('Erro ao parsear estado global do vídeo em updateInfo (description):', e);
            globalState = null;
          }
        }
        
        if (globalState && globalState.videoDescription) {
          this.videoDescriptionEl.textContent = globalState.videoDescription;
          this.videoDescription = globalState.videoDescription;
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
    
    // Usar StorageSafe se disponível, senão fallback para sessionStorage direto
    const videoStateKey = (window.Constants && window.Constants.STORAGE_KEYS && window.Constants.STORAGE_KEYS.VIDEO_GLOBAL_STATE) || 'video-global-state';
    if (window.StorageSafe && typeof window.StorageSafe.setSessionItem === 'function') {
      window.StorageSafe.setSessionItem(videoStateKey, progress);
    } else {
      try {
        sessionStorage.setItem(videoStateKey, JSON.stringify(progress));
      } catch (e) {
        window.Logger?.error('Erro ao salvar estado global do vídeo:', e);
      }
    }
    
    if (this.videoFile) {
      const videoKey = `video-${this.lessonId}`;
      if (window.StorageSafe && typeof window.StorageSafe.setItem === 'function') {
        window.StorageSafe.setItem(videoKey, progress);
      } else {
        try {
          localStorage.setItem(videoKey, JSON.stringify(progress));
        } catch (e) {
          window.Logger?.error('Erro ao salvar progresso do vídeo:', e);
        }
      }
    }
  }
  
  loadProgress() {
    const videoStateKey = (window.Constants && window.Constants.STORAGE_KEYS && window.Constants.STORAGE_KEYS.VIDEO_GLOBAL_STATE) || 'video-global-state';
    const defaultPlaybackRate = (window.Constants && window.Constants.MEDIA_PLAYER && window.Constants.MEDIA_PLAYER.DEFAULT_PLAYBACK_RATE) || 1.0;
    
    if (this.videoFile && this.video && this.video.src) {
      const videoKey = `video-${this.lessonId}`;
      let saved = null;
      
      // Usar StorageSafe se disponível
      if (window.StorageSafe && typeof window.StorageSafe.getItem === 'function') {
        saved = window.StorageSafe.getItem(videoKey);
      } else {
        try {
          const item = localStorage.getItem(videoKey);
          saved = item ? JSON.parse(item) : null;
        } catch (e) {
          window.Logger?.error('Erro ao carregar progresso do vídeo:', e);
          saved = null;
        }
      }
      
      if (saved && saved.currentTime !== undefined && saved.duration) {
        // Salvar o tempo salvo, mas NÃO aplicar ainda ao vídeo
        // Será aplicado apenas quando usuário clicar para reproduzir (evento 'play')
        // Isso evita que vídeo tente pular para um ponto sem buffer suficiente
        this.currentTime = saved.currentTime;
        this.duration = saved.duration;
        this.playbackRate = saved.playbackRate || defaultPlaybackRate;
        
        // Aplicar apenas playbackRate (seguro, não requer buffer)
        if (this.video && this.video.src) {
          this.video.playbackRate = this.playbackRate;
        }
        
        if (this.speedSelect) {
          this.speedSelect.value = this.playbackRate.toString();
        }
        
        // Atualizar displays (mas vídeo ainda está em 0:00 até usuário clicar play)
        this.updateDurationDisplay();
      }
    } else if (this.video && this.video.src) {
      let globalState = null;
      
      // Usar StorageSafe se disponível
      if (window.StorageSafe && typeof window.StorageSafe.getSessionItem === 'function') {
        globalState = window.StorageSafe.getSessionItem(videoStateKey);
      } else {
        try {
          const item = sessionStorage.getItem(videoStateKey);
          globalState = item ? JSON.parse(item) : null;
        } catch (e) {
          window.Logger?.error('Erro ao carregar estado global do vídeo:', e);
          globalState = null;
        }
      }
      
      if (globalState && globalState.videoFile && globalState.currentTime !== undefined) {
        // Salvar o tempo salvo, mas NÃO aplicar ainda ao vídeo
        // Será aplicado apenas quando usuário clicar para reproduzir (evento 'play')
        this.currentTime = globalState.currentTime;
        this.duration = globalState.duration || 0;
        this.playbackRate = globalState.playbackRate || defaultPlaybackRate;
        this.isPlaying = false; // Sempre começar como não reproduzindo para evitar autoplay
        
        // Aplicar apenas playbackRate (seguro, não requer buffer)
        if (this.video && this.video.src) {
          this.video.playbackRate = this.playbackRate;
        }
        
        if (this.speedSelect) {
          this.speedSelect.value = this.playbackRate.toString();
        }
        
        // Atualizar displays
        this.updateDurationDisplay();
        this.updateUI();
      }
    }
  }
  
  markAsWatched() {
    const progressKey = (window.Constants && window.Constants.STORAGE_KEYS && window.Constants.STORAGE_KEYS.COURSE_PROGRESS) || 'course-progress';
    
    // Usar StorageSafe se disponível
    let progress = {};
    if (window.StorageSafe && typeof window.StorageSafe.getItem === 'function') {
      progress = window.StorageSafe.getItem(progressKey) || {};
    } else {
      try {
        const item = localStorage.getItem(progressKey);
        progress = item ? JSON.parse(item) : {};
      } catch (e) {
        window.Logger?.error('Erro ao carregar progresso do curso:', e);
        progress = {};
      }
    }
    
    if (!progress.videos) progress.videos = {};
    progress.videos[this.lessonId] = {
      watched: true,
      progress: 100,
      completed_at: new Date().toISOString()
    };
    
    // Salvar usando StorageSafe se disponível
    if (window.StorageSafe && typeof window.StorageSafe.setItem === 'function') {
      window.StorageSafe.setItem(progressKey, progress);
    } else {
      try {
        localStorage.setItem(progressKey, JSON.stringify(progress));
      } catch (e) {
        window.Logger?.error('Erro ao salvar progresso do curso:', e);
      }
    }
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
      if (window.Toast && typeof window.Toast.error === 'function') {
        window.Toast.error(
          'Erro ao carregar o vídeo. Verifique sua conexão e tente novamente.',
          'Erro ao carregar vídeo',
          7000
        );
      } else {
        window.Logger?.error('Erro ao carregar vídeo. Verifique sua conexão e tente novamente.');
      }
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
  const videoElement = document.getElementById('video-element');
  
  // Só inicializar VideoPlayer se houver elemento de vídeo na página
  // O elemento só existe quando o include video-player.html foi renderizado
  if (!videoElement) {
    // Não há vídeo nesta página, não inicializar
    return;
  }
  
  let config = null;
  
  if (videoData) {
    try {
      config = JSON.parse(videoData.textContent);
      // Garantir que há vídeo configurado
      if (!config || (!config.videoFile && !videoElement.src)) {
        return; // Não há vídeo para reproduzir
      }
    } catch (e) {
      window.Logger?.error('Erro ao parsear dados do vídeo:', e);
      return;
    }
  } else {
    // Há elemento de vídeo mas sem video-data, criar config básico do elemento
    const lessonData = document.getElementById('lesson-data');
    if (lessonData) {
      try {
        const lesson = JSON.parse(lessonData.textContent);
        config = {
          lessonId: lesson.lesson_id,
          videoFile: videoElement.src || null,
          videoTitle: null,
          videoDescription: null
        };
      } catch (e) {
        window.Logger?.error('Erro ao parsear dados da lição:', e);
        return;
      }
    } else {
      return; // Sem dados necessários
    }
  }
  
  // Só criar instância se houver vídeo válido
  if (config && (config.videoFile || videoElement.src)) {
    // Se já existe instância válida, reutilizar
    if (window.videoPlayer && 
        window.videoPlayer instanceof VideoPlayer &&
        window.videoPlayer.lessonId === config.lessonId) {
      // Reutilizar instância existente
      window.Logger?.log('Reutilizando instância existente de VideoPlayer');
    } else {
      // Criar nova instância
      window.videoPlayer = new VideoPlayer(config);
    }
  }
});

