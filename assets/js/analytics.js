class Analytics {
  static trackPageView(title, path) {
    if (typeof gtag !== 'undefined') {
      gtag('config', window.GA_ID, {
        page_title: title,
        page_path: path
      });
    }
  }
  
  static trackTimeOnPage() {
    const startTime = Date.now();
    
    window.addEventListener('beforeunload', () => {
      const timeSpent = Math.round((Date.now() - startTime) / 1000);
      if (typeof gtag !== 'undefined' && timeSpent > 5) {
        gtag('event', 'time_on_page', {
          time_spent: timeSpent,
          page_path: window.location.pathname
        });
      }
    });
  }
  
  static trackScrollDepth() {
    let maxScroll = 0;
    const thresholds = [25, 50, 75, 100];
    const tracked = new Set();
    
    window.addEventListener('scroll', () => {
      const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
      const docHeight = document.documentElement.scrollHeight - window.innerHeight;
      const scrollPercent = Math.round((scrollTop / docHeight) * 100);
      
      if (scrollPercent > maxScroll) {
        maxScroll = scrollPercent;
        
        thresholds.forEach(threshold => {
          if (scrollPercent >= threshold && !tracked.has(threshold)) {
            tracked.add(threshold);
            if (typeof gtag !== 'undefined') {
              gtag('event', 'scroll_depth', {
                depth: threshold,
                page_path: window.location.pathname
              });
            }
          }
        });
      }
    });
  }
}

document.addEventListener('DOMContentLoaded', () => {
  Analytics.trackTimeOnPage();
  Analytics.trackScrollDepth();
});

