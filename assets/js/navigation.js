document.addEventListener('DOMContentLoaded', () => {
  const sidebar = document.querySelector('.sidebar-navigation');
  const toggleButton = document.getElementById('nav-toggle');
  
  if (toggleButton && sidebar) {
    toggleButton.addEventListener('click', () => {
      sidebar.classList.toggle('open');
    });
  }
  
  const currentPath = window.location.pathname.replace(/\/$/, '');
  const navLinks = document.querySelectorAll('.sidebar-navigation a');
  
  navLinks.forEach(link => {
    const linkPath = link.getAttribute('href').replace(/\/$/, '');
    if (linkPath === currentPath) {
      link.classList.add('active');
      
      const lessonItem = link.closest('.lesson-item');
      if (lessonItem) {
        const exercisesList = lessonItem.querySelector('.exercises-list');
        const lessonToggle = lessonItem.querySelector('.lesson-toggle');
        if (exercisesList && lessonToggle) {
          exercisesList.classList.remove('collapsed');
          lessonToggle.setAttribute('aria-expanded', 'true');
          const icon = lessonToggle.querySelector('.toggle-icon');
          if (icon) icon.textContent = '▼';
        }
        
        const moduleItem = lessonItem.closest('.module-item');
        if (moduleItem) {
          const lessonsList = moduleItem.querySelector('.lessons-list');
          const moduleToggle = moduleItem.querySelector('.module-toggle');
          if (lessonsList && moduleToggle) {
            lessonsList.classList.remove('collapsed');
            moduleToggle.setAttribute('aria-expanded', 'true');
            const icon = moduleToggle.querySelector('.toggle-icon');
            if (icon) icon.textContent = '▼';
          }
        }
      }
      
      const exerciseLink = link.closest('.exercises-list');
      if (exerciseLink) {
        exerciseLink.classList.remove('collapsed');
        const lessonItem = exerciseLink.closest('.lesson-item');
        if (lessonItem) {
          const lessonToggle = lessonItem.querySelector('.lesson-toggle');
          if (lessonToggle) {
            lessonToggle.setAttribute('aria-expanded', 'true');
            const icon = lessonToggle.querySelector('.toggle-icon');
            if (icon) icon.textContent = '▼';
          }
        }
      }
    }
  });
  
  const moduleToggles = document.querySelectorAll('.module-toggle');
  moduleToggles.forEach(toggle => {
    toggle.addEventListener('click', (e) => {
      e.stopPropagation();
      const moduleItem = toggle.closest('.module-item');
      const lessonsList = moduleItem.querySelector('.lessons-list');
      const isExpanded = toggle.getAttribute('aria-expanded') === 'true';
      const icon = toggle.querySelector('.toggle-icon');
      
      if (isExpanded) {
        lessonsList.classList.add('collapsed');
        toggle.setAttribute('aria-expanded', 'false');
        if (icon) icon.textContent = '►';
      } else {
        lessonsList.classList.remove('collapsed');
        toggle.setAttribute('aria-expanded', 'true');
        if (icon) icon.textContent = '▼';
      }
    });
  });
  
  const lessonToggles = document.querySelectorAll('.lesson-toggle');
  lessonToggles.forEach(toggle => {
    toggle.addEventListener('click', (e) => {
      e.stopPropagation();
      const lessonItem = toggle.closest('.lesson-item');
      const exercisesList = lessonItem.querySelector('.exercises-list');
      const isExpanded = toggle.getAttribute('aria-expanded') === 'true';
      const icon = toggle.querySelector('.toggle-icon');
      
      if (isExpanded) {
        exercisesList.classList.add('collapsed');
        toggle.setAttribute('aria-expanded', 'false');
        if (icon) icon.textContent = '►';
      } else {
        exercisesList.classList.remove('collapsed');
        toggle.setAttribute('aria-expanded', 'true');
        if (icon) icon.textContent = '▼';
      }
    });
  });
});

