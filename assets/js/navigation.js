document.addEventListener('DOMContentLoaded', () => {
  const sidebar = document.querySelector('.sidebar-navigation');
  const toggleButton = document.getElementById('nav-toggle');
  
  if (toggleButton && sidebar) {
    toggleButton.addEventListener('click', () => {
      sidebar.classList.toggle('open');
    });
  }
  
  const currentPath = window.location.pathname;
  const navLinks = document.querySelectorAll('.sidebar-navigation a');
  
  navLinks.forEach(link => {
    if (link.getAttribute('href') === currentPath) {
      link.classList.add('active');
    }
  });
});

