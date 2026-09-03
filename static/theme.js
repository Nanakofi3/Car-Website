document.addEventListener('DOMContentLoaded', function () {
  var toggles = document.querySelectorAll('[data-theme-toggle]');
  toggles.forEach(function (toggle) {
    toggle.addEventListener('click', function () {
      var isDark = document.documentElement.getAttribute('data-theme') === 'dark';
      if (isDark) {
        document.documentElement.removeAttribute('data-theme');
        localStorage.setItem('theme', 'light');
      } else {
        document.documentElement.setAttribute('data-theme', 'dark');
        localStorage.setItem('theme', 'dark');
      }
    });
  });
});
