// Dark Theme Toggle Hook for Phoenix LiveView
export const DarkThemeToggle = {
  mounted() {
    // Initialize theme on mount
    this.applyTheme(this.getTheme());
    this.updateIcon();
    
    // Add click handler
    this.el.addEventListener('click', () => {
      this.toggleTheme();
    });
    
    // Watch for system theme changes
    this.mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    this.mediaQuery.addEventListener('change', (e) => {
      if (!localStorage.getItem('theme')) {
        this.applyTheme(e.matches ? 'dark' : 'light');
        this.updateIcon();
      }
    });
  },
  
  destroyed() {
    // Clean up event listener
    if (this.mediaQuery) {
      this.mediaQuery.removeEventListener('change', () => {});
    }
  },
  
  toggleTheme() {
    const currentTheme = this.getTheme();
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    this.setTheme(newTheme);
    this.applyTheme(newTheme);
    this.updateIcon();
  },
  
  getTheme() {
    // Check localStorage first
    const storedTheme = localStorage.getItem('theme');
    if (storedTheme) return storedTheme;
    
    // Check system preference
    if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
      return 'dark';
    }
    
    return 'light';
  },
  
  setTheme(theme) {
    localStorage.setItem('theme', theme);
  },
  
  applyTheme(theme) {
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    
    // Update theme-color meta tag
    const metaThemeColor = document.querySelector('meta[name="theme-color"]');
    if (metaThemeColor) {
      metaThemeColor.setAttribute('content', theme === 'dark' ? '#020617' : '#ffffff');
    }
  },
  
  updateIcon() {
    const isDark = document.documentElement.classList.contains('dark');
    const lightIcon = document.getElementById('theme-toggle-light-icon');
    const darkIcon = document.getElementById('theme-toggle-dark-icon');
    
    if (lightIcon && darkIcon) {
      // Check if we're on homepage by looking at the URL path
      const isHomepage = window.location.pathname === '/';
      
      if (isDark) {
        // Show sun icon in dark mode
        lightIcon.classList.remove('hidden', 'text-transparent', 'text-white', 'text-gray-600');
        lightIcon.classList.add('text-yellow-400');
        darkIcon.classList.add('hidden', 'text-transparent');
      } else {
        // Show moon icon in light mode
        darkIcon.classList.remove('hidden', 'text-transparent', 'text-yellow-400');
        // Use white on homepage (dark header), gray elsewhere
        const lightModeColor = isHomepage ? 'text-white' : 'text-gray-600';
        darkIcon.classList.add(lightModeColor);
        lightIcon.classList.add('hidden', 'text-transparent');
      }
    }
  }
};

// Apply theme immediately on page load (before LiveView mounts)
(function() {
  const theme = localStorage.getItem('theme') || 
    (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  
  if (theme === 'dark') {
    document.documentElement.classList.add('dark');
  }
})();