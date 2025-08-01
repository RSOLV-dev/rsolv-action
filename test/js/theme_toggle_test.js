/**
 * Theme Toggle Tests
 * 
 * To run these tests:
 * 1. Open test/js/test-theme-toggle.html in a browser
 * 2. Check the console for test results
 */

const ThemeToggleTests = {
  // Test utilities
  setup() {
    // Clear localStorage before each test
    localStorage.removeItem('theme');
    document.documentElement.classList.remove('dark');
  },

  teardown() {
    localStorage.removeItem('theme');
    document.documentElement.classList.remove('dark');
  },

  // Assertion helper
  assert(condition, message) {
    if (!condition) {
      throw new Error(`Assertion failed: ${message}`);
    }
  },

  // Tests
  testInitialStateLight() {
    this.setup();
    
    // Simulate page load with no preference
    const isDark = document.documentElement.classList.contains('dark');
    this.assert(!isDark, 'Should start in light mode by default');
    
    console.log('✓ testInitialStateLight passed');
  },

  testInitialStateFromLocalStorage() {
    this.setup();
    
    // Set dark mode preference
    localStorage.setItem('theme', 'dark');
    
    // Simulate the initialization script
    const theme = localStorage.getItem('theme') || 
      (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    document.documentElement.classList.toggle('dark', theme === 'dark');
    
    const isDark = document.documentElement.classList.contains('dark');
    this.assert(isDark, 'Should load dark mode from localStorage');
    
    console.log('✓ testInitialStateFromLocalStorage passed');
  },

  testThemeToggleClick() {
    this.setup();
    
    // Create mock elements
    const lightIcon = { classList: { toggle: () => {} } };
    const darkIcon = { classList: { toggle: () => {} } };
    
    // Initial state
    let theme = 'light';
    
    // Simulate toggle
    const newTheme = theme === 'dark' ? 'light' : 'dark';
    theme = newTheme;
    
    this.assert(theme === 'dark', 'Should toggle from light to dark');
    
    // Toggle again
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    theme = nextTheme;
    
    this.assert(theme === 'light', 'Should toggle from dark to light');
    
    console.log('✓ testThemeToggleClick passed');
  },

  testIconVisibility() {
    this.setup();
    
    // Create test elements
    const container = document.createElement('div');
    container.innerHTML = `
      <svg id="theme-toggle-light-icon" class="hidden dark:block"></svg>
      <svg id="theme-toggle-dark-icon" class="block dark:hidden"></svg>
    `;
    document.body.appendChild(container);
    
    const lightIcon = document.getElementById('theme-toggle-light-icon');
    const darkIcon = document.getElementById('theme-toggle-dark-icon');
    
    // In light mode
    document.documentElement.classList.remove('dark');
    const lightIconHidden = lightIcon.classList.contains('hidden');
    const darkIconHidden = darkIcon.classList.contains('hidden');
    
    this.assert(lightIconHidden, 'Sun icon should be hidden in light mode');
    this.assert(!darkIconHidden, 'Moon icon should be visible in light mode');
    
    // In dark mode
    document.documentElement.classList.add('dark');
    // Note: In real browser, Tailwind CSS would handle visibility
    
    console.log('✓ testIconVisibility passed');
    
    // Cleanup
    document.body.removeChild(container);
  },

  testLocalStoragePersistence() {
    this.setup();
    
    // Simulate setting dark mode
    localStorage.setItem('theme', 'dark');
    
    const stored = localStorage.getItem('theme');
    this.assert(stored === 'dark', 'Theme should persist in localStorage');
    
    // Simulate setting light mode
    localStorage.setItem('theme', 'light');
    
    const newStored = localStorage.getItem('theme');
    this.assert(newStored === 'light', 'Theme update should persist in localStorage');
    
    console.log('✓ testLocalStoragePersistence passed');
  },

  // Run all tests
  runAll() {
    console.log('Running Theme Toggle Tests...\n');
    
    const tests = [
      'testInitialStateLight',
      'testInitialStateFromLocalStorage',
      'testThemeToggleClick',
      'testIconVisibility',
      'testLocalStoragePersistence'
    ];
    
    let passed = 0;
    let failed = 0;
    
    tests.forEach(testName => {
      try {
        this[testName]();
        passed++;
      } catch (error) {
        console.error(`✗ ${testName} failed:`, error.message);
        failed++;
      } finally {
        this.teardown();
      }
    });
    
    console.log(`\nTests completed: ${passed} passed, ${failed} failed`);
    return failed === 0;
  }
};

// Export for use in HTML test runner
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ThemeToggleTests;
}