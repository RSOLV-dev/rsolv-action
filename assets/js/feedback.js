/**
 * Feedback Module
 * 
 * Handles client-side feedback functionality including form submission,
 * validation, and UI interactions with robust error handling.
 * 
 * @module FeedbackModule
 * @version 1.0.1
 */

const FeedbackModule = {
  /**
   * Initialize the feedback module with error handling
   * @returns {boolean} Success status of initialization
   */
  init() {
    try {
      // Find feedback form elements
      const feedbackForms = document.querySelectorAll('[data-feedback-form]');
      
      // Attach event listeners to each form
      feedbackForms.forEach(form => {
        if (form instanceof HTMLFormElement) {
          form.addEventListener('submit', this.handleSubmit.bind(this));
        } else {
          console.warn('Non-form element found with data-feedback-form attribute:', form);
        }
      });
      
      // Initialize feedback triggers
      const feedbackTriggers = document.querySelectorAll('[data-feedback-trigger]');
      feedbackTriggers.forEach(trigger => {
        trigger.addEventListener('click', this.handleTriggerClick.bind(this));
      });
      
      console.log('Feedback module initialized successfully');
      return true;
    } catch (error) {
      console.error('Error initializing feedback module:', error);
      return false;
    }
  },
  
  /**
   * Handle form submission with comprehensive error handling
   * and validation of form data
   * @param {Event} event - The submit event
   * @returns {Promise<void>}
   */
  async handleSubmit(event) {
    if (!event || !(event.target instanceof HTMLFormElement)) {
      console.error('Invalid event in handleSubmit:', event);
      return;
    }
    
    event.preventDefault();
    
    const form = event.target;
    const submitButton = form.querySelector('[type="submit"]');
    const feedbackType = form.getAttribute('data-feedback-type') || 'general';
    
    // Disable submit button and show loading state
    if (submitButton) {
      submitButton.disabled = true;
      submitButton.innerHTML = 'Submitting...';
    }
    
    // Validate required fields
    const contentField = form.querySelector('[name="content"]');
    if (contentField && !contentField.value.trim()) {
      this.showMessage(form, 'error', 'Please provide feedback content.');
      if (submitButton) {
        submitButton.disabled = false;
        submitButton.innerHTML = 'Submit Feedback';
      }
      return;
    }
    
    // Gather form data
    try {
      const formData = new FormData(form);
      const feedbackData = {
        feedback_type: feedbackType,
        content: formData.get('content'),
        email: formData.get('email') || '',
        source: 'website',
        metadata: {
          url: window.location.href,
          userAgent: navigator.userAgent,
          timestamp: new Date().toISOString(),
          // Capture additional context that might be helpful
          referrer: document.referrer || '',
          screen_size: `${window.innerWidth}x${window.innerHeight}`
        }
      };
      
      // Submit feedback to API with timeout for better UX
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout
      
      try {
        const response = await fetch('/api/feedback', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(feedbackData),
          signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        if (!response.ok) {
          throw new Error(`Server error: ${response.status} ${response.statusText}`);
        }
        
        const result = await response.json();
        
        // Show success message
        this.showMessage(form, 'success', 'Thank you for your feedback!');
        
        // Reset form
        form.reset();
        
        // Track analytics event if available
        if (window.Analytics && typeof window.Analytics.trackEvent === 'function') {
          window.Analytics.trackEvent('feedback_submit_success', {
            feedback_type: feedbackType,
            has_email: !!feedbackData.email
          });
        }
      } catch (fetchError) {
        clearTimeout(timeoutId);
        
        // Specially handle timeout/abort errors
        if (fetchError.name === 'AbortError') {
          console.error('Feedback submission timed out');
          this.showMessage(form, 'error', 'The request timed out. Please try again.');
        } else {
          console.error('Feedback submission fetch error:', fetchError);
          this.showMessage(form, 'error', 'There was an error submitting your feedback. Please try again.');
        }
        
        // Track analytics event if available
        if (window.Analytics && typeof window.Analytics.trackEvent === 'function') {
          window.Analytics.trackEvent('feedback_submit_error', {
            error_type: fetchError.name,
            feedback_type: feedbackType
          });
        }
      }
    } catch (error) {
      console.error('Feedback form processing error:', error);
      this.showMessage(form, 'error', 'There was an error processing your feedback. Please try again.');
    } finally {
      // Always re-enable submit button
      if (submitButton) {
        submitButton.disabled = false;
        submitButton.innerHTML = 'Submit Feedback';
      }
    }
  },
  
  /**
   * Handle click on feedback trigger button
   * @param {Event} event - The click event
   */
  handleTriggerClick(event) {
    const trigger = event.currentTarget;
    const targetId = trigger.getAttribute('data-feedback-target');
    
    if (targetId) {
      const target = document.getElementById(targetId);
      if (target) {
        // Toggle visibility
        if (target.classList.contains('hidden')) {
          target.classList.remove('hidden');
        } else {
          target.classList.add('hidden');
        }
      }
    }
  },
  
  /**
   * Show a message in the form with improved accessibility and error handling
   * @param {HTMLElement} form - The form element
   * @param {string} type - The message type ('success' or 'error')
   * @param {string} message - The message text
   * @returns {boolean} Success status of the operation
   */
  showMessage(form, type, message) {
    try {
      if (!form || !(form instanceof HTMLElement)) {
        console.error('Invalid form element provided to showMessage:', form);
        return false;
      }
      
      if (!message || typeof message !== 'string') {
        console.warn('Invalid message provided to showMessage:', message);
        message = type === 'success' ? 'Operation successful.' : 'An error occurred.';
      }
      
      // Sanitize message to prevent XSS (basic sanitization)
      const sanitizedMessage = message
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
      
      // Find or create message container
      let messageContainer = form.querySelector('.feedback-message');
      
      if (!messageContainer) {
        messageContainer = document.createElement('div');
        messageContainer.className = 'feedback-message mt-4';
        form.appendChild(messageContainer);
      }
      
      // Set message content and styling with proper accessibility attributes
      messageContainer.innerHTML = sanitizedMessage;
      messageContainer.className = 'feedback-message mt-4 p-4 rounded';
      messageContainer.setAttribute('role', 'alert');
      messageContainer.setAttribute('aria-live', 'assertive');
      
      // Clear any existing timeout
      if (messageContainer.hideTimeout) {
        clearTimeout(messageContainer.hideTimeout);
        messageContainer.hideTimeout = null;
      }
      
      // Apply correct styling based on message type
      if (type === 'success') {
        messageContainer.classList.add('bg-green-100', 'text-green-800');
        messageContainer.setAttribute('aria-label', 'Success message');
      } else if (type === 'error') {
        messageContainer.classList.add('bg-red-100', 'text-red-800');
        messageContainer.setAttribute('aria-label', 'Error message');
      } else if (type === 'warning') {
        messageContainer.classList.add('bg-yellow-100', 'text-yellow-800');
        messageContainer.setAttribute('aria-label', 'Warning message');
      } else {
        messageContainer.classList.add('bg-blue-100', 'text-blue-800');
        messageContainer.setAttribute('aria-label', 'Information message');
      }
      
      // Ensure message is visible
      messageContainer.classList.remove('hidden', 'opacity-0');
      
      // Automatically hide the message after 5 seconds
      messageContainer.hideTimeout = setTimeout(() => {
        messageContainer.classList.add('opacity-0', 'transition-opacity', 'duration-500');
        
        const removeTimeout = setTimeout(() => {
          messageContainer.innerHTML = '';
          messageContainer.className = 'feedback-message mt-4 hidden';
          messageContainer.removeAttribute('role');
          messageContainer.removeAttribute('aria-live');
        }, 500);
        
        // Store the timeout ID for potential cleanup
        messageContainer.removeTimeout = removeTimeout;
      }, 5000);
      
      return true;
    } catch (error) {
      console.error('Error showing message:', error);
      return false;
    }
  }
};

// Initialize feedback module when document is loaded
document.addEventListener('DOMContentLoaded', () => {
  FeedbackModule.init();
});

export default FeedbackModule;