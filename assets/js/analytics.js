/**
 * RSOLV Analytics Module
 * 
 * Handles client-side tracking of user interactions and session data.
 * Sends data to server via lightweight beacon API for minimal performance impact.
 * Implements privacy-preserving best practices and error resilience.
 * 
 * Features:
 * - Privacy-focused tracking with anonymized data
 * - Session management with unique identifiers
 * - Event tracking (page views, clicks, form submissions)
 * - Scroll depth tracking and section visibility
 * - UTM parameter extraction and persistence
 * - Session duration measurement
 * - Exit intent detection
 * - Fallback mechanisms for all critical functions
 * 
 * @module Analytics
 * @author RSOLV Team
 * @version 1.0.0
 */

// Configuration
const config = {
  // Endpoint for tracking events
  trackingEndpoint: '/track',
  
  // Time between session heartbeats in seconds
  heartbeatInterval: 30,
  
  // Scroll depth thresholds as percentages
  scrollDepthThresholds: [25, 50, 75, 100],
  
  // Sections to track visibility
  sectionSelectors: [
    "#features",
    "#how-it-works",
    "#pricing",
    "#faq",
    "#early-access"
  ],
  
  // Interactions to track
  trackClicks: true,
  trackScrollDepth: true,
  trackSectionVisibility: true,
  trackSessionDuration: true,
  trackExitIntent: true,
  
  // Privacy settings
  anonymizeIp: true,
  honorDNT: true,
  cookieDuration: 30 // days
};

// State management
let state = {
  sessionId: null,
  sessionStartTime: null,
  lastHeartbeatTime: null,
  lastScrollDepth: 0,
  visitedSections: {},
  clickedElements: {},
  formInteractions: {}
};

/**
 * Initialize the analytics system
 * Sets up session tracking, registers event handlers, and sends initial page view
 * Respects Do Not Track setting if configured
 * @private
 * @returns {void}
 * @throws {Error} If session initialization fails critically
 */
function init() {
  // Check if DoNotTrack is enabled and respect it if configured
  if (config.honorDNT && navigator.doNotTrack === "1") {
    console.log("Analytics disabled due to Do Not Track setting");
    return;
  }
  
  try {
    // Create or retrieve session ID
    state.sessionId = getOrCreateSessionId();
    state.sessionStartTime = Date.now();
  } catch (error) {
    console.error("Failed to initialize analytics session:", error);
    // Create a fallback session ID if needed
    state.sessionId = generateFallbackId();
    state.sessionStartTime = Date.now();
  }
  state.lastHeartbeatTime = state.sessionStartTime;
  
  // Register various event listeners
  registerEventHandlers();
  
  // Track initial page view
  trackPageView();
  
  // Set up session tracking
  if (config.trackSessionDuration) {
    startSessionTracking();
  }
  
  // Track when the user is about to leave
  if (config.trackExitIntent) {
    trackExitIntent();
  }
  
  console.log("RSOLV Analytics initialized");
}

/**
 * Track page view with referrer and UTM parameters
 * Records the current page URL, referrer, and any UTM parameters
 * @private 
 * @returns {void}
 */
function trackPageView() {
  try {
    const data = {
      event: 'page_view',
      page: window.location.pathname,
      referrer: document.referrer || '',
      title: document.title || '',
      timestamp: new Date().toISOString(),
      session_id: state.sessionId,
      utm_params: extractUtmParams()
    };
    
    sendBeacon('page_view', data);
  } catch (error) {
    console.error("Error tracking page view:", error);
    // Non-blocking - continue even if tracking fails
  }
}

/**
 * Get or create a session ID from browser storage
 * @returns {string} The session ID
 */
function getOrCreateSessionId() {
  const storageKey = 'rsolv_session_id';
  
  try {
    // Try to get from sessionStorage first
    let sessionId = sessionStorage.getItem(storageKey);
    
    if (!sessionId) {
      // Generate a new ID
      sessionId = generateUUID();
      sessionStorage.setItem(storageKey, sessionId);
    }
    
    return sessionId;
  } catch (error) {
    // Handle private browsing or other storage errors
    console.warn("Session storage unavailable:", error);
    return generateFallbackId();
  }
}

/**
 * Generate a UUID v4 for anonymous tracking
 * @returns {string} A random UUID
 */
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

/**
 * Generate a fallback ID when storage is unavailable
 * Uses timestamp plus random numbers for uniqueness
 * @returns {string} A fallback ID
 */
function generateFallbackId() {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `fb-${timestamp}-${random}`;
}

/**
 * Extract UTM parameters from URL or sessionStorage with improved error handling
 * @returns {Object} UTM parameters found in the URL or session storage
 */
function extractUtmParams() {
  const utmParams = {};
  
  try {
    // Try URL parameters first
    const urlParams = new URLSearchParams(window.location.search || '');
    
    // UTM parameters to track
    const paramNames = [
      'utm_source', 
      'utm_medium', 
      'utm_campaign', 
      'utm_term', 
      'utm_content',
      // Extended parameters for detailed attribution
      'utm_source_platform',
      'utm_source_campaign',
      'utm_source_content'
    ];
    
    // Check URL parameters first, then fallback to sessionStorage
    paramNames.forEach(param => {
      try {
        const value = urlParams.get(param);
        if (value) {
          utmParams[param] = value;
          // Store in sessionStorage for persistence across pages
          try {
            sessionStorage.setItem(param, value);
          } catch (storageError) {
            // Ignore storage errors in private browsing
          }
        } else if (sessionStorage) {
          // If not in URL, try session storage
          const storedValue = sessionStorage.getItem(param);
          if (storedValue) {
            utmParams[param] = storedValue;
          }
        }
      } catch (paramError) {
        // Catch per-parameter errors to ensure we continue processing other parameters
        console.warn(`Error processing UTM parameter ${param}:`, paramError);
      }
    });
  } catch (error) {
    console.error("Error extracting UTM parameters:", error);
  }
  
  return utmParams;
}

// Register event handlers for various interactions
function registerEventHandlers() {
  // Track clicks on important elements
  if (config.trackClicks) {
    document.addEventListener('click', handleClick);
  }
  
  // Track scroll depth
  if (config.trackScrollDepth) {
    window.addEventListener('scroll', throttle(handleScroll, 500));
  }
  
  // Track section visibility
  if (config.trackSectionVisibility) {
    // Set up intersection observer for section tracking
    setupSectionObserver();
  }
  
  // Track form interactions
  document.addEventListener('submit', handleFormSubmit);
  document.querySelectorAll('form').forEach(form => {
    form.querySelectorAll('input, select, textarea').forEach(field => {
      field.addEventListener('focus', () => handleFormFieldInteraction(form, field, 'focus'));
      field.addEventListener('blur', () => handleFormFieldInteraction(form, field, 'blur'));
    });
  });
}

/**
 * Handles click events on interactive elements for analytics tracking
 * @param {Event} event - The DOM click event
 */
function handleClick(event) {
  try {
    // Identify clickable elements
    const targetElement = event.target.closest('a, button, [role="button"], [type="button"], [type="submit"]');
    
    if (!targetElement) return;
    
    // Get element identification (with fallbacks for each property)
    const elementId = targetElement.id || '';
    const elementClass = (targetElement.className && typeof targetElement.className === 'string') 
                         ? targetElement.className 
                         : '';
    const elementText = targetElement.innerText || targetElement.textContent || '';
    const elementType = targetElement.tagName.toLowerCase();
    const elementHref = targetElement.href || '';
    
    // Check if it's a CTA
    const isCTA = elementClass.includes('btn') || 
                  elementClass.includes('cta') || 
                  elementClass.includes('button');
    
    // Create a simple identification for the element
    const elementIdentifier = elementId || 
                            (elementText.length < 30 ? elementText.trim() : elementText.trim().substring(0, 30)) || 
                            `${elementType}:${elementClass.split(' ')[0] || 'unknown'}`;
    
    // Prepare data
    const data = {
      event: isCTA ? 'cta_click' : 'click',
      element_id: elementId,
      element_type: elementType,
      element_text: elementText.substring(0, 100),
      element_identifier: elementIdentifier,
      is_cta: isCTA,
      page: window.location.pathname,
      timestamp: new Date().toISOString(),
      session_id: state.sessionId
    };
    
    // Add URL for links (with security check)
    if (elementHref && typeof elementHref === 'string' && !elementHref.startsWith('javascript:')) {
      data.destination = elementHref;
    }
    // Track in state
    state.clickedElements[elementIdentifier] = (state.clickedElements[elementIdentifier] || 0) + 1;
    
    // Send beacon
    sendBeacon('click', data);
  } catch (error) {
    console.error("Error tracking click event:", error);
    // Continue execution - don't let analytics errors break site functionality
  }
}

/**
 * Track scroll depth through predefined thresholds
 * Fires events when user crosses configured scroll depth thresholds
 * @private
 * @returns {void}
 */
function handleScroll() {
  try {
    const scrollDepth = calculateScrollDepth();
    
    // Check if we've crossed any thresholds
    for (const threshold of config.scrollDepthThresholds) {
      if (scrollDepth >= threshold && state.lastScrollDepth < threshold) {
        // We've passed a new threshold
        const data = {
          event: 'scroll_depth',
          depth: threshold,
          page: window.location.pathname,
          timestamp: new Date().toISOString(),
          session_id: state.sessionId
        };
        
        sendBeacon('scroll_depth', data);
      }
    }
    
    // Update last scroll depth
    state.lastScrollDepth = scrollDepth;
  } catch (error) {
    console.error("Error tracking scroll depth:", error);
    // Non-blocking - continue even if tracking fails
  }
}

/**
 * Calculate scroll depth as a percentage of total scrollable content
 * @private
 * @returns {number} Scroll depth as a percentage (0-100)
 */
function calculateScrollDepth() {
  try {
    const scrollTop = window.pageYOffset || document.documentElement.scrollTop || 0;
    const scrollHeight = (document.documentElement.scrollHeight || document.body.scrollHeight || 0) - 
                        (document.documentElement.clientHeight || window.innerHeight || 0);
    
    if (scrollHeight <= 0) return 0; // Avoid division by zero
    
    const depth = Math.round((scrollTop / scrollHeight) * 100);
    
    // Ensure we return a value between 0-100
    return Math.max(0, Math.min(100, depth));
  } catch (error) {
    console.error("Error calculating scroll depth:", error);
    return 0; // Return 0 as fallback on error
  }
}

// Set up tracking for when sections come into view
function setupSectionObserver() {
  // Check if IntersectionObserver is available
  if (!('IntersectionObserver' in window)) return;
  
  const options = {
    root: null, // viewport
    rootMargin: '0px',
    threshold: 0.3 // 30% of section must be visible
  };
  
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const sectionId = entry.target.id;
        if (sectionId && !state.visitedSections[sectionId]) {
          state.visitedSections[sectionId] = true;
          
          const data = {
            event: 'section_view',
            section_id: sectionId,
            page: window.location.pathname,
            timestamp: new Date().toISOString(),
            session_id: state.sessionId
          };
          
          sendBeacon('section_view', data);
        }
      }
    });
  }, options);
  
  // Observe all configured sections
  config.sectionSelectors.forEach(selector => {
    const element = document.querySelector(selector);
    if (element) observer.observe(element);
  });
}

// Handle form submissions
function handleFormSubmit(event) {
  const form = event.target;
  const formId = form.id || form.getAttribute('name') || 'unknown_form';
  
  // Don't track if the form is prevented from submitting (validation error)
  if (event.defaultPrevented) return;
  
  // Get email domain if available (for privacy)
  let emailDomain = null;
  const emailField = form.querySelector('input[type="email"]');
  if (emailField && emailField.value) {
    const emailParts = emailField.value.split('@');
    if (emailParts.length === 2) {
      emailDomain = emailParts[1];
    }
  }
  
  const data = {
    event: 'form_submit',
    form_id: formId,
    page: window.location.pathname,
    timestamp: new Date().toISOString(),
    session_id: state.sessionId,
    email_domain: emailDomain
  };
  
  sendBeacon('form_submit', data);
}

// Track interactions with form fields
function handleFormFieldInteraction(form, field, interactionType) {
  const formId = form.id || form.getAttribute('name') || 'unknown_form';
  const fieldId = field.id || field.name || 'unknown_field';
  const fieldType = field.type || 'unknown';
  
  // Create a unique identifier for this field
  const fieldIdentifier = `${formId}:${fieldId}`;
  
  // Initialize if needed
  if (!state.formInteractions[fieldIdentifier]) {
    state.formInteractions[fieldIdentifier] = {
      focus: 0,
      blur: 0,
      lastFocusTime: null
    };
  }
  
  // Update state
  if (interactionType === 'focus') {
    state.formInteractions[fieldIdentifier].focus++;
    state.formInteractions[fieldIdentifier].lastFocusTime = Date.now();
  } else if (interactionType === 'blur') {
    state.formInteractions[fieldIdentifier].blur++;
    
    // If we have a lastFocusTime, calculate duration
    let duration = null;
    if (state.formInteractions[fieldIdentifier].lastFocusTime) {
      duration = Date.now() - state.formInteractions[fieldIdentifier].lastFocusTime;
    }
    
    const data = {
      event: 'form_field_interaction',
      form_id: formId,
      field_id: fieldId,
      field_type: fieldType,
      interaction_type: interactionType,
      interaction_duration: duration,
      page: window.location.pathname,
      timestamp: new Date().toISOString(),
      session_id: state.sessionId
    };
    
    sendBeacon('form_field_interaction', data);
  }
}

// Start session tracking with heartbeats
function startSessionTracking() {
  // Send initial session start event
  const startData = {
    event: 'session_start',
    page: window.location.pathname,
    referrer: document.referrer,
    timestamp: new Date().toISOString(),
    session_id: state.sessionId,
    utm_params: extractUtmParams()
  };
  
  sendBeacon('session_start', startData);
  
  // Set up heartbeat
  window.setInterval(() => {
    const currentTime = Date.now();
    const sessionDuration = Math.floor((currentTime - state.sessionStartTime) / 1000);
    const timeSinceLastHeartbeat = Math.floor((currentTime - state.lastHeartbeatTime) / 1000);
    
    // Update last heartbeat time
    state.lastHeartbeatTime = currentTime;
    
    const data = {
      event: 'heartbeat',
      page: window.location.pathname,
      session_duration: sessionDuration,
      time_since_last_heartbeat: timeSinceLastHeartbeat,
      timestamp: new Date().toISOString(),
      session_id: state.sessionId
    };
    
    sendBeacon('heartbeat', data);
  }, config.heartbeatInterval * 1000);
  
  // Track session end on page unload
  window.addEventListener('beforeunload', () => {
    const sessionDuration = Math.floor((Date.now() - state.sessionStartTime) / 1000);
    
    const data = {
      event: 'session_end',
      page: window.location.pathname,
      session_duration: sessionDuration,
      timestamp: new Date().toISOString(),
      session_id: state.sessionId,
      sections_visited: Object.keys(state.visitedSections).length,
      max_scroll_depth: state.lastScrollDepth
    };
    
    // Use sendBeacon API for reliable delivery during page unload
    navigator.sendBeacon(
      config.trackingEndpoint, 
      JSON.stringify({
        type: 'session_end',
        data: data
      })
    );
  });
}

// Track exit intent (user about to leave)
function trackExitIntent() {
  // Track mouse leaving the viewport at the top
  document.addEventListener('mouseleave', (event) => {
    // Only track if the mouse leaves at the top
    if (event.clientY <= 0) {
      const data = {
        event: 'exit_intent',
        page: window.location.pathname,
        session_duration: Math.floor((Date.now() - state.sessionStartTime) / 1000),
        timestamp: new Date().toISOString(),
        session_id: state.sessionId,
        max_scroll_depth: state.lastScrollDepth
      };
      
      sendBeacon('exit_intent', data);
    }
  });
}


/**
 * Send analytics data to the backend endpoint with enhanced error handling
 * and support for various browser environments
 * @param {string} type - The type of event being tracked
 * @param {Object} data - The event data to send
 * @returns {Promise<boolean>} Success status of the beacon send operation
 */
async function sendBeacon(type, data) {
  try {
    // Validate inputs to prevent malformed requests
    if (!type || typeof type !== 'string') {
      console.warn('Invalid event type provided to sendBeacon:', type);
      return false;
    }
    
    if (!data || typeof data !== 'object') {
      console.warn('Invalid data provided to sendBeacon:', data);
      return false;
    }
    
    // For development, log to console
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
      console.log(`[Analytics] ${type}:`, data);
      return true; // Don't send actual requests in development
    }
    
    // Deep clone data to avoid mutations affecting the original object
    const dataToSend = JSON.parse(JSON.stringify({
      ...data,
      client_timestamp: new Date().toISOString() // Ensure client timestamp
    }));
    
    // Prepare the payload
    const payload = JSON.stringify({
      type: type,
      data: dataToSend
    });
    
    // Check if endpoint is available
    if (!config.trackingEndpoint) {
      console.warn('No tracking endpoint configured');
      return false;
    }
    
    // Try to use the Navigator.sendBeacon API first if available (best for unload events)
    const isUnloadEvent = type === 'session_end' || type === 'page_unload';
    if (isUnloadEvent && navigator.sendBeacon) {
      try {
        const blob = new Blob([payload], {type: 'application/json'});
        const success = navigator.sendBeacon(config.trackingEndpoint, blob);
        if (success) return true;
        // Fall through to fetch if sendBeacon fails
      } catch (beaconError) {
        console.warn("sendBeacon API failed:", beaconError);
        // Fall through to fetch
      }
    }
    
    // Use fetch with keepalive for better reliability
    try {
      await fetch(config.trackingEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: payload,
        keepalive: true, // Helps for events near page unload
        credentials: 'same-origin' // Include cookies for auth if needed
      });
      return true;
    } catch (fetchError) {
      console.error('Error sending analytics data:', fetchError);
      
      // Last-resort fallback for critical events - pixel tracking fallback
      if (isUnloadEvent) {
        try {
          const img = new Image();
          img.src = `${config.trackingEndpoint}/pixel?event=${encodeURIComponent(type)}&sid=${encodeURIComponent(data.session_id || 'unknown')}`;
          return true; // Consider this a success since the image load is async
        } catch (imgError) {
          console.error('Failed to send pixel tracking fallback:', imgError);
          return false;
        }
      }
      return false;
    }
  } catch (error) {
    console.error('Fatal error in analytics system:', error);
    return false;
  }
}

// Throttle function for rate limiting events
function throttle(func, limit) {
  let lastCall = 0;
  return function(...args) {
    const now = Date.now();
    if (now - lastCall >= limit) {
      lastCall = now;
      return func.apply(this, args);
    }
  };
}

/**
 * Export the Analytics API with enhanced error handling
 */
export default {
  /**
   * Initialize the analytics system
   * @returns {boolean} Whether initialization was successful
   */
  init: function() {
    try {
      init();
      return true;
    } catch (error) {
      console.error("Failed to initialize analytics:", error);
      return false;
    }
  },
  
  /**
   * Track a page view
   * @returns {boolean} Whether the tracking was successful
   */
  trackPageView: function() {
    try {
      trackPageView();
      return true;
    } catch (error) {
      console.error("Failed to track page view:", error);
      return false;
    }
  },
  
  /**
   * Track a custom event
   * @param {string} eventName - The name of the event to track
   * @param {Object} eventData - Additional data to include with the event
   * @returns {boolean} Whether the tracking was successful
   */
  trackEvent: function(eventName, eventData = {}) {
    try {
      if (!state.sessionId) {
        console.warn("Analytics not initialized. Call Analytics.init() first.");
        return false;
      }
      
      sendBeacon(eventName, {
        ...eventData,
        event: eventName,
        timestamp: new Date().toISOString(),
        session_id: state.sessionId,
        page: window.location.pathname
      });
      return true;
    } catch (error) {
      console.error(`Error tracking event '${eventName}':`, error);
      return false;
    }
  },
  
  /**
   * Track a signup celebration event
   * @param {Object} signupData - Data about the signup
   * @returns {boolean} Whether the tracking was successful
   */
  trackSignupCelebration: function(signupData = {}) {
    try {
      const celebrationData = {
        ...signupData,
        event_type: 'celebration',
        celebration_type: 'new_signup',
        timestamp: new Date().toISOString()
      };
      
      // Track as special celebration event
      sendBeacon('early_access_signup', celebrationData);
      
      return true;
    } catch (error) {
      console.error('Error tracking signup celebration:', error);
      return false;
    }
  }
};