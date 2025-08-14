// If you want to use Phoenix channels, run `mix help phx.gen.channel`
// to get started and then uncomment the line below.
// import "./user_socket.js"

// Include phoenix_html to handle method=PUT/DELETE in forms and buttons.
import "phoenix_html"
// Establish Phoenix Socket and LiveView configuration.
import {Socket} from "phoenix"
import {LiveSocket} from "phoenix_live_view"
import topbar from "../vendor/topbar"
import Analytics from "./analytics"
import DashboardHooks from "./dashboard_charts"
import ResponsiveChartHooks from "./responsive_charts"
import FeedbackModule from "./feedback"
import { initRoiCalculator } from "./roi_calculator"

let csrfToken = document.querySelector("meta[name='csrf-token']").getAttribute("content")

// Define LiveView hooks
const Hooks = {
  ...DashboardHooks,
  ...ResponsiveChartHooks,
  
  
  FocusInput: {
    mounted() {
      // Create a completely unmanaged input that lives separately from Phoenix LiveView
      const inputEl = this.el;
      const formId = "early-access-form";
      
      // Create a standalone plain JS input element to replace the LiveView one
      const standaloneInput = document.createElement("input");
      
      // Copy all the attributes
      Array.from(inputEl.attributes).forEach(attr => {
        if (attr.name !== 'phx-hook' && attr.name !== 'id' && attr.name !== 'name') {
          standaloneInput.setAttribute(attr.name, attr.value);
        }
      });
      
      // Set additional properties
      standaloneInput.id = inputEl.id + "-js";
      standaloneInput.name = "email";
      standaloneInput.type = "email";
      standaloneInput.placeholder = "you@company.com";
      standaloneInput.required = true;
      standaloneInput.className = "email-input";
      
      // When user types, we'll forward the value to LiveView without 
      // letting LiveView actually control the input
      standaloneInput.addEventListener("input", e => {
        this.pushEvent("input-change", { value: e.target.value });
      });
      
      // When focus leaves, validate the input
      standaloneInput.addEventListener("blur", e => {
        this.pushEvent("validate", { email: e.target.value });
      });
      
      // Replace the original input
      inputEl.style.display = "none";
      inputEl.insertAdjacentElement("afterend", standaloneInput);
      
      // Add an event listener to the form for submission
      const form = document.getElementById(formId);
      if (form) {
        form.addEventListener("submit", e => {
          e.preventDefault();
          // Manually submit with the value from our standalone input
          this.pushEvent("submit", { email: standaloneInput.value });
        });
      }
    }
  }
};

let liveSocket = new LiveSocket("/live", Socket, {
  longPollFallbackMs: 10000,
  params: {_csrf_token: csrfToken},
  hooks: Hooks,
  transport: WebSocket
})

// Show progress bar on live navigation and form submits
topbar.config({barColors: {0: "#29d"}, shadowColor: "rgba(0, 0, 0, .3)"})
window.addEventListener("phx:page-loading-start", _info => topbar.show(300))
window.addEventListener("phx:page-loading-stop", _info => topbar.hide())

// connect if there are any LiveViews on the page
liveSocket.connect()

// expose liveSocket on window for web console debug logs and latency simulation:
// >> liveSocket.enableDebug()
// >> liveSocket.enableLatencySim(1000)  // enabled for duration of browser session
// >> liveSocket.disableLatencySim()
window.liveSocket = liveSocket

// Mobile menu functionality
document.addEventListener("DOMContentLoaded", function() {
  // Initialize analytics system
  Analytics.init();
  
  // Initialize feedback module
  FeedbackModule.init();
  
  // Initialize ROI calculator if present
  initRoiCalculator();
  
  // Mobile menu - handle non-LiveView pages
  const mobileMenuButton = document.getElementById('mobile-menu-button');
  const mobileMenu = document.getElementById('mobile-menu');
  
  // Only set up JS handlers if not in LiveView context
  if (mobileMenuButton && mobileMenu && !mobileMenuButton.hasAttribute('phx-click')) {
    mobileMenuButton.addEventListener('click', function() {
      mobileMenu.classList.toggle('hidden');
      const isExpanded = mobileMenu.classList.contains('hidden') ? 'false' : 'true';
      this.setAttribute('aria-expanded', isExpanded);
    });
    
    // Close menu when clicking links
    const links = mobileMenu.querySelectorAll('a');
    links.forEach(link => {
      link.addEventListener('click', () => {
        mobileMenu.classList.add('hidden');
        mobileMenuButton.setAttribute('aria-expanded', 'false');
      });
    });
  }
  
  // Track section visibility with Intersection Observer
  setupSectionVisibility();
  
  // Add UTM parameter persistence to all links
  preserveUtmParams();
  
});


// Track section visibility using Intersection Observer
function setupSectionVisibility() {
  const sections = [
    "#features",
    "#how-it-works",
    "#pricing", 
    "#faq",
    "#early-access"
  ];
  
  if (!('IntersectionObserver' in window)) return;
  
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const sectionId = entry.target.id;
        if (sectionId) {
          // Use analytics to track section view
          Analytics.trackEvent("section_view", {
            section_id: sectionId,
            visible_percent: Math.round(entry.intersectionRatio * 100)
          });
        }
      }
    });
  }, {
    threshold: [0.25, 0.5, 0.75, 1.0] // Track at different visibility thresholds
  });
  
  // Observe each section
  sections.forEach(selector => {
    const element = document.querySelector(selector);
    if (element) observer.observe(element);
  });
}

// Add UTM parameter preservation to all links
function preserveUtmParams() {
  // Extract UTM parameters from URL
  const urlParams = new URLSearchParams(window.location.search);
  const utmParams = {};
  
  ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content'].forEach(param => {
    const value = urlParams.get(param);
    if (value) {
      utmParams[param] = value;
      
      // Store in sessionStorage for persistence
      sessionStorage.setItem(param, value);
    } else if (sessionStorage.getItem(param)) {
      // Retrieve from sessionStorage if not in URL
      utmParams[param] = sessionStorage.getItem(param);
    }
  });
  
  // Only proceed if we have UTM parameters
  if (Object.keys(utmParams).length === 0) return;
  
  // Add UTM parameters to all internal links
  document.querySelectorAll('a[href^="/"], a[href^="#"]').forEach(link => {
    // Skip if link already has UTM parameters
    if (link.href.includes('utm_')) return;
    
    const url = new URL(link.href, window.location.origin);
    
    // Add each UTM parameter to the link
    Object.keys(utmParams).forEach(key => {
      url.searchParams.set(key, utmParams[key]);
    });
    
    link.href = url.toString();
  });
  
  // Add to all forms as hidden fields
  document.querySelectorAll('form').forEach(form => {
    // Add each UTM parameter to the form
    Object.keys(utmParams).forEach(key => {
      // Check if the field already exists
      let field = form.querySelector(`input[name="${key}"]`);
      
      if (!field) {
        // Create a new field
        field = document.createElement('input');
        field.type = 'hidden';
        field.name = key;
        form.appendChild(field);
      }
      
      // Set the value
      field.value = utmParams[key];
    });
  });
}