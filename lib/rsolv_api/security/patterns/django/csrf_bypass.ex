defmodule RsolvApi.Security.Patterns.Django.CsrfBypass do
  @moduledoc """
  Django CSRF Bypass pattern for Django applications.
  
  This pattern detects Cross-Site Request Forgery (CSRF) protection that has been
  disabled, bypassed, or improperly configured, leaving applications vulnerable
  to forged requests.
  
  ## Background
  
  CSRF attacks trick authenticated users into submitting unintended requests to
  a web application. Django provides built-in CSRF protection through:
  
  - CsrfViewMiddleware that validates tokens
  - {% csrf_token %} template tag for forms  
  - CSRF cookie and header validation
  - Secure cookie settings
  
  Disabling or bypassing these protections leaves applications vulnerable.
  
  ## Vulnerability Details
  
  Common CSRF bypass patterns include:
  - Using @csrf_exempt decorator on sensitive views
  - Disabling CSRF middleware globally
  - Missing {% csrf_token %} in forms
  - Insecure CSRF cookie settings
  - Improper AJAX request handling
  
  ## Examples
  
      # VULNERABLE - @csrf_exempt disables protection
      @csrf_exempt
      def transfer_funds(request):
          amount = request.POST.get('amount')
          recipient = request.POST.get('recipient')
          process_transfer(amount, recipient)
          
      # VULNERABLE - Form without CSRF token
      <form method="post" action="/transfer">
          <input type="text" name="amount">
          <input type="submit" value="Transfer">
      </form>
      
      # SAFE - CSRF protected by default
      def transfer_funds(request):
          # CsrfViewMiddleware validates token
          amount = request.POST.get('amount')
          recipient = request.POST.get('recipient')
          process_transfer(amount, recipient)
      
      # SAFE - Form with CSRF token
      <form method="post" action="/transfer">
          {% csrf_token %}
          <input type="text" name="amount">
          <input type="submit" value="Transfer">
      </form>
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  
  @impl true
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "django-csrf-bypass",
      name: "Django CSRF Bypass", 
      description: "CSRF protection disabled or bypassed",
      type: :csrf,
      severity: :high,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        # @csrf_exempt decorator
        ~r/@csrf_exempt/,
        
        # Insecure CSRF settings
        ~r/CSRF_COOKIE_SECURE\s*=\s*False/,
        ~r/CSRF_COOKIE_HTTPONLY\s*=\s*False/,
        ~r/CSRF_USE_SESSIONS\s*=\s*False/,
        ~r/CSRF_COOKIE_SAMESITE\s*=\s*['""]?None/,
        
        # Disabled CSRF middleware (commented out)
        ~r/#\s*['""]django\.middleware\.csrf\.CsrfViewMiddleware/,
        
        # AJAX requests without CSRF token
        ~r/\$\.ajax\s*\(\s*{\s*type:\s*['"]POST['"]/,
        ~r/fetch\s*\([^)]+method:\s*['"]POST['"]/,
        
        # Form POST without csrf_token (harder to detect with regex)
        ~r/<form[^>]+method\s*=\s*['""]?post['""]?[^>]*>(?!.*{%\s*csrf_token\s*%})/i
      ],
      cwe_id: "CWE-352",
      owasp_category: "A01:2021",
      recommendation: "Enable CSRF protection. Only use @csrf_exempt when absolutely necessary with additional security measures.",
      test_cases: %{
        vulnerable: [
          """
          @csrf_exempt
          def payment_view(request):
          """,
          "<form method=\"post\"><!-- Missing {% csrf_token %} -->",
          "CSRF_COOKIE_SECURE = False"
        ],
        safe: [
          """
          def payment_view(request):
              # CSRF protected by default
          """,
          "<form method=\"post\">{% csrf_token %}",
          "MIDDLEWARE = ['django.middleware.csrf.CsrfViewMiddleware']"
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Cross-Site Request Forgery (CSRF) is an attack that forces authenticated
      users to submit unwanted requests to a web application. Django provides
      comprehensive CSRF protection by default, but developers sometimes disable
      or bypass these protections, creating vulnerabilities.
      
      Common CSRF bypass patterns in Django include:
      
      1. **@csrf_exempt Decorator**: Completely disables CSRF protection for
         a view, often used inappropriately on sensitive endpoints
      
      2. **Disabled Middleware**: Commenting out or removing CsrfViewMiddleware
         from MIDDLEWARE settings disables protection globally
      
      3. **Missing Template Tags**: Forms without {% csrf_token %} tag won't
         include the required token for validation
      
      4. **Insecure Cookie Settings**: Setting CSRF_COOKIE_SECURE=False allows
         cookies to be sent over HTTP, enabling interception
      
      5. **AJAX Misconfiguration**: AJAX requests that don't include the
         X-CSRFToken header bypass protection
      
      Django's CSRF protection works by generating a unique token for each
      user session and requiring that token to be included with state-changing
      requests. When this protection is bypassed, attackers can trick users
      into performing unintended actions.
      """,
      
      references: [
        %{
          type: :cwe,
          id: "CWE-352",
          title: "Cross-Site Request Forgery (CSRF)",
          url: "https://cwe.mitre.org/data/definitions/352.html"
        },
        %{
          type: :owasp,
          id: "A01:2021",
          title: "Broken Access Control",
          url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
        },
        %{
          type: :owasp,
          id: "CSRF Prevention",
          title: "Cross-Site Request Forgery Prevention Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
        },
        %{
          type: :django,
          id: "CSRF Protection",
          title: "Django CSRF Protection Documentation",
          url: "https://docs.djangoproject.com/en/stable/ref/csrf/"
        }
      ],
      
      attack_vectors: [
        "Malicious form submission from attacker-controlled site",
        "AJAX requests without proper CSRF headers",
        "Image tags with state-changing URLs",
        "Automatic form submission via JavaScript",
        "Flash-based cross-site requests",
        "DNS rebinding attacks",
        "Login CSRF attacks",
        "Logout CSRF attacks"
      ],
      
      real_world_impact: [
        "Unauthorized financial transactions or transfers",
        "Account modification without user consent",
        "Privilege escalation through admin actions",
        "Data deletion or modification",
        "Password or email changes",
        "Social media actions (posting, following, etc.)",
        "Shopping cart manipulation",
        "Vote manipulation in polls or ratings"
      ],
      
      cve_examples: [
        %{
          id: "CVE-2016-7401",
          description: "Django CSRF protection bypass via Google Analytics cookies",
          severity: "high",
          cvss: 7.4,
          note: "Cookie parsing vulnerability allowed setting arbitrary cookies to bypass CSRF"
        },
        %{
          id: "CVE-2019-11457", 
          description: "django-crm CSRF vulnerabilities in multiple endpoints",
          severity: "high",
          cvss: 8.8,
          note: "Missing CSRF protection on /change-password-by-admin/, /api/settings/add/, /cases/create/"
        },
        %{
          id: "CVE-2022-34265",
          description: "Django SQL injection via Trunc/Extract functions",
          severity: "critical",
          cvss: 9.8,
          note: "While primarily SQL injection, could bypass CSRF checks through malformed requests"
        },
        %{
          id: "CVE-2014-0481",
          description: "Django file upload denial of service",
          severity: "medium",
          cvss: 5.0,
          note: "File upload handling could be exploited via CSRF to cause DoS"
        }
      ],
      
      detection_notes: """
      This pattern detects CSRF bypass through multiple methods:
      
      1. @csrf_exempt decorator usage - highest confidence
      2. CSRF settings explicitly set to False
      3. CSRF middleware commented out or removed
      4. AJAX/fetch POST requests without token configuration
      5. HTML forms with POST method lacking {% csrf_token %}
      
      Note that detecting missing {% csrf_token %} in templates via regex
      is imperfect and may have false positives. AST analysis would be
      more accurate for template validation.
      """,
      
      safe_alternatives: [
        """
        # Ensure CSRF middleware is enabled
        MIDDLEWARE = [
            'django.middleware.security.SecurityMiddleware',
            'django.contrib.sessions.middleware.SessionMiddleware',
            'django.middleware.csrf.CsrfViewMiddleware',  # Required
            # ... other middleware
        ]
        """,
        """
        # Include CSRF token in all forms
        <form method="post" action="/transfer">
            {% csrf_token %}
            <input type="text" name="amount" required>
            <input type="text" name="recipient" required>
            <button type="submit">Transfer</button>
        </form>
        """,
        """
        # Configure AJAX requests with CSRF token
        function getCookie(name) {
            let cookieValue = null;
            if (document.cookie && document.cookie !== '') {
                const cookies = document.cookie.split(';');
                for (let i = 0; i < cookies.length; i++) {
                    const cookie = cookies[i].trim();
                    if (cookie.substring(0, name.length + 1) === (name + '=')) {
                        cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                        break;
                    }
                }
            }
            return cookieValue;
        }
        
        const csrftoken = getCookie('csrftoken');
        
        fetch('/api/transfer', {
            method: 'POST',
            headers: {
                'X-CSRFToken': csrftoken,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
        """,
        """
        # Secure CSRF cookie settings
        CSRF_COOKIE_SECURE = True  # HTTPS only
        CSRF_COOKIE_HTTPONLY = True  # Not accessible via JavaScript
        CSRF_COOKIE_SAMESITE = 'Strict'  # Prevent cross-site usage
        """,
        """
        # Use @ensure_csrf_cookie for AJAX views
        from django.views.decorators.csrf import ensure_csrf_cookie
        
        @ensure_csrf_cookie
        def get_csrf_token(request):
            # This view ensures CSRF cookie is set
            return JsonResponse({'status': 'ok'})
        """,
        """
        # Alternative: Use Django REST Framework with proper authentication
        from rest_framework.authentication import SessionAuthentication
        from rest_framework.permissions import IsAuthenticated
        
        class TransferViewSet(viewsets.ModelViewSet):
            authentication_classes = [SessionAuthentication]
            permission_classes = [IsAuthenticated]
            # DRF handles CSRF automatically with SessionAuthentication
        """
      ],
      
      additional_context: %{
        common_mistakes: [
          "Using @csrf_exempt on all API endpoints",
          "Disabling CSRF for AJAX convenience",
          "Forgetting {% csrf_token %} in forms",
          "Not configuring AJAX requests with CSRF headers",
          "Using GET requests for state-changing operations",
          "Mixing cookie-based and token-based authentication",
          "Not updating CSRF_TRUSTED_ORIGINS for cross-origin requests",
          "Disabling CSRF in development and forgetting to re-enable"
        ],
        
        secure_patterns: [
          """
          # Selectively exempt only specific safe operations
          from django.views.decorators.csrf import csrf_exempt
          from django.views.decorators.http import require_POST
          from django.contrib.auth.decorators import login_required
          
          @login_required
          @require_POST
          def sensitive_action(request):
              # CSRF protected by default
              perform_action(request.user, request.POST)
          
          @csrf_exempt
          @require_POST
          def webhook_handler(request):
              # Only exempt webhooks with additional validation
              signature = request.headers.get('X-Webhook-Signature')
              if not verify_webhook_signature(request.body, signature):
                  return HttpResponseForbidden()
              process_webhook(request.body)
          """,
          """
          # Double Submit Cookie pattern for SPAs
          import secrets
          
          def set_csrf_cookie(response):
              csrf_token = secrets.token_urlsafe(32)
              response.set_cookie(
                  'csrf_token',
                  csrf_token,
                  secure=True,
                  httponly=False,  # Needs to be read by JS
                  samesite='Strict'
              )
              return response
          """,
          """
          # Custom CSRF validation for specific use cases
          from django.middleware.csrf import CsrfViewMiddleware
          
          class CustomCsrfMiddleware(CsrfViewMiddleware):
              def process_view(self, request, callback, callback_args, callback_kwargs):
                  # Skip CSRF for specific conditions
                  if request.path.startswith('/api/public/'):
                      return None
                  return super().process_view(
                      request, callback, callback_args, callback_kwargs
                  )
          """
        ],
        
        framework_specific_notes: [
          "Django enables CSRF protection by default via CsrfViewMiddleware",
          "CSRF tokens are rotated when a user logs in",
          "CSRF cookies are not tied to sessions by default (CSRF_USE_SESSIONS)",
          "Django 4.0+ requires CSRF_TRUSTED_ORIGINS to include scheme",
          "SameSite cookie attribute provides additional CSRF protection",
          "CSRF protection is not needed for safe HTTP methods (GET, HEAD, OPTIONS)",
          "Django REST Framework disables CSRF for token authentication",
          "Test client automatically includes CSRF tokens"
        ]
      }
    }
  end
  
  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.6,
      
      context_rules: %{
        csrf_settings: [
          "CSRF_COOKIE_SECURE",
          "CSRF_COOKIE_HTTPONLY", 
          "CSRF_USE_SESSIONS",
          "CSRF_COOKIE_SAMESITE",
          "CSRF_COOKIE_NAME",
          "CSRF_HEADER_NAME",
          "CSRF_TRUSTED_ORIGINS",
          "CSRF_COOKIE_AGE"
        ],
        
        safe_methods: [
          "GET",
          "HEAD",
          "OPTIONS",
          "TRACE"
        ],
        
        csrf_decorators: [
          "@csrf_exempt",
          "@csrf_protect",
          "@requires_csrf_token",
          "@ensure_csrf_cookie"
        ],
        
        middleware_names: [
          "CsrfViewMiddleware",
          "CsrfResponseMiddleware"
        ],
        
        ajax_libraries: [
          "$.ajax",
          "$.post", 
          "axios",
          "fetch",
          "XMLHttpRequest"
        ]
      },
      
      confidence_rules: %{
        adjustments: %{
          # High confidence patterns
          csrf_exempt_usage: +0.95,
          csrf_disabled_settings: +0.9,
          middleware_commented: +0.85,
          
          # Medium confidence
          ajax_without_header: +0.6,
          missing_in_template: +0.6,
          
          # Lower confidence
          safe_http_method: -0.9,
          webhook_endpoint: -0.7,
          public_api_endpoint: -0.6,
          in_test_file: -0.95,
          in_example_code: -0.9,
          
          # Context adjustments
          has_alternative_auth: -0.5,
          token_based_auth: -0.8,
          documented_exemption: -0.3
        }
      },
      
      ast_rules: %{
        csrf_analysis: %{
          detect_decorators: true,
          check_middleware: true,
          analyze_forms: true,
          check_ajax_calls: true,
          analyze_settings: true,
          check_templates: true
        },
        
        decorator_analysis: %{
          check_view_decorators: true,
          analyze_decorator_stack: true,
          detect_override_patterns: true
        },
        
        form_analysis: %{
          detect_post_forms: true,
          check_csrf_token_tag: true,
          analyze_form_action: true,
          check_method_attribute: true
        },
        
        ajax_analysis: %{
          detect_ajax_patterns: true,
          check_header_configuration: true,
          analyze_request_setup: true,
          check_cookie_handling: true
        }
      }
    }
  end
end
