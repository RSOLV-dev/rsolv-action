defmodule Rsolv.Security.Patterns.Django.Clickjacking do
  @moduledoc """
  Django Clickjacking Vulnerability pattern for Django applications.

  This pattern detects missing or misconfigured X-Frame-Options header protection
  that could allow clickjacking attacks where malicious sites embed your pages
  in iframes to trick users into unintended actions.

  ## Background

  Clickjacking (UI redress attack) occurs when a malicious site embeds a legitimate
  site within a transparent iframe and tricks users into clicking on concealed
  elements. Django provides protection through:

  - XFrameOptionsMiddleware that sets X-Frame-Options header
  - Configurable values: DENY, SAMEORIGIN, ALLOWALL (insecure)
  - View-specific decorators to override default behavior
  - Content-Security-Policy as modern alternative

  ## Vulnerability Details

  Common clickjacking vulnerabilities include:
  - Setting X_FRAME_OPTIONS = 'ALLOWALL' (allows all framing)
  - Using @xframe_options_exempt decorator on sensitive views
  - Missing XFrameOptionsMiddleware in MIDDLEWARE
  - Not considering Content-Security-Policy frame-ancestors

  ## Examples

      # VULNERABLE - Allows all sites to embed this page
      X_FRAME_OPTIONS = 'ALLOWALL'

      # VULNERABLE - Removes protection from view
      @xframe_options_exempt
      def payment_form(request):
          return render(request, 'payment.html')

      # VULNERABLE - Still allows same-origin attacks
      @xframe_options_sameorigin
      def sensitive_action(request):
          return render(request, 'sensitive.html')

      # SAFE - Denies all framing
      X_FRAME_OPTIONS = 'DENY'

      # SAFE - Protected by default middleware
      def secure_view(request):
          # XFrameOptionsMiddleware adds header
          return render(request, 'secure.html')
  """

  use Rsolv.Security.Patterns.PatternBase

  @impl true
  def pattern do
    %Rsolv.Security.Pattern{
      id: "django-clickjacking",
      name: "Django Clickjacking Vulnerability",
      description: "Missing X-Frame-Options header protection",
      type: :clickjacking,
      severity: :medium,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        # X_FRAME_OPTIONS = 'ALLOWALL' is insecure
        ~r/X_FRAME_OPTIONS\s*=\s*['"]ALLOWALL['"]/,

        # @xframe_options_exempt removes protection
        ~r/@xframe_options_exempt/,

        # @xframe_options_sameorigin still allows same-origin attacks
        ~r/@xframe_options_sameorigin/
      ],
      cwe_id: "CWE-1021",
      owasp_category: "A05:2021",
      recommendation: "Set X_FRAME_OPTIONS = 'DENY' in settings",
      test_cases: %{
        vulnerable: [
          ~s|X_FRAME_OPTIONS = 'ALLOWALL'|,
          ~s|@xframe_options_exempt
def sensitive_view(request):|
        ],
        safe: [
          ~s|X_FRAME_OPTIONS = 'DENY'|,
          ~s|X_FRAME_OPTIONS = 'SAMEORIGIN'|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Clickjacking (UI redress attack) is a malicious technique where a web page
      is embedded within an iframe on an attacker's site, with visual tricks used
      to deceive users into clicking on concealed elements. This can lead to
      unintended actions being performed on the legitimate site.

      Django provides built-in clickjacking protection through the
      XFrameOptionsMiddleware, which sets the X-Frame-Options HTTP header to
      control whether a browser should be allowed to render a page in a frame
      or iframe.

      Common vulnerabilities include:

      1. **ALLOWALL Setting**: Setting X_FRAME_OPTIONS = 'ALLOWALL' completely
         disables clickjacking protection, allowing any site to embed your pages

      2. **Exempt Decorator**: Using @xframe_options_exempt removes protection
         from specific views, which may be dangerous for sensitive actions

      3. **SAMEORIGIN Weakness**: While @xframe_options_sameorigin restricts
         framing to same origin, it still allows potential attacks from
         compromised subdomains or same-origin malicious pages

      4. **Missing Middleware**: If XFrameOptionsMiddleware is not included
         in MIDDLEWARE settings, no protection is applied

      Modern browsers also support Content-Security-Policy with frame-ancestors
      directive as a more flexible alternative to X-Frame-Options.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-1021",
          title: "Improper Restriction of Rendered UI Layers or Frames",
          url: "https://cwe.mitre.org/data/definitions/1021.html"
        },
        %{
          type: :owasp,
          id: "A05:2021",
          title: "Security Misconfiguration",
          url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
        },
        %{
          type: :owasp,
          id: "Clickjacking Defense",
          title: "OWASP Clickjacking Defense Cheat Sheet",
          url:
            "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"
        },
        %{
          type: :django,
          id: "Clickjacking Protection",
          title: "Django Clickjacking Protection Documentation",
          url: "https://docs.djangoproject.com/en/stable/ref/clickjacking/"
        },
        %{
          type: :mdn,
          id: "X-Frame-Options",
          title: "X-Frame-Options HTTP Header",
          url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
        }
      ],
      attack_vectors: [
        "Transparent iframe overlay on legitimate site",
        "Invisible iframe with positioned elements",
        "Double-click attack with rapid iframe switching",
        "Drag-and-drop attacks across frames",
        "Scrolling attacks to misalign visual elements",
        "Browser history manipulation clickjacking",
        "Cursorjacking - hiding real cursor position",
        "Likejacking - tricking users into social media actions",
        "Filejacking - accessing local files via file input",
        "Password manager clickjacking"
      ],
      real_world_impact: [
        "Unauthorized financial transactions",
        "Unintended social media actions (likes, shares, follows)",
        "Account settings modification without consent",
        "Privacy settings changes",
        "Unauthorized file uploads",
        "Deletion of important data",
        "Privilege escalation through admin actions",
        "OAuth authorization clickjacking",
        "Email/message sending on user's behalf",
        "Subscription to paid services"
      ],
      cve_examples: [
        %{
          id: "CVE-2015-2317",
          description:
            "Django before 1.8 allows remote attackers to cause DoS via unspecified vectors",
          severity: "medium",
          cvss: 5.0,
          note: "While primarily DoS, demonstrates Django security issue handling"
        },
        %{
          id: "CVE-2012-4520",
          description: "Django 1.3.x and 1.4.x host header poisoning",
          severity: "medium",
          cvss: 4.3,
          note: "Could be combined with clickjacking for more severe attacks"
        },
        %{
          id: "Twitter Worm 2010",
          description: "Clickjacking worm spread via Twitter's tweet button",
          severity: "high",
          cvss: 7.5,
          note: "Real-world clickjacking attack that affected thousands"
        },
        %{
          id: "Facebook Likejacking",
          description: "Multiple clickjacking attacks on Facebook Like button",
          severity: "medium",
          cvss: 6.5,
          note: "Widespread attacks tricking users into liking malicious pages"
        }
      ],
      detection_notes: """
      This pattern detects clickjacking vulnerabilities by identifying:

      1. X_FRAME_OPTIONS = 'ALLOWALL' which completely disables protection
      2. @xframe_options_exempt decorator that removes protection from views
      3. @xframe_options_sameorigin which still allows same-origin attacks

      The pattern focuses on explicit misconfigurations rather than missing
      settings, as absence of X_FRAME_OPTIONS defaults to SAMEORIGIN in
      modern Django versions when XFrameOptionsMiddleware is active.

      Note that this pattern doesn't detect:
      - Missing XFrameOptionsMiddleware (requires settings file analysis)
      - Content-Security-Policy frame-ancestors (alternative protection)
      - Complex conditional logic that might bypass protection
      """,
      safe_alternatives: [
        """
        # Recommended: Deny all framing by default
        X_FRAME_OPTIONS = 'DENY'

        # Ensure middleware is active
        MIDDLEWARE = [
            'django.middleware.security.SecurityMiddleware',
            'django.contrib.sessions.middleware.SessionMiddleware',
            'django.middleware.clickjacking.XFrameOptionsMiddleware',
            # ... other middleware
        ]
        """,
        """
        # For views that must be embedded, use specific decorators
        from django.views.decorators.clickjacking import xframe_options_deny
        from django.views.decorators.clickjacking import xframe_options_sameorigin

        @xframe_options_deny
        def highly_sensitive_view(request):
            # This view cannot be framed at all
            return render(request, 'sensitive.html')

        # Only use for views that MUST be embedded
        @xframe_options_sameorigin
        def embeddable_widget(request):
            # Can only be embedded on same origin
            return render(request, 'widget.html')
        """,
        """
        # Modern approach: Content-Security-Policy
        # In middleware or view
        response['Content-Security-Policy'] = "frame-ancestors 'none';"

        # Or for same-origin only
        response['Content-Security-Policy'] = "frame-ancestors 'self';"

        # Or for specific trusted domains
        response['Content-Security-Policy'] = "frame-ancestors 'self' https://trusted.example.com;"
        """,
        """
        # Use Django Security Middleware for comprehensive protection
        SECURE_BROWSER_XSS_FILTER = True
        SECURE_CONTENT_TYPE_NOSNIFF = True
        X_FRAME_OPTIONS = 'DENY'

        # For HTTPS sites
        SECURE_SSL_REDIRECT = True
        SECURE_HSTS_SECONDS = 31536000
        SECURE_HSTS_INCLUDE_SUBDOMAINS = True
        SECURE_HSTS_PRELOAD = True
        """,
        """
        # Custom middleware for dynamic frame control
        class DynamicFrameOptionsMiddleware:
            def __init__(self, get_response):
                self.get_response = get_response

            def __call__(self, request):
                response = self.get_response(request)

                # Allow framing only for specific paths
                if request.path.startswith('/embed/'):
                    response['X-Frame-Options'] = 'SAMEORIGIN'
                else:
                    response['X-Frame-Options'] = 'DENY'

                return response
        """
      ],
      additional_context: %{
        common_mistakes: [
          "Using ALLOWALL for development and forgetting to change for production",
          "Exempting views without understanding security implications",
          "Assuming SAMEORIGIN is always safe",
          "Not considering subdomain takeover risks with SAMEORIGIN",
          "Removing protection for OAuth callback URLs",
          "Not testing clickjacking protection in different browsers",
          "Ignoring Content-Security-Policy as additional layer",
          "Exempting API endpoints unnecessarily"
        ],
        secure_patterns: [
          """
          # Comprehensive clickjacking protection
          from django.views.decorators.clickjacking import xframe_options_deny
          from django.utils.decorators import method_decorator

          # Function-based view protection
          @xframe_options_deny
          def transfer_funds(request):
              # Critical action protected from framing
              if request.method == 'POST':
                  # Process transfer
                  pass
              return render(request, 'transfer.html')

          # Class-based view protection
          @method_decorator(xframe_options_deny, name='dispatch')
          class DeleteAccountView(View):
              def post(self, request):
                  # Sensitive action protected
                  request.user.delete()
                  return redirect('goodbye')
          """,
          """
          # Selective framing for widgets
          from django.views.decorators.clickjacking import xframe_options_exempt
          from django.contrib.auth.decorators import login_required

          # Public widget that needs embedding
          @xframe_options_exempt
          def public_widget(request):
              # Only non-sensitive, read-only content
              return render(request, 'widget.html', {
                  'data': PublicData.objects.all()
              })

          # Never exempt authenticated views
          @login_required
          # @xframe_options_exempt  # DON'T DO THIS!
          def user_dashboard(request):
              return render(request, 'dashboard.html')
          """,
          """
          # Advanced CSP with frame-ancestors
          class ContentSecurityPolicyMiddleware:
              def __init__(self, get_response):
                  self.get_response = get_response

              def __call__(self, request):
                  response = self.get_response(request)

                  # Build CSP based on view requirements
                  if hasattr(request, 'csp_frame_ancestors'):
                      ancestors = request.csp_frame_ancestors
                  else:
                      ancestors = "'none'"

                  csp = f"frame-ancestors {ancestors}; "
                  csp += "default-src 'self'; "

                  response['Content-Security-Policy'] = csp
                  return response
          """
        ],
        framework_specific_notes: [
          "Django defaults to SAMEORIGIN if X_FRAME_OPTIONS is not set",
          "XFrameOptionsMiddleware must be in MIDDLEWARE list to work",
          "X-Frame-Options is being replaced by CSP frame-ancestors",
          "Django admin is protected by default with X-Frame-Options",
          "Some browsers ignore X-Frame-Options for PDF responses",
          "ALLOWALL was added for legacy compatibility - avoid using",
          "Django 3.0+ supports SameSite cookie attribute for additional protection",
          "Test with browser developer tools to verify headers are set"
        ]
      }
    }
  end

  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.5,
      context_rules: %{
        settings_names: [
          "X_FRAME_OPTIONS",
          "SECURE_BROWSER_XSS_FILTER",
          "SECURE_CONTENT_TYPE_NOSNIFF"
        ],
        decorators: [
          "@xframe_options_exempt",
          "@xframe_options_deny",
          "@xframe_options_sameorigin"
        ],
        middleware_names: [
          "XFrameOptionsMiddleware",
          "SecurityMiddleware"
        ],
        safe_values: [
          "DENY",
          "SAMEORIGIN"
        ],
        unsafe_values: [
          "ALLOWALL",
          "ALLOW-FROM"
        ],
        csp_directives: [
          "frame-ancestors",
          "Content-Security-Policy"
        ]
      },
      confidence_rules: %{
        adjustments: %{
          # High confidence patterns
          allowall_setting: +0.95,
          exempt_decorator: +0.9,
          sameorigin_on_sensitive: +0.7,

          # Medium confidence
          missing_in_settings: +0.5,
          allow_from_usage: +0.8,

          # Lower confidence
          in_test_file: -0.95,
          in_example_code: -0.9,
          widget_or_embed_path: -0.7,
          public_api_endpoint: -0.6,

          # Mitigating factors
          has_csp_header: -0.8,
          frame_ancestors_none: -0.85,
          deny_in_production: -0.9,
          documented_requirement: -0.4
        }
      },
      ast_rules: %{
        clickjacking_analysis: %{
          check_settings: true,
          detect_decorators: true,
          check_middleware: true,
          analyze_csp: true,
          check_view_sensitivity: true,
          detect_iframe_usage: true
        },
        settings_analysis: %{
          check_x_frame_options: true,
          validate_middleware_order: true,
          check_security_headers: true,
          detect_environment_config: true
        },
        view_analysis: %{
          identify_sensitive_actions: true,
          check_authentication_required: true,
          detect_state_changing_ops: true,
          analyze_decorator_stack: true
        },
        csp_analysis: %{
          check_frame_ancestors: true,
          validate_csp_syntax: true,
          detect_header_setting: true,
          check_report_uri: true
        }
      }
    }
  end
end
