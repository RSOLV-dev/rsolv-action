defmodule Rsolv.Security.Patterns.Django.BrokenAuth do
  @moduledoc """
  Django Broken Authentication pattern for Django applications.

  This pattern detects weak or missing authentication checks in Django views
  that could allow unauthorized access to sensitive functionality.

  ## Background

  Broken authentication is a critical security vulnerability that occurs when:
  - Views handling sensitive data lack authentication requirements
  - Authentication mechanisms are improperly implemented
  - Session management is flawed
  - Credentials are exposed or weakly protected

  ## Vulnerability Details

  Django provides robust authentication mechanisms through:
  - Function-based views: @login_required decorator
  - Class-based views: LoginRequiredMixin
  - Permission checks: @permission_required, PermissionRequiredMixin
  - Custom authentication backends

  Missing these protections exposes applications to unauthorized access.

  ## Examples

      # VULNERABLE - No authentication required
      def admin_dashboard(request):
          users = User.objects.all()
          return render(request, 'admin/dashboard.html', {'users': users})

      # VULNERABLE - Authentication data from GET parameters
      user = authenticate(username=request.GET['username'])

      # SAFE - Protected with @login_required
      @login_required
      def admin_dashboard(request):
          users = User.objects.all()
          return render(request, 'admin/dashboard.html', {'users': users})

      # SAFE - Class-based view with LoginRequiredMixin
      class AdminDashboard(LoginRequiredMixin, View):
          def get(self, request):
              users = User.objects.all()
              return render(request, 'admin/dashboard.html', {'users': users})
  """

  use Rsolv.Security.Patterns.PatternBase

  @impl true
  def pattern do
    %Rsolv.Security.Pattern{
      id: "django-broken-auth",
      name: "Django Broken Authentication",
      description: "Weak or missing authentication checks in Django views",
      type: :authentication,
      severity: :high,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        # Function-based views without authentication decorators
        ~r/def\s+\w+\s*\(\s*request.*?\)(?!.*@login_required)(?!.*@staff_member_required)(?!.*@permission_required)/,

        # Class-based views without authentication mixins
        ~r/class\s+\w+\s*\(.*View.*\)(?!.*LoginRequiredMixin)(?!.*PermissionRequiredMixin)/,

        # Authentication with GET parameters (insecure)
        ~r/authenticate\s*\(\s*username\s*=\s*request\.GET/,
        ~r/authenticate\s*\(\s*password\s*=\s*request\.GET/,

        # User creation directly from request data
        ~r/User\.objects\.create_user\s*\(\s*request\./,

        # Password check with request data
        ~r/check_password\s*\(\s*request\./,

        # Direct session manipulation
        ~r/request\.session\[['"]user_id['"]\]\s*=\s*request\./,

        # Missing authentication in sensitive operations
        ~r/User\.objects\.filter\s*\(\s*\)\.delete\s*\(\s*\)(?!.*@login_required)/
      ],
      cwe_id: "CWE-287",
      owasp_category: "A07:2021",
      recommendation:
        "Use @login_required decorator or LoginRequiredMixin for views requiring authentication",
      test_cases: %{
        vulnerable: [
          """
          def admin_view(request):
              # No authentication check
              return render(request, 'admin.html')
          """,
          "user = authenticate(username=request.GET['user'], password=request.GET['pass'])",
          "User.objects.create_user(request.POST['username'], request.POST['email'])"
        ],
        safe: [
          """
          @login_required
          def admin_view(request):
              return render(request, 'admin.html')
          """,
          """
          class AdminView(LoginRequiredMixin, View):
              pass
          """
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Broken authentication vulnerabilities in Django applications occur when
      authentication mechanisms are missing, misconfigured, or improperly implemented.
      This can lead to unauthorized access to sensitive data and functionality.

      Common broken authentication patterns in Django include:

      1. **Missing Authentication Decorators**: Views that handle sensitive data
         without @login_required or similar protections

      2. **Insecure Credential Handling**: Using GET parameters for authentication,
         storing passwords in plain text, or weak session management

      3. **Improper Authentication Logic**: Custom authentication that bypasses
         Django's built-in security features

      4. **Session Fixation**: Not regenerating session IDs after login

      5. **Weak Password Policies**: Not enforcing strong passwords or allowing
         common/default credentials

      Django provides comprehensive authentication features that should be used
      instead of custom implementations. The framework handles password hashing,
      session management, CSRF protection, and more when used correctly.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-287",
          title: "Improper Authentication",
          url: "https://cwe.mitre.org/data/definitions/287.html"
        },
        %{
          type: :cwe,
          id: "CWE-306",
          title: "Missing Authentication for Critical Function",
          url: "https://cwe.mitre.org/data/definitions/306.html"
        },
        %{
          type: :cwe,
          id: "CWE-384",
          title: "Session Fixation",
          url: "https://cwe.mitre.org/data/definitions/384.html"
        },
        %{
          type: :owasp,
          id: "A07:2021",
          title: "Identification and Authentication Failures",
          url: "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
        }
      ],
      attack_vectors: [
        "Direct URL access to unprotected admin panels",
        "Session hijacking through exposed session IDs",
        "Brute force attacks on weak authentication",
        "Credential stuffing using leaked passwords",
        "Authentication bypass via parameter manipulation",
        "Privilege escalation through missing permission checks",
        "Account enumeration through timing attacks",
        "Session fixation attacks"
      ],
      real_world_impact: [
        "Unauthorized access to sensitive user data",
        "Account takeover leading to identity theft",
        "Data breaches exposing personal information",
        "Administrative access compromise",
        "Financial fraud through account access",
        "Reputation damage from security incidents",
        "Regulatory compliance violations (GDPR, HIPAA)",
        "Business logic manipulation"
      ],
      cve_examples: [
        %{
          id: "CVE-2014-0482",
          description: "Django RemoteUserMiddleware session hijacking vulnerability",
          severity: "high",
          cvss: 7.5,
          note: "Allowed authenticated users to hijack sessions via REMOTE_USER header"
        },
        %{
          id: "CVE-2013-1443",
          description: "Django authentication framework DoS via long passwords",
          severity: "medium",
          cvss: 5.0,
          note: "CPU exhaustion through extremely long password hashing"
        },
        %{
          id: "CVE-2022-24857",
          description: "django-mfa3 authentication bypass via admin login",
          severity: "high",
          cvss: 7.3,
          note: "Multi-factor authentication could be bypassed through admin interface"
        },
        %{
          id: "CVE-2024-21543",
          description: "djoser authentication bypass when authenticate() fails",
          severity: "high",
          cvss: 7.5,
          note: "Fallback to direct database query bypassed custom auth checks like 2FA"
        }
      ],
      detection_notes: """
      This pattern detects broken authentication by identifying:

      1. Function-based views without authentication decorators
      2. Authentication attempts using GET parameters (security risk)
      3. Direct user creation from request data without validation
      4. Password checks using request data directly
      5. Manual session manipulation that bypasses Django's auth
      6. Sensitive operations without authentication requirements

      Note that regex-based detection has limitations for class-based views
      and may produce false positives for public views. AST enhancement
      rules help reduce these false positives.
      """,
      safe_alternatives: [
        """
        # Function-based view with authentication
        @login_required
        def user_profile(request):
            return render(request, 'profile.html')
        """,
        """
        # Class-based view with authentication mixin
        from django.contrib.auth.mixins import LoginRequiredMixin

        class UserProfileView(LoginRequiredMixin, View):
            def get(self, request):
                return render(request, 'profile.html')
        """,
        """
        # Proper authentication with POST data
        from django.contrib.auth import authenticate, login

        def login_view(request):
            if request.method == 'POST':
                username = request.POST.get('username')
                password = request.POST.get('password')
                user = authenticate(request, username=username, password=password)
                if user is not None:
                    login(request, user)
                    return redirect('home')
        """,
        """
        # Permission-based access control
        @permission_required('app.change_model')
        def edit_view(request):
            # Only users with specific permission can access
            pass
        """,
        """
        # Staff member required
        @staff_member_required
        def admin_view(request):
            # Only staff members can access
            pass
        """
      ],
      additional_context: %{
        common_mistakes: [
          "Forgetting decorators on sensitive views",
          "Using GET parameters for authentication data",
          "Implementing custom authentication instead of using Django's",
          "Not regenerating session IDs after login",
          "Storing passwords in plain text or weak hashes",
          "Missing permission checks on object-level access",
          "Not using HTTPS for authentication pages",
          "Weak or default passwords in production"
        ],
        secure_patterns: [
          """
          # Comprehensive authentication setup
          from django.contrib.auth.decorators import login_required
          from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin

          # Function-based view
          @login_required
          @require_http_methods(["GET", "POST"])
          def secure_view(request):
              # Additional permission check
              if not request.user.has_perm('app.view_data'):
                  raise PermissionDenied
              return render(request, 'secure.html')
          """,
          """
          # Session security settings
          SESSION_COOKIE_SECURE = True
          SESSION_COOKIE_HTTPONLY = True
          SESSION_COOKIE_SAMESITE = 'Strict'
          SESSION_EXPIRE_AT_BROWSER_CLOSE = True
          """,
          """
          # Password validation
          AUTH_PASSWORD_VALIDATORS = [
              {
                  'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
              },
              {
                  'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
                  'OPTIONS': {
                      'min_length': 12,
                  }
              },
              {
                  'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
              },
              {
                  'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
              },
          ]
          """
        ],
        framework_specific_notes: [
          "Django's @login_required redirects to LOGIN_URL when not authenticated",
          "LoginRequiredMixin should be the leftmost mixin in class inheritance",
          "Use @staff_member_required for admin-only views",
          "Django automatically handles password hashing with PBKDF2",
          "Session cookies should be configured securely in production",
          "Consider django-axes for brute force protection",
          "Use django-two-factor for 2FA implementation",
          "Django 3.1+ includes built-in password reset rate limiting"
        ]
      }
    }
  end

  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.7,
      context_rules: %{
        auth_decorators: [
          "@login_required",
          "@staff_member_required",
          "@permission_required",
          "@user_passes_test",
          "@require_http_methods",
          "@require_POST",
          "@require_GET"
        ],
        auth_mixins: [
          "LoginRequiredMixin",
          "PermissionRequiredMixin",
          "UserPassesTestMixin",
          "AccessMixin",
          "StaffuserRequiredMixin",
          "SuperuserRequiredMixin"
        ],
        sensitive_views: [
          "admin",
          "profile",
          "settings",
          "account",
          "dashboard",
          "user",
          "staff",
          "manage",
          "edit",
          "delete",
          "update",
          "create"
        ],
        public_views: [
          "home",
          "index",
          "about",
          "contact",
          "login",
          "register",
          "signup",
          "public",
          "landing"
        ],
        auth_functions: [
          "authenticate",
          "login",
          "logout",
          "check_password",
          "set_password",
          "create_user",
          "create_superuser"
        ]
      },
      confidence_rules: %{
        adjustments: %{
          # High confidence patterns
          admin_view_no_auth: +0.95,
          sensitive_operation_no_auth: +0.9,
          get_auth_params: +0.95,
          direct_session_manipulation: +0.85,

          # Medium confidence
          user_view_no_auth: +0.6,
          generic_view_no_auth: +0.4,

          # Lower confidence
          public_view_no_auth: -0.8,
          has_custom_auth_check: -0.5,
          in_test_file: -0.9,
          in_migration_file: -0.95,

          # Context adjustments
          has_auth_decorator: -0.9,
          has_auth_mixin: -0.9,
          in_auth_backend: -0.7,
          is_api_view: -0.3
        }
      },
      ast_rules: %{
        view_analysis: %{
          detect_class_based_views: true,
          detect_function_based_views: true,
          check_decorators: true,
          check_mixins: true,
          analyze_view_name: true,
          check_method_calls: true
        },
        auth_analysis: %{
          detect_auth_checks: true,
          check_permission_calls: true,
          analyze_session_usage: true,
          detect_custom_auth: true
        },
        context_analysis: %{
          check_file_path: true,
          analyze_imports: true,
          detect_test_code: true,
          check_view_purpose: true
        },
        security_analysis: %{
          check_get_params: true,
          detect_password_handling: true,
          analyze_user_creation: true,
          check_session_security: true
        }
      }
    }
  end
end
