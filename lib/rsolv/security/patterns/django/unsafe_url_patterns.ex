defmodule Rsolv.Security.Patterns.Django.UnsafeUrlPatterns do
  @moduledoc """
  Django Unsafe URL Patterns pattern for Django applications.

  This pattern detects URL routing configurations that may expose sensitive
  endpoints or create security vulnerabilities. Common issues include exposing
  the Django admin panel on default URLs, using overly broad wildcard patterns,
  and including debug tools in production.

  ## Background

  Django's URL routing system is powerful but can introduce security risks when
  misconfigured. Common vulnerabilities include:

  - Exposing admin interface on predictable URLs
  - Using catch-all wildcard patterns that bypass security
  - Including debug tools without proper environment checks
  - Overly permissive URL patterns that expose internal endpoints

  ## Vulnerability Details

  Unsafe URL patterns typically manifest as:

  1. **Default Admin URLs**: Using 'admin/' exposes the admin interface to
     automated scanning and brute force attacks

  2. **Wildcard Patterns**: Patterns like '.*' can bypass other security
     measures and expose unintended functionality

  3. **Debug Tool Exposure**: Including django-debug-toolbar or similar
     tools without proper DEBUG checks exposes sensitive information

  4. **Overly Broad Includes**: Including entire URL namespaces without
     proper access controls

  ## Examples

      # VULNERABLE - Default admin URL
      urlpatterns = [
          path('admin/', admin.site.urls),
          path('', views.home),
      ]

      # VULNERABLE - Wildcard catch-all
      urlpatterns = [
          path('api/', include('api.urls')),
          path('.*', views.catch_all),  # Dangerous!
      ]

      # VULNERABLE - Debug toolbar in production
      urlpatterns = [
          path('', include('myapp.urls')),
          path('__debug__/', include('debug_toolbar.urls')),
      ]

      # SAFE - Obscured admin URL
      urlpatterns = [
          path('secure-admin-portal/', admin.site.urls),
          path('', views.home),
      ]

      # SAFE - Conditional debug inclusion
      if settings.DEBUG:
          urlpatterns += [
              path('__debug__/', include('debug_toolbar.urls')),
          ]
  """

  use Rsolv.Security.Patterns.PatternBase

  @impl true
  def pattern do
    %Rsolv.Security.Pattern{
      id: "django-unsafe-url-patterns",
      name: "Django Unsafe URL Patterns",
      description: "URL patterns that may expose sensitive endpoints",
      type: :misconfiguration,
      severity: :medium,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        # Default admin URL patterns (most common vulnerability)
        ~r/path\s*\(\s*['"']admin['"'],\s*admin\.site\.urls\s*\)/,
        ~r/path\s*\(\s*['"']admin\/['"'],\s*admin\.site\.urls\s*\)/,

        # Dangerous wildcard patterns
        ~r/path\s*\(\s*['"'].*\.\*['"'],/,
        ~r/re_path\s*\(\s*r['"']\^\.?\*['"'],/,

        # Debug toolbar exposure without DEBUG check
        ~r/include\s*\(\s*['"']debug_toolbar\.urls['"']\)/,
        ~r/include\s*\(\s*['"']silk\.urls['"']\)/,
        ~r/include\s*\(\s*['"']django_extensions\.urls['"']\)/,

        # Other dangerous debug/profiler tools
        ~r/include\s*\(\s*['"']rosetta\.urls['"']\)/,
        ~r/include\s*\(\s*['"']hijack\.urls['"']\)/
      ],
      cwe_id: "CWE-284",
      owasp_category: "A01:2021",
      recommendation:
        "Use specific URL patterns. Change default admin URL. Remove debug tools in production.",
      test_cases: %{
        vulnerable: [
          ~s|path('admin/', admin.site.urls)|,
          ~s|path('admin', admin.site.urls)|,
          ~s|path('.*', catch_all_view)|,
          ~s|path('', include('debug_toolbar.urls'))|
        ],
        safe: [
          ~s|path('secure-admin-url/', admin.site.urls)|,
          ~s|path('api/<str:endpoint>/', api_view)|,
          ~s|if settings.DEBUG:
    urlpatterns += [path('__debug__/', include('debug_toolbar.urls'))]|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Unsafe URL patterns in Django applications can expose sensitive endpoints,
      administrative interfaces, and debug information to unauthorized users.
      This vulnerability class encompasses several related security misconfigurations
      in Django's URL routing system.

      The most common issue is exposing the Django admin interface on predictable
      URLs like '/admin/' or '/admin'. This makes the admin panel discoverable
      by automated scanners and vulnerable to brute force attacks. The Django
      admin interface is a powerful tool that can provide complete access to
      application data and functionality.

      Another significant risk comes from overly broad URL patterns, particularly
      wildcard patterns like '.*' that can match any request. These patterns can
      bypass other security measures and expose unintended functionality, potentially
      allowing access to internal endpoints or debug information.

      Debug tools and profilers represent another major vulnerability when included
      in production deployments. Tools like django-debug-toolbar, django-silk,
      or django-rosetta can expose sensitive information including database queries,
      environment variables, application settings, and user session data.

      The impact of these vulnerabilities varies but commonly includes:
      - Administrative interface compromise leading to full application takeover
      - Information disclosure through debug interfaces
      - Bypass of intended access controls through wildcard patterns
      - Exposure of sensitive configuration and environment data
      - Database query inspection revealing application logic and data structure
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-284",
          title: "Improper Access Control",
          url: "https://cwe.mitre.org/data/definitions/284.html"
        },
        %{
          type: :owasp,
          id: "A01:2021",
          title: "Broken Access Control",
          url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
        },
        %{
          type: :owasp,
          id: "Django Security",
          title: "OWASP Django Security Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/Django_Security_Cheat_Sheet.html"
        },
        %{
          type: :django,
          id: "URL Dispatcher",
          title: "Django URL Dispatcher Documentation",
          url: "https://docs.djangoproject.com/en/stable/topics/http/urls/"
        },
        %{
          type: :django,
          id: "Admin Security",
          title: "Django Admin Site Security",
          url: "https://docs.djangoproject.com/en/stable/ref/contrib/admin/#admin-reverse-urls"
        },
        %{
          type: :security,
          id: "Debug Toolbar CVE",
          title: "Django Debug Toolbar Security Advisory",
          url: "https://github.com/jazzband/django-debug-toolbar/security/advisories"
        }
      ],
      attack_vectors: [
        "Admin panel brute force attacks on default URLs",
        "Automated scanning for exposed admin interfaces",
        "Information disclosure through debug toolbar access",
        "SQL injection via debug toolbar SQL panel",
        "Session hijacking through exposed debug information",
        "Environment variable extraction from debug interfaces",
        "Database schema reconnaissance via debug tools",
        "Wildcard pattern bypass of intended access controls",
        "CSRF attacks against exposed admin endpoints",
        "Credential stuffing attacks on discovered admin panels"
      ],
      real_world_impact: [
        "Complete admin panel compromise leading to data breach",
        "Exposure of sensitive information including customer and business data",
        "Database credential exposure through debug interfaces",
        "Application configuration and secret key disclosure",
        "User session data and authentication token exposure",
        "Business logic revelation through debug tool inspection",
        "Compliance violations due to data exposure",
        "Reputation damage from security incidents",
        "Financial losses from data breach remediation",
        "Legal liability from privacy regulation violations"
      ],
      cve_examples: [
        %{
          id: "CVE-2021-30459",
          description: "SQL injection vulnerability in Django Debug Toolbar SQL panel",
          severity: "high",
          cvss: 8.8,
          note: "Affects django-debug-toolbar before 1.11.1, 2.2.1, and 3.2.1"
        },
        %{
          id: "GHSA-pghf-347x-c2gj",
          description: "Django Debug Toolbar SQL injection via raw_sql input",
          severity: "high",
          cvss: 8.6,
          note: "Critical issue for production deployments with debug toolbar enabled"
        },
        %{
          id: "CVE-2019-14232",
          description: "Django admin interface denial of service via crafted requests",
          severity: "medium",
          cvss: 5.3,
          note: "Shows risks of exposing admin interface to untrusted users"
        },
        %{
          id: "Mozilla HackerOne Report",
          description: "Exposed Django Debug Panel in development environment",
          severity: "high",
          cvss: 7.5,
          note: "Real-world example of debug tool exposure in production-like environment"
        }
      ],
      detection_notes: """
      This pattern detects unsafe URL configurations by identifying:

      1. **Default Admin URLs**: Patterns matching 'admin/' or 'admin' that expose
         the Django admin interface on predictable URLs

      2. **Wildcard Patterns**: URL patterns using '.*' or similar catch-all
         patterns that can bypass security controls

      3. **Debug Tool Inclusion**: Detection of debug_toolbar, silk, django_extensions,
         and other development tools being included without proper DEBUG checks

      4. **Dangerous Includes**: Detection of potentially sensitive URL includes
         like hijack (user impersonation) or rosetta (translation interface)

      The pattern may produce false positives in development environments where
      these configurations are intentional. However, it's important to ensure
      these patterns don't make it to production deployments.

      Note that this pattern focuses on static URL configuration and may not
      detect dynamically generated URLs or complex conditional logic.
      """,
      safe_alternatives: [
        """
        # Secure admin URL configuration
        # Use unpredictable admin URLs
        urlpatterns = [
            # Use a random, hard-to-guess URL for admin
            path('secure-admin-portal-xyz123/', admin.site.urls),
            path('management-interface/', admin.site.urls),
            path('backend-dashboard/', admin.site.urls),
        ]

        # Additional admin security
        ADMIN_URL = os.environ.get('DJANGO_ADMIN_URL', 'admin/')
        urlpatterns = [
            path(ADMIN_URL, admin.site.urls),
        ]
        """,
        """
        # Conditional debug tool inclusion
        # Only include debug tools when DEBUG check is True
        urlpatterns = [
            path('', include('myapp.urls')),
            path('api/', include('api.urls')),
        ]

        if settings.DEBUG:
            # Only add debug URLs in development
            urlpatterns += [
                path('__debug__/', include('debug_toolbar.urls')),
                path('silk/', include('silk.urls')),
            ]
        """,
        """
        # Specific URL patterns instead of wildcards
        # Avoid catch-all patterns that bypass security
        urlpatterns = [
            path('', views.home, name='home'),
            path('about/', views.about, name='about'),
            path('contact/', views.contact, name='contact'),
            path('api/v1/', include('api.v1.urls')),
            path('api/v2/', include('api.v2.urls')),
            # Specific patterns for each endpoint
            path('reports/<int:report_id>/', views.report_detail),
            # Use 404 for unmatched URLs instead of catch-all
        ]
        """,
        """
        # Environment-based URL configuration
        # Different URL patterns for different environments
        urlpatterns = [
            path('', include('myapp.urls')),
        ]

        # Production admin URL from environment variable
        if not settings.DEBUG:
            admin_url = os.environ.get('ADMIN_URL')
            if admin_url:
                urlpatterns.append(path(f'{admin_url}/', admin.site.urls))
        else:
            # Development admin URL
            urlpatterns.append(path('admin/', admin.site.urls))
            # Debug tools only in development
            urlpatterns += [
                path('__debug__/', include('debug_toolbar.urls')),
            ]
        """,
        """
        # IP-restricted admin access
        # Additional security through middleware or web server config

        # Example nginx configuration for admin URL restriction:
        # location /secure-admin/ {
        #     allow 192.168.1.0/24;  # Office network
        #     allow 10.0.0.0/8;      # VPN network
        #     deny all;
        #     proxy_pass http://django_backend;
        # }

        # Or use Django middleware for IP restriction
        class AdminIPRestrictionMiddleware:
            def __init__(self, get_response):
                self.get_response = get_response

            def __call__(self, request):
                if request.path.startswith('/secure-admin/'):
                    client_ip = self.get_client_ip(request)
                    if not self.is_allowed_ip(client_ip):
                        return HttpResponseForbidden()
                return self.get_response(request)
        """
      ],
      additional_context: %{
        common_mistakes: [
          "Using default admin URL '/admin/' in production",
          "Including debug toolbar without DEBUG environment check",
          "Using wildcard patterns for convenience without considering security",
          "Forgetting to remove development URLs from production configuration",
          "Not changing default admin URLs during deployment",
          "Including user impersonation tools (hijack) in production",
          "Exposing translation interfaces (rosetta) to all users",
          "Using catch-all patterns instead of specific 404 handling"
        ],
        secure_patterns: [
          """
          # Environment-aware URL configuration
          import os
          from django.conf import settings
          from django.urls import path, include

          urlpatterns = [
              path('', include('myapp.urls')),
              path('api/', include('api.urls')),
          ]

          # Security-conscious admin URL
          admin_path = os.environ.get('DJANGO_ADMIN_PATH', 'admin/')
          if not admin_path.endswith('/'):
              admin_path += '/'
          urlpatterns.append(path(admin_path, admin.site.urls))

          # Development-only URLs
          if settings.DEBUG:
              try:
                  import debug_toolbar
                  urlpatterns.append(path('__debug__/', include('debug_toolbar.urls')))
              except ImportError:
                  pass
          """,
          """
          # Secure admin configuration with additional protections
          from django.contrib import admin
          from django.conf import settings

          # Custom admin site with security enhancements
          class SecureAdminSite(admin.AdminSite):
              site_header = 'Secure Administration'
              site_title = 'Admin'

              def has_permission(self, request):
                  # Additional permission checks
                  if not super().has_permission(request):
                      return False

                  # Check IP whitelist
                  if hasattr(settings, 'ADMIN_IP_WHITELIST'):
                      client_ip = self.get_client_ip(request)
                      if client_ip not in settings.ADMIN_IP_WHITELIST:
                          return False

                  return True

          secure_admin_site = SecureAdminSite(name='secure_admin')
          """,
          """
          # URL pattern validation middleware
          from django.core.exceptions import DisallowedHost
          from django.http import HttpResponseNotFound

          class URLSecurityMiddleware:
              def __init__(self, get_response):
                  self.get_response = get_response
                  self.dangerous_patterns = [
                      '/admin/',  # Block default admin URL
                      '/__debug__/',  # Block debug toolbar
                      '/silk/',  # Block silk profiler
                  ]

              def __call__(self, request):
                  # Block dangerous URLs in production
                  if not settings.DEBUG:
                      for pattern in self.dangerous_patterns:
                          if request.path.startswith(pattern):
                              return HttpResponseNotFound()

                  return self.get_response(request)
          """
        ],
        framework_specific_notes: [
          "Django admin URLs are case-sensitive and exact-match by default",
          "URL patterns are processed in order - place specific patterns before general ones",
          "re_path allows regex patterns but path is safer for most use cases",
          "include() can expose entire URL namespaces - use carefully",
          "Django's URL dispatcher doesn't automatically add trailing slashes",
          "APPEND_SLASH setting affects how Django handles missing trailing slashes",
          "URL patterns in included modules are resolved relative to the include point",
          "Debug toolbar automatically adds middleware when DEBUG=True"
        ]
      }
    }
  end

  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.6,
      context_rules: %{
        url_functions: [
          "path",
          "re_path",
          "include",
          # Legacy Django versions
          "url"
        ],
        dangerous_patterns: [
          "admin",
          "debug_toolbar",
          "silk",
          "rosetta",
          "hijack",
          "django_extensions"
        ],
        wildcard_indicators: [
          ".*",
          "^.*",
          ".*$",
          ".+",
          "*"
        ],
        safe_patterns: [
          "if settings.DEBUG",
          "if DEBUG",
          "settings.DEBUG:",
          "DEBUG:",
          "development",
          "dev"
        ],
        admin_variations: [
          "admin/",
          "admin",
          "administrator",
          "backend",
          "management"
        ]
      },
      confidence_rules: %{
        adjustments: %{
          # High confidence patterns
          default_admin_url: +0.9,
          wildcard_patterns: +0.8,
          debug_toolbar_without_check: +0.85,
          multiple_dangerous_patterns: +0.9,

          # Medium confidence
          admin_variations: +0.7,
          debug_tools: +0.75,
          catch_all_patterns: +0.7,

          # Lower confidence in safe contexts
          in_development_settings: -0.8,
          conditional_inclusion: -0.9,
          in_test_file: -0.95,
          in_local_settings: -0.8,

          # Context-based adjustments
          has_debug_check: -0.85,
          environment_variable_based: -0.6,
          ip_restricted: -0.7,
          custom_admin_class: -0.5
        }
      },
      ast_rules: %{
        url_analysis: %{
          detect_admin_patterns: true,
          check_wildcard_usage: true,
          analyze_debug_includes: true,
          check_url_ordering: true,
          detect_catch_all_patterns: true
        },
        conditional_analysis: %{
          check_debug_conditions: true,
          analyze_environment_checks: true,
          detect_settings_usage: true,
          check_import_conditions: true
        },
        security_analysis: %{
          check_ip_restrictions: true,
          analyze_middleware_usage: true,
          detect_custom_admin: true,
          check_environment_variables: true
        },
        pattern_analysis: %{
          detect_regex_patterns: true,
          check_pattern_specificity: true,
          analyze_include_scope: true,
          detect_namespace_exposure: true
        }
      }
    }
  end
end
