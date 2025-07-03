defmodule Rsolv.Security.Patterns.Django.Cve202133203 do
  @moduledoc """
  Django CVE-2021-33203 pattern for directory traversal via admindocs.
  
  This pattern detects a specific vulnerability in Django's contrib.admindocs module
  where the TemplateDetailView allows directory traversal attacks, enabling staff
  members to check the existence of arbitrary files outside template root directories.
  
  ## Background
  
  CVE-2021-33203 is a directory traversal vulnerability discovered in Django versions
  before 2.2.24, 3.x before 3.1.12, and 3.2.x before 3.2.4. The vulnerability exists
  in the django.contrib.admindocs module, specifically in the TemplateDetailView view.
  
  ## Vulnerability Details
  
  The vulnerability stems from unsafe path join operations in the admindocs module.
  An authenticated staff member can manipulate the template parameter in URLs to
  check for the existence of arbitrary files on the filesystem, including sensitive
  system files like /etc/passwd.
  
  ## Attack Example
  
      # Vulnerable URL pattern
      path('admin/doc/', include('django.contrib.admindocs.urls'))
      
      # Malicious request
      GET /admin/doc/templates//etc/passwd/
      
      # This allows checking for file existence outside template directories
  
  ## Safe Implementation
  
      # Django 3.2.4+ includes proper path validation
      from django.utils._os import safe_join
      template_path = safe_join(template_dir, template_name)
      
      # Or disable admindocs if not needed
      # Remove 'django.contrib.admindocs' from INSTALLED_APPS
  """
  
  use Rsolv.Security.Patterns.PatternBase
  
  @impl true
  def pattern do
    %Rsolv.Security.Pattern{
      id: "django-cve-2021-33203",
      name: "Django CVE-2021-33203 - Directory Traversal via admindocs",
      description: "Directory traversal via django.contrib.admindocs TemplateDetailView",
      type: :path_traversal,
      severity: :medium,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        # Django admindocs URL inclusion (includes literal dots for the test)
        ~r/path\s*\(\s*['"]admin\/doc\/['"],\s*include\s*\(\s*['"]django\.contrib\.admindocs\.urls['"]\)/,
        ~r/django\.contrib\.admindocs/,
        
        # TemplateDetailView usage
        ~r/from\s+django\.contrib\.admindocs\.views\s+import\s+TemplateDetailView/,
        ~r/class\s+\w+\s*\(\s*TemplateDetailView\s*\)/,
        ~r/TemplateDetailView/,
        
        # Vulnerable path operations without safe_join
        ~r/Path\s*\(\s*.*?join\s*\(\s*.*?,\s*template/,
        ~r/os\.path\.join\s*\(\s*.*?,\s*template.*?\)(?!.*safe_join)/,
        
        # Admindocs enabled in settings
        ~r/INSTALLED_APPS\s*=\s*\[[\s\S]*?['"]django\.contrib\.admindocs['"][\s\S]*?\]/,
        
        # Template parameter usage without validation
        ~r/template\s*=\s*request\.\w+\[['"]template['"]\](?!.*safe_join)/,
        
        # Template path patterns
        ~r/templates\//,
        ~r/path/
      ],
      cwe_id: "CWE-22",
      owasp_category: "A01:2021",
      recommendation: "Update Django to 2.2.24+, 3.1.12+, or 3.2.4+. Use safe_join for path operations.",
      test_cases: %{
        vulnerable: [
          ~s|path('admin/doc/', include('django.contrib.admindocs.urls'))|,
          ~s|from django.contrib.admindocs.views import TemplateDetailView
class CustomView(TemplateDetailView):
    pass|,
          ~s|template_path = os.path.join(template_dir, template)
# Path traversal: ../../../etc/passwd|,
          ~s|INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.admindocs',
]|
        ],
        safe: [
          ~s|# Django 3.2.4+ with proper validation
from django.utils._os import safe_join
template_path = safe_join(template_dir, template)|,
          ~s|# Remove admindocs from INSTALLED_APPS
INSTALLED_APPS = [
    'django.contrib.admin',
    # 'django.contrib.admindocs',  # Disabled
]|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      CVE-2021-33203 is a directory traversal vulnerability in Django's contrib.admindocs
      module that allows authenticated staff members to check the existence of arbitrary
      files outside the intended template root directories. This vulnerability affects
      Django versions before 2.2.24, 3.x before 3.1.12, and 3.2.x before 3.2.4.
      
      The vulnerability exists in the TemplateDetailView class within the admindocs
      module, where insufficient path validation allows attackers to manipulate the
      template parameter in URLs to perform directory traversal attacks. An attacker
      can craft malicious URLs to probe for the existence of sensitive files on the
      server filesystem.
      
      The vulnerability is particularly concerning because:
      
      1. **Authenticated Access**: Only requires staff-level authentication, which may
         be more easily obtained than admin privileges
      
      2. **Information Disclosure**: Allows reconnaissance of server file structure
         and sensitive file locations
      
      3. **Path Traversal**: Classic directory traversal using "../" sequences to
         escape template directories
      
      4. **Wide Impact**: Affects multiple Django LTS and current versions
      
      The attack is limited to checking file existence rather than reading file contents,
      but this information can be valuable for further attacks or system reconnaissance.
      Attackers can determine the presence of configuration files, application code,
      logs, and other sensitive resources.
      """,
      
      references: [
        %{
          type: :cve,
          id: "CVE-2021-33203",
          title: "Django Directory Traversal via admindocs",
          url: "https://nvd.nist.gov/vuln/detail/CVE-2021-33203"
        },
        %{
          type: :cwe,
          id: "CWE-22",
          title: "Improper Limitation of a Pathname to a Restricted Directory",
          url: "https://cwe.mitre.org/data/definitions/22.html"
        },
        %{
          type: :owasp,
          id: "A01:2021",
          title: "Broken Access Control",
          url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
        },
        %{
          type: :django,
          id: "Security Release",
          title: "Django 3.2.4 Security Release",
          url: "https://docs.djangoproject.com/en/stable/releases/3.2.4/"
        },
        %{
          type: :github,
          id: "GHSL-2021-075",
          title: "GitHub Security Lab Advisory",
          url: "https://securitylab.github.com/advisories/GHSL-2021-075-django/"
        },
        %{
          type: :django,
          id: "Admindocs Documentation",
          title: "Django contrib.admindocs Documentation",
          url: "https://docs.djangoproject.com/en/stable/ref/contrib/admin/admindocs/"
        }
      ],
      
      attack_vectors: [
        "Malicious URLs targeting admindocs template views with path traversal",
        "Directory traversal using '../' sequences in template parameters",
        "Probing for sensitive system files like /etc/passwd, /etc/hosts",
        "Reconnaissance of application file structure and configuration",
        "Discovery of log files and temporary directories",
        "Enumeration of installed applications and their file structures",
        "Testing for backup files and configuration dumps",
        "Identifying database configuration files and connection strings",
        "Locating application source code and sensitive business logic",
        "Finding SSL certificates and private key files"
      ],
      
      real_world_impact: [
        "Unauthorized file disclosure of sensitive locations and structure",
        "Information gathering for further exploitation attempts",
        "Discovery of configuration files containing credentials",
        "Reconnaissance of application architecture and dependencies",
        "Identification of backup files and sensitive data locations",
        "Privacy violations through unauthorized file system access",
        "Compliance violations due to unauthorized data access",
        "Potential escalation to more serious vulnerabilities",
        "Competitive intelligence gathering from file structure",
        "Security posture assessment by unauthorized parties"
      ],
      
      cve_examples: [
        %{
          id: "CVE-2021-33203",
          description: "Django directory traversal via admindocs TemplateDetailView",
          severity: "medium",
          cvss: 4.9,
          note: "Affects Django 2.2.x, 3.1.x, and 3.2.x before security patches"
        },
        %{
          id: "CVE-2013-4315",
          description: "Django directory traversal via ssi template tag",
          severity: "medium",
          cvss: 4.3,
          note: "Historical Django path traversal vulnerability showing pattern of similar issues"
        },
        %{
          id: "CVE-2021-3281",
          description: "Django directory traversal via archive extraction",
          severity: "high",
          cvss: 7.5,
          note: "Related Django path traversal vulnerability in archive handling"
        },
        %{
          id: "GHSA-68w8-qjq3-2gfm",
          description: "GitHub Security Advisory for CVE-2021-33203",
          severity: "medium",
          cvss: 4.9,
          note: "Comprehensive technical analysis and remediation guidance"
        }
      ],
      
      detection_notes: """
      This pattern detects CVE-2021-33203 by identifying:
      
      1. **Admindocs URL Configuration**: Detection of URL patterns that include
         django.contrib.admindocs.urls, which exposes the vulnerable views
      
      2. **TemplateDetailView Usage**: Import statements and class inheritance
         patterns that use the vulnerable TemplateDetailView class
      
      3. **Unsafe Path Operations**: Path join operations that don't use Django's
         safe_join utility for proper path validation
      
      4. **Configuration Issues**: INSTALLED_APPS settings that include admindocs
         without proper security considerations
      
      The pattern focuses on detecting code that could be vulnerable rather than
      actual exploitation attempts. It may produce false positives in:
      - Development environments where admindocs is intentionally enabled
      - Applications using patched Django versions
      - Custom implementations that properly validate paths
      
      The pattern does not detect:
      - Runtime exploitation attempts
      - Custom admindocs implementations with proper validation
      - Alternative path traversal vectors outside admindocs
      """,
      
      safe_alternatives: [
        """
        # Django upgrade to patched versions
        # Install Django 2.2.24+, 3.1.12+, or 3.2.4+
        pip install 'Django>=3.2.4'
        
        # Verify version in settings.py
        import django
        print(f"Django version: {django.get_version()}")
        
        # Or in requirements.txt
        Django>=3.2.4
        """,
        """
        # Use safe_join for path operations
        from django.utils._os import safe_join
        from pathlib import Path
        
        def get_template_path(template_dir, template_name):
            # Secure path joining with validation
            try:
                safe_path = safe_join(template_dir, template_name)
                if Path(safe_path).exists():
                    return safe_path
            except ValueError:
                # safe_join raises ValueError for invalid paths
                return None
            return None
        
        # Example usage in views
        class SecureTemplateView(TemplateView):
            def get_template_names(self):
                template = self.request.GET.get('template')
                if template:
                    safe_path = get_template_path(self.template_dir, template)
                    if safe_path:
                        return [safe_path]
                return super().get_template_names()
        """,
        """
        # Disable admindocs if not needed
        # Remove from INSTALLED_APPS in settings.py
        INSTALLED_APPS = [
            'django.contrib.admin',
            'django.contrib.auth',
            'django.contrib.contenttypes',
            'django.contrib.sessions',
            'django.contrib.messages',
            'django.contrib.staticfiles',
            # 'django.contrib.admindocs',  # Disabled for security
        ]
        
        # Remove admindocs URLs from url patterns
        urlpatterns = [
            path('admin/', admin.site.urls),
            # path('admin/doc/', include('django.contrib.admindocs.urls')),  # Disabled
        ]
        """,
        """
        # Implement custom path validation
        import os
        from pathlib import Path
        
        def validate_template_path(base_dir, template_path):
            '''Validate that template_path is within base_dir'''
            try:
                # Resolve absolute paths
                base = Path(base_dir).resolve()
                target = Path(base_dir, template_path).resolve()
                
                # Check if target is within base directory
                target.relative_to(base)
                return str(target)
            except (ValueError, OSError):
                # Path traversal attempt or invalid path
                raise ValueError(f"Invalid template path: {template_path}")
        
        # Usage example
        try:
            template_path = validate_template_path('/app/templates', user_template)
            with open(template_path, 'r') as f:
                content = f.read()
        except ValueError as e:
            # Handle path traversal attempt
            logger.warning(f"Path traversal attempt detected: {e}")
            return HttpResponseForbidden("Invalid template path")
        """,
        """
        # Restrict admindocs access with middleware
        from django.http import HttpResponseForbidden
        from django.conf import settings
        
        class AdminDocsSecurityMiddleware:
            def __init__(self, get_response):
                self.get_response = get_response
                
            def __call__(self, request):
                # Block admindocs in production
                if not settings.DEBUG and request.path.startswith('/admin/doc/'):
                    return HttpResponseForbidden("Admindocs disabled in production")
                
                # Additional IP restrictions for admindocs
                if request.path.startswith('/admin/doc/'):
                    allowed_ips = getattr(settings, 'ADMINDOCS_ALLOWED_IPS', [])
                    client_ip = self.get_client_ip(request)
                    if allowed_ips and client_ip not in allowed_ips:
                        return HttpResponseForbidden("IP not allowed for admindocs")
                
                return self.get_response(request)
            
            def get_client_ip(self, request):
                x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
                if x_forwarded_for:
                    ip = x_forwarded_for.split(',')[0]
                else:
                    ip = request.META.get('REMOTE_ADDR')
                return ip
        """
      ],
      
      additional_context: %{
        common_mistakes: [
          "Enabling admindocs in production without security considerations",
          "Using os.path.join instead of Django's safe_join for path operations",
          "Not updating Django versions promptly after security releases",
          "Assuming staff authentication is sufficient protection",
          "Ignoring directory traversal risks in admin interfaces",
          "Not implementing additional access controls for administrative features",
          "Leaving default admindocs URLs exposed without IP restrictions",
          "Not monitoring access logs for potential exploitation attempts"
        ],
        
        secure_patterns: [
          """
          # Environment-based admindocs configuration
          import os
          from django.conf import settings
          
          # Only enable admindocs in development
          INSTALLED_APPS = [
              'django.contrib.admin',
              'django.contrib.auth',
              'django.contrib.contenttypes',
              'django.contrib.sessions',
              'django.contrib.messages',
              'django.contrib.staticfiles',
          ]
          
          # Add admindocs only in development
          if os.environ.get('DJANGO_ENV') == 'development':
              INSTALLED_APPS.append('django.contrib.admindocs')
          
          # URL patterns with environment check
          urlpatterns = [
              path('admin/', admin.site.urls),
          ]
          
          if settings.DEBUG and 'django.contrib.admindocs' in settings.INSTALLED_APPS:
              urlpatterns.append(
                  path('admin/doc/', include('django.contrib.admindocs.urls'))
              )
          """,
          """
          # Custom secure template view
          from django.contrib.admindocs.views import TemplateDetailView
          from django.utils._os import safe_join
          from django.http import Http404
          from pathlib import Path
          
          class SecureTemplateDetailView(TemplateDetailView):
              def get_template(self):
                  template = self.kwargs.get('template', '')
                  
                  # Validate template parameter
                  if not template or '..' in template:
                      raise Http404("Invalid template")
                  
                  # Use safe_join for path operations
                  for template_dir in self.get_template_dirs():
                      try:
                          template_path = safe_join(template_dir, template)
                          if Path(template_path).exists():
                              return template_path
                      except ValueError:
                          # safe_join detected path traversal
                          continue
                  
                  raise Http404("Template not found")
          """,
          """
          # Comprehensive admindocs security configuration
          from django.conf import settings
          
          # Security settings for admindocs
          if 'django.contrib.admindocs' in settings.INSTALLED_APPS:
              # Restrict to superusers only
              settings.ADMINDOCS_REQUIRE_SUPERUSER = True
              
              # IP whitelist for admindocs access
              settings.ADMINDOCS_ALLOWED_IPS = [
                  '127.0.0.1',
                  '::1',
                  # Add your office IPs
              ]
              
              # Disable in production
              if not settings.DEBUG:
                  import warnings
                  warnings.warn(
                      "Admindocs should not be enabled in production",
                      category=SecurityWarning
                  )
          """
        ],
        
        framework_specific_notes: [
          "Django's safe_join function is the recommended way to join paths securely",
          "Admindocs should generally be disabled in production environments",
          "Path traversal vulnerabilities are common in Django admin interfaces",
          "Django security releases should be applied promptly",
          "Consider using environment variables to control admindocs availability",
          "Implement logging to monitor admindocs access patterns",
          "Use Django's permission system to restrict admindocs access",
          "Regular security audits should include review of admin interface exposure"
        ]
      }
    }
  end
  
  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.7,
      
      context_rules: %{
        django_modules: [
          "django.contrib.admindocs",
          "django.contrib.admindocs.views",
          "django.contrib.admindocs.urls"
        ],
        
        vulnerable_views: [
          "TemplateDetailView",
          "ViewDetailView",
          "ModelDetailView"
        ],
        
        path_operations: [
          "os.path.join",
          "Path",
          "safe_join",
          "pathlib.Path"
        ],
        
        safe_patterns: [
          "safe_join",
          "validate_path",
          "resolve()",
          "relative_to"
        ],
        
        dangerous_params: [
          "template",
          "../",
          "..\\",
          "/etc/",
          "/var/",
          "/proc/"
        ]
      },
      
      confidence_rules: %{
        adjustments: %{
          # High confidence patterns
          admindocs_usage: +0.9,
          template_detail_view: +0.85,
          unsafe_path_join: +0.8,
          installed_apps_admindocs: +0.75,
          
          # Medium confidence
          path_operations: +0.6,
          template_parameter_usage: +0.7,
          
          # Lower confidence in safe contexts
          has_safe_join: -0.8,
          has_path_validation: -0.85,
          django_version_check: -0.9,
          in_development_settings: -0.7,
          
          # Context-based adjustments
          in_test_file: -0.95,
          in_migration: -0.98,
          debug_only_context: -0.8,
          has_ip_restrictions: -0.6
        }
      },
      
      ast_rules: %{
        path_analysis: %{
          check_path_joins: true,
          detect_traversal_patterns: true,
          analyze_template_params: true,
          validate_safe_join_usage: true
        },
        
        django_analysis: %{
          check_installed_apps: true,
          analyze_url_patterns: true,
          detect_admindocs_usage: true,
          check_view_inheritance: true
        },
        
        security_analysis: %{
          check_version_constraints: true,
          analyze_access_controls: true,
          detect_unsafe_imports: true,
          check_middleware_usage: true
        },
        
        context_analysis: %{
          check_debug_context: true,
          analyze_environment_vars: true,
          detect_production_usage: true,
          check_conditional_includes: true
        }
      }
    }
  end
end
