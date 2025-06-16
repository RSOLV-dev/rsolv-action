defmodule RsolvApi.Security.Patterns.Django.TemplateInjection do
  @moduledoc """
  Django Template Injection pattern for Django applications.
  
  This pattern detects Server-Side Template Injection (SSTI) vulnerabilities in
  Django applications where user-controlled data is passed into template names
  or template strings, potentially allowing remote code execution.
  
  ## Background
  
  Django's template system is designed to be secure by default, automatically
  escaping variables. However, template injection can occur when:
  - User input controls which template file is loaded
  - User input is passed to Template() constructor
  - Dynamic template names are constructed from user data
  - Template strings are built from user input
  
  ## Vulnerability Details
  
  Template injection vulnerabilities allow attackers to:
  1. Execute arbitrary Python code on the server
  2. Access sensitive application data and configuration
  3. Read files from the file system
  4. Potentially achieve full server compromise
  
  ## Examples
  
      # VULNERABLE - User controls template name
      template_name = request.GET.get('template')
      return render_to_string(template_name, context)
      
      # VULNERABLE - User provides template code
      template_string = request.POST.get('template_code')
      template = Template(template_string)
      
      # VULNERABLE - Dynamic template path
      report_type = request.GET['type']
      return render(request, f"reports/{report_type}.html", context)
      
      # SAFE - Static template name
      return render_to_string('reports/summary.html', context)
      
      # SAFE - Whitelisted templates
      ALLOWED_TEMPLATES = ['report1.html', 'report2.html']
      template = request.GET.get('template', 'report1.html')
      if template in ALLOWED_TEMPLATES:
          return render(request, template, context)
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  
  @impl true
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "django-template-injection",
      name: "Django Template Injection",
      description: "Server-side template injection allowing code execution",
      type: :template_injection,
      severity: :critical,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        # render_to_string with request data
        ~r/render_to_string\s*\(\s*request\./,
        
        # Template constructor with request data
        ~r/Template\s*\(\s*request\./,
        
        # render with request data as template name or f-string template
        ~r/render\s*\(\s*request,\s*request\./,
        ~r/render\s*\(\s*request,\s*f['"]/,
        ~r/render\s*\(\s*request,\s*template_path/,
        
        # template.render with request data in first position
        ~r/template\.render\s*\(\s*.*?request\./,
        
        # get_template with user input
        ~r/get_template\s*\(\s*user_/,
        ~r/get_template\s*\(\s*request\./,
        # get_template with variable assignment from request
        ~r/=\s*request\.(?:GET|POST|data|session).*?get_template\s*\(\s*\w+/ms,
        
        # render_to_string with f-string or variables
        ~r/render_to_string\s*\(\s*f['"]/,
        ~r/render_to_string\s*\(\s*[a-zA-Z_]+_template/,
        ~r/render_to_string\s*\(\s*template_(?:name|path)/,
        # f-string template paths with user input
        ~r/template_path\s*=\s*f['"][^'"]*\{[^}]*request\./,
        # template_name/path assignment from request used directly in render functions (no validation)
        ~r/template_(?:name|path)\s*=\s*request\.(?:GET|POST|data|session)\.[^\n]*\n[^\n]*render\s*\(/ms,
        
        # Template path concatenation
        ~r/['"]\s*\+\s*request\..*?\.html/,
        
        # from_string with user input
        ~r/from_string\s*\(\s*request\./,
        # from_string with decoded request body
        ~r/request\.body\.decode.*?from_string\s*\(/ms,
        
        # Direct request data in render functions
        ~r/render_to_string\s*\(\s*request\./,
        ~r/render\s*\(\s*request,\s*request\./,
        ~r/[a-zA-Z_]+_template\s*=\s*request\.(?:GET|POST|data|session).*?render_to_string\s*\(\s*\w+_template/ms,
        
        # .format() with user data in template operations
        ~r/render.*?\.format\s*\(\s*.*?request\./,
        ~r/get_template.*?\.format\s*\(\s*.*?request\./
      ],
      default_tier: :protected,
      cwe_id: "CWE-94",
      owasp_category: "A03:2021",
      recommendation: "Never render user input as template code. Use static template names only.",
      test_cases: %{
        vulnerable: [
          ~s|render_to_string(request.GET.get('template'))|,
          ~s|Template(request.POST.get('template_code')).render()|,
          ~s|get_template(user_template_name)|
        ],
        safe: [
          ~s|render_to_string('static_template.html', {'data': user_data})|,
          ~s|get_template('users/profile.html')|,
          ~s|render(request, 'fixed_template.html', context)|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Server-Side Template Injection (SSTI) is a critical vulnerability that occurs when
      an attacker can inject malicious code into server-side templates. In Django applications,
      this template injection vulnerability typically happens when user input is used to 
      determine which template to render or when user input is passed directly to the 
      Template() constructor, enabling code execution.
      
      Django's template engine, while safer than some others (like Jinja2 in unsafe mode),
      can still be exploited for SSTI under certain conditions:
      
      1. **Dynamic Template Loading**: When user input controls template file selection
      2. **Template String Construction**: When user data is used to build template strings
      3. **Template Code Injection**: When user input is passed to Template() constructor
      
      The impact of SSTI in Django can be severe:
      - Remote Code Execution (RCE) through template tag exploitation
      - Information disclosure via debug template tags
      - Server-side file access and data exfiltration
      - Denial of Service through resource-intensive template operations
      
      Django templates have access to various built-in tags and filters that can be
      exploited, and in debug mode, even more dangerous functionality is exposed.
      """,
      
      attack_vectors: """
      1. **Debug Tag Exploitation**: `{% debug %}` exposes all context variables
      2. **Load Tag Abuse**: `{% load %}` can import custom template tags
      3. **Include Tag Path Traversal**: `{% include "../../../etc/passwd" %}`
      4. **Variable Resolution**: `{{ settings.SECRET_KEY }}` to leak secrets
      5. **Filter Chain Exploitation**: `{{ ''.__class__.__mro__[2].__subclasses__() }}`
      6. **With Tag Variable Assignment**: `{% with a=request %}{{ a }}{% endwith %}`
      7. **Template Inheritance Hijacking**: `{% extends user_template %}`
      8. **Custom Tag Registration**: Exploiting INSTALLED_APPS template tags
      9. **Context Processor Abuse**: Accessing request, user, and perms objects
      10. **Filesystem Access**: `{% ssi /etc/passwd %}` (if enabled)
      """,
      
      business_impact: """
      - Complete server compromise leading to data breach
      - Theft of sensitive customer data and PII
      - Financial losses from service disruption
      - Regulatory fines for data protection violations
      - Reputation damage and loss of customer trust
      - Legal liability from compromised user accounts
      - Intellectual property theft
      - Ransomware deployment risk
      - Supply chain attacks on customers
      - Compliance failures (PCI-DSS, GDPR, HIPAA)
      """,
      
      technical_impact: """
      - Remote code execution on the server
      - Arbitrary file read/write capabilities
      - Database access and data exfiltration
      - Internal network reconnaissance
      - Privilege escalation to system level
      - Installation of backdoors and persistence
      - Cryptocurrency mining malware deployment
      - Server resource exhaustion (DoS)
      - Container/VM escape in cloud environments
      - Lateral movement to other systems
      """,
      
      likelihood: "Medium - Developers often use dynamic template loading for flexibility without realizing the security implications",
      
      cve_examples: """
      CVE-2022-22818 (CVSS 6.1) - Django {% debug %} Template Tag XSS
      - Affected Django 2.2 < 2.2.27, 3.2 < 3.2.12, 4.0 < 4.0.2
      - The {% debug %} template tag didn't properly encode output
      - Could lead to XSS when combined with template injection
      - Demonstrated how debug features increase attack surface
      
      CVE-2020-7471 (CVSS 9.8) - Django SQL Injection via StringAgg
      - While not SSTI, shows Django's template/ORM interaction risks
      - Demonstrates how template rendering can interact with backend
      - Affected Django 1.11.x, 2.2.x, 3.0.x
      
      CVE-2019-14234 (CVSS 9.8) - Django JSONField/HStoreField SQL Injection
      - Shows how template rendering of database fields can be dangerous
      - Interaction between templates and ORM creates attack vectors
      
      CVE-2021-45116 (CVSS 7.5) - Django Template DoS
      - Excessive memory consumption in template engine
      - Shows how template injection can cause DoS
      - Affected Django 2.2, 3.2, 4.0
      
      Real-world SSTI in Django applications:
      - Multiple Django CMSs vulnerable to SSTI through plugin systems
      - E-commerce platforms with customizable email templates
      - Reporting systems with user-defined report templates
      - Documentation generators with dynamic template loading
      """,
      
      compliance_standards: [
        "OWASP Top 10 2021 - A03: Injection",
        "CWE-94: Improper Control of Generation of Code",
        "CWE-96: Improper Neutralization of Directives in Statically Saved Code",
        "CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine",
        "PCI DSS 6.5.1 - Injection flaws",
        "NIST SP 800-53 - SI-10 Information Input Validation",
        "ISO 27001 - A.14.2.5 Secure system engineering principles",
        "ASVS 4.0 - V5.2 Sanitization and Sandboxing",
        "SANS Top 25 - Injection vulnerabilities"
      ],
      
      remediation_steps: """
      1. **Use Static Template Names Only**:
         ```python
         # NEVER DO THIS - User controls template
         template_name = request.GET.get('template')
         return render_to_string(template_name, context)
         
         # SAFE - Static template name
         return render_to_string('reports/summary.html', {
             'data': user_data
         })
         ```
      
      2. **Whitelist Allowed Templates**:
         ```python
         # Define allowed templates
         ALLOWED_TEMPLATES = {
             'report': 'reports/standard_report.html',
             'summary': 'reports/summary_report.html',
             'detail': 'reports/detail_report.html'
         }
         
         def generate_report(request):
             report_type = request.GET.get('type', 'report')
             
             # Use whitelisted template only
             template_name = ALLOWED_TEMPLATES.get(report_type, ALLOWED_TEMPLATES['report'])
             
             return render(request, template_name, {
                 'report_data': get_report_data(request.user)
             })
         ```
      
      3. **Never Use Template() with User Input**:
         ```python
         # NEVER DO THIS - RCE vulnerability!
         from django.template import Template, Context
         
         user_template = request.POST.get('template')
         template = Template(user_template)  # DANGEROUS!
         output = template.render(Context({'user': request.user}))
         
         # SAFE - Use predefined templates with variable data
         from django.template.loader import get_template
         
         template = get_template('emails/notification.html')
         output = template.render({
             'user': request.user,
             'message': request.POST.get('message', '')
         })
         ```
      
      4. **Secure Dynamic Template Selection**:
         ```python
         # Map user choices to safe template paths
         TEMPLATE_MAPPING = {
             'invoice': {
                 'standard': 'invoices/standard.html',
                 'detailed': 'invoices/detailed.html',
                 'summary': 'invoices/summary.html'
             },
             'report': {
                 'daily': 'reports/daily.html',
                 'weekly': 'reports/weekly.html',
                 'monthly': 'reports/monthly.html'
             }
         }
         
         def render_document(request, doc_type):
             template_style = request.GET.get('style', 'standard')
             
             # Safely resolve template path
             templates = TEMPLATE_MAPPING.get(doc_type, {})
             template_path = templates.get(template_style)
             
             if not template_path:
                 return HttpResponseBadRequest('Invalid template selection')
             
             return render(request, template_path, context)
         ```
      
      5. **Avoid String Formatting in Template Paths**:
         ```python
         # NEVER DO THIS - Path injection risk
         template_path = f"emails/{request.GET['template_name']}.html"
         
         # NEVER DO THIS EITHER
         template_path = "emails/{}.html".format(user_input)
         
         # SAFE - Use dictionary lookup
         EMAIL_TEMPLATES = {
             'welcome': 'emails/welcome.html',
             'reset': 'emails/password_reset.html',
             'confirm': 'emails/confirmation.html'
         }
         
         email_type = request.GET.get('type', 'welcome')
         template_path = EMAIL_TEMPLATES.get(email_type, EMAIL_TEMPLATES['welcome'])
         ```
      
      6. **Implement Template Security Middleware**:
         ```python
         class TemplateSecurityMiddleware:
             def __init__(self, get_response):
                 self.get_response = get_response
                 self.allowed_dirs = [
                     os.path.join(settings.BASE_DIR, 'templates'),
                     os.path.join(settings.BASE_DIR, 'app_templates')
                 ]
             
             def __call__(self, request):
                 # Hook into template loading to validate paths
                 response = self.get_response(request)
                 return response
             
             def validate_template_path(self, template_path):
                 # Ensure template is within allowed directories
                 abs_path = os.path.abspath(template_path)
                 return any(abs_path.startswith(allowed) for allowed in self.allowed_dirs)
         ```
      
      7. **Disable Dangerous Template Features**:
         ```python
         # In production settings.py
         
         # Disable debug mode
         DEBUG = False
         
         # Remove dangerous template tags if not needed
         # Custom template tag libraries should be carefully reviewed
         
         # If using django.contrib.admindocs, ensure it's protected
         # The {% ssi %} tag should never be enabled in production
         ```
      
      8. **Content Security Policy (CSP)**:
         ```python
         # Add CSP headers to prevent XSS from template injection
         SECURE_CONTENT_TYPE_NOSNIFF = True
         SECURE_BROWSER_XSS_FILTER = True
         
         # In middleware or view
         response['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
         ```
      """,
      
      prevention_tips: """
      - Always use static template names for template loading
      - Never pass user input to Template() constructor
      - Implement strict template whitelisting
      - Disable debug mode in production
      - Review all template loading code during security audits
      - Use Django's built-in template loaders safely
      - Implement path traversal protection
      - Monitor template rendering errors and anomalies
      - Educate developers about SSTI risks
      - Use static analysis tools to detect dynamic template loading
      """,
      
      detection_methods: """
      - Search for render_to_string() and render() with dynamic arguments
      - Look for Template() constructor usage
      - Check for get_template() with user input
      - Identify f-strings or .format() in template paths
      - Review all template loading middleware and utilities
      - Static analysis with Semgrep or Bandit
      - Dynamic testing with SSTI payloads
      - Code review checklist for template operations
      - Monitor for template-not-found errors (potential SSTI attempts)
      """,
      
      safe_alternatives: """
      # 1. Always use static template names for render() and render_to_string()
      # Using static template names prevents SSTI as user input cannot control which template is loaded
      
      # 2. Use Template Inheritance Safely
      <!-- base_report.html -->
      <!DOCTYPE html>
      <html>
      <head>
          <title>{% block title %}Report{% endblock %}</title>
      </head>
      <body>
          {% block content %}{% endblock %}
      </body>
      </html>
      
      <!-- specific_report.html -->
      {% extends "base_report.html" %}
      {% block title %}Sales Report{% endblock %}
      {% block content %}
          <h1>{{ report_title }}</h1>
          <div>{{ report_data }}</div>
      {% endblock %}
      
      # 2. Safe Email Template System
      class EmailTemplateManager:
          TEMPLATES = {
              'welcome': 'emails/welcome.html',
              'password_reset': 'emails/password_reset.html',
              'order_confirmation': 'emails/order_confirmation.html',
              'newsletter': 'emails/newsletter.html'
          }
          
          @classmethod
          def render_email(cls, template_key, context):
              template_path = cls.TEMPLATES.get(template_key)
              if not template_path:
                  raise ValueError(f"Unknown email template: {template_key}")
              
              template = get_template(template_path)
              return template.render(context)
      
      # Usage
      email_html = EmailTemplateManager.render_email('welcome', {
          'user': user,
          'activation_link': generate_activation_link(user)
      })
      
      # 3. Safe Report Generation
      from enum import Enum
      
      class ReportType(Enum):
          SUMMARY = 'summary'
          DETAILED = 'detailed'
          EXECUTIVE = 'executive'
      
      class ReportGenerator:
          TEMPLATE_MAP = {
              ReportType.SUMMARY: 'reports/summary.html',
              ReportType.DETAILED: 'reports/detailed.html',
              ReportType.EXECUTIVE: 'reports/executive.html'
          }
          
          def generate(self, report_type: ReportType, data):
              template_path = self.TEMPLATE_MAP[report_type]
              return render_to_string(template_path, {'data': data})
      
      # 4. Internationalization-Safe Templates
      from django.utils.translation import get_language
      
      def get_localized_template(base_name):
          # Safe template resolution based on language
          lang = get_language()
          
          # Whitelist of available templates
          available = {
              'en': f'templates/en/{base_name}.html',
              'es': f'templates/es/{base_name}.html',
              'fr': f'templates/fr/{base_name}.html'
          }
          
          return available.get(lang, available['en'])
      
      # 5. Template Caching for Performance
      from django.core.cache import cache
      from django.template.loader import get_template
      
      class CachedTemplateRenderer:
          @staticmethod
          def render(template_name, context):
              # Only allow specific templates
              if template_name not in ALLOWED_TEMPLATES:
                  raise ValueError("Invalid template")
              
              cache_key = f"template_{template_name}"
              template = cache.get(cache_key)
              
              if not template:
                  template = get_template(template_name)
                  cache.set(cache_key, template, 3600)
              
              return template.render(context)
      """
    }
  end
  
  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.7,
      
      context_rules: %{
        # Template loading functions
        template_functions: [
          "render_to_string", "render", "get_template",
          "select_template", "Template", "from_string"
        ],
        
        # User input sources
        user_inputs: [
          "request.GET", "request.POST", "request.data",
          "request.FILES", "request.session", "request.COOKIES"
        ],
        
        # Safe template paths
        safe_paths: [
          ~r/^['"]['"]$/,  # Empty string
          ~r/^['"][a-zA-Z0-9_\/\-]+\.html['"]$/,  # Static paths
          ~r/^['"](?:templates\/|views\/|emails\/)/  # Known safe directories
        ],
        
        # Template variables that might be user-controlled
        dangerous_variables: [
          "template_name", "template_path", "template",
          "tpl", "view", "page", "report_type"
        ]
      },
      
      confidence_rules: %{
        adjustments: %{
          # High confidence patterns
          user_controlled_template_name: +0.9,
          template_constructor_with_input: +0.95,
          render_with_dynamic_path: +0.85,
          string_formatting_in_path: +0.8,
          
          # Medium confidence
          variable_template_assignment: +0.6,
          get_template_with_variable: +0.7,
          
          # Lower confidence for safer patterns
          whitelisted_templates: -0.8,
          static_template_paths: -0.9,
          template_in_settings: -0.7,
          
          # Context adjustments
          in_view_function: +0.2,
          in_template_tag: +0.3,
          in_form_handler: +0.2,
          
          # File location adjustments
          in_test_file: -0.9,
          in_migration: -0.8,
          commented_line: -1.0
        }
      },
      
      ast_rules: %{
        # Template analysis
        template_analysis: %{
          detect_dynamic_templates: true,
          check_template_sources: true,
          analyze_template_paths: true,
          track_template_variables: true
        },
        
        # Input flow analysis
        input_analysis: %{
          track_user_input: true,
          detect_string_formatting: true,
          check_variable_assignments: true,
          analyze_control_flow: true
        },
        
        # Security checks
        security_analysis: %{
          detect_whitelisting: true,
          check_path_validation: true,
          identify_safe_patterns: true,
          analyze_template_sources: true
        },
        
        # Framework-specific
        django_analysis: %{
          check_debug_mode: true,
          analyze_middleware: true,
          detect_template_loaders: true,
          check_installed_apps: true
        }
      }
    }
  end
  
  @impl true
  def applies_to_file?(file_path, frameworks \\ nil) do
    # Apply to Python files in Django projects
    is_python_file = String.ends_with?(file_path, ".py")
    
    # Django framework check
    frameworks_list = frameworks || []
    is_django = "django" in frameworks_list
    
    # Common Django file patterns
    is_django_file = String.contains?(file_path, "views.py") ||
                    String.contains?(file_path, "template") ||
                    String.contains?(file_path, "render") ||
                    String.contains?(file_path, "api_views.py")
    
    # Not a test file
    not_test = !String.contains?(file_path, "test") &&
               !String.contains?(file_path, "spec")
    
    # If no frameworks specified but it looks like Django, include it
    inferred_django = frameworks_list == [] && is_django_file
    
    is_python_file && (is_django || inferred_django) && not_test
  end
end