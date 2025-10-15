defmodule Rsolv.Security.Patterns.Django.Cve201814574 do
  @moduledoc """
  Django CVE-2018-14574 - Open Redirect in CommonMiddleware via APPEND_SLASH

  This pattern detects Django applications vulnerable to CVE-2018-14574, an open redirect 
  vulnerability in CommonMiddleware when APPEND_SLASH setting is enabled and the application 
  has URL patterns that accept paths ending in slashes.

  ## Vulnerability Details

  The vulnerability affects Django versions:
  - 1.11.x before 1.11.15
  - 2.0.x before 2.0.8

  When CommonMiddleware and APPEND_SLASH setting are both enabled, and the project has 
  a URL pattern that accepts any path ending in a slash, an attacker can craft malicious 
  URLs that redirect users to external sites, enabling phishing attacks and social engineering.

  ### Attack Example
  ```python
  # Vulnerable configuration in settings.py
  MIDDLEWARE = [
      'django.middleware.common.CommonMiddleware',
      # ... other middleware
  ]
  APPEND_SLASH = True  # Default Django setting

  # Vulnerable URL pattern in urls.py
  urlpatterns = [
      path('content/<path:page>/', views.content_page),
      # ... other patterns
  ]

  # Attack scenario:
  # 1. Attacker creates malicious URL: http://example.com/content//evil.com/
  # 2. CommonMiddleware processes the URL with APPEND_SLASH logic
  # 3. Django redirects to: http://evil.com/ (attacker's site)
  # 4. User is redirected to phishing site without realizing it

  # Vulnerable redirect patterns
  def view(request):
      next_url = request.GET.get('next')
      return redirect(next_url)  # No validation - open redirect

  def another_view(request):
      return HttpResponseRedirect(request.META.get('HTTP_REFERER'))  # Unsafe
  ```

  ### Safe Example
  ```python
  # Safe: Validate redirect URLs against whitelist
  from django.utils.http import is_safe_url

  def safe_view(request):
      next_url = request.GET.get('next', '/')
      if is_safe_url(next_url, allowed_hosts={request.get_host()}):
          return redirect(next_url)
      else:
          return redirect('/')  # Default safe redirect

  # Safe: Use Django 2.1.2+ which fixes the vulnerability
  # Or disable APPEND_SLASH if not needed
  APPEND_SLASH = False
  ```
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @impl true
  def pattern do
    %Pattern{
      id: "django-cve-2018-14574",
      name: "Django CVE-2018-14574 - Open Redirect",
      description: "Open redirect in CommonMiddleware via APPEND_SLASH and URL redirection",
      type: :open_redirect,
      severity: :medium,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        ~r/APPEND_SLASH\s*=\s*True/,
        ~r/redirect\s*\(\s*request\./,
        ~r/HttpResponseRedirect\s*\(\s*request\./,
        ~r/return\s+redirect\s*\(\s*request\./,
        ~r/django\.middleware\.common\.CommonMiddleware/,
        ~r/from\s+django\.http\s+import.*HttpResponseRedirect/,
        ~r/redirect_url\s*=\s*request\./,
        ~r/next_url\s*=\s*request\./,
        ~r/\.get\(\s*['\"]next['\"].*redirect/,
        ~r/\.get\(\s*['\"]url['\"].*redirect/,
        ~r/HTTP_REFERER.*HttpResponseRedirect/,
        ~r/user_url.*redirect/,
        ~r/redirect\s*\(\s*request\.POST\.get/,
        ~r/redirect\s*\(\s*request\.session\.get/,
        ~r/HttpResponseRedirect\s*\(\s*user_url\s*\)/
      ],
      cwe_id: "CWE-601",
      owasp_category: "A01:2021",
      recommendation:
        "Update Django 2.1.2+, Django 2.0.9+, or Django 1.11.16+. Validate redirect URLs against whitelist using is_safe_url().",
      test_cases: %{
        vulnerable: [
          ~s|return redirect(request.GET['next'])|,
          ~s|return HttpResponseRedirect(request.META.get('HTTP_REFERER'))|,
          ~s|APPEND_SLASH = True
MIDDLEWARE = ['django.middleware.common.CommonMiddleware']|,
          ~s|redirect_url = request.GET.get('url')
return redirect(redirect_url)|
        ],
        safe: [
          ~s|# Django 2.1.2+ handles this safely
from django.utils.http import is_safe_url
if is_safe_url(url, allowed_hosts={request.get_host()}):
    return redirect(url)|,
          ~s|# Safe default redirect
next_url = request.GET.get('next', '/')
return redirect('/dashboard/')|,
          ~s|# Validate against whitelist
ALLOWED_REDIRECTS = ['/dashboard/', '/profile/']
if redirect_url in ALLOWED_REDIRECTS:
    return redirect(redirect_url)|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      CVE-2018-14574 is an open redirect vulnerability affecting Django's CommonMiddleware 
      when used with the APPEND_SLASH setting. The vulnerability occurs when Django 
      automatically appends slashes to URLs and performs redirects without proper validation 
      of the destination URL.

      This vulnerability specifically affects applications that have both CommonMiddleware 
      enabled and URL patterns that accept paths ending with slashes. Attackers can craft 
      malicious URLs that exploit Django's URL normalization process to redirect users to 
      external malicious sites.

      The issue was discovered as part of Django's security audit and affects a significant 
      number of Django applications since CommonMiddleware and APPEND_SLASH are default 
      settings. The vulnerability is particularly dangerous because it allows attackers to 
      create legitimate-looking URLs that redirect to phishing sites.
      """,
      references: [
        %{
          type: :cve,
          id: "CVE-2018-14574",
          title: "Django Open redirect possibility in CommonMiddleware",
          url: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14574"
        },
        %{
          type: :cwe,
          id: "CWE-601",
          title: "URL Redirection to Untrusted Site ('Open Redirect')",
          url: "https://cwe.mitre.org/data/definitions/601.html"
        },
        %{
          type: :advisory,
          id: "GHSA-5hg3-6c2f-f3wr",
          title: "Django open redirect vulnerability in CommonMiddleware",
          url: "https://github.com/advisories/GHSA-5hg3-6c2f-f3wr"
        },
        %{
          type: :security_release,
          id: "Django-2018-08-01",
          title: "Django security releases issued: 2.0.8 and 1.11.15",
          url: "https://www.djangoproject.com/weblog/2018/aug/01/security-releases/"
        },
        %{
          type: :research,
          id: "StackHawk-Django-Open-Redirect",
          title: "Django Open Redirect Guide: Examples and Prevention",
          url:
            "https://www.stackhawk.com/blog/django-open-redirect-guide-examples-and-prevention/"
        }
      ],
      attack_vectors: [
        "Malicious URL crafting exploiting APPEND_SLASH behavior in CommonMiddleware",
        "Phishing attacks using legitimate domain names to redirect to malicious sites",
        "Social engineering attacks leveraging trusted URLs for credential harvesting",
        "URL manipulation in applications with wildcard path patterns",
        "Cross-site redirect chains for bypassing referrer-based security controls"
      ],
      real_world_impact: [
        "Phishing attacks targeting users with legitimate-looking URLs from trusted domains",
        "Social engineering campaigns exploiting user trust in familiar domain names",
        "Credential harvesting through redirect-based attacks to fake login pages",
        "Malware distribution via redirects to compromised or malicious websites",
        "Reputation damage to legitimate sites used as redirect intermediaries"
      ],
      cve_examples: [
        %{
          id: "CVE-2018-14574",
          description:
            "Django CommonMiddleware open redirect vulnerability allowing phishing attacks via malicious URL redirection",
          severity: "medium",
          cvss: 6.1,
          note: "NIST CVSS 3.1 score - medium severity with user interaction required"
        }
      ],
      detection_notes: """
      This pattern detects:
      1. APPEND_SLASH setting enabled in Django configuration
      2. CommonMiddleware usage in MIDDLEWARE setting
      3. Direct usage of request parameters in redirect() and HttpResponseRedirect()
      4. Unsafe redirect patterns without URL validation
      5. HTTP_REFERER usage in redirect operations

      The pattern focuses on identifying configurations and code patterns that create 
      open redirect vulnerabilities, particularly those related to Django's automatic 
      slash appending behavior and unsafe user input handling in redirect operations.
      """,
      safe_alternatives: [
        "Update Django 2.1.2+, Django 2.0.9+, or Django 1.11.16+ which includes the security fix",
        "Use django.utils.http.is_safe_url() to validate redirect URLs against allowed hosts",
        "Implement URL whitelisting for allowed redirect destinations",
        "Disable APPEND_SLASH setting if automatic slash appending is not required",
        "Use relative URLs or hardcoded safe URLs instead of user-provided redirect targets"
      ],
      additional_context: %{
        common_mistakes: [
          "Using request parameters directly in redirect functions without validation",
          "Assuming Django's URL processing automatically prevents open redirects",
          "Not implementing proper URL validation when accepting redirect parameters",
          "Relying solely on client-side validation for redirect URL security"
        ],
        secure_patterns: [
          "Always validate redirect URLs against a whitelist of allowed destinations",
          "Use Django's is_safe_url() function for redirect URL validation",
          "Implement default safe redirects when user-provided URLs are invalid",
          "Log and monitor redirect attempts for security analysis"
        ],
        framework_specific_notes: [
          "This vulnerability specifically affects Django's CommonMiddleware component",
          "APPEND_SLASH is a default Django setting that enables automatic slash appending",
          "The vulnerability requires both CommonMiddleware and URL patterns accepting trailing slashes",
          "Upgrading Django versions automatically fixes the underlying middleware issue"
        ]
      }
    }
  end

  @impl true
  def ast_enhancement do
    %{
      ast_rules: [
        %{
          type: :exclusion,
          patterns: [
            ~r/Django.*2\.1\.2|Django.*2\.0\.9|Django.*1\.11\.16/,
            ~r/is_safe_url\s*\(/,
            ~r/allowed_hosts\s*=.*request\.get_host/,
            ~r/ALLOWED_REDIRECTS\s*=|redirect_whitelist\s*=/,
            ~r/APPEND_SLASH\s*=\s*False/
          ],
          description:
            "Exclude if using patched Django versions, URL validation, or APPEND_SLASH disabled"
        },
        %{
          type: :validation,
          context: %{
            required_imports: ["django.middleware.common", "django.http"],
            file_patterns: ["settings.py", "*.py"],
            framework_indicators: ["django", "MIDDLEWARE", "redirect", "HttpResponseRedirect"]
          },
          description: "Validate Django middleware and redirect context"
        },
        %{
          type: :confidence_adjustment,
          adjustments: %{
            direct_user_input_to_redirect: 0.9,
            append_slash_with_commonmiddleware: 0.8,
            http_referer_in_redirect: 0.85,
            request_parameter_in_redirect: 0.75
          },
          description: "Adjust confidence based on redirect and middleware usage patterns"
        }
      ],
      min_confidence: 0.6
    }
  end
end
