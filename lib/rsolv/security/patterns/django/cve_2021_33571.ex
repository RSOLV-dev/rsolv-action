defmodule Rsolv.Security.Patterns.Django.Cve202133571 do
  @moduledoc """
  Django CVE-2021-33571 - IPv4 Address Validation Bypass via Leading Zeros

  This pattern detects Django applications vulnerable to CVE-2021-33571, where
  URLValidator, validate_ipv4_address, and validate_ipv46_address functions do not
  prohibit leading zero characters in octal literals, potentially allowing bypass
  of IP address-based access control.

  ## Vulnerability Details

  The vulnerability affects Django versions:
  - 2.2 before 2.2.24
  - 3.x before 3.1.12
  - 3.2 before 3.2.4

  Leading zeros in IPv4 addresses can be interpreted as octal literals by some
  systems, causing validation bypass. For example:
  - `0177.0.0.1` = `127.0.0.1` (localhost)
  - `0300.0.0.1` = `192.0.0.1`

  ### Attack Example
  ```python
  from django.core.validators import URLValidator, validate_ipv4_address

  # Vulnerable: Accepts octal IP addresses
  validator = URLValidator()
  validator('http://0177.0.0.1/admin/')  # Bypasses localhost restrictions

  # Vulnerable: Direct validation bypass
  ip = request.GET.get('ip_address')  # User provides "0177.0.0.1"
  validate_ipv4_address(ip)  # Passes validation but resolves to 127.0.0.1
  ```

  ### Safe Example
  ```python
  # Safe: Updated Django versions handle this correctly
  from django.core.validators import URLValidator, validate_ipv4_address

  # Django 3.2.4+ rejects leading zeros in IP addresses
  validator = URLValidator()
  try:
      validator('http://0177.0.0.1/admin/')  # Raises ValidationError
  except ValidationError:
      # Handle invalid IP address
      pass
  ```
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @impl true
  def pattern do
    %Pattern{
      id: "django-cve-2021-33571",
      name: "Django CVE-2021-33571 - IPv4 Validation Bypass",
      description:
        "IPv4 addresses with leading zeros can bypass validation in URLValidator and validate_ipv4_address",
      type: :input_validation,
      severity: :high,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        ~r/URLValidator\s*\(\s*\)(?!.*schemes)/,
        ~r/validate_ipv4_address\s*\(\s*request\./,
        ~r/validate_ipv46_address\s*\(\s*request\./,
        ~r/URLValidator\s*\(\s*\)\s*\(\s*['\"]?http:\/\/0\d+\./,
        ~r/from\s+django\.core\.validators\s+import.*URLValidator/,
        ~r/from\s+django\.core\.validators\s+import.*validate_ipv4_address/
      ],
      cwe_id: "CWE-20",
      owasp_category: "A03:2021",
      recommendation:
        "Update Django to 3.2.4+, 3.1.12+, or 2.2.24+ and validate IP addresses properly",
      test_cases: %{
        vulnerable: [
          ~s|URLValidator()(user_url)|,
          ~s|validate_ipv4_address(request.GET['ip'])|,
          ~s|validate_ipv46_address(request.POST.get('address'))|,
          ~s|validator = URLValidator()
validator('http://0177.0.0.1/')|
        ],
        safe: [
          ~s|# Django 3.2.4+ handles this correctly
URLValidator(schemes=['http', 'https'])(user_url)|,
          ~s|# Django 3.1.12+ rejects leading zeros
validate_ipv4_address(validated_ip)|,
          ~s|# Updated Django 2.2.24+ version
from django.core.validators import URLValidator
validator = URLValidator()
# Now properly rejects octal IP addresses|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      CVE-2021-33571 affects Django's URLValidator, validate_ipv4_address, and validate_ipv46_address
      functions which do not prohibit leading zero characters in octal literals. This allows attackers
      to potentially bypass IP address-based access control by using octal notation for IP addresses
      (e.g., 0177.0.0.1 = 127.0.0.1).

      The vulnerability can lead to Server-Side Request Forgery (SSRF), Remote File Inclusion (RFI),
      and Local File Inclusion (LFI) attacks when applications rely on IP address validation for
      access control or URL filtering.
      """,
      references: [
        %{
          type: :cve,
          id: "CVE-2021-33571",
          title: "Django Access Control Bypass possibly leading to SSRF, RFI, and LFI attacks",
          url: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33571"
        },
        %{
          type: :cwe,
          id: "CWE-20",
          title: "Improper Input Validation",
          url: "https://cwe.mitre.org/data/definitions/20.html"
        },
        %{
          type: :advisory,
          id: "GHSA-p99v-5w3c-jqq9",
          title: "Django - GitHub Security Advisory",
          url: "https://github.com/advisories/GHSA-p99v-5w3c-jqq9"
        },
        %{
          type: :security_release,
          id: "Django-2021-06-02",
          title: "Django security releases issued: 3.2.4, 3.1.12, and 2.2.24",
          url: "https://www.djangoproject.com/weblog/2021/jun/02/security-releases/"
        }
      ],
      attack_vectors: [
        "SSRF (Server-Side Request Forgery) via octal IP address manipulation",
        "RFI (Remote File Inclusion) through validation bypass",
        "LFI (Local File Inclusion) using localhost octal notation",
        "Access control bypass using equivalent octal IP representations",
        "Internal network enumeration via octal IP scanning"
      ],
      real_world_impact: [
        "Access control bypass allowing unauthorized network access",
        "Internal network scanning and enumeration capabilities",
        "Potential data exfiltration via SSRF attacks",
        "Administrative interface access via localhost bypass",
        "Cloud metadata service access in cloud environments"
      ],
      cve_examples: [
        %{
          id: "CVE-2021-33571",
          description:
            "Django URLValidator and IP validation functions allow leading zeros in IPv4 addresses",
          severity: "high",
          cvss: 7.5,
          note: "NIST CVSS 3.x score. GitHub Advisory Database rates it as 8.7/10"
        }
      ],
      detection_notes: """
      This pattern detects:
      1. URLValidator usage without schemes restriction
      2. validate_ipv4_address with user input
      3. validate_ipv46_address with request data
      4. Direct import of vulnerable validator functions
      5. Octal IP address patterns with leading zero notation in code

      The pattern focuses on Django applications using these validators with user-controlled input,
      particularly in contexts where IP address validation is used for access control.
      """,
      safe_alternatives: [
        "Update Django to version 3.2.4+, 3.1.12+, or 2.2.24+",
        "Use URLValidator with explicit schemes parameter: URLValidator(schemes=['http', 'https'])",
        "Implement additional input validation to reject octal notation IP addresses",
        "Use whitelist-based URL validation instead of blacklist approaches",
        "Validate IP addresses using ipaddress module with strict parsing"
      ],
      additional_context: %{
        common_mistakes: [
          "Relying solely on Django validators for security-critical IP validation",
          "Not updating Django framework despite security advisories",
          "Using user input directly in IP validation without sanitization",
          "Implementing IP-based access control without considering octal literal notation"
        ],
        secure_patterns: [
          "Always use latest stable Django versions",
          "Implement defense-in-depth for access control",
          "Use explicit scheme validation in URLValidator",
          "Sanitize and normalize IP addresses before validation"
        ],
        framework_specific_notes: [
          "This affects Django core validators, not third-party packages",
          "The fix involves rejecting IPv4 addresses with leading zeros",
          "Affects both URLValidator and standalone IP validation functions",
          "Impact varies based on how IP validation is used in access control"
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
            ~r/URLValidator\s*\(\s*schemes\s*=/,
            ~r/Django.*3\.2\.4|Django.*3\.1\.12|Django.*2\.2\.24/,
            ~r/version.*>=.*3\.2\.4|version.*>=.*3\.1\.12|version.*>=.*2\.2\.24/
          ],
          description: "Exclude if schemes parameter is used or Django version is patched"
        },
        %{
          type: :validation,
          context: %{
            required_imports: ["django.core.validators"],
            file_patterns: ["*.py"],
            framework_indicators: ["django", "Django"]
          },
          description: "Validate Django context and framework usage"
        },
        %{
          type: :confidence_adjustment,
          adjustments: %{
            urlvalidator_without_schemes: 0.8,
            direct_ip_validation_with_request: 0.9,
            octal_ip_pattern_detected: 0.95
          },
          description: "Adjust confidence based on specific vulnerability indicators"
        }
      ],
      min_confidence: 0.7
    }
  end
end
