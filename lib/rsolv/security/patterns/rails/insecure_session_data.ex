defmodule Rsolv.Security.Patterns.Rails.InsecureSessionData do
  @moduledoc """
  Rails Insecure Session Data Storage Pattern.

  Detects storage of sensitive information in Rails session cookies, which can lead
  to data exposure, compliance violations, and security breaches.

  ## Vulnerability Details

  Rails sessions are typically stored in cookies (CookieStore) which, while encrypted,
  are transmitted with every request and stored on the client side. Storing sensitive
  data in sessions creates several risks:

  1. **Data Exposure**: Session cookies can be intercepted or leaked
  2. **Compliance Violations**: Violates PCI DSS, GDPR, HIPAA requirements
  3. **Client-Side Storage**: Sensitive data leaves server control
  4. **Session Replay**: Old session cookies may contain outdated sensitive data

  ### Attack Example
  ```ruby
  # Vulnerable: Storing sensitive data in session
  def login
    if user.authenticate(params[:password])
      session[:user_id] = user.id
      session[:password] = params[:password]  # DANGEROUS!
      session[:credit_card] = user.credit_card  # DANGEROUS!
      session[:ssn] = user.ssn  # DANGEROUS!
    end
  end
  ```

  ### Safe Example
  ```ruby
  # Safe: Only store non-sensitive identifiers
  def login
    if user.authenticate(params[:password])
      session[:user_id] = user.id  # Safe - just an ID
      session[:role] = user.role   # Safe - not sensitive
      # Store sensitive data in database with session ID reference
    end
  end
  ```
  """

  use Rsolv.Security.Patterns.PatternBase

  def pattern do
    %Rsolv.Security.Pattern{
      id: "rails-insecure-session-data",
      name: "Sensitive Data in Session",
      description: "Storing sensitive information in session cookies",
      type: :sensitive_data_exposure,
      severity: :high,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        # Authentication credentials (exclude commented lines)
        ~r/^(?!.*#).*session\[:password\]/,
        ~r/^(?!.*#).*session\['password'\]/,
        ~r/^(?!.*#).*session\["password"\]/,
        ~r/^(?!.*#).*session\[:user_password\]/,
        ~r/^(?!.*#).*session\[:admin_password\]/,
        ~r/^(?!.*#).*session\[:current_password\]/,

        # Financial information (exclude commented lines)
        ~r/^(?!.*#).*session\[:credit_card\]/,
        ~r/^(?!.*#).*session\['credit_card'\]/,
        ~r/^(?!.*#).*session\["credit_card"\]/,
        ~r/^(?!.*#).*session\[:cc_number\]/,
        ~r/^(?!.*#).*session\[:card_number\]/,
        ~r/^(?!.*#).*session\[:payment_card\]/,
        ~r/^(?!.*#).*session\[:bank_account\]/,
        ~r/^(?!.*#).*session\[:account_number\]/,
        ~r/^(?!.*#).*session\[:routing_number\]/,
        ~r/^(?!.*#).*session\[:iban\]/,
        ~r/^(?!.*#).*session\[:financial_data\]/,
        ~r/^(?!.*#).*session\[:balance\]/,

        # Personal identifiers (exclude commented lines)
        ~r/^(?!.*#).*session\[:ssn\]/,
        ~r/^(?!.*#).*session\['ssn'\]/,
        ~r/^(?!.*#).*session\["ssn"\]/,
        ~r/^(?!.*#).*session\[:social_security\]/,
        ~r/^(?!.*#).*session\[:tax_id\]/,
        ~r/^(?!.*#).*session\[:national_id\]/,

        # API keys and tokens (exclude commented lines)
        ~r/^(?!.*#).*session\[:api_key\]/,
        ~r/^(?!.*#).*session\['api_key'\]/,
        ~r/^(?!.*#).*session\["api_key"\]/,
        ~r/^(?!.*#).*session\[:secret_token\]/,
        ~r/^(?!.*#).*session\[:auth_token\]/,
        ~r/^(?!.*#).*session\[:access_token\]/,

        # Private keys and certificates (exclude commented lines)
        ~r/^(?!.*#).*session\[:private_key\]/,
        ~r/^(?!.*#).*session\['private_key'\]/,
        ~r/^(?!.*#).*session\["private_key"\]/,
        ~r/^(?!.*#).*session\[:ssl_key\]/,
        ~r/^(?!.*#).*session\[:encryption_key\]/,
        ~r/^(?!.*#).*session\[:cert_key\]/,

        # Medical and health information (exclude commented lines)
        ~r/^(?!.*#).*session\[:medical_record\]/,
        ~r/^(?!.*#).*session\[:health_info\]/,
        ~r/^(?!.*#).*session\[:diagnosis\]/,
        ~r/^(?!.*#).*session\[:medication\]/,
        ~r/^(?!.*#).*session\[:treatment\]/,
        ~r/^(?!.*#).*session\[:patient_data\]/
      ],
      cwe_id: "CWE-200",
      owasp_category: "A02:2021",
      recommendation:
        "Store only non-sensitive identifiers in Rails sessions. Keep sensitive data in secure server-side storage, not Rails session cookies.",
      test_cases: %{
        vulnerable: [
          "session[:password] = params[:password]",
          "session[:credit_card] = user.credit_card",
          "session[:ssn] = user.ssn",
          "session[:api_key] = api_token"
        ],
        safe: [
          "session[:user_id] = user.id",
          "session[:role] = user.role",
          "session[:theme] = 'dark'",
          "session[:locale] = 'en'"
        ]
      }
    }
  end

  def vulnerability_metadata do
    %{
      description: """
      Insecure Session Data Storage in Rails applications occurs when sensitive
      information such as passwords, credit card numbers, SSNs, API keys, or
      private keys are stored in Rails session cookies. Even though Rails
      encrypts session cookies, storing sensitive data in sessions violates
      security best practices and compliance requirements, creating multiple
      attack vectors and regulatory violations.
      """,
      attack_vectors: """
      1. Session Cookie Interception: Network-level interception of session cookies
      2. Client-Side Extraction: Malware extracting cookies from browser storage
      3. Session Replay Attacks: Reusing old session cookies with sensitive data
      4. Proxy Caching: Accidental caching of Set-Cookie headers by proxies
      5. Cross-Site Scripting: XSS attacks extracting session cookies
      6. Man-in-the-Middle: MITM attacks on insecure connections
      """,
      business_impact: """
      - Regulatory compliance violations (PCI DSS, GDPR, HIPAA, SOX)
      - Financial penalties and legal liability for data breaches
      - Loss of customer trust and brand reputation damage
      - Identity theft and financial fraud involving customer data
      - Competitive disadvantage from security incidents
      - Audit failures and certification revocations
      - Insurance claims and litigation costs
      """,
      technical_impact: """
      - Complete exposure of sensitive user data stored in sessions
      - Unauthorized access to financial and personal information
      - Compromise of authentication credentials and API keys
      - Data persistence in browser history and cache files
      - Potential for credential stuffing and account takeover
      - Violation of data minimization and privacy principles
      """,
      likelihood:
        "High - Storing sensitive data in sessions is a common mistake in Rails applications, especially in custom authentication implementations",
      cve_examples: """
      CVE-2024-26144 - Rails Active Storage sensitive session information leak
      CVE-2022-23633 - Rails information exposure vulnerability in Action Pack
      GHSA-44vf-8ffm-v2qh - Sensitive data exposure in rails-session-decoder
      GHSA-8h22-8cf7-hq6g - Active Storage session cookie caching vulnerability
      """,
      compliance_standards: [
        "OWASP Top 10 2021 - A02: Cryptographic Failures",
        "CWE-200: Information Exposure",
        "PCI DSS 3.2.1 - Requirements 3.4, 4.1",
        "GDPR Article 25 - Data Protection by Design",
        "HIPAA Security Rule 164.312(a)(1)",
        "NIST SP 800-63B - Session Management",
        "SOX Section 404 - Internal Controls"
      ],
      remediation_steps: """
      1. Store only non-sensitive identifiers (user_id, role) in Rails sessions
      2. Move sensitive data to secure server-side storage (database, Redis)
      3. Use session references to retrieve sensitive data when needed
      4. Implement proper data classification and handling policies
      5. Enable secure session configuration (HTTPOnly, Secure flags)
      6. Regular audit of session data storage practices
      """,
      prevention_tips: """
      - Never store passwords, credit cards, SSNs, or API keys in sessions
      - Use database or encrypted server-side storage for sensitive data
      - Store only the minimum required data in session cookies
      - Implement data classification policies for development teams
      - Use Rails secure session configuration defaults
      - Regular security code reviews focusing on session usage
      - Implement automated scanning for sensitive data in sessions
      """,
      detection_methods: """
      - Static analysis tools like Brakeman for Rails session usage
      - Code review focusing on session assignment statements
      - Dynamic testing with session cookie analysis
      - Automated scanning for sensitive data patterns in sessions
      - Compliance audits and penetration testing
      - Runtime monitoring of session cookie contents
      """,
      safe_alternatives: """
      # Safe Rails session management
      class SessionsController < ApplicationController
        def create
          user = User.authenticate(params[:email], params[:password])
          if user
            reset_session  # Prevent session fixation
            session[:user_id] = user.id  # Safe - just an ID
            session[:role] = user.role   # Safe - not sensitive

            # Store sensitive data server-side with session reference
            Rails.cache.write("user_session_\#{session.id}", {
              encrypted_data: user.sensitive_data.encrypt
            }, expires_in: 30.minutes)

            redirect_to dashboard_path
          end
        end

      # Retrieve sensitive data when needed
      def get_user_sensitive_data
        session_data = Rails.cache.read("user_session_\#{session.id}")
        session_data&.dig(:encrypted_data)&.decrypt
      end
      """
    }
  end

  def ast_enhancement do
    %{
      min_confidence: 0.8,
      context_rules: %{
        # Patterns that indicate sensitive data
        sensitive_data_patterns: [
          ~r/password/i,
          ~r/credit_card/i,
          ~r/ssn/i,
          ~r/social_security/i,
          ~r/api_key/i,
          ~r/secret_token/i,
          ~r/private_key/i,
          ~r/bank_account/i,
          ~r/medical/i,
          ~r/health/i,
          ~r/diagnosis/i,
          ~r/financial/i
        ],

        # Session fields that are typically safe
        safe_session_fields: [
          "user_id",
          "username",
          "role",
          "permissions",
          "locale",
          "timezone",
          "theme",
          "preferences",
          "last_login",
          "visited_pages",
          "cart_id",
          "current_page",
          "referrer",
          "flash_messages"
        ],

        # Context patterns that reduce false positives
        safe_patterns: [
          # User ID is safe
          ~r/session\[:user_id\]/,
          # User role is safe
          ~r/session\[:role\]/,
          # User preferences
          ~r/session\[:preferences\]/,
          # UI theme
          ~r/session\[:theme\]/,
          # Language setting
          ~r/session\[:locale\]/,
          # Timezone setting
          ~r/session\[:timezone\]/,
          # Commented code
          ~r/#.*session\[:/,
          # Flash messages
          ~r/flash\[:/,
          # Cookies, not sessions
          ~r/cookies\[:/
        ]
      },
      confidence_rules: %{
        adjustments: %{
          # High confidence indicators
          contains_sensitive_keywords: +0.4,
          multiple_sensitive_fields: +0.3,
          financial_data_pattern: +0.5,
          authentication_data_pattern: +0.5,

          # Lower confidence adjustments
          safe_session_field: -0.6,
          commented_code: -1.0,
          test_file_context: -0.7,
          configuration_context: -0.5,

          # Context-based adjustments
          in_authentication_controller: +0.2,
          in_payment_controller: +0.4,
          in_admin_controller: +0.3
        }
      },
      ast_rules: %{
        # Session usage analysis
        session_analysis: %{
          check_session_assignments: true,
          detect_sensitive_data: true,
          validate_data_classification: true,
          check_compliance_requirements: true
        },

        # Data sensitivity analysis
        data_sensitivity: %{
          check_pii_patterns: true,
          detect_financial_data: true,
          validate_health_information: true,
          check_authentication_data: true
        }
      }
    }
  end
end
