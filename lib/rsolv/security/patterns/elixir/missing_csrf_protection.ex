defmodule Rsolv.Security.Patterns.Elixir.MissingCsrfProtection do
  @moduledoc """
  Detects missing CSRF (Cross-Site Request Forgery) protection in Phoenix forms.

  This pattern identifies instances where CSRF protection is explicitly disabled
  or missing in Phoenix forms, which can lead to unauthorized actions being performed
  on behalf of authenticated users.

  ## Vulnerability Details

  CSRF attacks occur when a malicious website tricks an authenticated user's browser
  into submitting a request to a vulnerable application. Without proper CSRF protection,
  attackers can perform unauthorized actions such as:
  - Changing user passwords or email addresses
  - Transferring money or making purchases
  - Modifying user settings or data
  - Performing any state-changing action the user is authorized to do

  Phoenix provides excellent CSRF protection by default, but developers can accidentally
  disable it or forget to include it in manual forms.

  ### Attack Example

  Vulnerable code:
  ```elixir
  # Form with CSRF protection explicitly disabled
  form_for(@changeset, Routes.user_path(@conn, :update), [csrf_token: false], fn f ->
    # form fields...
  end)

  # Manual form without CSRF token
  <form action="/transfer-money" method="post">
    <input name="amount" value="1000">
    <input name="to_account" value="attacker_account">
    <button>Transfer</button>
  </form>
  ```

  An attacker could create a malicious page:
  ```html
  <!-- Malicious page that tricks user into submitting the form -->
  <form action="https://vulnerable-bank.com/transfer-money" method="post" style="display:none">
    <input name="amount" value="1000">
    <input name="to_account" value="attacker_account">
  </form>
  <script>document.forms[0].submit();</script>
  ```

  ### Safe Alternative

  Safe code:
  ```elixir
  # Phoenix forms include CSRF protection by default
  form_for(@changeset, Routes.user_path(@conn, :update), fn f ->
    # CSRF token automatically included
  end)

  # Manual form with CSRF token
  <form action="/transfer-money" method="post">
    <input type="hidden" name="_csrf_token" value="<%= csrf_token %>">
    <input name="amount" value="1000">
    <input name="to_account" value="user_account">
    <button>Transfer</button>
  </form>

  # Form with explicit CSRF protection
  form_for(@changeset, Routes.user_path(@conn, :update), [csrf_token: true], fn f ->
    # form fields...
  end)
  ```
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @impl true
  def pattern do
    %Pattern{
      id: "elixir-missing-csrf-protection",
      name: "Missing CSRF Protection",
      description:
        "Forms without CSRF tokens are vulnerable to cross-site request forgery attacks",
      type: :csrf,
      severity: :medium,
      languages: ["elixir"],
      frameworks: ["phoenix"],
      regex: [
        # form_for with csrf_token: false (handles multiline and nested parens)
        ~r/form_for\s*\(.*?csrf_token:\s*false/s,
        # form_with with csrf: false
        ~r/form_with\s*\(.*?csrf:\s*false/s,
        # Phoenix.HTML.Form.form_for with csrf_token: false
        ~r/Phoenix\.HTML\.Form\.form_for\s*\(.*?csrf_token:\s*false/s,
        # Manual forms without CSRF token (POST, PUT, DELETE, PATCH)
        ~r/<form[^>]+method\s*=\s*["'](?:post|put|delete|patch)["'][^>]*>(?![^<]*_csrf_token)/i,
        # Plug.CSRFProtection.delete_csrf_token usage
        ~r/Plug\.CSRFProtection\.delete_csrf_token\s*\(\s*\)/,
        # Manually disabling CSRF protection in pipelines
        ~r/plug\s+:protect_from_forgery\s*,\s*\[\s*with:\s*:clear_session\s*\]/,
        # Forms in templates without csrf_token
        ~r/<%=?\s*form_for[^%]*csrf_token:\s*false/,
        # LiveView forms without CSRF (edge case)
        ~r/phx-submit\s*=\s*["'][^"']*["'][^>]*>(?![^<]*csrf)/i
      ],
      cwe_id: "CWE-352",
      owasp_category: "A01:2021",
      recommendation:
        "Enable CSRF protection in all state-changing forms. Phoenix includes it by default.",
      test_cases: %{
        vulnerable: [
          ~S|form_for(@changeset, Routes.user_path(@conn, :create), [csrf_token: false], fn f ->|,
          ~S|form_with(@changeset, csrf: false) do|,
          ~S|Phoenix.HTML.Form.form_for(@changeset, @action, [csrf_token: false])|,
          ~S|<form action="/submit" method="post">|,
          ~S|Plug.CSRFProtection.delete_csrf_token()|
        ],
        safe: [
          ~S|form_for(@changeset, Routes.user_path(@conn, :create), fn f ->|,
          ~S|form_for(@changeset, Routes.user_path(@conn, :create), [csrf_token: true], fn f ->|,
          ~S|form_with(@changeset) do|,
          ~S|<form><input type="hidden" name="_csrf_token" value="<%= csrf_token %>"></form>|,
          ~S|<form action="/search" method="get">|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Cross-Site Request Forgery (CSRF) is a web security vulnerability that allows an attacker
      to induce users to perform actions that they do not intend to perform. In the context of
      Phoenix applications, this typically occurs when forms lack proper CSRF token protection.

      Phoenix provides excellent CSRF protection by default through the Plug.CSRFProtection plug,
      which automatically generates and validates CSRF tokens. However, developers can accidentally
      disable this protection or forget to include it in manually constructed forms.

      CSRF attacks are particularly dangerous because they:
      - Exploit the trust a website has in a user's browser
      - Can be executed without the user's knowledge
      - Use the user's existing authentication/session
      - Can perform any action the user is authorized to do
      - Often leave no trace in server logs

      In Phoenix applications, CSRF vulnerabilities commonly occur when:
      - Setting csrf_token: false in form_for or form_with helpers
      - Creating manual HTML forms without including _csrf_token
      - Disabling CSRF protection in controller pipelines
      - Using AJAX requests without CSRF headers
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
          title: "OWASP Top 10 2021 - A01 Broken Access Control",
          url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
        },
        %{
          type: :owasp,
          id: "csrf_prevention",
          title: "OWASP CSRF Prevention Cheat Sheet",
          url:
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
        },
        %{
          type: :framework,
          id: "phoenix_csrf",
          title: "Phoenix CSRF Protection Documentation",
          url: "https://hexdocs.pm/plug/Plug.CSRFProtection.html"
        },
        %{
          type: :research,
          id: "paraxial_csrf",
          title: "Introduction to Cross Site Request Forgery (CSRF) - Paraxial",
          url: "https://paraxial.io/blog/csrf-intro"
        }
      ],
      attack_vectors: [
        "Malicious website with hidden forms that auto-submit to target application",
        "Email with embedded malicious form or image that triggers request",
        "Social engineering to click malicious links while authenticated",
        "Malicious browser extensions performing unauthorized actions",
        "Drive-by downloads with embedded CSRF exploits",
        "Compromised third-party websites with injected CSRF attacks",
        "Image tags with malicious src URLs performing GET-based CSRF"
      ],
      real_world_impact: [
        "uTorrent vulnerability (CVE-2009-4501) allowed remote command execution via CSRF",
        "Banking applications compromised allowing unauthorized money transfers",
        "Social media account takeovers through profile modification attacks",
        "E-commerce platforms enabling unauthorized purchases",
        "Admin panel compromises leading to system configuration changes",
        "Password change attacks locking users out of accounts",
        "Data modification attacks in business applications"
      ],
      cve_examples: [
        %{
          id: "CVE-2022-42975",
          description:
            "Phoenix Origin Validation Error in socket/transport check_origin wildcarding",
          severity: "medium",
          cvss: 6.5,
          note: "Related to Phoenix security but focused on WebSocket origin validation"
        },
        %{
          id: "CVE-2009-4501",
          description: "uTorrent CSRF vulnerability allowing remote command execution",
          severity: "high",
          cvss: 8.8,
          note: "Classic example of CSRF enabling remote code execution"
        }
      ],
      detection_notes: """
      This pattern detects:
      - form_for and form_with helpers with explicit csrf_token: false or csrf: false
      - Phoenix.HTML.Form.form_for with disabled CSRF protection
      - Manual HTML forms using POST/PUT/DELETE/PATCH without _csrf_token
      - Plug.CSRFProtection.delete_csrf_token() function calls
      - Controller pipelines that disable CSRF protection
      - Template forms with explicitly disabled CSRF tokens
      - LiveView forms without proper CSRF protection
      """,
      safe_alternatives: [
        "Use Phoenix form helpers with default CSRF protection: form_for(@changeset, @action, fn f ->",
        "Include CSRF tokens in manual forms: <input type=\"hidden\" name=\"_csrf_token\" value=\"<%= csrf_token %>\">",
        "Use CSRF tokens in AJAX requests: headers: {'X-CSRF-TOKEN': csrf_token}",
        "Enable CSRF protection in controller pipelines: plug :protect_from_forgery, with: :exception",
        "Use form_with helper which includes CSRF by default",
        "For APIs, use proper authentication tokens instead of session-based auth",
        "Implement SameSite cookie attributes for additional protection"
      ],
      additional_context: %{
        common_mistakes: [
          "Disabling CSRF for 'convenience' during development and forgetting to re-enable",
          "Assuming AJAX requests are safe from CSRF (they're not without proper headers)",
          "Using GET requests for state-changing operations to 'avoid' CSRF",
          "Implementing custom CSRF protection instead of using Phoenix's built-in protection",
          "Forgetting to include CSRF tokens in manually constructed forms",
          "Disabling CSRF globally instead of handling specific cases properly"
        ],
        secure_patterns: [
          "Always use Phoenix's default CSRF protection",
          "Include CSRF tokens in all state-changing requests",
          "Use POST/PUT/DELETE/PATCH appropriately for state changes",
          "Implement proper error handling for CSRF validation failures",
          "Use SameSite cookie attributes for defense in depth",
          "Validate referrer headers as additional protection"
        ],
        phoenix_specific: [
          "Phoenix includes CSRF protection by default in generated applications",
          "CSRF tokens are automatically included in form_for and form_with helpers",
          "The protect_from_forgery plug should be included in browser pipelines",
          "LiveView handles CSRF protection automatically for most cases",
          "API pipelines typically don't need CSRF protection (use proper auth instead)"
        ]
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between legitimate cases where CSRF might
  be disabled (like API endpoints) and actual security vulnerabilities.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Elixir.MissingCsrfProtection.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]

      iex> enhancement = Rsolv.Security.Patterns.Elixir.MissingCsrfProtection.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        form_analysis: %{
          check_form_helpers: true,
          form_functions: ["form_for", "form_with", "form"],
          csrf_parameters: ["csrf_token", "csrf"],
          check_method_analysis: true
        },
        template_analysis: %{
          check_html_forms: true,
          state_changing_methods: ["post", "put", "delete", "patch"],
          csrf_field_names: ["_csrf_token", "csrf_token"],
          check_hidden_inputs: true
        },
        pipeline_analysis: %{
          check_plug_usage: true,
          csrf_plugs: ["protect_from_forgery", "Plug.CSRFProtection"],
          check_pipeline_context: true
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/_test\.exs$/, ~r/api/],
        phoenix_contexts: ["form_for", "form_with", "Phoenix.HTML", "template", "html"],
        api_contexts: ["json", "api", "graphql", "rest"],
        legitimate_disabling: ["api", "webhook", "external", "cors", "health_check"],
        exclude_if_api: true,
        exclude_if_get_method: true
      },
      confidence_rules: %{
        base: 0.7,
        adjustments: %{
          "csrf_disabled" => 0.3,
          "state_changing_form" => 0.2,
          "in_api_context" => -1.0,
          "in_test_code" => -1.0,
          "get_method_form" => -0.8,
          "manual_html_form" => 0.1,
          "explicit_false_setting" => 0.4
        }
      },
      min_confidence: 0.8
    }
  end
end
