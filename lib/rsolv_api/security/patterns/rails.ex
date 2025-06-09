defmodule RsolvApi.Security.Patterns.Rails do
  @moduledoc """
  Ruby on Rails framework-specific security patterns.
  
  This module contains 20 security patterns specifically designed for Rails
  applications. These patterns detect Rails-specific vulnerabilities beyond 
  base Ruby patterns. All patterns are tagged with frameworks: ["rails"].
  """
  
  alias RsolvApi.Security.Pattern
  
  @doc """
  Returns all Rails security patterns.
  
  ## Examples
  
      iex> patterns = RsolvApi.Security.Patterns.Rails.all()
      iex> length(patterns)
      20
      iex> Enum.all?(patterns, &match?(%Pattern{}, &1))
      true
      iex> Enum.all?(patterns, & &1.frameworks == ["rails"])
      true
  """
  def all do
    [
      missing_strong_parameters(),
      dangerous_attr_accessible(),
      activerecord_injection(),
      dynamic_finder_injection(),
      erb_injection(),
      template_xss(),
      unsafe_route_constraints(),
      unsafe_globbing(),
      insecure_session_config(),
      dangerous_production_config(),
      insecure_cors(),
      actionmailer_injection(),
      session_fixation(),
      insecure_session_data(),
      cve_2022_22577(),
      cve_2021_22880(),
      cve_2020_8264(),
      cve_2019_5418()
    ]
  end
  
  @doc """
  Missing Strong Parameters pattern.
  
  Detects Rails controllers using params without permit().
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Rails.missing_strong_parameters()
      iex> pattern.id
      "rails-strong-parameters"
      iex> pattern.frameworks
      ["rails"]
  """
  def missing_strong_parameters do
    %Pattern{
      id: "rails-strong-parameters",
      name: "Missing Strong Parameters",
      description: "Rails controllers using params without permit() allowing mass assignment",
      type: :mass_assignment,
      severity: :high,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        ~r/\.(create|update|update_attributes|assign_attributes)\s*\(\s*params(?!\s*\.\s*(require|permit))/,
        ~r/User\.new\s*\(\s*params\[/,
        ~r/\.permit!\s*\)/,
        ~r/\.(create!|update!)\s*\(\s*params\[/,
        ~r/\.insert_all\s*\(\s*params\[/,
        ~r/\.upsert_all\s*\(\s*params\[/
      ],
      default_tier: :protected,
      cwe_id: "CWE-915",
      owasp_category: "A01:2021",
      recommendation: "Use strong parameters with permit(): params.require(:model).permit(:field1, :field2). Never use permit! in production.",
      test_cases: %{
        vulnerable: [
          "@user = User.create(params[:user])"
        ],
        safe: [
          "@user = User.create(user_params)",
          "params.require(:user).permit(:name, :email)"
        ]
      }
    }
  end
  
  @doc """
  Dangerous attr_accessible Usage pattern.
  
  Detects overly permissive attr_accessible in older Rails versions.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Rails.dangerous_attr_accessible()
      iex> pattern.type
      :mass_assignment
  """
  def dangerous_attr_accessible do
    %Pattern{
      id: "rails-attr-accessible",
      name: "Dangerous attr_accessible Usage",
      description: "Overly permissive attr_accessible in older Rails versions or missing protection",
      type: :mass_assignment,
      severity: :high,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        ~r/class\s+\w+\s*<\s*ActiveRecord::Base[\s\S]+?end/,
        ~r/attr_accessible\s+:role\s*,\s*:admin/,
        ~r/attr_accessible\s+:password/,
        ~r/attr_accessible\s+:.*\s*,\s*:as\s*=>\s*:admin/
      ],
      default_tier: :protected,
      cwe_id: "CWE-915",
      owasp_category: "A01:2021",
      recommendation: "Upgrade to Rails 4+ and use strong parameters. If using older Rails, carefully restrict attr_accessible fields.",
      test_cases: %{
        vulnerable: [
          "attr_accessible :role, :admin"
        ],
        safe: [
          "attr_accessible :name, :email",
          "attr_protected :role, :admin"
        ]
      }
    }
  end
  
  @doc """
  ActiveRecord SQL Injection pattern.
  
  Detects SQL injection through ActiveRecord methods using string interpolation.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Rails.activerecord_injection()
      iex> vulnerable = "User.where(\\\"name = '\#{params[:name]}'\\\")"
      iex> Regex.match?(List.first(pattern.regex), vulnerable)
      true
  """
  def activerecord_injection do
    %Pattern{
      id: "rails-activerecord-injection",
      name: "ActiveRecord SQL Injection",
      description: "SQL injection through ActiveRecord methods using string interpolation",
      type: :sql_injection,
      severity: :critical,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        ~r/\.where\s*\(\s*["'`].*?#\{[^}]+\}/,
        ~r/\.joins\s*\(\s*["'`].*?#\{[^}]+\}/,
        ~r/\.group\s*\(\s*["'`].*?#\{[^}]+\}/,
        ~r/\.having\s*\(\s*["'`].*?#\{[^}]+\}/,
        ~r/\.order\s*\(\s*["'`].*?#\{[^}]+\}/,
        ~r/\.select\s*\(\s*["'`].*?#\{[^}]+\}/,
        ~r/\.find_by_sql\s*\(\s*["'`].*?#\{[^}]+\}/,
        ~r/\.count_by_sql\s*\(\s*["'`].*?#\{[^}]+\}/,
        ~r/\.exists\?\s*\(\s*\[["'`].*?#\{[^}]+\}/,
        ~r/\.update_all\s*\(\s*["'`].*?#\{[^}]+\}/,
        ~r/\.delete_all\s*\(\s*["'`].*?#\{[^}]+\}/
      ],
      default_tier: :protected,
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation: "Use Rails parameterized queries: where(\"name = ?\", params[:name]) or ActiveRecord hash conditions: where(name: params[:name])",
      test_cases: %{
        vulnerable: [
          "User.where(\"name = '\#{params[:name]}'\")"
        ],
        safe: [
          "User.where(\"name = ?\", params[:name])",
          "User.where(name: params[:name])"
        ]
      }
    }
  end
  
  @doc """
  Dynamic Finder Injection pattern.
  
  Detects SQL injection through dynamic method calls with user input.
  """
  def dynamic_finder_injection do
    %Pattern{
      id: "rails-dynamic-finder-injection",
      name: "Dynamic Finder Injection",
      description: "SQL injection through dynamic method calls with user input",
      type: :sql_injection,
      severity: :high,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        ~r/\.send\s*\(\s*["'`]find_by_#\{[^}]+\}/,
        ~r/\.method\s*\(\s*["'`]find_by_#\{[^}]+\}/,
        ~r/\.send\s*\(\s*["'`]#\{[^}]+\}.*?_users["'`]/,
        ~r/\.send\s*\(\s*["'`]#\{[^}]+\}["'`]\s*,/,
        ~r/\.send\s*\(\s*\w*params\[/,
        ~r/\.send\s*\(\s*["'`]#\{[^}]*params[^}]*\}[=]?["'`]/
      ],
      default_tier: :protected,
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation: "Avoid dynamic method names with user input in Rails. Use whitelisted method names or ActiveRecord hash-based queries.",
      test_cases: %{
        vulnerable: [
          "User.send(\"find_by_\#{params[:field]}\", params[:value])"
        ],
        safe: [
          "allowed_fields = [\"name\", \"email\"]\nif allowed_fields.include?(params[:field])\n  User.where(params[:field] => params[:value])\nend"
        ]
      }
    }
  end
  
  @doc """
  ERB Template Injection pattern.
  
  Detects server-side template injection through ERB evaluation with user input.
  """
  def erb_injection do
    %Pattern{
      id: "rails-erb-injection",
      name: "ERB Template Injection",
      description: "Server-side template injection through ERB evaluation with user input",
      type: :template_injection,
      severity: :critical,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        ~r/ERB\.new\s*\(\s*params\[/,
        ~r/ERB\.new\s*\(\s*user_template\)/,
        ~r/ERB\.new\s*\(\s*["'`]<%= #\{params\[:code\]\}/,
        ~r/ActionView::Template\.new\s*\(\s*params\[/,
        ~r/render\s+inline:\s*params\[/,
        ~r/render\s+plain:\s*erb_template/,
        ~r/render\s+template:\s*["'`]#\{params\[/,
        ~r/render\s+partial:\s*params\[/,
        ~r/Haml::Engine\.new\s*\(\s*params\[/,
        ~r/Haml\.render\s*\(\s*user_input\)/
      ],
      default_tier: :protected,
      cwe_id: "CWE-94",
      owasp_category: "A03:2021",
      recommendation: "Never render user input as Rails ERB templates. Use static Rails templates with safe data binding and Rails helpers.",
      test_cases: %{
        vulnerable: [
          "ERB.new(params[:template]).result"
        ],
        safe: [
          "render template: \"fixed_template\", locals: { data: params[:data] }"
        ]
      }
    }
  end
  
  @doc """
  Rails Template XSS pattern.
  
  Detects cross-site scripting through unsafe template output.
  """
  def template_xss do
    %Pattern{
      id: "rails-template-xss",
      name: "Rails Template XSS",
      description: "Cross-site scripting through unsafe template output",
      type: :xss,
      severity: :medium,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        ~r/<%=\s*raw\s+[\w@]+/,
        ~r/\.html_safe/,
        ~r/<%==\s*[\w@.]+/,
        ~r/content_tag.*?raw\s*\(/,
        ~r/link_to\s+raw\s*\(/,
        ~r/link_to.*?\.html_safe/,
        ~r/!=\s*[\w@.]+/  # Haml unescaped
      ],
      default_tier: :public,
      cwe_id: "CWE-79",
      owasp_category: "A03:2021",
      recommendation: "Use Rails built-in escaping or Rails sanitize helpers: sanitize(), strip_tags(), or escape HTML entities. Remove raw() and html_safe calls on user content.",
      test_cases: %{
        vulnerable: [
          "<%= raw user_content %>"
        ],
        safe: [
          "<%= sanitize user_content %>",
          "<%= user_content %>"
        ]
      }
    }
  end
  
  @doc """
  Unsafe Route Constraints pattern.
  
  Detects route constraints that can be bypassed or allow code execution.
  """
  def unsafe_route_constraints do
    %Pattern{
      id: "rails-unsafe-route-constraints",
      name: "Unsafe Route Constraints",
      description: "Route constraints that can be bypassed or allow code execution",
      type: :broken_access_control,
      severity: :high,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        ~r/constraints:\s*\{\s*\w+:\s*\/\.\*\//,
        ~r/constraints:\s*\{\s*\w+:\s*\/.*?#\{.*?params/,
        ~r/constraints:\s*lambda.*?eval\s*\(/,
        ~r/constraints\s+lambda.*?\{\s*\|\s*req\s*\|\s*true\s*\}/,
        ~r/constraints\s+subdomain:\s*\/\.\*/
      ],
      default_tier: :protected,
      cwe_id: "CWE-285",
      owasp_category: "A01:2021",
      recommendation: "Use specific, restrictive regex patterns for Rails route constraints. Avoid dynamic constraints with user input in Rails routes.",
      test_cases: %{
        vulnerable: [
          "get \"users/:id\", constraints: { id: /.*/ }"
        ],
        safe: [
          "get \"users/:id\", constraints: { id: /\\d+/ }"
        ]
      }
    }
  end
  
  @doc """
  Unsafe Route Globbing pattern.
  
  Detects glob routes that allow path traversal attacks.
  """
  def unsafe_globbing do
    %Pattern{
      id: "rails-unsafe-globbing",
      name: "Unsafe Route Globbing",
      description: "Glob routes that allow path traversal attacks",
      type: :path_traversal,
      severity: :high,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        ~r/get\s+["'`].*?\*\w+["'`]\s*,\s*to:/,
        ~r/match\s+["'`]\*\w+["'`]/,
        ~r/get\s+["'`]files\/\*path["'`]/,
        ~r/get\s+["'`]download\/\*\w+["'`]/
      ],
      default_tier: :protected,
      cwe_id: "CWE-22",
      owasp_category: "A01:2021",
      recommendation: "Validate Rails glob parameters thoroughly and restrict file access to safe directories in Rails routes",
      test_cases: %{
        vulnerable: [
          "get \"files/*path\", to: \"files#show\""
        ],
        safe: [
          "get \"files/*path\", to: \"files#show\", constraints: { path: /[^.]+/ }"
        ]
      }
    }
  end
  
  @doc """
  Insecure Session Configuration pattern.
  
  Detects Rails session configuration without proper security flags.
  """
  def insecure_session_config do
    %Pattern{
      id: "rails-insecure-session-config",
      name: "Insecure Session Configuration",
      description: "Rails session configuration without proper security flags",
      type: :security_misconfiguration,
      severity: :medium,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        ~r/config\.session_store.*?secure:\s*false/,
        ~r/config\.session_store.*?httponly:\s*false/,
        ~r/config\.session_store.*?same_site:\s*:none/,
        ~r/config\.session_store\s*:cookie_store,\s*key:/,
        ~r/Rails\.application\.config\.session_store\s*:cookie_store/,
        ~r/session_store.*?secret:\s*["'][^"']{1,8}["']/
      ],
      default_tier: :public,
      cwe_id: "CWE-614",
      owasp_category: "A05:2021",
      recommendation: "Configure Rails sessions with secure: true, httponly: true, and same_site: :strict for HTTPS environments. Review Rails session store configuration.",
      test_cases: %{
        vulnerable: [
          "config.session_store :cookie_store, key: \"_app_session\""
        ],
        safe: [
          "config.session_store :cookie_store, key: \"_app_session\", secure: true, httponly: true, same_site: :strict"
        ]
      }
    }
  end
  
  @doc """
  Dangerous Production Configuration pattern.
  
  Detects development settings enabled in production environment.
  """
  def dangerous_production_config do
    %Pattern{
      id: "rails-dangerous-production-config",
      name: "Dangerous Production Configuration",
      description: "Development settings enabled in production environment",
      type: :debug_mode,
      severity: :medium,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        ~r/config\.consider_all_requests_local\s*=\s*true/,
        ~r/config\.action_controller\.perform_caching\s*=\s*false/,
        ~r/config\.log_level\s*=\s*:debug/,
        ~r/config\.eager_load\s*=\s*false/,
        ~r/config\.cache_classes\s*=\s*false/,
        ~r/gem\s+["']byebug["']/,
        ~r/gem\s+["']pry["']/,
        ~r/gem\s+["']pry-rails["']/,
        ~r/config\.assets\.debug\s*=\s*true/,
        ~r/config\.assets\.compress\s*=\s*false/
      ],
      default_tier: :public,
      cwe_id: "CWE-489",
      owasp_category: "A05:2021",
      recommendation: "Ensure Rails production environment has consider_all_requests_local=false, debug gems removed, and proper Rails caching enabled",
      test_cases: %{
        vulnerable: [
          "config.consider_all_requests_local = true"
        ],
        safe: [
          "config.consider_all_requests_local = Rails.env.development?"
        ]
      }
    }
  end
  
  @doc """
  Insecure CORS Configuration pattern.
  
  Detects overly permissive Cross-Origin Resource Sharing configuration.
  """
  def insecure_cors do
    %Pattern{
      id: "rails-insecure-cors",
      name: "Insecure CORS Configuration",
      description: "Overly permissive Cross-Origin Resource Sharing configuration",
      type: :security_misconfiguration,
      severity: :medium,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        ~r/origins\s+["']\*["']/,
        ~r/headers\s+:any/,
        ~r/methods\s+:any/,
        ~r/origins\s+["']\*["'].*?credentials\s+true/s
      ],
      default_tier: :public,
      cwe_id: "CWE-346",
      owasp_category: "A05:2021",
      recommendation: "Specify explicit origins, headers, and methods in Rails CORS. Never use credentials: true with origins: \"*\" in Rails",
      test_cases: %{
        vulnerable: [
          "origins \"*\"\ncredentials true"
        ],
        safe: [
          "origins \"https://example.com\"\ncredentials true"
        ]
      }
    }
  end
  
  @doc """
  ActionMailer Injection pattern.
  
  Detects email header injection through ActionMailer with unvalidated input.
  """
  def actionmailer_injection do
    %Pattern{
      id: "rails-actionmailer-injection",
      name: "ActionMailer Injection",
      description: "Email header injection through ActionMailer with unvalidated input",
      type: :template_injection,
      severity: :high,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        ~r/mail\s*\(\s*to:\s*params\[/,
        ~r/mail\s*\(\s*.*?subject:\s*["'`].*?#\{[^}]*params/,
        ~r/mail\s*\(\s*.*?from:\s*["'`].*?#\{[^}]*params/,
        ~r/mail\s*\(\s*.*?cc:\s*params\[/,
        ~r/mail\s*\(\s*.*?bcc:\s*params\[/,
        ~r/mail\s*\(\s*.*?body:\s*ERB\.new\s*\(\s*params\[/,
        ~r/mail\s*\(\s*.*?template_name:\s*params\[/
      ],
      default_tier: :protected,
      cwe_id: "CWE-117",
      owasp_category: "A03:2021",
      recommendation: "Validate and sanitize email headers. Use address validation for email fields.",
      test_cases: %{
        vulnerable: [
          "mail(to: params[:email], subject: \"Hello \#{params[:name]}\")"
        ],
        safe: [
          "mail(to: validate_email(params[:email]), subject: \"Hello \#{sanitize(params[:name])}\")"
        ]
      }
    }
  end
  
  @doc """
  Session Fixation Vulnerability pattern.
  
  Detects missing session regeneration after authentication.
  """
  def session_fixation do
    %Pattern{
      id: "rails-session-fixation",
      name: "Session Fixation Vulnerability",
      description: "Missing session regeneration after authentication allowing session fixation",
      type: :broken_authentication,
      severity: :medium,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        ~r/def\s+login[\s\S]*?session\[:user_id\]\s*=[\s\S]*?end/,
        ~r/session\[:user_id\]\s*=.*?\.id/,
        ~r/def\s+create[\s\S]*?session\[:admin\]\s*=\s*true/
      ],
      default_tier: :protected,
      cwe_id: "CWE-384",
      owasp_category: "A07:2021",
      recommendation: "Call Rails reset_session or session.regenerate before setting authentication session variables in Rails controllers",
      test_cases: %{
        vulnerable: [
          "def login\n  if user.authenticate(params[:password])\n    session[:user_id] = user.id\n  end\nend"
        ],
        safe: [
          "def login\n  if user.authenticate(params[:password])\n    reset_session\n    session[:user_id] = user.id\n  end\nend"
        ]
      }
    }
  end
  
  @doc """
  Sensitive Data in Session pattern.
  
  Detects storing sensitive information in session cookies.
  """
  def insecure_session_data do
    %Pattern{
      id: "rails-insecure-session-data",
      name: "Sensitive Data in Session",
      description: "Storing sensitive information in session cookies",
      type: :sensitive_data_exposure,
      severity: :high,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        ~r/session\[:password\]/,
        ~r/session\[:credit_card\]/,
        ~r/session\[:ssn\]/,
        ~r/session\[:api_key\]/,
        ~r/session\[:secret_token\]/,
        ~r/session\[:private_key\]/
      ],
      default_tier: :protected,
      cwe_id: "CWE-200",
      owasp_category: "A02:2021",
      recommendation: "Store only non-sensitive identifiers in Rails sessions. Keep sensitive data in secure server-side storage, not Rails session cookies.",
      test_cases: %{
        vulnerable: [
          "session[:password] = params[:password]"
        ],
        safe: [
          "session[:user_id] = user.id  # Store ID only"
        ]
      }
    }
  end
  
  @doc """
  CVE-2022-22577 - XSS in Action Pack pattern.
  
  Detects XSS vulnerability in CSP headers allowing script injection.
  """
  def cve_2022_22577 do
    %Pattern{
      id: "rails-cve-2022-22577",
      name: "CVE-2022-22577 - XSS in Action Pack",
      description: "XSS vulnerability in CSP headers allowing script injection",
      type: :xss,
      severity: :medium,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        ~r/response\.headers\["Content-Security-Policy"\]\s*=.*?#\{params\[:csp\]\}/,
        ~r/content_security_policy[\s\S]*?policy\.[\w_]+\s+params\[/
      ],
      default_tier: :public,
      cwe_id: "CWE-79",
      owasp_category: "A03:2021",
      recommendation: "Validate and sanitize any user input used in Content-Security-Policy headers",
      test_cases: %{
        vulnerable: [
          "response.headers[\"Content-Security-Policy\"] = \"default-src \#{params[:csp]}\""
        ],
        safe: [
          "response.headers[\"Content-Security-Policy\"] = \"default-src 'self'\""
        ]
      }
    }
  end
  
  @doc """
  CVE-2021-22880 - Open Redirect pattern.
  
  Detects host header injection leading to open redirect vulnerability.
  """
  def cve_2021_22880 do
    %Pattern{
      id: "rails-cve-2021-22880",
      name: "CVE-2021-22880 - Open Redirect",
      description: "Host header injection leading to open redirect vulnerability",
      type: :open_redirect,
      severity: :medium,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        ~r/redirect_to\s+request\.protocol\s*\+\s*request\.host/,
        ~r/redirect_to\s+["'`]#\{request\.protocol\}#\{request\.host\}/,
        ~r/url_for\s*\(\s*host:\s*request\.host.*?path:\s*params\[/
      ],
      default_tier: :public,
      cwe_id: "CWE-601",
      owasp_category: "A01:2021",
      recommendation: "Validate host headers against an allowlist before using in Rails redirects",
      test_cases: %{
        vulnerable: [
          "redirect_to request.protocol + request.host + \"/path\""
        ],
        safe: [
          "redirect_to root_url + \"/path\""
        ]
      }
    }
  end
  
  @doc """
  CVE-2020-8264 - Security Constraint Bypass pattern.
  
  Detects bypass of security constraints through skip callback conditions.
  """
  def cve_2020_8264 do
    %Pattern{
      id: "rails-cve-2020-8264",
      name: "CVE-2020-8264 - Security Constraint Bypass",
      description: "Bypass of security constraints through skip callback conditions",
      type: :broken_access_control,
      severity: :high,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        ~r/skip_before_action.*?if:\s*->\s*\{.*?params\[/,
        ~r/skip_around_action.*?if:\s*params\[/,
        ~r/skip_after_action.*?if:\s*->\s*\{.*?eval\s*\(/
      ],
      default_tier: :protected,
      cwe_id: "CWE-285",
      owasp_category: "A01:2021",
      recommendation: "Never use user input in Rails skip callback conditions. Use safe, predefined conditions in Rails controllers.",
      test_cases: %{
        vulnerable: [
          "skip_before_action :authenticate, if: -> { params[:skip] }"
        ],
        safe: [
          "skip_before_action :authenticate, if: :public_action?"
        ]
      }
    }
  end
  
  @doc """
  CVE-2019-5418 - File Content Disclosure pattern.
  
  Detects path traversal vulnerability in render file allowing arbitrary file disclosure.
  """
  def cve_2019_5418 do
    %Pattern{
      id: "rails-cve-2019-5418",
      name: "CVE-2019-5418 - File Content Disclosure",
      description: "Path traversal vulnerability in render file allowing arbitrary file disclosure",
      type: :path_traversal,
      severity: :critical,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        ~r/render\s+file:\s*params\[/,
        ~r/render\s+file:\s*["'`]#\{Rails\.root\}.*?#\{[^}]*params/,
        ~r/render\s+template:\s*params\[.*?path/,
        ~r/render\s+partial:\s*["'`]\.\.\/.*?#\{[^}]*params/
      ],
      default_tier: :protected,
      cwe_id: "CWE-22",
      owasp_category: "A01:2021",
      recommendation: "Never use user input directly in Rails render file/template. Use predefined Rails templates or validate against allowlist.",
      test_cases: %{
        vulnerable: [
          "render file: params[:template]"
        ],
        safe: [
          "allowed = [\"user\", \"admin\"]\nrender template: allowed.include?(params[:type]) ? params[:type] : \"default\""
        ]
      }
    }
  end
end