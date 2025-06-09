defmodule RsolvApi.Security.Patterns.Ruby do
  @moduledoc """
  Ruby security patterns for detecting vulnerabilities.
  
  This module contains 20 security patterns specifically designed for Ruby
  code. Each pattern includes detection rules, test cases, and educational
  documentation.
  """
  
  alias RsolvApi.Security.Pattern
  
  @doc """
  Returns all Ruby security patterns.
  
  ## Examples
  
      iex> patterns = RsolvApi.Security.Patterns.Ruby.all()
      iex> length(patterns)
      20
      iex> Enum.all?(patterns, &match?(%RsolvApi.Security.Pattern{}, &1))
      true
  """
  def all do
    [
      missing_authentication(),
      mass_assignment(),
      weak_crypto_md5(),
      hardcoded_secrets(),
      sql_injection_interpolation(),
      command_injection(),
      xpath_injection(),
      ldap_injection(),
      weak_random(),
      debug_mode_enabled(),
      eval_usage(),
      weak_password_storage(),
      unsafe_deserialization_marshal(),
      unsafe_yaml(),
      insufficient_logging(),
      ssrf_open_uri(),
      xss_erb_raw(),
      path_traversal(),
      open_redirect(),
      insecure_cookie()
    ]
  end
  
  @doc """
  Missing Authentication in Rails Controller pattern.
  
  Detects Rails controllers without authentication filters.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.missing_authentication()
      iex> pattern.id
      "ruby-broken-access-control-missing-auth"
      iex> pattern.severity
      :high
  """
  def missing_authentication do
    %Pattern{
      id: "ruby-broken-access-control-missing-auth",
      name: "Missing Authentication in Rails Controller",
      description: "Detects Rails controllers without authentication filters",
      type: :authentication,
      severity: :high,
      languages: ["ruby"],
      regex: ~r/class\s+\w+Controller\s*<\s*ApplicationController(?:(?!before_action|before_filter|authenticate).)*end/s,
      default_tier: :protected,
      cwe_id: "CWE-862",
      owasp_category: "A01:2021",
      recommendation: "Add before_action :authenticate_user! to protect sensitive actions",
      test_cases: %{
        vulnerable: [
          ~S|class AdminController < ApplicationController
  def users
    @users = User.all
  end
end|
        ],
        safe: [
          ~S|class AdminController < ApplicationController
  before_action :authenticate_user!
  before_action :require_admin
  
  def users
    @users = User.all
  end
end|
        ]
      }
    }
  end
  
  @doc """
  Mass Assignment Vulnerability pattern.
  
  Detects unfiltered params in model operations.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.mass_assignment()
      iex> pattern.type
      :mass_assignment
  """
  def mass_assignment do
    %Pattern{
      id: "ruby-mass-assignment",
      name: "Mass Assignment Vulnerability",
      description: "Detects unfiltered params in model operations",
      type: :mass_assignment,
      severity: :high,
      languages: ["ruby"],
      regex: [
        ~r/\.(create|update|update_attributes|assign_attributes)\s*\(\s*params\[/,
        ~r/\.(create!|update!)\s*\(\s*params\[/,
        ~r/\.new\s*\(\s*params\[/,
        ~r/\.(insert|upsert)\s*\(\s*params\[/
      ],
      default_tier: :protected,
      cwe_id: "CWE-915",
      owasp_category: "A01:2021",
      recommendation: "Use strong parameters in Rails: params.require(:model).permit(:field1, :field2)",
      test_cases: %{
        vulnerable: [
          "User.create(params[:user])",
          "user.update_attributes(params[:user])"
        ],
        safe: [
          "User.create(user_params)",
          "user.update(user_params)",
          "params.require(:user).permit(:name, :email)"
        ]
      }
    }
  end
  
  @doc """
  Weak Cryptography - MD5 Usage pattern.
  
  Detects usage of weak MD5 hash algorithm.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.weak_crypto_md5()
      iex> pattern.cwe_id
      "CWE-328"
  """
  def weak_crypto_md5 do
    %Pattern{
      id: "ruby-weak-crypto-md5",
      name: "Weak Cryptography - MD5 Usage",
      description: "Detects usage of weak MD5 hash algorithm",
      type: :cryptographic_failure,
      severity: :medium,
      languages: ["ruby"],
      regex: [
        ~r/Digest::MD5/,
        ~r/OpenSSL::Digest(?:\.new\(['"]MD5['"]\)|::MD5)/,
        ~r/\.md5\s*\(/
      ],
      default_tier: :public,
      cwe_id: "CWE-328",
      owasp_category: "A02:2021",
      recommendation: "Use SHA-256 or SHA-384 for cryptographic hashing. For password hashing, use bcrypt.",
      test_cases: %{
        vulnerable: [
          ~S|Digest::MD5.hexdigest(password)|,
          ~S|OpenSSL::Digest.new('MD5')|,
          ~S|require 'digest'
hash = Digest::MD5.hexdigest(data)|
        ],
        safe: [
          ~S|Digest::SHA256.hexdigest(data)|,
          ~S|BCrypt::Password.create(password)|,
          ~S|OpenSSL::Digest.new('SHA256')|
        ]
      }
    }
  end
  
  @doc """
  Hardcoded Secrets pattern.
  
  Detects hardcoded API keys, passwords, and secrets.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.hardcoded_secrets()
      iex> pattern.severity
      :critical
  """
  def hardcoded_secrets do
    %Pattern{
      id: "ruby-hardcoded-secrets",
      name: "Hardcoded Secrets",
      description: "Detects hardcoded API keys, passwords, and secrets",
      type: :sensitive_data_exposure,
      severity: :critical,
      languages: ["ruby"],
      regex: [
        ~r/password\s*=\s*['"]\w+['"]/i,
        ~r/api_key\s*=\s*['"]\w+['"]/i,
        ~r/secret(?:_key)?\s*=\s*['"]\w+['"]/i,
        ~r/AWS_ACCESS_KEY_ID\s*=\s*['"]\w+['"]/,
        ~r/private_key\s*=\s*['"]\w+['"]/i
      ],
      default_tier: :public,
      cwe_id: "CWE-798",
      owasp_category: "A07:2021",
      recommendation: "Use environment variables or secure key management systems",
      test_cases: %{
        vulnerable: [
          ~S|password = "super_secret123"|,
          ~S|API_KEY = "sk_test_123456"|,
          ~S|config.secret_key = "hardcoded_secret"|
        ],
        safe: [
          ~S|password = ENV['DATABASE_PASSWORD']|,
          ~S|api_key = Rails.application.credentials.api_key|,
          ~S|secret = KeyVault.fetch('app_secret')|
        ]
      }
    }
  end
  
  @doc """
  SQL Injection via String Interpolation pattern.
  
  Detects SQL queries built with string interpolation.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.sql_injection_interpolation()
      iex> pattern.type
      :sql_injection
  """
  def sql_injection_interpolation do
    %Pattern{
      id: "ruby-sql-injection-interpolation",
      name: "SQL Injection via String Interpolation",
      description: "Detects SQL queries built with string interpolation",
      type: :sql_injection,
      severity: :critical,
      languages: ["ruby"],
      regex: [
        ~r/ActiveRecord::Base\.connection\.execute\s*\(\s*["'].*?#\{/,
        ~r/\.execute\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE).*?#\{/i,
        ~r/\.find_by_sql\s*\(\s*["'].*?#\{/,
        ~r/\.where\s*\(\s*["'].*?#\{/
      ],
      default_tier: :protected,
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation: "Use parameterized queries or ActiveRecord query interface",
      test_cases: %{
        vulnerable: [
          ~S|User.where("name = '#{params[:name]}'")|,
          ~S|ActiveRecord::Base.connection.execute("SELECT * FROM users WHERE id = #{id}")|
        ],
        safe: [
          ~S|User.where(name: params[:name])|,
          ~S|User.where("name = ?", params[:name])|,
          ~S|User.find_by(name: params[:name])|
        ]
      }
    }
  end
  
  @doc """
  Command Injection pattern.
  
  Detects shell command execution with user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.command_injection()
      iex> pattern.severity
      :critical
  """
  def command_injection do
    %Pattern{
      id: "ruby-command-injection",
      name: "Command Injection",
      description: "Detects shell command execution with user input",
      type: :command_injection,
      severity: :critical,
      languages: ["ruby"],
      regex: [
        ~r/system\s*\(\s*["'].*?#\{/,
        ~r/`.*?#\{.*?`/,
        ~r/exec\s*\(\s*["'].*?#\{/,
        ~r/%x[{\[].*?#\{/,
        ~r/IO\.popen\s*\(\s*["'].*?#\{/,
        ~r/Open3\.\w+\s*\(\s*["'].*?#\{/
      ],
      default_tier: :protected,
      cwe_id: "CWE-78",
      owasp_category: "A03:2021",
      recommendation: "Use array form of system calls or shellescape user input",
      test_cases: %{
        vulnerable: [
          ~S|system("ls #{params[:dir]}")|,
          ~S|`cat #{filename}`|,
          ~S|exec("rm -rf #{path}")|
        ],
        safe: [
          ~S|system("ls", params[:dir])|,
          ~S|system("cat", Shellwords.escape(filename))|,
          ~S|Open3.capture2("ls", "-la", dir)|
        ]
      }
    }
  end
  
  @doc """
  XPath Injection pattern.
  
  Detects XPath queries with user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.xpath_injection()
      iex> pattern.type
      :xpath_injection
  """
  def xpath_injection do
    %Pattern{
      id: "ruby-xpath-injection",
      name: "XPath Injection",
      description: "Detects XPath queries with user input",
      type: :xpath_injection,
      severity: :high,
      languages: ["ruby"],
      regex: [
        ~r/\.xpath\s*\(\s*["'].*?#\{/,
        ~r/Nokogiri.*?\.xpath\s*\(\s*["'].*?#\{/,
        ~r/REXML.*?\.elements\s*\[\s*["'].*?#\{/
      ],
      default_tier: :protected,
      cwe_id: "CWE-643",
      owasp_category: "A03:2021",
      recommendation: "Sanitize user input or use parameterized XPath queries",
      test_cases: %{
        vulnerable: [
          ~S|doc.xpath("//user[name='#{params[:name]}']")|,
          ~S|xml.elements["//product[@id='#{id}']"]|
        ],
        safe: [
          ~S|doc.xpath("//user[name=$name]", nil, name: params[:name])|,
          ~S|doc.at_xpath("//user[@id=?]", params[:id])|
        ]
      }
    }
  end
  
  @doc """
  LDAP Injection pattern.
  
  Detects LDAP queries with unsanitized user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.ldap_injection()
      iex> pattern.cwe_id
      "CWE-90"
  """
  def ldap_injection do
    %Pattern{
      id: "ruby-ldap-injection",
      name: "LDAP Injection",
      description: "Detects LDAP queries with unsanitized user input",
      type: :ldap_injection,
      severity: :high,
      languages: ["ruby"],
      regex: [
        ~r/Net::LDAP.*?filter.*?#\{/,
        ~r/\.search\s*\(.*?:filter\s*=>\s*["'].*?#\{/,
        ~r/ldap_search\s*\(\s*["'].*?#\{/
      ],
      default_tier: :protected,
      cwe_id: "CWE-90",
      owasp_category: "A03:2021",
      recommendation: "Escape special LDAP characters in user input",
      test_cases: %{
        vulnerable: [
          ~S|ldap.search(filter: "(uid=#{username})")|,
          ~S|filter = Net::LDAP::Filter.construct("(cn=#{name})")|
        ],
        safe: [
          ~S|filter = Net::LDAP::Filter.eq("uid", username)|,
          ~S|escaped = Net::LDAP::Filter.escape(user_input)|
        ]
      }
    }
  end
  
  @doc """
  Weak Random Number Generation pattern.
  
  Detects use of predictable random number generators.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.weak_random()
      iex> pattern.severity
      :medium
  """
  def weak_random do
    %Pattern{
      id: "ruby-weak-random",
      name: "Weak Random Number Generation",
      description: "Detects use of predictable random number generators",
      type: :cryptographic_failure,
      severity: :medium,
      languages: ["ruby"],
      regex: [
        ~r/Random\.rand/,
        ~r/rand\s*\(/,
        ~r/srand\s*\(/,
        ~r/Kernel\.rand/
      ],
      default_tier: :public,
      cwe_id: "CWE-330",
      owasp_category: "A02:2021",
      recommendation: "Use SecureRandom for cryptographic purposes",
      test_cases: %{
        vulnerable: [
          ~S|token = rand(100000)|,
          ~S|session_id = Random.rand(10**8)|,
          ~S|password_reset = (0...8).map { rand(65..90).chr }.join|
        ],
        safe: [
          ~S|token = SecureRandom.hex(16)|,
          ~S|session_id = SecureRandom.uuid|,
          ~S|password_reset = SecureRandom.urlsafe_base64|
        ]
      }
    }
  end
  
  @doc """
  Debug Mode Enabled pattern.
  
  Detects debugging code in production.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.debug_mode_enabled()
      iex> pattern.type
      :information_disclosure
  """
  def debug_mode_enabled do
    %Pattern{
      id: "ruby-debug-mode",
      name: "Debug Mode Enabled",
      description: "Detects debugging code that might leak information",
      type: :information_disclosure,
      severity: :medium,
      languages: ["ruby"],
      regex: [
        ~r/require\s+['"]pry['"]/,
        ~r/binding\.pry/,
        ~r/byebug/,
        ~r/debugger/,
        ~r/save_and_open_page/,
        ~r/Rails\.logger\.debug.*?password/i
      ],
      default_tier: :public,
      cwe_id: "CWE-489",
      owasp_category: "A05:2021",
      recommendation: "Remove debugging code before deploying to production",
      test_cases: %{
        vulnerable: [
          ~S|require 'pry'
binding.pry|,
          ~S|byebug|,
          ~S|Rails.logger.debug "User password: #{password}"|
        ],
        safe: [
          ~S|Rails.logger.info "User logged in: #{user.email}"|,
          ~S|# Removed: binding.pry|
        ]
      }
    }
  end
  
  @doc """
  Dangerous Eval Usage pattern.
  
  Detects eval usage with user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.eval_usage()
      iex> pattern.severity
      :critical
  """
  def eval_usage do
    %Pattern{
      id: "ruby-eval-usage",
      name: "Dangerous Eval Usage",
      description: "Detects eval usage which can lead to code injection",
      type: :code_injection,
      severity: :critical,
      languages: ["ruby"],
      regex: [
        ~r/eval\s*\(/,
        ~r/instance_eval/,
        ~r/class_eval/,
        ~r/module_eval/,
        ~r/send\s*\(\s*params/
      ],
      default_tier: :protected,
      cwe_id: "CWE-94",
      owasp_category: "A03:2021",
      recommendation: "Avoid eval. Use safer alternatives like JSON parsing or whitelisted method calls",
      test_cases: %{
        vulnerable: [
          ~S|eval(params[:code])|,
          ~S|instance_eval(user_input)|,
          ~S|obj.send(params[:method])|
        ],
        safe: [
          ~S|JSON.parse(params[:data])|,
          ~S|allowed_methods = [:name, :email]
if allowed_methods.include?(params[:method].to_sym)
  obj.send(params[:method])
end|
        ]
      }
    }
  end
  
  @doc """
  Weak Password Storage pattern.
  
  Detects insecure password storage methods.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.weak_password_storage()
      iex> pattern.type
      :cryptographic_failure
  """
  def weak_password_storage do
    %Pattern{
      id: "ruby-weak-password-storage",
      name: "Weak Password Storage",
      description: "Detects insecure password storage methods",
      type: :cryptographic_failure,
      severity: :critical,
      languages: ["ruby"],
      regex: [
        ~r/password\s*=\s*Digest::(MD5|SHA1)/,
        ~r/\.password\s*=\s*[^B]/,
        ~r/encrypted_password\s*=\s*Digest/
      ],
      default_tier: :protected,
      cwe_id: "CWE-256",
      owasp_category: "A02:2021",
      recommendation: "Use bcrypt or argon2 for password hashing",
      test_cases: %{
        vulnerable: [
          ~S|user.password = Digest::MD5.hexdigest(params[:password])|,
          ~S|user.password = Digest::SHA1.hexdigest(params[:password] + salt)|
        ],
        safe: [
          ~S|user.password = BCrypt::Password.create(params[:password])|,
          ~S|has_secure_password # Rails built-in|
        ]
      }
    }
  end
  
  @doc """
  Unsafe Deserialization - Marshal pattern.
  
  Detects unsafe use of Marshal.load with user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.unsafe_deserialization_marshal()
      iex> pattern.severity
      :critical
  """
  def unsafe_deserialization_marshal do
    %Pattern{
      id: "ruby-unsafe-deserialization-marshal",
      name: "Unsafe Deserialization - Marshal",
      description: "Detects unsafe use of Marshal.load with user input",
      type: :deserialization,
      severity: :critical,
      languages: ["ruby"],
      regex: [
        ~r/Marshal\.load\s*\(\s*params/,
        ~r/Marshal\.load\s*\(\s*request/,
        ~r/Marshal\.load\s*\(\s*Base64\.decode64\s*\(\s*params/
      ],
      default_tier: :protected,
      cwe_id: "CWE-502",
      owasp_category: "A08:2021",
      recommendation: "Use JSON or other safe serialization formats instead of Marshal",
      test_cases: %{
        vulnerable: [
          ~S|data = Marshal.load(params[:data])|,
          ~S|obj = Marshal.load(Base64.decode64(cookies[:session]))|
        ],
        safe: [
          ~S|data = JSON.parse(params[:data])|,
          ~S|# Use Rails session handling instead of manual Marshal|
        ]
      }
    }
  end
  
  @doc """
  Unsafe YAML Loading pattern.
  
  Detects unsafe YAML.load usage.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.unsafe_yaml()
      iex> pattern.type
      :deserialization
  """
  def unsafe_yaml do
    %Pattern{
      id: "ruby-unsafe-yaml",
      name: "Unsafe YAML Loading",
      description: "Detects unsafe YAML.load usage which can execute arbitrary code",
      type: :deserialization,
      severity: :critical,
      languages: ["ruby"],
      regex: [
        ~r/YAML\.load\s*\(\s*params/,
        ~r/YAML\.load\s*\(\s*request/,
        ~r/YAML\.load\s*\(\s*File\.read.*?user/
      ],
      default_tier: :protected,
      cwe_id: "CWE-502",
      owasp_category: "A08:2021",
      recommendation: "Use YAML.safe_load or Psych.safe_load instead",
      test_cases: %{
        vulnerable: [
          ~S|config = YAML.load(params[:config])|,
          ~S|data = YAML.load(user_input)|
        ],
        safe: [
          ~S|config = YAML.safe_load(user_input)|,
          ~S|data = YAML.load_file("config.yml")|,
          ~S|Psych.safe_load(params[:yaml], permitted_classes: [Symbol, Date])|
        ]
      }
    }
  end
  
  @doc """
  Insufficient Security Logging pattern.
  
  Missing logging for security-relevant events.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.insufficient_logging()
      iex> pattern.severity
      :low
  """
  def insufficient_logging do
    %Pattern{
      id: "ruby-insufficient-logging",
      name: "Insufficient Security Logging",
      description: "Missing logging for security-relevant events",
      type: :information_disclosure,
      severity: :low,
      languages: ["ruby"],
      regex: ~r/rescue\s*(?:Exception|StandardError)?\s*(?:=>)?\s*\w*\s*\n\s*end|rescue\s*\n\s*nil\s*\n\s*end/,
      default_tier: :public,
      cwe_id: "CWE-778",
      owasp_category: "A09:2021",
      recommendation: "Log security events and errors appropriately",
      test_cases: %{
        vulnerable: [
          ~S|begin
  authenticate_user
rescue => e
  nil
end|
        ],
        safe: [
          ~S|begin
  authenticate_user
rescue => e
  Rails.logger.error "Authentication failed: #{e.message}"
  raise
end|
        ]
      }
    }
  end
  
  @doc """
  SSRF via open-uri pattern.
  
  Detects Server-Side Request Forgery vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.ssrf_open_uri()
      iex> pattern.type
      :ssrf
  """
  def ssrf_open_uri do
    %Pattern{
      id: "ruby-ssrf-open-uri",
      name: "SSRF via open-uri",
      description: "Detects Server-Side Request Forgery vulnerabilities",
      type: :ssrf,
      severity: :high,
      languages: ["ruby"],
      regex: [
        ~r/open\s*\(\s*params/,
        ~r/open\s*\(\s*URI/,
        ~r/Net::HTTP\.get\s*\(\s*URI\s*\(\s*params/,
        ~r/RestClient\.get\s*\(\s*params/
      ],
      default_tier: :protected,
      cwe_id: "CWE-918",
      owasp_category: "A10:2021",
      recommendation: "Validate and whitelist URLs, implement request timeouts",
      test_cases: %{
        vulnerable: [
          ~S|data = open(params[:url]).read|,
          ~S|response = Net::HTTP.get(URI(params[:endpoint]))|
        ],
        safe: [
          ~S|allowed_hosts = ['api.example.com']
uri = URI(params[:url])
if allowed_hosts.include?(uri.host)
  data = open(uri).read
end|
        ]
      }
    }
  end
  
  @doc """
  XSS in ERB Templates pattern.
  
  Detects cross-site scripting vulnerabilities in ERB.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.xss_erb_raw()
      iex> pattern.type
      :xss
  """
  def xss_erb_raw do
    %Pattern{
      id: "ruby-xss-erb-raw",
      name: "XSS in ERB Templates",
      description: "Detects cross-site scripting vulnerabilities in ERB templates",
      type: :xss,
      severity: :high,
      languages: ["ruby"],
      regex: [
        ~r/<%=\s*raw\s+/,
        ~r/\.html_safe/,
        ~r/<%==\s*params/
      ],
      default_tier: :public,
      cwe_id: "CWE-79",
      owasp_category: "A03:2021",
      recommendation: "Use Rails' built-in HTML escaping, avoid raw and html_safe on user input",
      test_cases: %{
        vulnerable: [
          ~S|<%= raw params[:content] %>|,
          ~S|<%= params[:name].html_safe %>|,
          ~S|<%== user_input %>|
        ],
        safe: [
          ~S|<%= params[:content] %>|,
          ~S|<%= sanitize(params[:content]) %>|,
          ~S|<%= h(user_input) %>|
        ]
      }
    }
  end
  
  @doc """
  Path Traversal pattern.
  
  Detects file access with user-controlled paths.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.path_traversal()
      iex> pattern.severity
      :high
  """
  def path_traversal do
    %Pattern{
      id: "ruby-path-traversal",
      name: "Path Traversal",
      description: "Detects file access with user-controlled paths",
      type: :path_traversal,
      severity: :high,
      languages: ["ruby"],
      regex: [
        ~r/File\.read\s*\(\s*params/,
        ~r/File\.open\s*\(\s*["'].*?#\{.*?params/,
        ~r/send_file\s+params/,
        ~r/\.read\s*\(\s*File\.join\s*\(.*?params/
      ],
      default_tier: :protected,
      cwe_id: "CWE-22",
      owasp_category: "A01:2021",
      recommendation: "Validate file paths, use basename, and restrict to safe directories",
      test_cases: %{
        vulnerable: [
          ~S|File.read(params[:file])|,
          ~S|send_file "uploads/#{params[:filename]}"|
        ],
        safe: [
          ~S|filename = File.basename(params[:file])
filepath = File.join(SAFE_DIR, filename)
if filepath.start_with?(SAFE_DIR)
  File.read(filepath)
end|
        ]
      }
    }
  end
  
  @doc """
  Open Redirect pattern.
  
  Detects unvalidated redirect destinations.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.open_redirect()
      iex> pattern.type
      :open_redirect
  """
  def open_redirect do
    %Pattern{
      id: "ruby-open-redirect",
      name: "Open Redirect",
      description: "Detects unvalidated redirect destinations",
      type: :open_redirect,
      severity: :medium,
      languages: ["ruby"],
      regex: [
        ~r/redirect_to\s+params/,
        ~r/redirect_to\s+request\.referer/,
        ~r/redirect_to\s+:back/
      ],
      default_tier: :public,
      cwe_id: "CWE-601",
      owasp_category: "A01:2021",
      recommendation: "Validate redirect URLs against a whitelist",
      test_cases: %{
        vulnerable: [
          ~S|redirect_to params[:return_url]|,
          ~S|redirect_to request.referer|
        ],
        safe: [
          ~S|redirect_to root_path|,
          ~S|safe_urls = [root_path, dashboard_path]
if safe_urls.include?(params[:return_url])
  redirect_to params[:return_url]
else
  redirect_to root_path
end|
        ]
      }
    }
  end
  
  @doc """
  Insecure Cookie Settings pattern.
  
  Detects cookies without security flags.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.insecure_cookie()
      iex> pattern.severity
      :medium
  """
  def insecure_cookie do
    %Pattern{
      id: "ruby-insecure-cookie",
      name: "Insecure Cookie Settings",
      description: "Detects cookies without proper security flags",
      type: :session_management,
      severity: :medium,
      languages: ["ruby"],
      regex: [
        ~r/cookies\[.+?\]\s*=\s*(?!.*:secure)/,
        ~r/cookies\[.+?\]\s*=\s*\{[^}]*:httponly\s*=>\s*false/,
        ~r/cookies\.permanent\[/
      ],
      default_tier: :public,
      cwe_id: "CWE-614",
      owasp_category: "A05:2021",
      recommendation: "Set secure: true and httponly: true for sensitive cookies",
      test_cases: %{
        vulnerable: [
          ~S|cookies[:auth_token] = token|,
          ~S|cookies[:session] = { value: session_id, httponly: false }|
        ],
        safe: [
          ~S|cookies[:auth_token] = {
  value: token,
  secure: true,
  httponly: true,
  same_site: :strict
}|
        ]
      }
    }
  end
end