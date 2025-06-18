defmodule RsolvApi.Security.Patterns.Ruby.UnsafeDeserializationMarshal do
  @moduledoc """
  Pattern for detecting unsafe deserialization vulnerabilities using Ruby's Marshal library.
  
  This pattern identifies when applications use Marshal.load() with untrusted user input,
  which can lead to remote code execution through deserialization gadget chains.
  
  ## Vulnerability Details
  
  Marshal deserialization is one of the most dangerous vulnerabilities in Ruby applications.
  The Marshal library can deserialize arbitrary Ruby objects, including those that execute
  code during instantiation. When user-controlled data is passed to Marshal.load(), attackers
  can craft malicious payloads that execute arbitrary code on the server.
  
  ### Attack Example
  ```ruby
  # Vulnerable Marshal deserialization in various contexts
  class UserController < ApplicationController
    def restore_session
      # VULNERABLE: Direct Marshal.load with user params
      session_data = Marshal.load(params[:session])
      
      # VULNERABLE: Marshal.load with Base64 decoding
      user_data = Marshal.load(Base64.decode64(params[:data]))
      
      # VULNERABLE: Marshal.load with cookies
      auth_token = Marshal.load(cookies[:auth])
      
      # VULNERABLE: Marshal.load with request body
      payload = Marshal.load(request.body.read)
      
      # VULNERABLE: ActiveStorage deserialization (CVE-2019-5420)
      blob = Marshal.load(URI.decode(signed_blob_id))
    end
  end
  
  # Example exploit payload (simplified)
  # This creates a gadget chain for remote code execution:
  exploit_payload = Marshal.dump(
    Gem::Specification.new.tap do |spec|
      spec.loaded_gems = {}
      spec.instance_variable_set(:@loaded_gems, {'system' => 'rm -rf /'})
    end
  )
  
  # When Marshal.load(exploit_payload) is called, it executes the system command
  ```
  
  **Real-world Impact:**
  CVE-2019-5420 and CVE-2020-8165 demonstrated critical Marshal deserialization 
  vulnerabilities in Rails, leading to remote code execution in production applications.
  The elttam universal gadget chain works across Ruby versions 2.x and 3.x.
  
  **Safe Alternative:**
  ```ruby
  # SECURE: Use JSON for data serialization
  class SecureUserController < ApplicationController
    def restore_session
      # SECURE: JSON parsing instead of Marshal
      session_data = JSON.parse(params[:session])
      
      # SECURE: Strong parameters with validation
      user_data = user_params.to_h
      
      # SECURE: Rails encrypted cookies (automatic security)
      auth_token = cookies.encrypted[:auth]
      
      # SECURE: Structured data parsing with validation
      payload = JSON.parse(request.body.read)
      validate_payload_structure!(payload)
    end
    
    private
    
    def user_params
      params.require(:user).permit(:id, :name, :email)
    end
    
    def validate_payload_structure!(payload)
      required_keys = %w[action data timestamp]
      raise ArgumentError unless required_keys.all? { |key| payload.key?(key) }
    end
  end
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "ruby-unsafe-deserialization-marshal",
      name: "Unsafe Deserialization - Marshal",
      description: "Detects unsafe use of Marshal.load with user-controlled input that can lead to remote code execution",
      type: :deserialization,
      severity: :critical,
      languages: ["ruby"],
      regex: [
        # Direct Marshal.load with params
        ~r/Marshal\.load\s*\(\s*params\[/,
        ~r/Marshal\.load\s*\(\s*params\./,
        ~r/Marshal\.load\s*\(\s*params\s*\[/,
        
        # Marshal.load with request data
        ~r/Marshal\.load\s*\(\s*request\./,
        ~r/Marshal\.load\s*\(\s*request\s*\./,
        ~r/Marshal\.load\s*\(\s*request\.body/,
        ~r/Marshal\.load\s*\(\s*request\.raw_post/,
        
        # Marshal.load with cookies
        ~r/Marshal\.load\s*\(\s*cookies\[/,
        ~r/Marshal\.load\s*\(\s*cookies\./,
        ~r/Marshal\.load\s*\(\s*cookies\.signed/,
        ~r/Marshal\.load\s*\(\s*cookies\.encrypted/,
        
        # Marshal.load with Base64 decoding (common pattern)
        ~r/Marshal\.load\s*\(\s*Base64\.(decode64|strict_decode64|urlsafe_decode64)/,
        
        # Marshal.load with user input variables
        ~r/Marshal\.load\s*\(\s*user_input/,
        ~r/Marshal\.load\s*\(\s*untrusted_data/,
        ~r/Marshal\.load\s*\(\s*external_data/,
        ~r/Marshal\.load\s*\(\s*client_data/,
        ~r/Marshal\.load\s*\(\s*uploaded_file/,
        
        # ActiveStorage-specific patterns (CVE-2019-5420)
        ~r/Marshal\.load\s*\(\s*URI\.decode/,
        ~r/Marshal\.load\s*\(\s*.*?\.verify\s*\(/,
        ~r/Marshal\.load\s*\(\s*Rails\.application\.message_verifier/,
        ~r/Marshal\.load\s*\(\s*ActiveStorage::Verifier/,
        
        # Rails session and cache patterns
        ~r/Marshal\.load\s*\(\s*session\[/,
        ~r/Marshal\.load\s*\(\s*cache\.read/,
        ~r/Marshal\.load\s*\(\s*Rails\.cache/
      ],
      default_tier: :ai,
      cwe_id: "CWE-502",
      owasp_category: "A08:2021",
      recommendation: "Never use Marshal.load with untrusted data. Use JSON.parse or other safe serialization formats. For Rails, use encrypted cookies and strong parameters.",
      test_cases: %{
        vulnerable: [
          ~S|data = Marshal.load(params[:data])|,
          ~S|obj = Marshal.load(Base64.decode64(cookies[:session]))|,
          ~S|user = Marshal.load(request.body.read)|,
          ~S|result = Marshal.load(URI.decode(signed_blob_id))|
        ],
        safe: [
          ~S|data = JSON.parse(params[:data])|,
          ~S|obj = Marshal.load(File.read("trusted_file.dat"))|,
          ~S|Marshal.dump(user_object)|,
          ~S|# Marshal.load(params[:data]) # Commented|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Unsafe Marshal deserialization is one of the most critical vulnerabilities in Ruby
      applications. The Marshal library is Ruby's native binary serialization format that
      can deserialize arbitrary Ruby objects, including those that execute code during
      instantiation or initialization.
      
      **How Marshal Deserialization Works:**
      Ruby's Marshal library can serialize and deserialize almost any Ruby object:
      - **Complete Object Reconstruction**: Recreates objects with their exact state
      - **Code Execution During Deserialization**: Objects can execute code in initialize methods
      - **Gadget Chain Exploitation**: Chaining objects to achieve arbitrary code execution
      - **No Built-in Security**: Marshal provides no protection against malicious objects
      
      **Ruby-Specific Exploitation Techniques:**
      Marshal deserialization attacks rely on "gadget chains" - sequences of Ruby objects
      that, when deserialized together, execute arbitrary code:
      - **Universal Gadget Chain**: Works across Ruby 2.x and 3.x versions
      - **Gem::Specification Gadgets**: Exploiting RubyGems internals
      - **ERB Template Gadgets**: Using ERB for code execution
      - **ActiveSupport Gadgets**: Leveraging Rails framework objects
      - **Custom Application Gadgets**: Using application-specific classes
      
      **Critical Security Impact:**
      Marshal deserialization provides complete remote code execution:
      - **System Command Execution**: Full shell access on the target server
      - **File System Access**: Read, write, delete any files with app privileges
      - **Database Compromise**: Access to database credentials and sensitive data
      - **Network Pivot**: Use compromised server to attack internal systems
      - **Persistent Access**: Install backdoors and maintain persistence
      
      **Rails-Specific Vulnerabilities:**
      Rails applications are particularly vulnerable due to:
      - **Session Storage**: Historical use of Marshal for session serialization
      - **Cache Storage**: Marshal used in Redis and MemCache implementations
      - **ActiveStorage**: File upload handling with signed URLs (CVE-2019-5420)
      - **ActionCable**: WebSocket message deserialization
      - **Background Jobs**: Job queue payload deserialization
      
      **Common Attack Scenarios:**
      - **Session Hijacking**: Crafting malicious session cookies
      - **File Upload Exploitation**: Malicious file metadata deserialization
      - **Cache Poisoning**: Injecting malicious objects into application cache
      - **Message Queue Attacks**: Exploiting background job processing
      - **API Endpoint Exploitation**: Sending malicious serialized payloads
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-502",
          title: "Deserialization of Untrusted Data",
          url: "https://cwe.mitre.org/data/definitions/502.html"
        },
        %{
          type: :owasp,
          id: "A08:2021",
          title: "OWASP Top 10 2021 - A08 Software and Data Integrity Failures",
          url: "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
        },
        %{
          type: :research,
          id: "elttam_universal_gadget",
          title: "Ruby 2.x Universal RCE Deserialization Gadget Chain",
          url: "https://www.elttam.com/blog/ruby-deserialization/"
        },
        %{
          type: :research,
          id: "bishopfox_ruby_exploits",
          title: "Ruby Vulnerabilities: Exploiting Open, Send, and Deserialization",
          url: "https://bishopfox.com/blog/ruby-vulnerabilities-exploits"
        },
        %{
          type: :research,
          id: "github_ruby_deserialization",
          title: "Proof of Concepts for unsafe deserialization in Ruby",
          url: "https://github.com/GitHubSecurityLab/ruby-unsafe-deserialization"
        },
        %{
          type: :research,
          id: "zdi_activestorage",
          title: "Remote Code Execution via Ruby on Rails Active Storage Insecure Deserialization",
          url: "https://www.thezdi.com/blog/2019/6/20/remote-code-execution-via-ruby-on-rails-active-storage-insecure-deserialization"
        },
        %{
          type: :research,
          id: "ruby_security_docs",
          title: "Ruby Security Documentation - Marshal",
          url: "https://docs.ruby-lang.org/en/master/security_rdoc.html"
        }
      ],
      attack_vectors: [
        "Direct Marshal.load with params[:data] allowing arbitrary object deserialization",
        "Base64-encoded Marshal payloads in cookies or headers for stealth attacks",
        "ActiveStorage signed URL exploitation (CVE-2019-5420) for file upload RCE",
        "Session cookie manipulation with crafted Marshal payloads",
        "Request body deserialization in API endpoints accepting binary data",
        "Cache poisoning through Redis/MemCache Marshal-based storage",
        "Background job queue exploitation with malicious job payloads",
        "WebSocket message deserialization in ActionCable implementations",
        "File upload metadata exploitation through Marshal-stored file information",
        "Message verifier bypass leading to unsigned Marshal payload processing"
      ],
      real_world_impact: [
        "CVE-2019-5420: Rails development mode secret key vulnerability enabling Marshal RCE",
        "CVE-2020-8165: Rails MemCacheStore and RedisCacheStore deserialization vulnerability",
        "CVE-2019-5418: Rails file content disclosure chained with CVE-2019-5420 for full RCE",
        "GitHub SecurityLab demonstrated universal gadget chains working across Ruby versions",
        "Multiple Rails applications compromised through session cookie manipulation",
        "Production server compromises via ActiveStorage file upload exploitation",
        "E-commerce platforms breached through Marshal deserialization in payment processing",
        "Corporate networks compromised via Rails application entry points",
        "Cryptocurrency exchanges attacked through Marshal vulnerabilities in trading platforms",
        "Government systems compromised through Rails-based citizen services applications"
      ],
      cve_examples: [
        %{
          id: "CVE-2019-5420",
          description: "Rails development mode secret key vulnerability",
          severity: "critical",
          cvss: 9.8,
          note: "Predictable secret_key_base in development mode allows Marshal deserialization attacks"
        },
        %{
          id: "CVE-2020-8165",
          description: "Rails MemCacheStore and RedisCacheStore deserialization vulnerability",
          severity: "critical",
          cvss: 9.8,
          note: "Untrusted data deserialization in cache stores allows remote code execution"
        },
        %{
          id: "CVE-2019-5418",
          description: "Rails file content disclosure vulnerability",
          severity: "high",
          cvss: 7.5,
          note: "Often chained with CVE-2019-5420 to achieve full remote code execution"
        },
        %{
          id: "CVE-2022-21831",
          description: "Rails ActiveStorage code injection vulnerability",
          severity: "high",
          cvss: 7.2,
          note: "Code injection in ActiveStorage image processing with unsafe deserialization"
        }
      ],
      detection_notes: """
      This pattern detects unsafe Marshal deserialization by identifying Marshal.load()
      calls that receive user-controlled input:
      
      **Primary Detection Points:**
      - Marshal.load() with params, request, or cookies as arguments
      - Marshal.load() with Base64 decoding of user input
      - Marshal.load() with user input variables or external data sources
      - ActiveStorage-specific patterns like URI.decode with Marshal.load
      - Rails session and cache patterns using Marshal deserialization
      
      **Ruby-Specific Patterns:**
      - Direct parameter access: Marshal.load(params[:data])
      - Request body access: Marshal.load(request.body.read)
      - Cookie manipulation: Marshal.load(cookies[:session])
      - Base64 encoding: Marshal.load(Base64.decode64(user_input))
      - File upload handling: Marshal.load(uploaded_file.read)
      
      **False Positive Considerations:**
      - Marshal.load with trusted file sources (acceptable in some contexts)
      - Marshal.load with hardcoded constants or application-controlled data
      - Commented out Marshal.load statements
      - Marshal.dump operations (serialization, not deserialization)
      - Test code with Marshal operations on known safe data
      
      **Detection Enhancements:**
      The AST enhancement provides sophisticated analysis:
      - User input flow tracking from HTTP requests to Marshal.load
      - Gadget chain detection for known exploitation patterns
      - Context analysis to distinguish trusted vs untrusted data sources
      - Rails-specific pattern recognition for framework vulnerabilities
      """,
      safe_alternatives: [
        "Use JSON.parse() for data interchange instead of Marshal.load()",
        "Use Rails encrypted cookies: cookies.encrypted[:data] instead of Marshal",
        "Implement strong parameters with permit() for input validation",
        "Use MessagePack for binary serialization with built-in safety features",
        "Use YAML.safe_load() with permitted classes for complex object serialization",
        "For Rails sessions, use default cookie storage instead of Marshal-based storage",
        "Implement input validation and sanitization before any deserialization",
        "Use signed and encrypted tokens for stateless authentication",
        "For background jobs, use JSON payloads instead of Marshal-serialized objects",
        "Regular security audits to identify and eliminate Marshal.load usage"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing Base64 encoding provides security for Marshal payloads",
          "Thinking signed cookies prevent Marshal deserialization attacks",
          "Using Marshal for session storage in production environments",
          "Not understanding that Marshal can deserialize any Ruby object",
          "Assuming input validation prevents Marshal exploitation",
          "Using Marshal in cache implementations without considering attack vectors",
          "Not realizing that gadget chains work across different Ruby versions",
          "Implementing custom serialization without understanding security implications"
        ],
        secure_patterns: [
          "JSON.parse(params[:data]) # Safe data interchange format",
          "cookies.encrypted[:session] # Rails encrypted cookies",
          "params.require(:user).permit(:name, :email) # Strong parameters",
          "YAML.safe_load(data, permitted_classes: [Symbol]) # Safe YAML loading",
          "MessagePack.unpack(data) # Safe binary serialization",
          "Rails.application.message_verifier.verify(token) # Signed verification",
          "ActiveJob.perform_later(safe_params) # Safe background job queuing"
        ],
        ruby_specific: %{
          gadget_chains: [
            "Universal Gadget Chain: Works across Ruby 2.x and 3.x versions",
            "Gem::Specification: Exploiting RubyGems metadata handling",
            "ERB Templates: Using ERB eval for code execution",
            "ActiveSupport::Dependencies: Rails autoloading exploitation",
            "ActionController::Routing: Route definition manipulation",
            "YAML::Store: File-based YAML storage exploitation"
          ],
          rails_specifics: [
            "Session storage: Rails historically used Marshal for sessions",
            "Cache implementations: Redis and MemCache with Marshal serialization",
            "ActiveStorage: File handling with signed URLs and Marshal",
            "ActionCable: WebSocket message deserialization",
            "Background jobs: Sidekiq, Resque, DelayedJob payload handling",
            "Database serialization: ActiveRecord serialize with Marshal"
          ],
          mitigation_strategies: [
            "Audit all Marshal.load usage in application and dependencies",
            "Replace Marshal with JSON or MessagePack for new implementations",
            "Use Rails secure defaults for sessions and cookies",
            "Implement Content Security Policy to limit attack impact",
            "Monitor for suspicious deserialization attempts in logs",
            "Regular dependency updates to patch known vulnerabilities",
            "Code review processes to catch new Marshal.load introductions"
          ]
        }
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual security issues and
  acceptable Marshal usage patterns.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.UnsafeDeserializationMarshal.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.UnsafeDeserializationMarshal.ast_enhancement()
      iex> enhancement.min_confidence
      0.9
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        receiver_analysis: %{
          object_name: "Marshal",
          check_receiver_type: true,
          validate_method_context: true
        },
        method_analysis: %{
          method_name: "load",
          check_argument_count: true,
          analyze_argument_sources: true
        },
        user_input_analysis: %{
          check_user_input_sources: true,
          input_sources: ["params", "request", "cookies", "session", "user_input", "uploaded_file"],
          dangerous_patterns: [
            "params[",
            "request.",
            "cookies[",
            "session[",
            "user_input",
            "uploaded_file",
            "external_data",
            "client_data",
            "untrusted_data"
          ],
          check_base64_decoding: true,
          base64_methods: ["Base64.decode64", "Base64.strict_decode64", "Base64.urlsafe_decode64"]
        },
        gadget_analysis: %{
          check_known_gadgets: true,
          universal_gadget_patterns: true,
          detect_gadget_chains: true,
          known_gadget_classes: [
            "Gem::Specification",
            "ERB",
            "ActiveSupport::Dependencies",
            "ActionController::Routing"
          ]
        },
        rails_specific: %{
          check_activestorage_patterns: true,
          activestorage_methods: ["URI.decode", "message_verifier.verify", "ActiveStorage::Verifier"],
          check_cache_patterns: true,
          cache_methods: ["Rails.cache", "cache.read", "MemCacheStore", "RedisCacheStore"]
        }
      },
      context_rules: %{
        exclude_paths: [
          ~r/test/,
          ~r/spec/,
          ~r/fixtures/,
          ~r/factories/,
          ~r/seeds/,
          ~r/migrations/,
          ~r/examples/,
          ~r/demo/
        ],
        check_trusted_sources: %{
          file_sources: ~r/File\.(read|open)/,
          constant_sources: ~r/[A-Z_]+/,
          application_config: ~r/Rails\.(application|config)/,
          environment_variables: ~r/ENV\[/
        },
        safe_patterns: %{
          marshal_dump: ~r/Marshal\.dump/,
          json_usage: ~r/JSON\.(parse|load)/,
          yaml_safe_load: ~r/YAML\.safe_load/,
          encrypted_cookies: ~r/cookies\.encrypted/,
          strong_parameters: ~r/\.permit\(/
        },
        dangerous_contexts: [
          "controller action",
          "API endpoint",
          "session handling",
          "file upload processing",
          "cache implementation",
          "background job processing",
          "websocket message handling"
        ],
        rails_patterns: %{
          check_development_mode: true,
          development_indicators: [
            "Rails.env.development?",
            "development mode",
            "secret_key_base"
          ],
          production_safety_checks: true
        }
      },
      confidence_rules: %{
        base: 0.7,
        adjustments: %{
          "direct_params_access" => 0.2,
          "request_body_access" => 0.2,
          "cookie_access" => 0.15,
          "base64_decoding_present" => 0.1,
          "activestorage_pattern" => 0.15,
          "cache_pattern" => 0.1,
          "known_gadget_class" => 0.1,
          "user_input_variable" => 0.1,
          "file_upload_context" => 0.1,
          "trusted_file_source" => -0.3,
          "constant_source" => -0.4,
          "marshal_dump_only" => -0.5,
          "json_alternative_present" => -0.2,
          "encrypted_cookies_used" => -0.2,
          "strong_parameters_used" => -0.1,
          "test_context" => -0.3,
          "commented_out" => -1.0
        }
      },
      min_confidence: 0.9
    }
  end
end