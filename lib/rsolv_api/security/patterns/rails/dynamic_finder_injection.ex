defmodule RsolvApi.Security.Patterns.Rails.DynamicFinderInjection do
  @moduledoc """
  Dynamic Finder Injection pattern for Rails applications.
  
  This pattern detects SQL injection vulnerabilities through Ruby's metaprogramming
  features, particularly the `send` and `method` methods when used with dynamic
  finder methods in Rails. This was a critical vulnerability in Rails applications
  that allowed attackers to execute arbitrary SQL commands.
  
  ## Background
  
  Rails provides dynamic finder methods like `find_by_name`, `find_by_email`, etc.
  When combined with Ruby's metaprogramming capabilities (send, method), untrusted
  input can be used to construct method names dynamically, leading to SQL injection
  or even remote code execution if arbitrary methods can be called.
  
  ## Vulnerability Details
  
  The vulnerability occurs when:
  1. User input is used to construct method names dynamically
  2. The `send` or `method` methods are used to invoke these dynamic methods
  3. No whitelist validation is performed on the method names
  4. Attackers can potentially call any method on the object
  
  ## Known CVEs
  
  - CVE-2012-6496: SQL injection via dynamic finders in ActiveRecord
  - CVE-2017-17916: SQL injection in find_by method (disputed by Rails team)
  - Multiple metaprogramming-based RCE vulnerabilities in Rails applications
  
  ## Examples
  
      # Vulnerable - dynamic method construction
      User.send("find_by_\#{params[:field]}", params[:value])
      
      # Vulnerable - arbitrary method invocation
      model.send(params[:method], params[:args])
      
      # Safe - whitelist validation
      allowed_fields = ["name", "email"]
      if allowed_fields.include?(params[:field])
        User.where(params[:field] => params[:value])
      end
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "rails-dynamic-finder-injection",
      name: "Dynamic Finder Injection",
      description: "SQL injection through dynamic method calls with user input",
      type: :sql_injection,
      severity: :high,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        # send with find_by interpolation
        ~r/\.send\s*\(\s*["'`]find_by_#\{[^}]+\}/,
        # method with find_by interpolation
        ~r/\.method\s*\(\s*["'`]find_by_#\{[^}]+\}/,
        # send with find_all_by interpolation
        ~r/\.send\s*\(\s*["'`]find_all_by_#\{[^}]+\}/,
        # send with interpolated method ending in _users or similar
        ~r/\.send\s*\(\s*["'`]#\{[^}]+\}.*?_users["'`]/,
        # send with interpolated method ending in _posts or similar
        ~r/\.send\s*\(\s*["'`]#\{[^}]+\}_\w+["'`]/,
        # send with any interpolated method name (including setters with =)
        ~r/\.send\s*\(\s*["'`]#\{[^}]+\}=?["'`]\s*,/,
        # send with params directly
        ~r/\.send\s*\(\s*\w*params\[/,
        # send with request.params
        ~r/\.send\s*\(\s*request\.params\[/,
        # send with interpolated method containing params
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
  
  def vulnerability_metadata do
    %{
      description: """
      Dynamic finder injection is a severe vulnerability in Rails applications that
      exploits Ruby's metaprogramming capabilities. The `send` and `method` methods
      allow calling methods by name dynamically, which becomes dangerous when the
      method name is constructed from user input. In Rails, this often involves
      dynamic finder methods like find_by_*, but can extend to any method on the
      object, potentially leading to remote code execution.
      
      The vulnerability is particularly dangerous because:
      1. It can bypass normal method visibility (calling private methods)
      2. It allows calling ANY method on the object, not just finders
      3. In worst cases, it can lead to arbitrary code execution
      4. It's often overlooked in security reviews due to Ruby idioms
      """,
      
      attack_vectors: """
      1. **SQL Injection via Dynamic Finders**: field=email' OR '1'='1
      2. **Method Traversal**: method=instance_eval&args=system('whoami')
      3. **Private Method Access**: method=send&args[]=eval&args[]=params[:code]
      4. **Object Manipulation**: method=update_attribute&args[]=admin&args[]=true
      5. **Denial of Service**: method=exit! or method=raise
      6. **Information Disclosure**: method=inspect or method=to_yaml
      7. **File System Access**: method=read&args[]=/etc/passwd (if such methods exist)
      8. **Database Manipulation**: method=destroy_all or method=delete_all
      """,
      
      business_impact: """
      - Complete system compromise through remote code execution
      - Full database access and potential data breach
      - Privilege escalation by calling admin methods
      - Service disruption through DoS attacks
      - Reputation damage from security incidents
      - Legal liability from data breaches
      - Financial losses from fraud or system downtime
      """,
      
      technical_impact: """
      - Arbitrary method invocation on objects
      - SQL injection through dynamic finders
      - Remote code execution via eval-like methods
      - Bypass of method visibility restrictions
      - Access to private/protected methods
      - Potential file system access
      - Memory exhaustion through recursive calls
      """,
      
      likelihood: "High - Metaprogramming is common in Ruby, and developers often use send() without proper validation",
      
      cve_examples: [
        "CVE-2012-6496 - SQL injection in ActiveRecord dynamic finders affecting Rails < 3.2.10",
        "CVE-2017-17916 - SQL injection in find_by method (disputed but highlights the risk)",
        "CVE-2013-0156 - Rails YAML deserialization leading to RCE (related metaprogramming issue)",
        "Multiple unnamed vulnerabilities in Rails apps using unsafe metaprogramming"
      ],
      
      compliance_standards: [
        "OWASP Top 10 2021 - A03: Injection",
        "CWE-89: SQL Injection",
        "CWE-470: Use of Externally-Controlled Input to Select Classes or Code",
        "PCI DSS 6.5.1 - Injection flaws",
        "NIST SP 800-53 - SI-10 Information Input Validation"
      ],
      
      remediation_steps: """
      1. **Use Hash-Based Queries (Preferred)**:
         ```ruby
         # Instead of dynamic finders
         User.send("find_by_\#{params[:field]}", params[:value])  # VULNERABLE
         
         # Use ActiveRecord where with hash
         User.where(params[:field] => params[:value])            # STILL RISKY
         
         # Better - validate field names first
         allowed_fields = %w[name email created_at]
         field = params[:field]
         if allowed_fields.include?(field)
           User.where(field => params[:value])                   # SAFE
         end
         ```
      
      2. **Implement Strict Whitelisting**:
         ```ruby
         class SafeFinder
           ALLOWED_METHODS = {
             'by_name' => :find_by_name,
             'by_email' => :find_by_email,
             'active' => :active_users
           }.freeze
           
           def self.find(method_key, *args)
             method = ALLOWED_METHODS[method_key]
             return nil unless method
             User.public_send(method, *args)
           end
         ```
      
      3. **Use Case Statements for Method Dispatch**:
         ```ruby
         def find_user(field, value)
           case field
           when 'name'
             User.find_by_name(value)
           when 'email'
             User.find_by_email(value)
           when 'id'
             User.find_by_id(value)
           else
             raise ArgumentError, "Invalid field: \#{field}"
           end
         ```
      
      4. **Avoid send() with User Input**:
         ```ruby
         # NEVER do this
         object.send(params[:method], params[:args])
         
         # If you must use metaprogramming, use public_send with whitelist
         SAFE_METHODS = [:to_s, :name, :email].freeze
         method = params[:method].to_sym
         if SAFE_METHODS.include?(method)
           object.public_send(method)
         end
         ```
      
      5. **Modern Rails Approach**:
         ```ruby
         # Use strong parameters and query objects
         class UserQuery
           include ActiveModel::Model
           
           attr_accessor :search_field, :search_value
           
           SEARCHABLE_FIELDS = %w[name email username].freeze
           
           validates :search_field, inclusion: { in: SEARCHABLE_FIELDS }
           
           def results
             return User.none unless valid?
             User.where(search_field => search_value)
           end
         
         # In controller
         query = UserQuery.new(search_params)
         @users = query.results
         ```
      """,
      
      prevention_tips: """
      - Never use send() or method() with unvalidated user input
      - Always whitelist allowed method names explicitly
      - Use Rails' built-in query methods instead of dynamic finders
      - Implement query objects for complex searches
      - Use static method calls whenever possible
      - Enable strong parameters in Rails
      - Code review all metaprogramming usage
      - Use static analysis tools like Brakeman
      - Prefer public_send over send to prevent private method access
      - Document all dynamic method usage
      """,
      
      detection_methods: """
      - Static analysis with Brakeman scanner
      - Grep for patterns: \\.send.*params, \\.method.*params
      - Code review focusing on metaprogramming
      - Dynamic testing with method fuzzing
      - Security testing tools like OWASP ZAP
      - Manual penetration testing
      - Review all uses of send, __send__, public_send, method
      - Automated security scanning in CI/CD
      """,
      
      safe_alternatives: """
      # 1. Use ActiveRecord query interface instead of dynamic metaprogramming
      User.where(email: params[:email])
      User.find_by(name: params[:name])
      
      # 2. Query objects pattern with explicit whitelist validation
      class UserSearchQuery
        def initialize(params)
          @field = params[:field]
          @value = params[:value]
        end
        
        def execute
          return User.none unless valid_field?
          User.where(@field => @value)
        end
        
        private
        
        def valid_field?
          # Use a whitelist of allowed fields to prevent dynamic method calls
          %w[name email username].include?(@field)
        end
      end
      
      # 3. Service objects with explicit methods and whitelist approach
      class UserFinder
        # Whitelist of allowed search methods
        ALLOWED_METHODS = {
          'name' => :by_name,
          'email' => :by_email
        }.freeze
        
        def self.by_name(name)
          User.where(name: name)
        end
        
        def self.by_email(email)
          User.where(email: email)
        end
        
        def self.find(field, value)
          # Use whitelist validation before method dispatch
          method = ALLOWED_METHODS[field]
          return User.none unless method
          public_send(method, value)
        end
      end
      
      # 4. Rails scopes with whitelist validation
      class User < ActiveRecord::Base
        scope :by_field, ->(field, value) {
          # Always use a whitelist to validate dynamic field names
          allowed = %w[name email username]
          return none unless allowed.include?(field)
          where(field => value)
        }
      end
      
      # 5. Form objects with explicit whitelist validation
      class SearchForm
        include ActiveModel::Model
        
        # Define a whitelist of searchable fields
        ALLOWED_FIELDS = %w[name email].freeze
        
        attr_accessor :field, :value
        
        validates :field, inclusion: { in: ALLOWED_FIELDS }
        
        def search
          return User.none unless valid?
          User.where(field => value)
        end
      """
    }
  end
  
  def ast_enhancement do
    %{
      min_confidence: 0.8,
      
      context_rules: %{
        # Metaprogramming methods that can be dangerous
        metaprogramming_methods: [
          "send", "__send__", "public_send", "method",
          "instance_eval", "class_eval", "module_eval"
        ],
        
        # Patterns that indicate user input
        user_input_sources: [
          "params", "request", "cookies", "session",
          "query_params", "form_params", "user_input"
        ],
        
        # Safe method patterns
        safe_patterns: [
          ~r/send\s*\(\s*:\w+\s*\)/,  # Static symbol methods
          ~r/public_send\s*\(\s*:\w+\s*\)/,
          ~r/ALLOWED_METHODS\s*\[/,     # Whitelist pattern
          ~r/case\s+\w+\s+when/         # Case statement dispatch
        ],
        
        # Dangerous patterns to increase confidence
        dangerous_patterns: [
          "find_by_", "find_all_by_", "destroy_", "update_",
          "eval", "instance_eval", "class_eval", "system"
        ]
      },
      
      confidence_rules: %{
        adjustments: %{
          # High confidence for direct user input
          has_params_interpolation: +0.4,
          # Medium confidence for any send usage
          uses_send_method: +0.2,
          # Very high for find_by patterns
          has_find_by_pattern: +0.3,
          # Lower if whitelist detected
          uses_whitelist: -0.5,
          # Lower if static method call
          static_method_call: -0.6,
          # Higher for dangerous method patterns
          dangerous_method_pattern: +0.3,
          # Much lower in test files
          in_test_file: -0.7
        }
      },
      
      ast_rules: %{
        # Method call analysis
        method_analysis: %{
          check_receiver: true,
          check_method_name: true,
          trace_variable_flow: true,
          detect_interpolation: true
        },
        
        # Metaprogramming detection
        metaprogramming_patterns: %{
          method_construction: true,
          dynamic_dispatch: true,
          string_to_method: true
        },
        
        # Validation detection
        validation_patterns: %{
          whitelist_check: true,
          case_statement: true,
          include_check: true,
          safe_list_constant: true
        }
      }
    }
  end
  
end

