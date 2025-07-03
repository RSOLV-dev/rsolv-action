defmodule Rsolv.Security.Patterns.Rails.DangerousProductionConfig do
  @moduledoc """
  Rails Dangerous Production Configuration pattern for Rails applications.
  
  This pattern detects development settings that are incorrectly enabled in 
  production environments, leading to information disclosure, performance 
  issues, and security vulnerabilities. These misconfigurations can expose 
  sensitive debugging information, application internals, and create attack 
  vectors for malicious actors.
  
  ## Background
  
  Rails has different configuration modes for development, test, and production
  environments. Development mode includes helpful features like detailed error
  pages, debug information, and hot reloading, but these features can be
  dangerous when exposed in production environments.
  
  ## Vulnerability Details
  
  The vulnerability occurs when:
  1. consider_all_requests_local is set to true (shows detailed errors)
  2. Debug logging level is enabled (logs sensitive information)
  3. Caching is disabled (performance and security impact)
  4. Asset debugging and compression are misconfigured
  5. Development gems like byebug or pry are included in production
  6. eager_load and cache_classes are disabled (development settings)
  
  ## Known Issues
  
  - Information disclosure through detailed error pages
  - Performance degradation from disabled caching
  - Security vulnerabilities from debug mode exposure
  - Sensitive data logging in debug mode
  - Remote code execution through debug console access
  
  ## Examples
  
      # Critical - Development settings in production
      config.consider_all_requests_local = true
      
      # Critical - Debug logging in production
      config.log_level = :debug
      
      # Critical - Caching disabled
      config.action_controller.perform_caching = false
      
      # Critical - Development gems in production
      gem 'byebug'
      gem 'pry'
      
      # Safe - Production settings
      config.consider_all_requests_local = false
      config.log_level = :info
      config.action_controller.perform_caching = true
  """
  
  use Rsolv.Security.Patterns.PatternBase
  
  def pattern do
    %Rsolv.Security.Pattern{
      id: "rails-dangerous-production-config",
      name: "Dangerous Production Configuration",
      description: "Development settings enabled in production environment",
      type: :debug_mode,
      severity: :medium,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        # consider_all_requests_local enabled (shows detailed errors to all users)
        ~r/config\.consider_all_requests_local\s*=\s*true/,
        ~r/app\.config\.consider_all_requests_local\s*=\s*true/,
        
        # Caching disabled in production
        ~r/config\.action_controller\.perform_caching\s*=\s*false/,
        
        # Debug log level in production
        ~r/config\.log_level\s*=\s*:debug/,
        ~r/config\.logger\.level\s*=\s*:debug/,
        
        # eager_load disabled (development setting)
        ~r/config\.eager_load\s*=\s*false/,
        
        # cache_classes disabled (development setting)
        ~r/config\.cache_classes\s*=\s*false/,
        
        # Development/debugging gems in production (dangerous, exclude comments)
        ~r/^(?!.*#).*gem\s+['"]byebug['"]/,
        ~r/^(?!.*#).*gem\s+['"]pry['"]/,
        ~r/^(?!.*#).*gem\s+['"]pry-rails['"]/,
        ~r/^(?!.*#).*gem\s+['"]web-console['"]/,
        ~r/^(?!.*#).*gem\s+['"]better_errors['"]/,
        ~r/^(?!.*#).*gem\s+['"]binding_of_caller['"]/,
        
        # Asset debugging enabled (development setting)
        ~r/config\.assets\.debug\s*=\s*true/,
        
        # Asset compression disabled (development setting)
        ~r/config\.assets\.compress\s*=\s*false/,
        
        # Development mode forced
        ~r/Rails\.env\s*=\s*['"]development['"]/,
        ~r/ENV\[['"]RAILS_ENV['"]\]\s*=\s*['"]development['"]/,
        
        # SSL forced to false (dangerous)
        ~r/config\.force_ssl\s*=\s*false/,
        ~r/config\.ssl_options\s*=\s*\{.*?secure_cookies:\s*false/,
        
        # Show exceptions enabled (development setting)
        ~r/config\.action_dispatch\.show_exceptions\s*=\s*true/,
        ~r/config\.action_dispatch\.show_detailed_exceptions\s*=\s*true/,
        
        # Console access enabled
        ~r/config\.web_console\.whitelisted_ips\s*=.*?['"]0\.0\.0\.0['"]/,
        ~r/config\.web_console\.permissions\s*=.*?['"]0\.0\.0\.0['"]/
      ],
      cwe_id: "CWE-489",
      owasp_category: "A05:2021",
      recommendation: "Ensure Rails production environment has consider_all_requests_local=false, debug gems removed, and proper Rails caching enabled",
      test_cases: %{
        vulnerable: [
          "config.consider_all_requests_local = true",
          "config.log_level = :debug",
          "config.action_controller.perform_caching = false",
          "gem 'byebug'"
        ],
        safe: [
          "config.consider_all_requests_local = Rails.env.development?",
          "config.log_level = :info",
          "config.action_controller.perform_caching = true"
        ]
      }
    }
  end
  
  def vulnerability_metadata do
    %{
      description: """
      Dangerous Production Configuration in Rails applications occurs when 
      development-specific settings are incorrectly enabled in production 
      environments. This misconfiguration can lead to serious security 
      vulnerabilities including information disclosure, performance degradation, 
      and potential remote code execution. Development settings like detailed 
      error pages, debug logging, and development gems should never be enabled 
      in production as they expose sensitive application internals and create 
      attack vectors.
      
      The vulnerability is particularly dangerous because:
      1. It exposes detailed application stack traces and internal structure
      2. Debug information can reveal database schemas, file paths, and secrets
      3. Development gems like byebug can provide remote code execution
      4. Performance issues from disabled caching can lead to denial of service
      5. Error pages can reveal source code and configuration details
      """,
      
      attack_vectors: """
      1. **Information Disclosure via Error Pages**: Detailed stack traces reveal application structure
      2. **Debug Console Access**: Remote code execution through web console or debug gems
      3. **Log File Analysis**: Debug logs contain sensitive data and application secrets
      4. **Source Code Disclosure**: Error pages and debug info reveal application source
      5. **Database Schema Discovery**: Stack traces and errors reveal database structure
      6. **File System Exploration**: Debug tools allow filesystem browsing
      7. **Environment Variable Exposure**: Debug pages show environment configuration
      8. **Session/Cookie Analysis**: Debug tools reveal session management internals
      9. **Denial of Service**: Disabled caching leads to performance degradation
      10. **Memory Dumps**: Debug tools can expose memory contents and sensitive data
      """,
      
      business_impact: """
      - Complete application source code and information disclosure exposing intellectual property
      - Database schema and sensitive data exposure through debug information
      - Potential remote code execution through debug console access
      - Performance degradation leading to poor user experience and higher costs
      - Regulatory compliance violations from exposed sensitive information
      - Competitive disadvantage from disclosed business logic and algorithms
      - Legal liability from customer data exposure in error messages
      - Reputation damage from security incidents and data breaches
      - Increased infrastructure costs from performance issues
      - Loss of customer trust and business continuity impact
      """,
      
      technical_impact: """
      - Complete application source code and configuration disclosure
      - Database credentials and connection string exposure
      - API keys, secrets, and tokens revealed in debug output
      - File system access through debug console and error pages
      - Memory contents and application state exposure
      - Session management and authentication mechanism disclosure
      - Network configuration and internal service discovery
      - Environment variables and system configuration exposure
      - Application framework internals and dependency versions revealed
      - Potential remote code execution through debug interfaces
      """,
      
      likelihood: "High - Production misconfigurations are common, especially when promoting development settings or using development environment configurations",
      
      cve_examples: """
      Multiple Rails applications with production misconfigurations leading to:
      - CVE-2020-8264: XSS vulnerability in Rails Actionable Exceptions middleware (development mode features in production)
      - Information disclosure through consider_all_requests_local=true
      - Remote code execution through exposed debug consoles
      - Performance issues from disabled caching in production
      - Debug gem exposure leading to code execution vulnerabilities
      - Asset debugging exposing source maps and application structure
      - Log level misconfiguration exposing sensitive authentication data
      Note: Many production misconfigurations are not assigned CVEs but are common security issues
      """,
      
      compliance_standards: [
        "OWASP Top 10 2021 - A05: Security Misconfiguration",
        "CVE-2020-8264: XSS in Rails Actionable Exceptions middleware",
        "CWE-489: Active Debug Code",
        "CWE-200: Information Exposure",
        "CWE-79: Cross-Site Scripting (related to CVE-2020-8264)",
        "PCI DSS 6.5.5 - Improper error handling",
        "NIST SP 800-53 - SI-11 Error Handling",
        "ISO 27001 - A.14.2.5 Secure system engineering principles",
        "ASVS 4.0 - V7.4 Error Handling and Logging Verification Requirements",
        "SANS Top 25 - CWE-200 Information Exposure"
      ],
      
      remediation_steps: """
      1. **Production Environment Configuration (Critical)**:
         ```ruby
         # config/environments/production.rb
         
         # NEVER do this in production - Dangerous misconfigurations
         config.consider_all_requests_local = true          # DANGEROUS
         config.log_level = :debug                          # DANGEROUS
         config.action_controller.perform_caching = false   # DANGEROUS
         config.eager_load = false                          # DANGEROUS
         config.cache_classes = false                       # DANGEROUS
         
         # Always use these settings in production
         Rails.application.configure do
           config.consider_all_requests_local = false       # Hide detailed errors
           config.action_controller.perform_caching = true  # Enable caching
           config.log_level = :info                         # Appropriate log level
           config.eager_load = true                         # Load all code at startup
           config.cache_classes = true                      # Cache class definitions
           config.assets.compile = false                    # Precompiled assets only
           config.assets.debug = false                      # Disable asset debugging
           config.assets.compress = true                    # Compress assets
           config.force_ssl = true                          # Force HTTPS
         end
         ```
      
      2. **Gemfile Management**:
         ```ruby
         # Gemfile - Properly group development gems
         
         # NEVER do this - Development gems in all environments
         gem 'byebug'                                       # DANGEROUS
         gem 'pry'                                          # DANGEROUS
         gem 'web-console'                                  # DANGEROUS
         
         # Always group development/debugging gems properly
         group :development do
           gem 'byebug', platforms: [:mri, :mingw, :x64_mingw]
           gem 'web-console', '>= 4.1.0'
           gem 'listen', '~> 3.3'
           gem 'spring'
           gem 'spring-watcher-listen', '~> 2.0.0'
         end
         
         group :development, :test do
           gem 'pry-rails'
           gem 'pry-byebug'
           gem 'better_errors'
           gem 'binding_of_caller'
         end
         
         group :test do
           gem 'rspec-rails'
           gem 'factory_bot_rails'
         end
         ```
      
      3. **Environment-Specific Configuration**:
         ```ruby
         # config/application.rb
         module MyApp
           class Application < Rails::Application
             # Use environment-specific settings
             config.consider_all_requests_local = Rails.env.development?
             config.action_controller.perform_caching = !Rails.env.development?
             
             # Set appropriate log levels
             config.log_level = case Rails.env
                               when 'development' then :debug
                               when 'test' then :warn
                               when 'production' then :info
                               else :info
                               end
           end
         ```
      
      4. **Configuration Validation**:
         ```ruby
         # config/environments/production.rb
         Rails.application.configure do
           # Validate critical production settings
           config.after_initialize do
             unless Rails.application.config.consider_all_requests_local == false
               raise "consider_all_requests_local must be false in production!"
             end
             
             unless Rails.application.config.action_controller.perform_caching == true
               raise "Caching must be enabled in production!"
             end
             
             if Rails.application.config.log_level == :debug
               Rails.logger.warn "WARNING: Debug logging enabled in production!"
             end
         end
         ```
      
      5. **Custom Error Pages**:
         ```ruby
         # app/controllers/application_controller.rb
         class ApplicationController < ActionController::Base
           rescue_from StandardError, with: :handle_standard_error if Rails.env.production?
           
           private
           
           def handle_standard_error(exception)
             # Log the error for debugging
             Rails.logger.error "Application Error: \#{exception.message}"
             Rails.logger.error exception.backtrace.join("\\\\n")
             
             # Show generic error page to users
             render template: "errors/500", status: 500, layout: 'error'
           end
         ```
      """,
      
      prevention_tips: """
      - Always use environment-specific configuration files
      - Group development gems properly in Gemfile
      - Set consider_all_requests_local=false in production
      - Use appropriate log levels (info/warn) in production
      - Enable caching and asset optimization in production
      - Remove or disable debug gems in production
      - Implement custom error pages for production
      - Use configuration validation to check production settings
      - Regular audits of production configuration files
      - Automated deployment checks for dangerous settings
      - Environment variable validation in CI/CD pipelines
      - Security scanning for common misconfigurations
      """,
      
      detection_methods: """
      - Static analysis of config/environments/production.rb files
      - Gemfile analysis for development gems in production dependencies
      - Runtime checks for consider_all_requests_local setting
      - Log level monitoring and alerting
      - Performance monitoring for caching effectiveness
      - Security scanners checking for detailed error page exposure
      - Manual testing of error handling in production-like environments
      - Automated configuration audits in CI/CD pipelines
      - Penetration testing focusing on information disclosure
      - Monitoring for debug-related HTTP headers and responses
      """,
      
      safe_alternatives: """
      # 1. Production-Ready Configuration Template
      # config/environments/production.rb
      Rails.application.configure do
        # Security settings
        config.consider_all_requests_local = false
        config.action_dispatch.show_exceptions = false
        config.action_dispatch.show_detailed_exceptions = false
        
        # Performance settings
        config.action_controller.perform_caching = true
        config.cache_classes = true
        config.eager_load = true
        
        # Asset settings
        config.assets.compile = false
        config.assets.debug = false
        config.assets.compress = true
        config.assets.css_compressor = :sass
        config.assets.js_compressor = :terser
        
        # Logging
        config.log_level = :info
        config.log_tags = [:request_id]
        
        # SSL/Security
        config.force_ssl = true
        config.ssl_options = {
          secure_cookies: true,
          hsts: { expires: 1.year, subdomains: true }
        }
        
        # Error handling
        config.exceptions_app = self.routes
      end
      
      # 2. Environment Detection Helper
      class EnvironmentValidator
        def self.validate_production!
          return unless Rails.env.production?
          
          dangerous_settings = []
          
          dangerous_settings << "consider_all_requests_local is true" if 
            Rails.application.config.consider_all_requests_local
          
          dangerous_settings << "caching is disabled" unless 
            Rails.application.config.action_controller.perform_caching
          
          dangerous_settings << "debug logging is enabled" if 
            Rails.application.config.log_level == :debug
          
          if dangerous_settings.any?
            raise "Production configuration errors: \#{dangerous_settings.join(', ')}"
          end
        end
      
      # 3. Custom Error Handler
      class ProductionErrorHandler
        def self.handle_error(exception, request)
          # Log detailed error for developers
          Rails.logger.error "Error in \#{request.path}: \#{exception.message}"
          Rails.logger.error exception.backtrace.first(10).join("\n")
          
          # Return generic error response
          {
            status: 500,
            content_type: 'application/json',
            body: { error: 'Internal server error' }.to_json
          }
        end
      
      # 4. Configuration Monitoring
      class ConfigurationMonitor
        def self.check_production_settings
          return unless Rails.env.production?
          
          checks = {
            consider_all_requests_local: Rails.application.config.consider_all_requests_local,
            perform_caching: Rails.application.config.action_controller.perform_caching,
            log_level: Rails.application.config.log_level,
            force_ssl: Rails.application.config.force_ssl
          }
          
          Rails.logger.info "Production configuration check: \#{checks}"
          
          # Alert if dangerous settings detected
          if checks[:consider_all_requests_local] || !checks[:perform_caching]
            Rails.logger.error "SECURITY WARNING: Dangerous production configuration detected!"
          end
      end
      
      # 5. Automated Configuration Test
      # test/integration/production_config_test.rb
      class ProductionConfigTest < ActionDispatch::IntegrationTest
        test "production configuration is secure" do
          with_env('RAILS_ENV' => 'production') do
            Rails.application.configure do
              refute config.consider_all_requests_local, "consider_all_requests_local should be false"
              assert config.action_controller.perform_caching, "caching should be enabled"
              refute_equal :debug, config.log_level, "debug logging should be disabled"
              assert config.force_ssl, "SSL should be forced"
            end
        end
        
        private
        
        def with_env(env)
          old_env = ENV.to_hash
          ENV.update(env)
          yield
        ensure
          ENV.replace(old_env)
        end
      """
    }
  end
  
  def ast_enhancement do
    %{
      min_confidence: 0.7,
      
      context_rules: %{
        # Configuration methods that can be dangerous
        config_methods: [
          "config.consider_all_requests_local",
          "config.action_controller.perform_caching",
          "config.log_level", "config.logger.level",
          "config.eager_load", "config.cache_classes",
          "config.assets.debug", "config.assets.compress",
          "config.force_ssl"
        ],
        
        # Development settings that are dangerous in production
        dangerous_development_settings: [
          "consider_all_requests_local = true",
          "perform_caching = false",
          "log_level = :debug",
          "eager_load = false",
          "cache_classes = false",
          "assets.debug = true",
          "assets.compress = false"
        ],
        
        # Development gems that shouldn't be in production
        development_gems: [
          "byebug", "pry", "pry-rails", "web-console",
          "better_errors", "binding_of_caller"
        ],
        
        # Environment files where this pattern applies
        environment_files: [
          "config/environments/production.rb",
          "config/application.rb",
          "Gemfile"
        ],
        
        # Safe patterns to reduce false positives
        safe_patterns: [
          ~r/consider_all_requests_local\s*=\s*false/,
          ~r/consider_all_requests_local\s*=\s*Rails\.env\.development\?/,
          ~r/perform_caching\s*=\s*true/,
          ~r/log_level\s*=\s*:info/,
          ~r/log_level\s*=\s*:warn/,
          ~r/eager_load\s*=\s*true/,
          ~r/cache_classes\s*=\s*true/,
          ~r/group\s+:development/,  # Gems properly grouped
          ~r/#.*gem\s+['"]byebug['"]/  # Commented out gems
        ]
      },
      
      confidence_rules: %{
        adjustments: %{
          # High confidence for clearly dangerous settings
          development_setting_in_production: +0.4,
          debug_logging_enabled: +0.3,
          caching_disabled: +0.3,
          development_gems_included: +0.5,
          
          # Medium confidence for potentially dangerous settings
          consider_all_requests_local_true: +0.4,
          asset_debugging_enabled: +0.2,
          ssl_disabled: +0.3,
          
          # Lower confidence for safer patterns
          environment_conditional_config: -0.4,
          properly_grouped_gems: -0.6,
          commented_configuration: -0.8,
          
          # Context-based adjustments
          in_production_env_file: +0.2,
          in_development_env_file: -0.7,
          in_test_file: -0.9,
          in_gemfile_development_group: -0.5,
          
          # File location adjustments
          in_application_config: +0.1,
          in_initializer: +0.1
        }
      },
      
      ast_rules: %{
        # Configuration analysis
        configuration_analysis: %{
          check_config_assignments: true,
          detect_boolean_values: true,
          analyze_gem_declarations: true,
          check_environment_context: true
        },
        
        # Environment detection
        environment_detection: %{
          check_file_path: true,
          detect_environment_conditionals: true,
          analyze_rails_env_usage: true
        },
        
        # Gem analysis
        gem_analysis: %{
          check_gem_groups: true,
          detect_development_gems: true,
          analyze_gem_conditions: true
        },
        
        # Value analysis
        value_analysis: %{
          dangerous_boolean_values: [true],
          dangerous_symbol_values: [:debug],
          safe_boolean_values: [false],
          safe_symbol_values: [:info, :warn, :error]
        }
      }
    }
  end
  
end

