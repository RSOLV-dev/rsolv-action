import { describe, it, expect } from 'vitest';
import { PatternRegistry } from '../../patterns.js';
import { VulnerabilityType } from '../../types.js';

describe('Ruby on Rails Security Patterns', () => {
  const registry = new PatternRegistry();

  describe('Rails-specific Mass Assignment Vulnerabilities', () => {
    it('should detect missing strong parameters in Rails controllers', () => {
      const patterns = registry.getPatterns(VulnerabilityType.MASS_ASSIGNMENT);
      const railsPatterns = patterns.filter(p => 
        p.languages.includes('ruby') && p.id.includes('rails-strong-parameters')
      );
      
      expect(railsPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Vulnerable: Direct params without permit
        'User.create(params[:user])',
        'user.update_attributes(params[:user])',
        'User.new(params[:user])',
        'user.assign_attributes(params[:user])',
        // Vulnerable: Permit all
        'User.create(params.require(:user).permit!)',
        'user.update(params[:user].permit!)',
        // Vulnerable: Mass assignment in bulk operations
        'User.create!(params[:users])',
        'User.insert_all(params[:users])'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = railsPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
      
      // Safe code should not match
      const safeCodes = [
        'User.create(user_params)',
        'user.update(params.require(:user).permit(:name, :email))',
        'User.new(user_params)',
        'user.assign_attributes(user_params)'
      ];
      
      safeCodes.forEach(code => {
        const detected = railsPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(false, `False positive for: ${code}`);
      });
    });

    it('should detect attr_accessible vulnerabilities in older Rails', () => {
      const patterns = registry.getPatterns(VulnerabilityType.MASS_ASSIGNMENT);
      const railsPatterns = patterns.filter(p => 
        p.languages.includes('ruby') && p.id.includes('rails-attr-accessible')
      );
      
      expect(railsPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Missing attr_accessible
        'class User < ActiveRecord::Base\n  # No attr_accessible\nend',
        // Overly permissive attr_accessible
        'attr_accessible :role, :admin',
        'attr_accessible :password, :password_confirmation'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = railsPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });
  });

  describe('Rails ActiveRecord Injection Vulnerabilities', () => {
    it('should detect SQL injection in ActiveRecord methods', () => {
      const patterns = registry.getPatterns(VulnerabilityType.SQL_INJECTION);
      const railsPatterns = patterns.filter(p => 
        p.languages.includes('ruby') && p.id.includes('rails-activerecord-injection')
      );
      
      expect(railsPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // where clause injection
        'User.where("name = \'#{params[:name]}\'")',
        'Post.where("title LIKE \'%#{search}%\'")',
        // joins injection
        'User.joins("LEFT JOIN posts ON posts.user_id = #{user_id}")',
        // group/having injection
        'Order.group("DATE(#{params[:date_field]})")',
        'Sale.having("SUM(amount) > #{params[:amount]}")',
        // order injection
        'User.order("#{params[:sort_field]} #{params[:direction]}")',
        // select injection
        'User.select("#{params[:fields]}")',
        // find_by_sql injection
        'User.find_by_sql("SELECT * FROM users WHERE name = \'#{name}\'")',
        // count_by_sql injection
        'User.count_by_sql("SELECT COUNT(*) FROM users WHERE role = \'#{role}\'")',
        // exists injection
        'User.exists?(["name = \'#{params[:name]}\'")',
        // update_all injection
        'User.update_all("name = \'#{new_name}\'")',
        // delete_all injection
        'User.delete_all("created_at < \'#{cutoff_date}\'")'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = railsPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
      
      // Safe parameterized queries should not match
      const safeCodes = [
        'User.where("name = ?", params[:name])',
        'Post.where(title: params[:title])',
        'User.joins(:posts)',
        'User.order(:name)',
        'User.select(:id, :name)',
        'User.find_by_sql(["SELECT * FROM users WHERE name = ?", name])'
      ];
      
      safeCodes.forEach(code => {
        const detected = railsPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(false, `False positive for: ${code}`);
      });
    });

    it('should detect dynamic finder injection vulnerabilities', () => {
      const patterns = registry.getPatterns(VulnerabilityType.SQL_INJECTION);
      const railsPatterns = patterns.filter(p => 
        p.languages.includes('ruby') && p.id.includes('rails-dynamic-finder-injection')
      );
      
      expect(railsPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Dynamic finder with interpolated values
        'User.send("find_by_#{params[:field]}", params[:value])',
        'User.method("find_by_#{field}").call(value)',
        // Dynamic scopes
        'User.send("#{params[:scope]}_users")',
        // Dynamic column access
        'user.send("#{params[:attribute]}")',
        'user.send("#{params[:attribute]}=")',
        // Method chaining with dynamic methods
        'User.where(status: "active").send("find_by_#{field}", value)'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = railsPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });
  });

  describe('Rails Template Vulnerabilities', () => {
    it('should detect ERB template injection', () => {
      const patterns = registry.getPatterns(VulnerabilityType.TEMPLATE_INJECTION);
      const railsPatterns = patterns.filter(p => 
        p.languages.includes('ruby') && p.id.includes('rails-erb-injection')
      );
      
      expect(railsPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Direct ERB evaluation
        'ERB.new(params[:template]).result',
        'ERB.new(user_template).result(binding)',
        // Inline ERB with user input
        'ERB.new("<%= #{params[:code]} %>").result',
        // ActionView template rendering with user input
        'ActionView::Template.new(params[:template]).render',
        'render inline: params[:template]',
        'render plain: erb_template',
        // Dynamic template selection
        'render template: "#{params[:template_name]}"',
        'render partial: params[:partial_name]',
        // Haml injection
        'Haml::Engine.new(params[:template]).render',
        'Haml.render(user_input)'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = railsPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
      
      // Safe template usage should not match
      const safeCodes = [
        'render template: "users/show"',
        'render partial: "shared/header"',
        'ERB.new(File.read("template.erb")).result',
        'render json: @user'
      ];
      
      safeCodes.forEach(code => {
        const detected = railsPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(false, `False positive for: ${code}`);
      });
    });

    it('should detect XSS in Rails templates', () => {
      const patterns = registry.getPatterns(VulnerabilityType.XSS);
      const railsPatterns = patterns.filter(p => 
        p.languages.includes('ruby') && p.id.includes('rails-template-xss')
      );
      
      expect(railsPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Raw output without sanitization
        '<%= raw user_content %>',
        '<%= @comment.body.html_safe %>',
        '<%= content.html_safe %>',
        // Unescaped ERB
        '<%== user_input %>',
        '<%== @post.title %>',
        // Content_tag with unsafe content
        '<%= content_tag :div, raw(user_content) %>',
        '<%= content_tag :span, content.html_safe %>',
        // Link helpers with unsafe content
        '<%= link_to raw(title), path %>',
        '<%= link_to title.html_safe, path %>',
        // Haml unescaped output
        '!= user_content',
        '!= @post.body'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = railsPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
      
      // Safe templates should not match
      const safeCodes = [
        '<%= user_content %>',
        '<%= sanitize @comment.body %>',
        '<%= content_tag :div, @post.title %>',
        '<%= link_to @user.name, user_path(@user) %>'
      ];
      
      safeCodes.forEach(code => {
        const detected = railsPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(false, `False positive for: ${code}`);
      });
    });
  });

  describe('Rails Routing Security Issues', () => {
    it('should detect unsafe route constraints', () => {
      const patterns = registry.getPatterns(VulnerabilityType.BROKEN_ACCESS_CONTROL);
      const railsPatterns = patterns.filter(p => 
        p.languages.includes('ruby') && p.id.includes('rails-unsafe-route-constraints')
      );
      
      expect(railsPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Regex constraints that can be bypassed
        'get "users/:id", constraints: { id: /.*/ }',
        'get "admin/:action", constraints: { action: /#{params[:allowed]}/ }',
        // Lambda constraints with user input
        'get "files/:path", constraints: lambda { |req| eval(req.params[:check]) }',
        // Overly permissive constraints
        'constraints subdomain: /.*/ do',
        'constraints lambda { |req| true } do'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = railsPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });

    it('should detect unsafe route globbing', () => {
      const patterns = registry.getPatterns(VulnerabilityType.PATH_TRAVERSAL);
      const railsPatterns = patterns.filter(p => 
        p.languages.includes('ruby') && p.id.includes('rails-unsafe-globbing')
      );
      
      expect(railsPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Glob routes without proper validation
        'get "files/*path", to: "files#show"',
        'get "download/*filename", to: "downloads#show"',
        'match "*path", to: "pages#show"',
        // Catch-all routes
        'get "*any", to: "application#not_found"'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = railsPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });
  });

  describe('Rails Configuration Vulnerabilities', () => {
    it('should detect insecure session configuration', () => {
      const patterns = registry.getPatterns(VulnerabilityType.SECURITY_MISCONFIGURATION);
      const railsPatterns = patterns.filter(p => 
        p.languages.includes('ruby') && p.id.includes('rails-insecure-session-config')
      );
      
      expect(railsPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Insecure session store
        'config.session_store :cookie_store, key: "_app_session"',
        'config.session_store :cookie_store, secure: false',
        'config.session_store :cookie_store, httponly: false',
        'config.session_store :cookie_store, same_site: :none',
        // Missing session configuration
        'Rails.application.config.session_store :cookie_store',
        // Weak session key
        'config.session_store :cookie_store, key: "_app", secret: "short"'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = railsPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });

    it('should detect dangerous development settings in production', () => {
      const patterns = registry.getPatterns(VulnerabilityType.DEBUG_MODE);
      const railsPatterns = patterns.filter(p => 
        p.languages.includes('ruby') && p.id.includes('rails-dangerous-production-config')
      );
      
      expect(railsPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Development settings in production
        'config.consider_all_requests_local = true',
        'config.action_controller.perform_caching = false',
        'config.log_level = :debug',
        'config.eager_load = false',
        'config.cache_classes = false',
        // Debug gems in production
        'gem "byebug"',
        'gem "pry"',
        'gem "pry-rails"',
        // Asset debugging
        'config.assets.debug = true',
        'config.assets.compress = false'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = railsPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });

    it('should detect insecure CORS configuration', () => {
      const patterns = registry.getPatterns(VulnerabilityType.SECURITY_MISCONFIGURATION);
      const railsPatterns = patterns.filter(p => 
        p.languages.includes('ruby') && p.id.includes('rails-insecure-cors')
      );
      
      expect(railsPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Permissive CORS
        'config.middleware.insert_before 0, Rack::Cors do\n  allow do\n    origins "*"',
        'origins "*"',
        'headers :any',
        'methods :any',
        // Credentials with wildcard origin
        'origins "*"\n    credentials true'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = railsPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });
  });

  describe('ActionMailer Security Issues', () => {
    it('should detect email injection in ActionMailer', () => {
      const patterns = registry.getPatterns(VulnerabilityType.TEMPLATE_INJECTION);
      const railsPatterns = patterns.filter(p => 
        p.languages.includes('ruby') && p.id.includes('rails-actionmailer-injection')
      );
      
      expect(railsPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Email header injection
        'mail(to: params[:email], subject: "Hello #{params[:name]}")',
        'mail(from: "noreply@#{params[:domain]}.com")',
        'mail(cc: params[:cc_list])',
        'mail(bcc: params[:bcc_list])',
        // Template injection in email body
        'mail(body: ERB.new(params[:template]).result)',
        // Dynamic template selection
        'mail(template_name: params[:template])'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = railsPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });
  });

  describe('Rails Session Management Vulnerabilities', () => {
    it('should detect session fixation vulnerabilities', () => {
      const patterns = registry.getPatterns(VulnerabilityType.BROKEN_AUTHENTICATION);
      const railsPatterns = patterns.filter(p => 
        p.languages.includes('ruby') && p.id.includes('rails-session-fixation')
      );
      
      expect(railsPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Missing session regeneration after login
        'def login\n  if user.authenticate(params[:password])\n    session[:user_id] = user.id\n  end\nend',
        // Session without regeneration
        'session[:user_id] = authenticate_user.id',
        // Missing reset_session before login
        'def create\n  session[:admin] = true\nend'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = railsPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });

    it('should detect insecure session data storage', () => {
      const patterns = registry.getPatterns(VulnerabilityType.SENSITIVE_DATA_EXPOSURE);
      const railsPatterns = patterns.filter(p => 
        p.languages.includes('ruby') && p.id.includes('rails-insecure-session-data')
      );
      
      expect(railsPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Storing sensitive data in session
        'session[:password] = params[:password]',
        'session[:credit_card] = params[:cc_number]',
        'session[:ssn] = user.ssn',
        'session[:api_key] = user.api_key',
        'session[:secret_token] = generate_token'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = railsPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });
  });

  describe('Real Rails CVE Patterns', () => {
    it('should detect CVE-2022-22577 (XSS in Action Pack)', () => {
      const patterns = registry.getPatterns(VulnerabilityType.XSS);
      const railsPatterns = patterns.filter(p => 
        p.languages.includes('ruby') && p.id.includes('rails-cve-2022-22577')
      );
      
      expect(railsPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Vulnerable CSP usage
        'response.headers["Content-Security-Policy"] = "default-src #{params[:csp]}"',
        'content_security_policy do |policy|\n  policy.default_src params[:source]\nend'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = railsPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });

    it('should detect CVE-2021-22880 (Open Redirect)', () => {
      const patterns = registry.getPatterns(VulnerabilityType.OPEN_REDIRECT);
      const railsPatterns = patterns.filter(p => 
        p.languages.includes('ruby') && p.id.includes('rails-cve-2021-22880')
      );
      
      expect(railsPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Host header injection leading to open redirect
        'redirect_to request.protocol + request.host + "/path"',
        'redirect_to "#{request.protocol}#{request.host}#{params[:path]}"',
        'redirect_to url_for(host: request.host, path: params[:path])'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = railsPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });

    it('should detect CVE-2020-8264 (Bypass of security constraints)', () => {
      const patterns = registry.getPatterns(VulnerabilityType.BROKEN_ACCESS_CONTROL);
      const railsPatterns = patterns.filter(p => 
        p.languages.includes('ruby') && p.id.includes('rails-cve-2020-8264')
      );
      
      expect(railsPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Skip callbacks with user input
        'skip_before_action :authenticate, if: -> { params[:skip] }',
        'skip_around_action :verify_permission, if: params[:bypass]',
        'skip_after_action :log_access, if: -> { eval(params[:condition]) }'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = railsPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });

    it('should detect CVE-2019-5418 (File Content Disclosure)', () => {
      const patterns = registry.getPatterns(VulnerabilityType.PATH_TRAVERSAL);
      const railsPatterns = patterns.filter(p => 
        p.languages.includes('ruby') && p.id.includes('rails-cve-2019-5418')
      );
      
      expect(railsPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Vulnerable render file with user input
        'render file: params[:template]',
        'render file: "#{Rails.root}/#{params[:path]}"',
        'render template: params[:template_path]',
        'render partial: "../#{params[:file]}"'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = railsPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });
  });

  it('should have comprehensive Rails pattern coverage', () => {
    const railsPatterns = registry.getPatternsByLanguage('ruby')
      .filter(p => p.id.includes('rails-'));
    
    // Should have Rails-specific patterns for major vulnerability types
    expect(railsPatterns.length).toBeGreaterThanOrEqual(15);
    
    // Check for specific Rails vulnerability categories
    const categories = railsPatterns.map(p => p.type);
    expect(categories).toContain(VulnerabilityType.MASS_ASSIGNMENT);
    expect(categories).toContain(VulnerabilityType.SQL_INJECTION);
    expect(categories).toContain(VulnerabilityType.TEMPLATE_INJECTION);
    expect(categories).toContain(VulnerabilityType.XSS);
    expect(categories).toContain(VulnerabilityType.SECURITY_MISCONFIGURATION);
    expect(categories).toContain(VulnerabilityType.BROKEN_ACCESS_CONTROL);
  });

  it('should provide Rails-specific remediation guidance', () => {
    const railsPatterns = registry.getPatternsByLanguage('ruby')
      .filter(p => p.id.includes('rails-'));
    
    railsPatterns.forEach(pattern => {
      expect(pattern.remediation).toBeTruthy();
      expect(pattern.remediation.length).toBeGreaterThan(20);
      expect(pattern.examples.vulnerable).toBeTruthy();
      expect(pattern.examples.secure).toBeTruthy();
      // Rails patterns should mention Rails-specific solutions
      expect(
        pattern.remediation.toLowerCase().includes('rails') ||
        pattern.remediation.toLowerCase().includes('active') ||
        pattern.remediation.toLowerCase().includes('strong parameters') ||
        pattern.remediation.toLowerCase().includes('permit') ||
        pattern.remediation.toLowerCase().includes('sanitize')
      ).toBe(true);
    });
  });
});