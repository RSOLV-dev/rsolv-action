
const VulnerabilityType = {
  SQL_INJECTION: 'sql_injection',
  XSS: 'xss',
  COMMAND_INJECTION: 'command_injection',
  PATH_TRAVERSAL: 'path_traversal',
  HARDCODED_SECRET: 'hardcoded_secret',
  WEAK_CRYPTO: 'weak_crypto',
  BROKEN_ACCESS_CONTROL: 'broken_access_control',
  SENSITIVE_DATA_EXPOSURE: 'sensitive_data_exposure',
  XML_EXTERNAL_ENTITIES: 'xxe',
  SECURITY_MISCONFIGURATION: 'security_misconfiguration',
  VULNERABLE_COMPONENTS: 'vulnerable_components',
  BROKEN_AUTHENTICATION: 'broken_authentication',
  INSECURE_DESERIALIZATION: 'insecure_deserialization',
  INSUFFICIENT_LOGGING: 'insufficient_logging',
  UNVALIDATED_REDIRECT: 'open_redirect',
  SSRF: 'ssrf',
  LDAP_INJECTION: 'ldap_injection',
  NOSQL_INJECTION: 'nosql_injection',
  CSRF: 'csrf',
  XXE: 'xxe',
  DESERIALIZATION: 'deserialization',
  RCE: 'rce',
  // Ruby/Rails specific
  MASS_ASSIGNMENT: 'mass_assignment',
  UNSAFE_REFLECTION: 'unsafe_reflection',
  DEBUG_MODE: 'debug_mode',
  WEAK_CRYPTOGRAPHY: 'weak_cryptography',
  // Django specific
  TEMPLATE_INJECTION: 'template_injection',
  ORM_INJECTION: 'orm_injection',
  MIDDLEWARE_BYPASS: 'middleware_bypass'
};
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.rubySecurityPatterns = void 0;
const types_js_1 = {};
exports.rubySecurityPatterns = [
    {
        id: 'ruby-broken-access-control-missing-auth',
        type: types_js_1.VulnerabilityType.BROKEN_ACCESS_CONTROL,
        name: 'Missing Authentication in Rails Controller',
        description: 'Detects Rails controllers without authentication filters',
        patterns: {
            regex: [
                /class\s+\w+Controller\s*<\s*ApplicationController(?:(?!before_action|before_filter|authenticate).)*end/gs,
                /def\s+(admin|delete|update|create)(?:(?!current_user|logged_in|authenticate).)*end/gs
            ]
        },
        severity: 'high',
        cweId: 'CWE-862',
        owaspCategory: 'A01:2021 - Broken Access Control',
        languages: ['ruby'],
        remediation: 'Add before_action :authenticate_user! to protect sensitive actions',
        examples: {
            vulnerable: `class AdminController < ApplicationController
  def users
    @users = User.all
  end
end`,
            secure: `class AdminController < ApplicationController
  before_action :authenticate_user!
  before_action :require_admin
  
  def users
    @users = User.all
  end
end`
        }
    },
    {
        id: 'ruby-mass-assignment',
        type: types_js_1.VulnerabilityType.MASS_ASSIGNMENT,
        name: 'Mass Assignment Vulnerability',
        description: 'Detects unfiltered params in model operations',
        patterns: {
            regex: [
                /\.(create|update|update_attributes|assign_attributes)\s*\(\s*params(?!\s*\.\s*(require|permit))/g,
                /User\.new\s*\(\s*params\[/g
            ]
        },
        severity: 'high',
        cweId: 'CWE-915',
        owaspCategory: 'A01:2021 - Broken Access Control',
        languages: ['ruby'],
        remediation: 'Use strong parameters: params.require(:user).permit(:name, :email)',
        examples: {
            vulnerable: 'User.create(params[:user])',
            secure: 'User.create(user_params) # with private user_params method using permit()'
        }
    },
    {
        id: 'ruby-weak-crypto-md5',
        type: types_js_1.VulnerabilityType.WEAK_CRYPTOGRAPHY,
        name: 'Weak Cryptography - MD5',
        description: 'MD5 is cryptographically broken and should not be used',
        patterns: {
            regex: [
                /Digest::MD5/g,
                /OpenSSL::Digest::MD5/g,
                /\.md5\(/g
            ]
        },
        severity: 'medium',
        cweId: 'CWE-327',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
        languages: ['ruby'],
        remediation: 'Use SHA-256 or SHA-3: Digest::SHA256.hexdigest(data)',
        examples: {
            vulnerable: 'password_hash = Digest::MD5.hexdigest(password)',
            secure: 'password_hash = BCrypt::Password.create(password)'
        }
    },
    {
        id: 'ruby-hardcoded-secrets',
        type: types_js_1.VulnerabilityType.HARDCODED_SECRETS,
        name: 'Hardcoded Secrets',
        description: 'Detects hardcoded passwords, API keys, and secrets',
        patterns: {
            regex: [
                /(?:password|passwd|pwd|secret|api_key|apikey|token|private_key)\s*[:=]\s*["'][^"']{8,}/gi,
                /secret_key_base\s*=\s*["'][a-f0-9]{32,}/gi,
                /AWS_SECRET_ACCESS_KEY\s*=\s*["'][A-Za-z0-9/+=]{40}/g
            ]
        },
        severity: 'critical',
        cweId: 'CWE-798',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
        languages: ['ruby'],
        remediation: 'Use environment variables: ENV["SECRET_KEY"] or Rails credentials',
        examples: {
            vulnerable: 'API_KEY = "sk_live_abcd1234efgh5678"',
            secure: 'API_KEY = ENV.fetch("API_KEY")'
        }
    },
    {
        id: 'ruby-sql-injection-interpolation',
        type: types_js_1.VulnerabilityType.SQL_INJECTION,
        name: 'SQL Injection via String Interpolation',
        description: 'Detects SQL injection through string interpolation',
        patterns: {
            regex: [
                /\.(find_by_sql|execute|exec_query|select_all|select_one|select_rows)\s*\(\s*["'`].*?#\{[^}]+\}/g,
                /\.where\s*\(\s*["'`].*?#\{[^}]+\}/g,
                /\.order\s*\(\s*["'`].*?#\{[^}]+\}/g
            ]
        },
        severity: 'critical',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['ruby'],
        remediation: 'Use parameterized queries: where("name = ?", user_input)',
        examples: {
            vulnerable: 'User.where("name = \'#{params[:name]}\'")',
            secure: 'User.where("name = ?", params[:name])'
        }
    },
    {
        id: 'ruby-command-injection',
        type: types_js_1.VulnerabilityType.COMMAND_INJECTION,
        name: 'Command Injection',
        description: 'Detects OS command injection vulnerabilities',
        patterns: {
            regex: [
                /(?:system|exec|spawn|%x)\s*\(\s*["'`].*?#\{[^}]+\}/g,
                /`[^`]*#\{[^}]+\}[^`]*`/g,
                /IO\.popen\s*\(\s*["'`].*?#\{[^}]+\}/g
            ]
        },
        severity: 'critical',
        cweId: 'CWE-78',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['ruby'],
        remediation: 'Use array form: system("echo", user_input) or Open3.capture3',
        examples: {
            vulnerable: 'system("echo #{user_input}")',
            secure: 'system("echo", user_input)'
        }
    },
    {
        id: 'ruby-xpath-injection',
        type: types_js_1.VulnerabilityType.XPATH_INJECTION,
        name: 'XPath Injection',
        description: 'Detects XPath injection vulnerabilities',
        patterns: {
            regex: [
                /\.xpath\s*\(\s*["'`].*?#\{[^}]+\}/g,
                /Nokogiri.*?\.xpath\s*\(\s*["'`].*?#\{[^}]+\}/g
            ]
        },
        severity: 'high',
        cweId: 'CWE-643',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['ruby'],
        remediation: 'Sanitize input or use parameterized XPath queries',
        examples: {
            vulnerable: 'doc.xpath("//user[name=\'#{name}\']")',
            secure: 'doc.xpath("//user[name=$name]", nil, name: name)'
        }
    },
    {
        id: 'ruby-ldap-injection',
        type: types_js_1.VulnerabilityType.LDAP_INJECTION,
        name: 'LDAP Injection',
        description: 'Detects LDAP injection vulnerabilities',
        patterns: {
            regex: [
                /Net::LDAP.*?filter.*?#\{[^}]+\}/g,
                /\bfilter\s*=.*?#\{[^}]+\}/g
            ]
        },
        severity: 'high',
        cweId: 'CWE-90',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['ruby'],
        remediation: 'Use Net::LDAP::Filter.escape() to sanitize input',
        examples: {
            vulnerable: 'filter = "(uid=#{username})"',
            secure: 'filter = "(uid=#{Net::LDAP::Filter.escape(username)})"'
        }
    },
    {
        id: 'ruby-weak-random',
        type: types_js_1.VulnerabilityType.WEAK_CRYPTOGRAPHY,
        name: 'Weak Random Number Generation',
        description: 'Using predictable random number generation',
        patterns: {
            regex: [
                /\brand\s*\(/g,
                /Random\.rand(?!\s*\(\s*SecureRandom)/g,
                /\bsrand\s*\(/g
            ]
        },
        severity: 'medium',
        cweId: 'CWE-330',
        owaspCategory: 'A04:2021 - Insecure Design',
        languages: ['ruby'],
        remediation: 'Use SecureRandom for security-sensitive randomness',
        examples: {
            vulnerable: 'token = rand(1000000)',
            secure: 'token = SecureRandom.hex(16)'
        }
    },
    {
        id: 'ruby-debug-mode-enabled',
        type: types_js_1.VulnerabilityType.DEBUG_MODE,
        name: 'Debug Mode Enabled',
        description: 'Debug mode exposes sensitive information',
        patterns: {
            regex: [
                /config\.consider_all_requests_local\s*=\s*true/g,
                /\bbyebug\b/g,
                /\bdebugger\b/g,
                /binding\.pry/g
            ]
        },
        severity: 'medium',
        cweId: 'CWE-489',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        languages: ['ruby'],
        remediation: 'Remove debug statements and disable debug mode in production',
        examples: {
            vulnerable: 'config.consider_all_requests_local = true',
            secure: 'config.consider_all_requests_local = false'
        }
    },
    {
        id: 'ruby-eval-usage',
        type: types_js_1.VulnerabilityType.VULNERABLE_COMPONENTS,
        name: 'Use of eval()',
        description: 'eval() can execute arbitrary code',
        patterns: {
            regex: [
                /\beval\s*\(/g,
                /instance_eval/g,
                /class_eval/g,
                /module_eval/g
            ]
        },
        severity: 'high',
        cweId: 'CWE-95',
        owaspCategory: 'A06:2021 - Vulnerable and Outdated Components',
        languages: ['ruby'],
        remediation: 'Avoid eval() or validate/sanitize input thoroughly',
        examples: {
            vulnerable: 'eval(user_input)',
            secure: 'send(method_name) if allowed_methods.include?(method_name)'
        }
    },
    {
        id: 'ruby-weak-password-storage',
        type: types_js_1.VulnerabilityType.BROKEN_AUTHENTICATION,
        name: 'Weak Password Storage',
        description: 'Passwords stored without proper hashing',
        patterns: {
            regex: [
                /password\s*=\s*Digest::(MD5|SHA1)/g,
                /user\.password\s*=\s*params/g,
                /password.*?\.downcase(?!.*bcrypt)/g
            ]
        },
        severity: 'critical',
        cweId: 'CWE-256',
        owaspCategory: 'A07:2021 - Identification and Authentication Failures',
        languages: ['ruby'],
        remediation: 'Use BCrypt for password hashing',
        examples: {
            vulnerable: 'user.password = Digest::SHA1.hexdigest(params[:password])',
            secure: 'user.password = BCrypt::Password.create(params[:password])'
        }
    },
    {
        id: 'ruby-unsafe-deserialization-marshal',
        type: types_js_1.VulnerabilityType.INSECURE_DESERIALIZATION,
        name: 'Unsafe Deserialization with Marshal',
        description: 'Marshal.load can execute arbitrary code',
        patterns: {
            regex: [
                /Marshal\.load/g,
                /Marshal\.restore/g
            ]
        },
        severity: 'critical',
        cweId: 'CWE-502',
        owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
        languages: ['ruby'],
        remediation: 'Use JSON or MessagePack for serialization',
        examples: {
            vulnerable: 'data = Marshal.load(user_input)',
            secure: 'data = JSON.parse(user_input)'
        }
    },
    {
        id: 'ruby-unsafe-yaml',
        type: types_js_1.VulnerabilityType.INSECURE_DESERIALIZATION,
        name: 'Unsafe YAML Loading',
        description: 'YAML.load can execute arbitrary code',
        patterns: {
            regex: [
                /YAML\.load(?!_file|_stream)/g,
                /Psych\.load(?!_file|_stream)/g
            ]
        },
        severity: 'high',
        cweId: 'CWE-502',
        owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
        languages: ['ruby'],
        remediation: 'Use YAML.safe_load for untrusted input',
        examples: {
            vulnerable: 'config = YAML.load(user_input)',
            secure: 'config = YAML.safe_load(user_input)'
        }
    },
    {
        id: 'ruby-insufficient-logging',
        type: types_js_1.VulnerabilityType.INSUFFICIENT_LOGGING,
        name: 'Insufficient Security Logging',
        description: 'Missing logging for security-relevant events',
        patterns: {
            regex: [
                /rescue\s*(?:Exception|StandardError)?\s*(?:=>)?\s*\w*\s*\n\s*end/g,
                /rescue\s*\n\s*nil\s*\n\s*end/g
            ]
        },
        severity: 'low',
        cweId: 'CWE-778',
        owaspCategory: 'A09:2021 - Security Logging and Monitoring Failures',
        languages: ['ruby'],
        remediation: 'Log security events and errors appropriately',
        examples: {
            vulnerable: `rescue => e
  nil
end`,
            secure: `rescue => e
  Rails.logger.error "Security event: #{e.message}"
  raise
end`
        }
    },
    {
        id: 'ruby-ssrf-open-uri',
        type: types_js_1.VulnerabilityType.OPEN_REDIRECT,
        name: 'SSRF via open-uri',
        description: 'Unvalidated URLs in open() can lead to SSRF',
        patterns: {
            regex: [
                /open\s*\(\s*params/g,
                /URI\.open\s*\(\s*params/g,
                /Net::HTTP\.get.*params/g
            ]
        },
        severity: 'high',
        cweId: 'CWE-918',
        owaspCategory: 'A10:2021 - Server-Side Request Forgery',
        languages: ['ruby'],
        remediation: 'Validate URLs against allowlist before making requests',
        examples: {
            vulnerable: 'data = open(params[:url]).read',
            secure: 'data = open(validate_url(params[:url])).read'
        }
    },
    {
        id: 'ruby-xss-erb-raw',
        type: types_js_1.VulnerabilityType.XSS,
        name: 'XSS in ERB Templates',
        description: 'Using raw() or html_safe without sanitization',
        patterns: {
            regex: [
                /<%=\s*raw\s+/g,
                /\.html_safe(?!.*sanitize)/g,
                /<%==\s*\w+/g
            ]
        },
        severity: 'medium',
        cweId: 'CWE-79',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['ruby'],
        remediation: 'Use Rails sanitize helpers or escape output by default',
        examples: {
            vulnerable: '<%= raw user_content %>',
            secure: '<%= sanitize user_content %>'
        }
    },
    {
        id: 'ruby-path-traversal',
        type: types_js_1.VulnerabilityType.PATH_TRAVERSAL,
        name: 'Path Traversal',
        description: 'Unvalidated file paths can access unauthorized files',
        patterns: {
            regex: [
                /File\.(read|open|new)\s*\([^)]*params/g,
                /send_file\s*\([^)]*params/g,
                /Dir\.\w+\s*\([^)]*params/g
            ]
        },
        severity: 'high',
        cweId: 'CWE-22',
        owaspCategory: 'A01:2021 - Broken Access Control',
        languages: ['ruby'],
        remediation: 'Validate and sanitize file paths, use File.expand_path with checks',
        examples: {
            vulnerable: 'File.read("uploads/#{params[:file]}")',
            secure: 'File.read(Rails.root.join("uploads", File.basename(params[:file])))'
        }
    },
    {
        id: 'ruby-open-redirect',
        type: types_js_1.VulnerabilityType.OPEN_REDIRECT,
        name: 'Open Redirect',
        description: 'Unvalidated redirects can lead to phishing',
        patterns: {
            regex: [
                /redirect_to\s+params/g,
                /redirect_to\s+request\.(referrer|referer)/g
            ]
        },
        severity: 'medium',
        cweId: 'CWE-601',
        owaspCategory: 'A01:2021 - Broken Access Control',
        languages: ['ruby'],
        remediation: 'Validate redirect URLs against an allowlist',
        examples: {
            vulnerable: 'redirect_to params[:return_to]',
            secure: 'redirect_to safe_redirect_path(params[:return_to]) || root_path'
        }
    },
    {
        id: 'ruby-insecure-cookie',
        type: types_js_1.VulnerabilityType.SECURITY_MISCONFIGURATION,
        name: 'Insecure Cookie Configuration',
        description: 'Cookies without secure flags',
        patterns: {
            regex: [
                /cookies\[.*?\]\s*=(?!.*secure:\s*true)/g,
                /session\[.*?\]\s*=(?!.*secure:\s*true)/g
            ]
        },
        severity: 'medium',
        cweId: 'CWE-614',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        languages: ['ruby'],
        remediation: 'Set secure: true and httponly: true for cookies',
        examples: {
            vulnerable: 'cookies[:auth_token] = token',
            secure: 'cookies[:auth_token] = { value: token, secure: true, httponly: true }'
        }
    }
];
