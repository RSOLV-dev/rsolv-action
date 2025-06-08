
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
exports.railsSecurityPatterns = void 0;
const types_js_1 = {};
exports.railsSecurityPatterns = [
    {
        id: 'rails-strong-parameters',
        type: types_js_1.VulnerabilityType.MASS_ASSIGNMENT,
        name: 'Missing Strong Parameters',
        description: 'Rails controllers using params without permit() allowing mass assignment',
        patterns: {
            regex: [
                /\.(create|update|update_attributes|assign_attributes)\s*\(\s*params(?!\s*\.\s*(require|permit))/,
                /User\.new\s*\(\s*params\[/,
                /\.permit!\s*\)/,
                /\.(create!|update!)\s*\(\s*params\[/,
                /\.insert_all\s*\(\s*params\[/,
                /\.upsert_all\s*\(\s*params\[/
            ]
        },
        severity: 'high',
        cweId: 'CWE-915',
        owaspCategory: 'A01:2021 - Broken Access Control',
        languages: ['ruby'],
        remediation: 'Use strong parameters with permit(): params.require(:model).permit(:field1, :field2). Never use permit! in production.',
        examples: {
            vulnerable: `def create
  @user = User.create(params[:user])  # Mass assignment vulnerability
end`,
            secure: `def create
  @user = User.create(user_params)
end

private

def user_params
  params.require(:user).permit(:name, :email)
end`
        }
    },
    {
        id: 'rails-attr-accessible',
        type: types_js_1.VulnerabilityType.MASS_ASSIGNMENT,
        name: 'Dangerous attr_accessible Usage',
        description: 'Overly permissive attr_accessible in older Rails versions or missing protection',
        patterns: {
            regex: [
                /class\s+\w+\s*<\s*ActiveRecord::Base[\s\S]+?end/,
                /attr_accessible\s+:role\s*,\s*:admin/,
                /attr_accessible\s+:password/,
                /attr_accessible\s+:.*\s*,\s*:as\s*=>\s*:admin/
            ]
        },
        severity: 'high',
        cweId: 'CWE-915',
        owaspCategory: 'A01:2021 - Broken Access Control',
        languages: ['ruby'],
        remediation: 'Upgrade to Rails 4+ and use strong parameters. If using older Rails, carefully restrict attr_accessible fields.',
        examples: {
            vulnerable: `class User < ActiveRecord::Base
  attr_accessible :role, :admin  # Dangerous
end`,
            secure: `class User < ActiveRecord::Base
  attr_accessible :name, :email
  attr_protected :role, :admin
end`
        }
    },
    {
        id: 'rails-activerecord-injection',
        type: types_js_1.VulnerabilityType.SQL_INJECTION,
        name: 'ActiveRecord SQL Injection',
        description: 'SQL injection through ActiveRecord methods using string interpolation',
        patterns: {
            regex: [
                /\.where\s*\(\s*["'`].*?#\{[^}]+\}/,
                /\.joins\s*\(\s*["'`].*?#\{[^}]+\}/,
                /\.group\s*\(\s*["'`].*?#\{[^}]+\}/,
                /\.having\s*\(\s*["'`].*?#\{[^}]+\}/,
                /\.order\s*\(\s*["'`].*?#\{[^}]+\}/,
                /\.select\s*\(\s*["'`].*?#\{[^}]+\}/,
                /\.find_by_sql\s*\(\s*["'`].*?#\{[^}]+\}/,
                /\.count_by_sql\s*\(\s*["'`].*?#\{[^}]+\}/,
                /\.exists\?\s*\(\s*\[["'`].*?#\{[^}]+\}/,
                /\.update_all\s*\(\s*["'`].*?#\{[^}]+\}/,
                /\.delete_all\s*\(\s*["'`].*?#\{[^}]+\}/
            ]
        },
        severity: 'critical',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['ruby'],
        remediation: 'Use Rails parameterized queries: where("name = ?", params[:name]) or ActiveRecord hash conditions: where(name: params[:name])',
        examples: {
            vulnerable: 'User.where("name = \'#{params[:name]}\'")',
            secure: 'User.where("name = ?", params[:name]) or User.where(name: params[:name])'
        }
    },
    {
        id: 'rails-dynamic-finder-injection',
        type: types_js_1.VulnerabilityType.SQL_INJECTION,
        name: 'Dynamic Finder Injection',
        description: 'SQL injection through dynamic method calls with user input',
        patterns: {
            regex: [
                /\.send\s*\(\s*["'`]find_by_#\{[^}]+\}/,
                /\.method\s*\(\s*["'`]find_by_#\{[^}]+\}/,
                /\.send\s*\(\s*["'`]#\{[^}]+\}.*?_users["'`]/,
                /\.send\s*\(\s*["'`]#\{[^}]+\}["'`]\s*,/,
                /\.send\s*\(\s*\w*params\[/,
                /\.send\s*\(\s*["'`]#\{[^}]*params[^}]*\}[=]?["'`]/
            ]
        },
        severity: 'high',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['ruby'],
        remediation: 'Avoid dynamic method names with user input in Rails. Use whitelisted method names or ActiveRecord hash-based queries.',
        examples: {
            vulnerable: 'User.send("find_by_#{params[:field]}", params[:value])',
            secure: 'allowed_fields = ["name", "email"]\nif allowed_fields.include?(params[:field])\n  User.where(params[:field] => params[:value])\nend'
        }
    },
    {
        id: 'rails-erb-injection',
        type: types_js_1.VulnerabilityType.TEMPLATE_INJECTION,
        name: 'ERB Template Injection',
        description: 'Server-side template injection through ERB evaluation with user input',
        patterns: {
            regex: [
                /ERB\.new\s*\(\s*params\[/,
                /ERB\.new\s*\(\s*user_template\)/,
                /ERB\.new\s*\(\s*["'`]<%= #\{params\[:code\]\}/,
                /ActionView::Template\.new\s*\(\s*params\[/,
                /render\s+inline:\s*params\[/,
                /render\s+plain:\s*erb_template/,
                /render\s+template:\s*["'`]#\{params\[/,
                /render\s+partial:\s*params\[/,
                /Haml::Engine\.new\s*\(\s*params\[/,
                /Haml\.render\s*\(\s*user_input\)/
            ]
        },
        severity: 'critical',
        cweId: 'CWE-94',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['ruby'],
        remediation: 'Never render user input as Rails ERB templates. Use static Rails templates with safe data binding and Rails helpers.',
        examples: {
            vulnerable: 'ERB.new(params[:template]).result',
            secure: 'render template: "fixed_template", locals: { data: params[:data] }'
        }
    },
    {
        id: 'rails-template-xss',
        type: types_js_1.VulnerabilityType.XSS,
        name: 'Rails Template XSS',
        description: 'Cross-site scripting through unsafe template output',
        patterns: {
            regex: [
                /<%=\s*raw\s+[\w@]+/,
                /\.html_safe/,
                /<%==\s*[\w@.]+/,
                /content_tag.*?raw\s*\(/,
                /link_to\s+raw\s*\(/,
                /link_to.*?\.html_safe/,
                /!=\s*[\w@.]+/
            ]
        },
        severity: 'medium',
        cweId: 'CWE-79',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['ruby'],
        remediation: 'Use Rails built-in escaping or Rails sanitize helpers: sanitize(), strip_tags(), or escape HTML entities. Remove raw() and html_safe calls on user content.',
        examples: {
            vulnerable: '<%= raw user_content %>',
            secure: '<%= sanitize user_content %> or <%= user_content %>'
        }
    },
    {
        id: 'rails-unsafe-route-constraints',
        type: types_js_1.VulnerabilityType.BROKEN_ACCESS_CONTROL,
        name: 'Unsafe Route Constraints',
        description: 'Route constraints that can be bypassed or allow code execution',
        patterns: {
            regex: [
                /constraints:\s*\{\s*\w+:\s*\/\.\*\//,
                /constraints:\s*\{\s*\w+:\s*\/.*?#\{.*?params/,
                /constraints:\s*lambda.*?eval\s*\(/,
                /constraints\s+lambda.*?\{\s*\|\s*req\s*\|\s*true\s*\}/,
                /constraints\s+subdomain:\s*\/\.\*/
            ]
        },
        severity: 'high',
        cweId: 'CWE-285',
        owaspCategory: 'A01:2021 - Broken Access Control',
        languages: ['ruby'],
        remediation: 'Use specific, restrictive regex patterns for Rails route constraints. Avoid dynamic constraints with user input in Rails routes.',
        examples: {
            vulnerable: 'get "users/:id", constraints: { id: /.*/ }',
            secure: 'get "users/:id", constraints: { id: /\\d+/ }'
        }
    },
    {
        id: 'rails-unsafe-globbing',
        type: types_js_1.VulnerabilityType.PATH_TRAVERSAL,
        name: 'Unsafe Route Globbing',
        description: 'Glob routes that allow path traversal attacks',
        patterns: {
            regex: [
                /get\s+["'`].*?\*\w+["'`]\s*,\s*to:/,
                /match\s+["'`]\*\w+["'`]/,
                /get\s+["'`]files\/\*path["'`]/,
                /get\s+["'`]download\/\*\w+["'`]/
            ]
        },
        severity: 'high',
        cweId: 'CWE-22',
        owaspCategory: 'A01:2021 - Broken Access Control',
        languages: ['ruby'],
        remediation: 'Validate Rails glob parameters thoroughly and restrict file access to safe directories in Rails routes',
        examples: {
            vulnerable: 'get "files/*path", to: "files#show"',
            secure: 'get "files/*path", to: "files#show", constraints: { path: /[^.]+/ }'
        }
    },
    {
        id: 'rails-insecure-session-config',
        type: types_js_1.VulnerabilityType.SECURITY_MISCONFIGURATION,
        name: 'Insecure Session Configuration',
        description: 'Rails session configuration without proper security flags',
        patterns: {
            regex: [
                /config\.session_store.*?secure:\s*false/,
                /config\.session_store.*?httponly:\s*false/,
                /config\.session_store.*?same_site:\s*:none/,
                /config\.session_store\s*:cookie_store,\s*key:/,
                /Rails\.application\.config\.session_store\s*:cookie_store/,
                /session_store.*?secret:\s*["'][^"']{1,8}["']/
            ]
        },
        severity: 'medium',
        cweId: 'CWE-614',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        languages: ['ruby'],
        remediation: 'Configure Rails sessions with secure: true, httponly: true, and same_site: :strict for HTTPS environments. Review Rails session store configuration.',
        examples: {
            vulnerable: 'config.session_store :cookie_store, key: "_app_session"',
            secure: 'config.session_store :cookie_store, key: "_app_session", secure: true, httponly: true, same_site: :strict'
        }
    },
    {
        id: 'rails-dangerous-production-config',
        type: types_js_1.VulnerabilityType.DEBUG_MODE,
        name: 'Dangerous Production Configuration',
        description: 'Development settings enabled in production environment',
        patterns: {
            regex: [
                /config\.consider_all_requests_local\s*=\s*true/,
                /config\.action_controller\.perform_caching\s*=\s*false/,
                /config\.log_level\s*=\s*:debug/,
                /config\.eager_load\s*=\s*false/,
                /config\.cache_classes\s*=\s*false/,
                /gem\s+["']byebug["']/,
                /gem\s+["']pry["']/,
                /gem\s+["']pry-rails["']/,
                /config\.assets\.debug\s*=\s*true/,
                /config\.assets\.compress\s*=\s*false/
            ]
        },
        severity: 'medium',
        cweId: 'CWE-489',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        languages: ['ruby'],
        remediation: 'Ensure Rails production environment has consider_all_requests_local=false, debug gems removed, and proper Rails caching enabled',
        examples: {
            vulnerable: 'config.consider_all_requests_local = true',
            secure: 'config.consider_all_requests_local = Rails.env.development?'
        }
    },
    {
        id: 'rails-insecure-cors',
        type: types_js_1.VulnerabilityType.SECURITY_MISCONFIGURATION,
        name: 'Insecure CORS Configuration',
        description: 'Overly permissive Cross-Origin Resource Sharing configuration',
        patterns: {
            regex: [
                /origins\s+["']\*["']/,
                /headers\s+:any/,
                /methods\s+:any/,
                /origins\s+["']\*["'].*?credentials\s+true/s
            ]
        },
        severity: 'medium',
        cweId: 'CWE-346',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        languages: ['ruby'],
        remediation: 'Specify explicit origins, headers, and methods in Rails CORS. Never use credentials: true with origins: "*" in Rails',
        examples: {
            vulnerable: 'origins "*"\ncredentials true',
            secure: 'origins "https://example.com"\ncredentials true'
        }
    },
    {
        id: 'rails-actionmailer-injection',
        type: types_js_1.VulnerabilityType.TEMPLATE_INJECTION,
        name: 'ActionMailer Injection',
        description: 'Email header injection through ActionMailer with unvalidated input',
        patterns: {
            regex: [
                /mail\s*\(\s*to:\s*params\[/,
                /mail\s*\(\s*.*?subject:\s*["'`].*?#\{[^}]*params/,
                /mail\s*\(\s*.*?from:\s*["'`].*?#\{[^}]*params/,
                /mail\s*\(\s*.*?cc:\s*params\[/,
                /mail\s*\(\s*.*?bcc:\s*params\[/,
                /mail\s*\(\s*.*?body:\s*ERB\.new\s*\(\s*params\[/,
                /mail\s*\(\s*.*?template_name:\s*params\[/
            ]
        },
        severity: 'high',
        cweId: 'CWE-117',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['ruby'],
        remediation: 'Validate and sanitize email headers. Use address validation for email fields.',
        examples: {
            vulnerable: 'mail(to: params[:email], subject: "Hello #{params[:name]}")',
            secure: 'mail(to: validate_email(params[:email]), subject: "Hello #{sanitize(params[:name])}")'
        }
    },
    {
        id: 'rails-session-fixation',
        type: types_js_1.VulnerabilityType.BROKEN_AUTHENTICATION,
        name: 'Session Fixation Vulnerability',
        description: 'Missing session regeneration after authentication allowing session fixation',
        patterns: {
            regex: [
                /def\s+login[\s\S]*?session\[:user_id\]\s*=[\s\S]*?end/,
                /session\[:user_id\]\s*=.*?\.id/,
                /def\s+create[\s\S]*?session\[:admin\]\s*=\s*true/
            ]
        },
        severity: 'medium',
        cweId: 'CWE-384',
        owaspCategory: 'A07:2021 - Identification and Authentication Failures',
        languages: ['ruby'],
        remediation: 'Call Rails reset_session or session.regenerate before setting authentication session variables in Rails controllers',
        examples: {
            vulnerable: `def login
  if user.authenticate(params[:password])
    session[:user_id] = user.id
  end
end`,
            secure: `def login
  if user.authenticate(params[:password])
    reset_session
    session[:user_id] = user.id
  end
end`
        }
    },
    {
        id: 'rails-insecure-session-data',
        type: types_js_1.VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
        name: 'Sensitive Data in Session',
        description: 'Storing sensitive information in session cookies',
        patterns: {
            regex: [
                /session\[:password\]/,
                /session\[:credit_card\]/,
                /session\[:ssn\]/,
                /session\[:api_key\]/,
                /session\[:secret_token\]/,
                /session\[:private_key\]/
            ]
        },
        severity: 'high',
        cweId: 'CWE-200',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
        languages: ['ruby'],
        remediation: 'Store only non-sensitive identifiers in Rails sessions. Keep sensitive data in secure server-side storage, not Rails session cookies.',
        examples: {
            vulnerable: 'session[:password] = params[:password]',
            secure: 'session[:user_id] = user.id  # Store ID only'
        }
    },
    {
        id: 'rails-cve-2022-22577',
        type: types_js_1.VulnerabilityType.XSS,
        name: 'CVE-2022-22577 - XSS in Action Pack',
        description: 'XSS vulnerability in CSP headers allowing script injection',
        patterns: {
            regex: [
                /response\.headers\["Content-Security-Policy"\]\s*=.*?#\{params\[:csp\]\}/,
                /content_security_policy[\s\S]*?policy\.[\w_]+\s+params\[/
            ]
        },
        severity: 'medium',
        cweId: 'CWE-79',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['ruby'],
        remediation: 'Validate and sanitize any user input used in Content-Security-Policy headers',
        examples: {
            vulnerable: 'response.headers["Content-Security-Policy"] = "default-src #{params[:csp]}"',
            secure: 'response.headers["Content-Security-Policy"] = "default-src \'self\'"'
        }
    },
    {
        id: 'rails-cve-2021-22880',
        type: types_js_1.VulnerabilityType.OPEN_REDIRECT,
        name: 'CVE-2021-22880 - Open Redirect',
        description: 'Host header injection leading to open redirect vulnerability',
        patterns: {
            regex: [
                /redirect_to\s+request\.protocol\s*\+\s*request\.host/,
                /redirect_to\s+["'`]#\{request\.protocol\}#\{request\.host\}/,
                /url_for\s*\(\s*host:\s*request\.host.*?path:\s*params\[/
            ]
        },
        severity: 'medium',
        cweId: 'CWE-601',
        owaspCategory: 'A01:2021 - Broken Access Control',
        languages: ['ruby'],
        remediation: 'Validate host headers against an allowlist before using in Rails redirects',
        examples: {
            vulnerable: 'redirect_to request.protocol + request.host + "/path"',
            secure: 'redirect_to root_url + "/path"'
        }
    },
    {
        id: 'rails-cve-2020-8264',
        type: types_js_1.VulnerabilityType.BROKEN_ACCESS_CONTROL,
        name: 'CVE-2020-8264 - Security Constraint Bypass',
        description: 'Bypass of security constraints through skip callback conditions',
        patterns: {
            regex: [
                /skip_before_action.*?if:\s*->\s*\{.*?params\[/,
                /skip_around_action.*?if:\s*params\[/,
                /skip_after_action.*?if:\s*->\s*\{.*?eval\s*\(/
            ]
        },
        severity: 'high',
        cweId: 'CWE-285',
        owaspCategory: 'A01:2021 - Broken Access Control',
        languages: ['ruby'],
        remediation: 'Never use user input in Rails skip callback conditions. Use safe, predefined conditions in Rails controllers.',
        examples: {
            vulnerable: 'skip_before_action :authenticate, if: -> { params[:skip] }',
            secure: 'skip_before_action :authenticate, if: :public_action?'
        }
    },
    {
        id: 'rails-cve-2019-5418',
        type: types_js_1.VulnerabilityType.PATH_TRAVERSAL,
        name: 'CVE-2019-5418 - File Content Disclosure',
        description: 'Path traversal vulnerability in render file allowing arbitrary file disclosure',
        patterns: {
            regex: [
                /render\s+file:\s*params\[/,
                /render\s+file:\s*["'`]#\{Rails\.root\}.*?#\{[^}]*params/,
                /render\s+template:\s*params\[.*?path/,
                /render\s+partial:\s*["'`]\.\.\/.*?#\{[^}]*params/
            ]
        },
        severity: 'critical',
        cweId: 'CWE-22',
        owaspCategory: 'A01:2021 - Broken Access Control',
        languages: ['ruby'],
        remediation: 'Never use user input directly in Rails render file/template. Use predefined Rails templates or validate against allowlist.',
        examples: {
            vulnerable: 'render file: params[:template]',
            secure: 'allowed = ["user", "admin"]\nrender template: allowed.include?(params[:type]) ? params[:type] : "default"'
        }
    }
];
