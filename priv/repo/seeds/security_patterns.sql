-- Security Patterns Data Load
-- Generated: 2025-06-08T03:41:59.704Z
-- Total Patterns: 40

-- Clear existing patterns
DELETE FROM security_patterns;

-- Pattern Distribution:
-- protected: 40 patterns

-- Insert patterns
INSERT INTO security_patterns (
  id, name, description, language, type, severity,
  cwe_id, owasp_category, remediation, confidence,
  framework, regex_patterns, safe_usage_patterns,
  example_code, fix_template, tier_id, is_active,
  source, tags, inserted_at, updated_at
) VALUES
(
  'eed24e71-894d-4210-8ee6-bbf71a127ce1',
  'TypeScript Non-Null Assertion',
  'Detects unsafe non-null assertions that may cause runtime errors',
  'javascript',
  'null_pointer_dereference',
  'medium',
  'CWE-476',
  'A04:2021 - Insecure Design',
  'Use proper null checks instead of non-null assertions',
  'medium',
  NULL,
  ARRAY['\w+!\.(?!length|toString|valueOf)'],
  ARRAY[]::text[],
  '// Vulnerable:
const name = user!.name;

// Secure:
const name = user?.name ||',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['javascript', 'severity-medium', 'owasp-A04'],
  NOW(),
  NOW()
),
(
  '39c160c2-84c3-4bf6-b1e5-f867ea7c4252',
  'GraphQL Introspection Enabled',
  'Detects GraphQL introspection enabled in production',
  'javascript',
  'information_disclosure',
  'medium',
  'CWE-200',
  'A01:2021 - Broken Access Control',
  'Disable GraphQL introspection in production environments',
  'medium',
  NULL,
  ARRAY['introspection:\s*true', 'GraphQLSchema.*introspection:\s*true'],
  ARRAY[]::text[],
  '// Vulnerable:
new GraphQLServer({ schema, introspection: true });

// Secure:
new GraphQLServer({ schema, introspection: process.env.NODE_ENV ===',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['javascript', 'severity-medium', 'owasp-A01'],
  NOW(),
  NOW()
),
(
  '76d4b24b-bbfe-4893-a2b1-79c45e58256e',
  'Electron Node Integration Enabled',
  'Detects unsafe Electron configurations with Node integration',
  'javascript',
  'security_misconfiguration',
  'critical',
  'CWE-829',
  'A05:2021 - Security Misconfiguration',
  'Disable Node integration and enable context isolation',
  'medium',
  NULL,
  ARRAY['nodeIntegration:\s*true', 'contextIsolation:\s*false', 'webSecurity:\s*false'],
  ARRAY[]::text[],
  '// Vulnerable:
new BrowserWindow({ webPreferences: { nodeIntegration: true } });

// Secure:
new BrowserWindow({ webPreferences: { nodeIntegration: false, contextIsolation: true } });',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['javascript', 'severity-critical', 'owasp-A05'],
  NOW(),
  NOW()
),
(
  'e84359a9-dd12-4362-9ea7-0eca516b77c5',
  'Missing Authentication in Rails Controller',
  'Detects Rails controllers without authentication filters',
  'ruby',
  'broken_access_control',
  'high',
  'CWE-862',
  'A01:2021 - Broken Access Control',
  'Add before_action :authenticate_user! to protect sensitive actions',
  'medium',
  NULL,
  ARRAY['class\s+\w+Controller\s*<\s*ApplicationController(?:(?!before_action|before_filter|authenticate).)*end', 'def\s+(admin|delete|update|create)(?:(?!current_user|logged_in|authenticate).)*end'],
  ARRAY[]::text[],
  '// Vulnerable:
class AdminController < ApplicationController
  def users
    @users = User.all
  end
end

// Secure:
class AdminController < ApplicationController
  before_action :authenticate_user!
  before_action :require_admin
  
  def users
    @users = User.all
  end
end',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['ruby', 'severity-high', 'owasp-A01'],
  NOW(),
  NOW()
),
(
  'eb217d13-aa17-4b46-9fc7-edc6ec9e435d',
  'Mass Assignment Vulnerability',
  'Detects unfiltered params in model operations',
  'ruby',
  'mass_assignment',
  'high',
  'CWE-915',
  'A01:2021 - Broken Access Control',
  'Use strong parameters: params.require(:user).permit(:name, :email)',
  'medium',
  NULL,
  ARRAY['\.(create|update|update_attributes|assign_attributes)\s*\(\s*params(?!\s*\.\s*(require|permit))', 'User\.new\s*\(\s*params\['],
  ARRAY[]::text[],
  '// Vulnerable:
User.create(params[:user])

// Secure:
User.create(user_params) # with private user_params method using permit()',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['ruby', 'severity-high', 'owasp-A01'],
  NOW(),
  NOW()
),
(
  '072cad8c-bc53-49b4-939b-95bb721f2ee0',
  'Weak Cryptography - MD5',
  'MD5 is cryptographically broken and should not be used',
  'ruby',
  'weak_cryptography',
  'medium',
  'CWE-327',
  'A02:2021 - Cryptographic Failures',
  'Use SHA-256 or SHA-3: Digest::SHA256.hexdigest(data)',
  'medium',
  NULL,
  ARRAY['Digest::MD5', 'OpenSSL::Digest::MD5', '\.md5\('],
  ARRAY[]::text[],
  '// Vulnerable:
password_hash = Digest::MD5.hexdigest(password)

// Secure:
password_hash = BCrypt::Password.create(password)',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['ruby', 'severity-medium', 'owasp-A02'],
  NOW(),
  NOW()
),
(
  '2bdb1dd1-a24e-4d37-a353-24d8a7dccb5c',
  'Weak Random Number Generation',
  'Using predictable random number generation',
  'ruby',
  'weak_cryptography',
  'medium',
  'CWE-330',
  'A04:2021 - Insecure Design',
  'Use SecureRandom for security-sensitive randomness',
  'medium',
  NULL,
  ARRAY['\brand\s*\(', 'Random\.rand(?!\s*\(\s*SecureRandom)', '\bsrand\s*\('],
  ARRAY[]::text[],
  '// Vulnerable:
token = rand(1000000)

// Secure:
token = SecureRandom.hex(16)',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['ruby', 'severity-medium', 'owasp-A04'],
  NOW(),
  NOW()
),
(
  '9abf0914-be72-4cde-ad67-72af08b0f695',
  'Debug Mode Enabled',
  'Debug mode exposes sensitive information',
  'ruby',
  'debug_mode',
  'medium',
  'CWE-489',
  'A05:2021 - Security Misconfiguration',
  'Remove debug statements and disable debug mode in production',
  'medium',
  NULL,
  ARRAY['config\.consider_all_requests_local\s*=\s*true', '\bbyebug\b', '\bdebugger\b', 'binding\.pry'],
  ARRAY[]::text[],
  '// Vulnerable:
config.consider_all_requests_local = true

// Secure:
config.consider_all_requests_local = false',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['ruby', 'severity-medium', 'owasp-A05'],
  NOW(),
  NOW()
),
(
  'e7116844-44ee-453c-8832-4f4f71c54edf',
  'Use of eval()',
  'eval() can execute arbitrary code',
  'ruby',
  'vulnerable_components',
  'high',
  'CWE-95',
  'A06:2021 - Vulnerable and Outdated Components',
  'Avoid eval() or validate/sanitize input thoroughly',
  'medium',
  NULL,
  ARRAY['\beval\s*\(', 'instance_eval', 'class_eval', 'module_eval'],
  ARRAY[]::text[],
  '// Vulnerable:
eval(user_input)

// Secure:
send(method_name) if allowed_methods.include?(method_name)',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['ruby', 'severity-high', 'owasp-A06'],
  NOW(),
  NOW()
),
(
  '4018ca6a-e03a-4412-a40c-dc5c2bfa325a',
  'Weak Password Storage',
  'Passwords stored without proper hashing',
  'ruby',
  'broken_authentication',
  'critical',
  'CWE-256',
  'A07:2021 - Identification and Authentication Failures',
  'Use BCrypt for password hashing',
  'medium',
  NULL,
  ARRAY['password\s*=\s*Digest::(MD5|SHA1)', 'user\.password\s*=\s*params', 'password.*?\.downcase(?!.*bcrypt)'],
  ARRAY[]::text[],
  '// Vulnerable:
user.password = Digest::SHA1.hexdigest(params[:password])

// Secure:
user.password = BCrypt::Password.create(params[:password])',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['ruby', 'severity-critical', 'owasp-A07'],
  NOW(),
  NOW()
),
(
  'eb847eea-244b-4b9a-87a0-9c00adcda710',
  'Unsafe Deserialization with Marshal',
  'Marshal.load can execute arbitrary code',
  'ruby',
  'insecure_deserialization',
  'critical',
  'CWE-502',
  'A08:2021 - Software and Data Integrity Failures',
  'Use JSON or MessagePack for serialization',
  'medium',
  NULL,
  ARRAY['Marshal\.load', 'Marshal\.restore'],
  ARRAY[]::text[],
  '// Vulnerable:
data = Marshal.load(user_input)

// Secure:
data = JSON.parse(user_input)',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['ruby', 'severity-critical', 'owasp-A08'],
  NOW(),
  NOW()
),
(
  '0a1bf244-6bee-4e65-8c82-0c0004e39383',
  'Unsafe YAML Loading',
  'YAML.load can execute arbitrary code',
  'ruby',
  'insecure_deserialization',
  'high',
  'CWE-502',
  'A08:2021 - Software and Data Integrity Failures',
  'Use YAML.safe_load for untrusted input',
  'medium',
  NULL,
  ARRAY['YAML\.load(?!_file|_stream)', 'Psych\.load(?!_file|_stream)'],
  ARRAY[]::text[],
  '// Vulnerable:
config = YAML.load(user_input)

// Secure:
config = YAML.safe_load(user_input)',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['ruby', 'severity-high', 'owasp-A08'],
  NOW(),
  NOW()
),
(
  'ad417378-7859-4a32-8068-ae15827a2c2c',
  'Insufficient Security Logging',
  'Missing logging for security-relevant events',
  'ruby',
  'insufficient_logging',
  'low',
  'CWE-778',
  'A09:2021 - Security Logging and Monitoring Failures',
  'Log security events and errors appropriately',
  'medium',
  NULL,
  ARRAY['rescue\s*(?:Exception|StandardError)?\s*(?:=>)?\s*\w*\s*\n\s*end', 'rescue\s*\n\s*nil\s*\n\s*end'],
  ARRAY[]::text[],
  '// Vulnerable:
rescue => e
  nil
end

// Secure:
rescue => e
  Rails.logger.error',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['ruby', 'severity-low', 'owasp-A09'],
  NOW(),
  NOW()
),
(
  'c8c1d341-e694-4091-8bbc-ea0bb3a70033',
  'SSRF via open-uri',
  'Unvalidated URLs in open() can lead to SSRF',
  'ruby',
  'open_redirect',
  'high',
  'CWE-918',
  'A10:2021 - Server-Side Request Forgery',
  'Validate URLs against allowlist before making requests',
  'medium',
  NULL,
  ARRAY['open\s*\(\s*params', 'URI\.open\s*\(\s*params', 'Net::HTTP\.get.*params'],
  ARRAY[]::text[],
  '// Vulnerable:
data = open(params[:url]).read

// Secure:
data = open(validate_url(params[:url])).read',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['ruby', 'severity-high', 'owasp-A10'],
  NOW(),
  NOW()
),
(
  '3a7aefcf-c70f-4ffa-913f-42d09e61fd75',
  'XSS in ERB Templates',
  'Using raw() or html_safe without sanitization',
  'ruby',
  'xss',
  'medium',
  'CWE-79',
  'A03:2021 - Injection',
  'Use Rails sanitize helpers or escape output by default',
  'medium',
  NULL,
  ARRAY['<%=\s*raw\s+', '\.html_safe(?!.*sanitize)', '<%==\s*\w+'],
  ARRAY[]::text[],
  '// Vulnerable:
<%= raw user_content %>

// Secure:
<%= sanitize user_content %>',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['ruby', 'severity-medium', 'owasp-A03'],
  NOW(),
  NOW()
),
(
  '55d0eba4-5338-4d4f-9f66-b72cd3a70ce0',
  'Open Redirect',
  'Unvalidated redirects can lead to phishing',
  'ruby',
  'open_redirect',
  'medium',
  'CWE-601',
  'A01:2021 - Broken Access Control',
  'Validate redirect URLs against an allowlist',
  'medium',
  NULL,
  ARRAY['redirect_to\s+params', 'redirect_to\s+request\.(referrer|referer)'],
  ARRAY[]::text[],
  '// Vulnerable:
redirect_to params[:return_to]

// Secure:
redirect_to safe_redirect_path(params[:return_to]) || root_path',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['ruby', 'severity-medium', 'owasp-A01'],
  NOW(),
  NOW()
),
(
  '6db61144-a583-4db8-acf9-3b8b0b1d2b63',
  'Weak Password Hashing in Elixir',
  'Detects use of weak hashing algorithms for passwords',
  'elixir',
  'broken_authentication',
  'high',
  'CWE-916',
  'A07:2021 - Identification and Authentication Failures',
  'Use Bcrypt, Argon2, or Pbkdf2 with appropriate cost factors in Elixir. For Bcrypt, use at least 12 rounds with the bcrypt_elixir library',
  'medium',
  NULL,
  ARRAY[':crypto\.hash\s*\(\s*:(?:md5|sha|sha1|sha256)\s*,', 'Base\.encode\d+\s*\(\s*:crypto\.hash\s*\(\s*:(?:md5|sha|sha1|sha256)\s*,'],
  ARRAY[]::text[],
  '// Vulnerable:
:crypto.hash(:md5, password)

// Secure:
Bcrypt.hash_pwd_salt(password, log_rounds: 12)',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['elixir', 'severity-high', 'owasp-A07'],
  NOW(),
  NOW()
),
(
  '37bee02c-88b2-498a-a546-0ffdd719b7e4',
  'Unsafe Atom Creation',
  'Detects dynamic atom creation from user input which can lead to memory exhaustion',
  'elixir',
  'insecure_deserialization',
  'medium',
  'CWE-502',
  'A08:2021 - Software and Data Integrity Failures',
  'Use Elixir\',
  'medium',
  NULL,
  ARRAY['String\.to_atom\s*\('],
  ARRAY[]::text[],
  '// Vulnerable:
String.to_atom(user_input)

// Secure:
String.to_existing_atom(user_input)',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['elixir', 'severity-medium', 'owasp-A08'],
  NOW(),
  NOW()
),
(
  '20a9b0d1-5354-47a3-a328-e08be5a052d1',
  'Unsafe Code Evaluation',
  'Detects dynamic code evaluation vulnerabilities',
  'elixir',
  'insecure_deserialization',
  'critical',
  'CWE-94',
  'A08:2021 - Software and Data Integrity Failures',
  'Avoid dynamic code evaluation in Elixir. If necessary, strictly validate and sandbox the execution using proper Elixir patterns',
  'medium',
  NULL,
  ARRAY['Code\.eval_string\s*\(', 'Code\.eval_quoted\s*\('],
  ARRAY[]::text[],
  '// Vulnerable:
Code.eval_string(user_input)

// Secure:
case user_input do\n',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['elixir', 'severity-critical', 'owasp-A08'],
  NOW(),
  NOW()
),
(
  '1c06eef6-f16a-48c0-9492-a5ba3ba96a79',
  'Weak Random Number Generation',
  'Detects use of weak random number generators for security purposes',
  'elixir',
  'weak_cryptography',
  'medium',
  'CWE-338',
  'A02:2021 - Cryptographic Failures',
  'Use Elixir\',
  'medium',
  NULL,
  ARRAY[':rand\.uniform\s*\(', 'Enum\.random\s*\(', ':random\.uniform\s*\('],
  ARRAY[]::text[],
  '// Vulnerable:
:rand.uniform(1000000)

// Secure:
:crypto.strong_rand_bytes(4) |> :binary.decode_unsigned()',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['elixir', 'severity-medium', 'owasp-A02'],
  NOW(),
  NOW()
),
(
  '9534fccd-0803-4514-a33e-2ee770743f84',
  'XML External Entity Injection',
  'Detects potential XXE vulnerabilities in XML parsing',
  'elixir',
  'xml_external_entities',
  'high',
  'CWE-611',
  'A05:2021 - Security Misconfiguration',
  'Disable external entity processing in Elixir XML parsers. Use SweetXml or other safe Elixir XML parsing libraries with XXE protection enabled by default',
  'medium',
  NULL,
  ARRAY[':xmerl_scan\.string\s*\('],
  ARRAY[]::text[],
  '// Vulnerable:
:xmerl_scan.string(xml_content)

// Secure:
SweetXml.parse(xml_content, dtd: :none)',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['elixir', 'severity-high', 'owasp-A05'],
  NOW(),
  NOW()
),
(
  '8c96aace-662c-4ba6-90ee-2e3c21a49012',
  'Use of Vulnerable Dependencies',
  'Detects potentially vulnerable Elixir/Erlang functions',
  'elixir',
  'vulnerable_components',
  'medium',
  'CWE-1104',
  'A06:2021 - Vulnerable and Outdated Components',
  'Use modern Elixir alternatives: System.monotonic_time instead of :erlang.now, :rand instead of :random, and always use safe option with binary_to_term',
  'medium',
  NULL,
  ARRAY[':erlang\.now\s*\(\)', ':random\.'],
  ARRAY[]::text[],
  '// Vulnerable:
:erlang.now()

// Secure:
System.monotonic_time()',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['elixir', 'severity-medium', 'owasp-A06'],
  NOW(),
  NOW()
),
(
  '186e4786-fc15-42a3-9409-099ad50b8963',
  'Missing Strong Parameters',
  'Rails controllers using params without permit() allowing mass assignment',
  'rails',
  'mass_assignment',
  'high',
  'CWE-915',
  'A01:2021 - Broken Access Control',
  'Use strong parameters with permit(): params.require(:model).permit(:field1, :field2). Never use permit! in production.',
  'medium',
  NULL,
  ARRAY['\.(create|update|update_attributes|assign_attributes)\s*\(\s*params(?!\s*\.\s*(require|permit))', 'User\.new\s*\(\s*params\[', '\.permit!\s*\)', '\.(create!|update!)\s*\(\s*params\[', '\.insert_all\s*\(\s*params\[', '\.upsert_all\s*\(\s*params\['],
  ARRAY[]::text[],
  '// Vulnerable:
def create
  @user = User.create(params[:user])  # Mass assignment vulnerability
end

// Secure:
def create
  @user = User.create(user_params)
end

private

def user_params
  params.require(:user).permit(:name, :email)
end',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['rails', 'severity-high', 'owasp-A01'],
  NOW(),
  NOW()
),
(
  '846a74ba-5e32-4c43-8033-dc74eafbb2fb',
  'ERB Template Injection',
  'Server-side template injection through ERB evaluation with user input',
  'rails',
  'template_injection',
  'critical',
  'CWE-94',
  'A03:2021 - Injection',
  'Never render user input as Rails ERB templates. Use static Rails templates with safe data binding and Rails helpers.',
  'medium',
  NULL,
  ARRAY['ERB\.new\s*\(\s*params\[', 'ERB\.new\s*\(\s*user_template\)'],
  ARRAY[]::text[],
  '// Vulnerable:
ERB.new(params[:template]).result

// Secure:
render template:',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['rails', 'severity-critical', 'owasp-A03'],
  NOW(),
  NOW()
),
(
  '464189e4-f133-4269-a879-4ac1107e8adb',
  'Unsafe Route Constraints',
  'Route constraints that can be bypassed or allow code execution',
  'rails',
  'broken_access_control',
  'high',
  'CWE-285',
  'A01:2021 - Broken Access Control',
  'Use specific, restrictive regex patterns for Rails route constraints. Avoid dynamic constraints with user input in Rails routes.',
  'medium',
  NULL,
  ARRAY['constraints:\s*\{\s*\w+:\s*\', 'constraints:\s*\{\s*\w+:\s*\', ',
        ', ',
        ', ',
        ', '\.\*'],
  ARRAY[]::text[],
  '// Vulnerable:
get 

// Secure:
get',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['rails', 'severity-high', 'owasp-A01'],
  NOW(),
  NOW()
),
(
  'd5782810-a98e-4c7b-9ab9-58e1d3cdac73',
  'Insecure Session Configuration',
  'Rails session configuration without proper security flags',
  'rails',
  'security_misconfiguration',
  'medium',
  'CWE-614',
  'A05:2021 - Security Misconfiguration',
  'Configure Rails sessions with secure: true, httponly: true, and same_site: :strict for HTTPS environments. Review Rails session store configuration.',
  'medium',
  NULL,
  ARRAY['config\.session_store.*?secure:\s*false', 'config\.session_store.*?httponly:\s*false', 'config\.session_store.*?same_site:\s*:none', 'config\.session_store\s*:cookie_store,\s*key:', 'Rails\.application\.config\.session_store\s*:cookie_store'],
  ARRAY[]::text[],
  '// Vulnerable:
config.session_store :cookie_store, key: 

// Secure:
config.session_store :cookie_store, key:',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['rails', 'severity-medium', 'owasp-A05'],
  NOW(),
  NOW()
),
(
  'fb970967-2363-4212-a267-3ff7c2ee13dc',
  'Dangerous Production Configuration',
  'Development settings enabled in production environment',
  'rails',
  'debug_mode',
  'medium',
  'CWE-489',
  'A05:2021 - Security Misconfiguration',
  'Ensure Rails production environment has consider_all_requests_local=false, debug gems removed, and proper Rails caching enabled',
  'medium',
  NULL,
  ARRAY['config\.consider_all_requests_local\s*=\s*true', 'config\.action_controller\.perform_caching\s*=\s*false', 'config\.log_level\s*=\s*:debug', 'config\.eager_load\s*=\s*false', 'config\.cache_classes\s*=\s*false'],
  ARRAY[]::text[],
  '// Vulnerable:
config.consider_all_requests_local = true

// Secure:
config.consider_all_requests_local = Rails.env.development?',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['rails', 'severity-medium', 'owasp-A05'],
  NOW(),
  NOW()
),
(
  '0e177d01-7544-4b56-bd71-20b74854ca6c',
  'ActionMailer Injection',
  'Email header injection through ActionMailer with unvalidated input',
  'rails',
  'template_injection',
  'high',
  'CWE-117',
  'A03:2021 - Injection',
  'Validate and sanitize email headers. Use address validation for email fields.',
  'medium',
  NULL,
  ARRAY['mail\s*\(\s*to:\s*params\['],
  ARRAY[]::text[],
  '// Vulnerable:
mail(to: params[:email], subject: 

// Secure:
mail(to: validate_email(params[:email]), subject:',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['rails', 'severity-high', 'owasp-A03'],
  NOW(),
  NOW()
),
(
  '83db6854-95fb-4bf6-b01d-e981016aecc0',
  'CVE-2021-22880 - Open Redirect',
  'Host header injection leading to open redirect vulnerability',
  'rails',
  'open_redirect',
  'medium',
  'CWE-601',
  'A01:2021 - Broken Access Control',
  'Validate host headers against an allowlist before using in Rails redirects',
  'medium',
  NULL,
  ARRAY['redirect_to\s+request\.protocol\s*\+\s*request\.host'],
  ARRAY[]::text[],
  '// Vulnerable:
redirect_to request.protocol + request.host + 

// Secure:
redirect_to root_url +',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['rails', 'severity-medium', 'owasp-A01'],
  NOW(),
  NOW()
),
(
  '4d8b23db-2ac1-4f9d-813d-93fbfbf5395a',
  'CVE-2020-8264 - Security Constraint Bypass',
  'Bypass of security constraints through skip callback conditions',
  'rails',
  'broken_access_control',
  'high',
  'CWE-285',
  'A01:2021 - Broken Access Control',
  'Never use user input in Rails skip callback conditions. Use safe, predefined conditions in Rails controllers.',
  'medium',
  NULL,
  ARRAY['skip_before_action.*?if:\s*->\s*\{.*?params\[', 'skip_around_action.*?if:\s*params\[', 'skip_after_action.*?if:\s*->\s*\{.*?eval\s*\('],
  ARRAY[]::text[],
  '// Vulnerable:
skip_before_action :authenticate, if: -> { params[:skip] }

// Secure:
skip_before_action :authenticate, if: :public_action?',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['rails', 'severity-high', 'owasp-A01'],
  NOW(),
  NOW()
),
(
  '9736e592-5ff6-41aa-880d-98e6122a55c6',
  'CVE-2019-5418 - File Content Disclosure',
  'Path traversal vulnerability in render file allowing arbitrary file disclosure',
  'rails',
  'path_traversal',
  'critical',
  'CWE-22',
  'A01:2021 - Broken Access Control',
  'Never use user input directly in Rails render file/template. Use predefined Rails templates or validate against allowlist.',
  'medium',
  NULL,
  ARRAY['render\s+file:\s*params\['],
  ARRAY[]::text[],
  '// Vulnerable:
render file: params[:template]

// Secure:
allowed = [',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['rails', 'severity-critical', 'owasp-A01'],
  NOW(),
  NOW()
),
(
  '618adff3-0b63-4525-94dc-e882fd96b4d2',
  'Django Template XSS',
  'Cross-site scripting through unsafe Django template filters',
  'django',
  'xss',
  'medium',
  'CWE-79',
  'A03:2021 - Injection',
  'Use Django template automatic escaping or Django escape filter. Only use |safe with trusted, sanitized content in Django templates.',
  'medium',
  NULL,
  ARRAY['\{\{\s*\w*\w*content\w*\s*\|\s*safe\s*\}\}', '\{\{\s*.*?\.body\s*\|\s*safe\s*\}\}', 'mark_safe\s*\(\s*user_\w+'],
  ARRAY[]::text[],
  '// Vulnerable:
{{ user_content|safe }}

// Secure:
{{ user_content }} or {{ user_content|escape }}',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['django', 'severity-medium', 'owasp-A03'],
  NOW(),
  NOW()
),
(
  'fb741131-d6b8-4ca5-b7d9-c753e34dbe2a',
  'Dangerous Django Debug Settings',
  'Debug mode and development settings enabled in production',
  'django',
  'debug_mode',
  'high',
  'CWE-489',
  'A05:2021 - Security Misconfiguration',
  'Set Django DEBUG=False, configure Django ALLOWED_HOSTS, remove debug apps from Django INSTALLED_APPS, and use Django environment-specific settings',
  'medium',
  NULL,
  ARRAY['DEBUG\s*=\s*True'],
  ARRAY[]::text[],
  '// Vulnerable:
DEBUG = True\nALLOWED_HOSTS = []

// Secure:
DEBUG = False\nALLOWED_HOSTS = [',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['django', 'severity-high', 'owasp-A05'],
  NOW(),
  NOW()
),
(
  '1daa09b5-af83-489c-91a0-aee5f68da6ae',
  'Insecure Django Session Configuration',
  'Django session and cookie settings without proper security flags',
  'django',
  'security_misconfiguration',
  'medium',
  'CWE-614',
  'A05:2021 - Security Misconfiguration',
  'Set Django session secure=True, httponly=True, and samesite=',
  'medium',
  NULL,
  ARRAY['SESSION_COOKIE_SECURE\s*=\s*False', 'SESSION_COOKIE_HTTPONLY\s*=\s*False', 'SESSION_COOKIE_SAMESITE\s*=\s*None', 'CSRF_COOKIE_SECURE\s*=\s*False', 'CSRF_COOKIE_HTTPONLY\s*=\s*False', 'SESSION_EXPIRE_AT_BROWSER_CLOSE\s*=\s*False', 'SESSION_COOKIE_AGE\s*=\s*31536000', 'SESSION_SAVE_EVERY_REQUEST\s*=\s*False'],
  ARRAY[]::text[],
  '// Vulnerable:
SESSION_COOKIE_SECURE = False

// Secure:
SESSION_COOKIE_SECURE = True\nSESSION_COOKIE_HTTPONLY = True',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['django', 'severity-medium', 'owasp-A05'],
  NOW(),
  NOW()
),
(
  '911a6e98-9056-4a75-a171-85efa49230d3',
  'Django Broken Authentication',
  'Weak authentication patterns and missing validation',
  'django',
  'broken_authentication',
  'high',
  'CWE-287',
  'A07:2021 - Identification and Authentication Failures',
  'Use Django built-in authentication system, require Django login decorators, implement Django password validators, avoid hardcoded credentials',
  'medium',
  NULL,
  ARRAY['def\s+\w*admin\w*.*?\(.*?request.*?\):(?!.*@login_required)(?!.*request\.user\.is_authenticated)'],
  ARRAY[]::text[],
  '// Vulnerable:
if user.password == password:

// Secure:
if user.check_password(password):',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['django', 'severity-high', 'owasp-A07'],
  NOW(),
  NOW()
),
(
  '5e69c63a-10bd-4acf-bb56-a141ec1f8ca4',
  'Django CSRF Protection Bypass',
  'Cross-Site Request Forgery protection bypassed or disabled',
  'django',
  'csrf',
  'high',
  'CWE-352',
  'A01:2021 - Broken Access Control',
  'Remove Django @csrf_exempt from sensitive views, include Django {% csrf_token %} in forms, send CSRF token in AJAX requests using Django CSRF middleware',
  'medium',
  NULL,
  ARRAY['@csrf_exempt\s+def\s+transfer_money', '@csrf_exempt\s+def\s+delete_account', '@csrf_exempt\s+def\s+change_password'],
  ARRAY[]::text[],
  '// Vulnerable:
@csrf_exempt\ndef transfer_money(request):

// Secure:
def transfer_money(request):  # Uses CSRF protection by default',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['django', 'severity-high', 'owasp-A01'],
  NOW(),
  NOW()
),
(
  'ad017b9e-2ce2-4c0f-8e6f-900a19faee3a',
  'Django Clickjacking Vulnerability',
  'Missing or disabled X-Frame-Options protection',
  'django',
  'security_misconfiguration',
  'medium',
  'CWE-1021',
  'A05:2021 - Security Misconfiguration',
  'Use Django X_FRAME_OPTIONS = ',
  'medium',
  NULL,
  ARRAY['@xframe_options_exempt'],
  ARRAY[]::text[],
  '// Vulnerable:
@xframe_options_exempt\ndef sensitive_view(request):

// Secure:
def sensitive_view(request):  # Uses X-Frame-Options by default',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['django', 'severity-medium', 'owasp-A05'],
  NOW(),
  NOW()
),
(
  '3fccf2f2-dbb9-458f-8b85-1c548b4049b8',
  'Django Mass Assignment',
  'Mass assignment vulnerabilities in Django model operations',
  'django',
  'mass_assignment',
  'high',
  'CWE-915',
  'A01:2021 - Broken Access Control',
  'Use ModelForm with explicit fields, validate input, implement field whitelisting',
  'medium',
  NULL,
  ARRAY['User\.objects\.create\s*\(\s*\*\*\s*request\.POST\s*\)', 'User\s*\(\s*\*\*\s*request\.POST\.dict\(\)\s*\)\.save\(\)', 'User\.objects\.bulk_create\s*\(\s*\[\s*User\s*\(\s*\*\*\s*data\s*\)', 'User\.objects\.filter\s*\(.*?\)\.update\s*\(\s*\*\*\s*request\.POST\s*\)', 'user\.__dict__\.update\s*\(\s*request\.POST\s*\)', 'form\s*=\s*ModelForm\s*\(\s*request\.POST.*?instance\s*=\s*user\s*\)', 'class\s+\w+Form\s*\(\s*ModelForm\s*\):.*?class\s+Meta:.*?model\s*=\s*\w+(?!.*fields)'],
  ARRAY[]::text[],
  '// Vulnerable:
User.objects.create(**request.POST)

// Secure:
User.objects.create(name=request.POST[',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['django', 'severity-high', 'owasp-A01'],
  NOW(),
  NOW()
),
(
  'fb621946-2494-4a3e-908c-e7ca37b78cdf',
  'CVE-2021-33571 - URL Validation Bypass',
  'URL validation bypass allowing open redirects',
  'django',
  'open_redirect',
  'medium',
  'CWE-601',
  'A01:2021 - Broken Access Control',
  'Validate redirect URLs against allowlist, sanitize URL schemes, use Django is_safe_url() for redirects',
  'medium',
  NULL,
  ARRAY['URLValidator\(\)\s*\(\s*user_\w+'],
  ARRAY[]::text[],
  '// Vulnerable:
HttpResponseRedirect(request.GET[

// Secure:
from django.utils.http import is_safe_url\nif is_safe_url(url, allowed_hosts={request.get_host()}):\n    return HttpResponseRedirect(url)',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['django', 'severity-medium', 'owasp-A01'],
  NOW(),
  NOW()
),
(
  '19ad1d09-42f0-4c22-89ad-f802b0aa371c',
  'CVE-2018-14574 - CommonMiddleware Open Redirect',
  'Open redirect vulnerability in Django CommonMiddleware',
  'django',
  'open_redirect',
  'medium',
  'CWE-601',
  'A01:2021 - Broken Access Control',
  'Validate redirect URLs in Django, use absolute URLs instead of Django get_full_path(), implement URL allowlisting',
  'medium',
  NULL,
  ARRAY['return\s+HttpResponsePermanentRedirect\s*\(\s*request\.get_full_path\(\)\s*\)'],
  ARRAY[]::text[],
  '// Vulnerable:
return HttpResponseRedirect(request.get_full_path())

// Secure:
return HttpResponseRedirect(',
  NULL,
  (SELECT id FROM pattern_tiers WHERE name = 'protected'),
  true,
  'rsolv',
  ARRAY['django', 'severity-medium', 'owasp-A01'],
  NOW(),
  NOW()
)
;