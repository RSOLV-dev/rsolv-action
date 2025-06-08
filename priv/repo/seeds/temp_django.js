
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
exports.djangoSecurityPatterns = void 0;
const types_js_1 = {};
exports.djangoSecurityPatterns = [
    {
        id: 'django-orm-injection',
        type: types_js_1.VulnerabilityType.SQL_INJECTION,
        name: 'Django ORM SQL Injection',
        description: 'SQL injection through Django ORM using string formatting',
        patterns: {
            regex: [
                /\.filter\s*\(\s*["'].*?%s["'].*?%/,
                /\.extra\s*\(\s*where\s*=\s*\[["'].*?%s["'].*?%/,
                /\.raw\s*\(\s*["'].*?%s["'].*?%/,
                /\.filter\s*\(\s*f["'].*?\{.*?\}["']/,
                /\.extra\s*\(\s*where\s*=\s*\[f["'].*?\{.*?\}["']/,
                /\.raw\s*\(\s*f["'].*?\{.*?\}["']/,
                /\.filter\s*\(\s*["'].*?\.format\s*\(/,
                /\.extra\s*\(\s*.*?\.format\s*\(/,
                /\.raw\s*\(\s*["'].*?\.format\s*\(/,
                /cursor\.execute\s*\(\s*["'].*?%s["'].*?%/,
                /cursor\.execute\s*\(\s*f["'].*?\{.*?\}["']/,
                /\.extra\s*\(\s*select_related\s*=.*?user_input/,
                /\.extra\s*\(\s*order_by\s*=.*?user_\w+/,
                /\.extra\s*\(\s*where\s*=\s*\[user_condition\]/,
                /\.extra\s*\(\s*tables\s*=\s*\[user_table\]/
            ]
        },
        severity: 'critical',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['python'],
        remediation: 'Use Django parameterized queries: Model.objects.raw("SELECT * FROM table WHERE id = %s", [user_id]) or Django ORM methods: filter(name=username)',
        examples: {
            vulnerable: 'User.objects.filter("name = \'%s\'" % username)',
            secure: 'User.objects.filter(name=username) or User.objects.raw("SELECT * FROM users WHERE name = %s", [username])'
        }
    },
    {
        id: 'django-nosql-injection',
        type: types_js_1.VulnerabilityType.NOSQL_INJECTION,
        name: 'Django NoSQL Injection',
        description: 'NoSQL injection through MongoDB, Elasticsearch, or Redis with user input',
        patterns: {
            regex: [
                /\.raw\s*\(\s*\{\s*["\']?\$where["\']?:\s*.*?user_\w+/g,
                /\.mongo_find\s*\(\s*\{\s*["\']?\$where["\']?:\s*f["'`]/g,
                /collection\.find\s*\(\s*\{\s*["\']?\$where["\']?:\s*.*?user_\w+/g,
                /\.aggregate\s*\(\s*\[.*?eval\s*\(/g,
                /client\.search\s*\(\s*body\s*=\s*\{\s*["']query["'].*?user_query/g,
                /Search\(\)\.query\s*\(\s*user_\w+/g,
                /redis_client\.eval\s*\(\s*user_\w+/g,
                /redis_client\.execute_command\s*\(\s*user_\w+/
            ]
        },
        severity: 'critical',
        cweId: 'CWE-943',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['python'],
        remediation: 'Sanitize NoSQL queries in Django, use parameterized queries where available, and validate user input against allowlists with Django validators',
        examples: {
            vulnerable: 'collection.find({"$where": f"this.name == \'{name}\'"})',
            secure: 'collection.find({"name": name})'
        }
    },
    {
        id: 'django-template-xss',
        type: types_js_1.VulnerabilityType.XSS,
        name: 'Django Template XSS',
        description: 'Cross-site scripting through unsafe Django template filters',
        patterns: {
            regex: [
                /\{\{\s*\w*\w*content\w*\s*\|\s*safe\s*\}\}/g,
                /\{\{\s*.*?\.body\s*\|\s*safe\s*\}\}/g,
                /mark_safe\s*\(\s*user_\w+/g,
                /mark_safe\s*\(\s*f["'`].*?\{.*?user_\w+/g,
                /SafeString\s*\(\s*user_\w+/g,
                /SafeText\s*\(\s*user_\w+/g,
                /format_html\s*\(.*?mark_safe\s*\(/g,
                /\{\{\s*.*?\|\s*safe\s*\}\}/g,
                /\{\%\s*autoescape\s+off\s*\%\}\s*\{\{\s*user_\w+/
            ]
        },
        severity: 'medium',
        cweId: 'CWE-79',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['python'],
        remediation: 'Use Django template automatic escaping or Django escape filter. Only use |safe with trusted, sanitized content in Django templates.',
        examples: {
            vulnerable: '{{ user_content|safe }}',
            secure: '{{ user_content }} or {{ user_content|escape }}'
        }
    },
    {
        id: 'django-template-injection',
        type: types_js_1.VulnerabilityType.TEMPLATE_INJECTION,
        name: 'Django Template Injection',
        description: 'Server-side template injection through dynamic template compilation',
        patterns: {
            regex: [
                /Template\s*\(\s*request\.GET\[["']\w+["']\]/g,
                /Engine\(\)\.from_string\s*\(\s*user_\w+/g,
                /get_template\s*\(\s*request\.POST\[["']\w+["']\]/g,
                /select_template\s*\(\s*\[\s*user_\w+/g,
                /render_to_string\s*\(\s*user_\w+/g,
                /jinja2\.Template\s*\(\s*user_\w+/g,
                /Environment\(\)\.from_string\s*\(\s*user_\w+/g,
                /custom_engine\.compile\s*\(\s*user_\w+/g,
                /template_engine\.render\s*\(\s*user_\w+/
            ]
        },
        severity: 'critical',
        cweId: 'CWE-94',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['python'],
        remediation: 'Never compile user input as Django templates. Use static Django templates with context variables and Django template system.',
        examples: {
            vulnerable: 'Template(request.GET["template"]).render(context)',
            secure: 'get_template("fixed_template.html").render(context)'
        }
    },
    {
        id: 'django-debug-settings',
        type: types_js_1.VulnerabilityType.DEBUG_MODE,
        name: 'Dangerous Django Debug Settings',
        description: 'Debug mode and development settings enabled in production',
        patterns: {
            regex: [
                /DEBUG\s*=\s*True/,
                /ALLOWED_HOSTS\s*=\s*\[\s*\]/,
                /ALLOWED_HOSTS\s*=\s*\[\s*["']\*["']\s*\]/,
                /SECRET_KEY\s*=\s*["']django-insecure-/,
                /MIDDLEWARE\s*=[\s\S]*?["']debug_toolbar\.middleware\.DebugToolbarMiddleware["']/,
                /DATABASES\s*=[\s\S]*?["']ENGINE["']:\s*["']django\.db\.backends\.sqlite3["']/,
                /INSTALLED_APPS\s*=[\s\S]*?["']debug_toolbar["']/,
                /["']django_extensions["']/
            ]
        },
        severity: 'high',
        cweId: 'CWE-489',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        languages: ['python'],
        remediation: 'Set Django DEBUG=False, configure Django ALLOWED_HOSTS, remove debug apps from Django INSTALLED_APPS, and use Django environment-specific settings',
        examples: {
            vulnerable: 'DEBUG = True\nALLOWED_HOSTS = []',
            secure: 'DEBUG = False\nALLOWED_HOSTS = ["yourdomain.com"]'
        }
    },
    {
        id: 'django-insecure-session',
        type: types_js_1.VulnerabilityType.SECURITY_MISCONFIGURATION,
        name: 'Insecure Django Session Configuration',
        description: 'Django session and cookie settings without proper security flags',
        patterns: {
            regex: [
                /SESSION_COOKIE_SECURE\s*=\s*False/g,
                /SESSION_COOKIE_HTTPONLY\s*=\s*False/g,
                /SESSION_COOKIE_SAMESITE\s*=\s*None/g,
                /CSRF_COOKIE_SECURE\s*=\s*False/g,
                /CSRF_COOKIE_HTTPONLY\s*=\s*False/g,
                /SESSION_EXPIRE_AT_BROWSER_CLOSE\s*=\s*False/g,
                /SESSION_COOKIE_AGE\s*=\s*31536000/g,
                /SESSION_SAVE_EVERY_REQUEST\s*=\s*False/g,
                /CSRF_COOKIE_SAMESITE\s*=\s*["']None["']/g,
                /CSRF_TRUSTED_ORIGINS\s*=\s*\[\s*["']\*["']\s*\]/
            ]
        },
        severity: 'medium',
        cweId: 'CWE-614',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        languages: ['python'],
        remediation: 'Set Django session secure=True, httponly=True, and samesite="Lax" for cookies in HTTPS environments using Django settings',
        examples: {
            vulnerable: 'SESSION_COOKIE_SECURE = False',
            secure: 'SESSION_COOKIE_SECURE = True\nSESSION_COOKIE_HTTPONLY = True'
        }
    },
    {
        id: 'django-missing-security-middleware',
        type: types_js_1.VulnerabilityType.SECURITY_MISCONFIGURATION,
        name: 'Missing Django Security Middleware',
        description: 'Missing or incorrectly configured security middleware',
        patterns: {
            regex: [
                /MIDDLEWARE\s*=\s*\[(?!.*django\.middleware\.security\.SecurityMiddleware).*?\]/s,
                /[#]\s*["']django\.middleware\.security\.SecurityMiddleware["']/g,
                /[#]\s*["']django\.middleware\.csrf\.CsrfViewMiddleware["']/g,
                /MIDDLEWARE\s*=\s*\[.*?["']django\.middleware\.csrf\.CsrfViewMiddleware["'].*?["']django\.middleware\.security\.SecurityMiddleware["']/s,
                /SECURE_SSL_REDIRECT\s*=\s*False/g,
                /SECURE_HSTS_SECONDS\s*=\s*0/
            ]
        },
        severity: 'medium',
        cweId: 'CWE-693',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        languages: ['python'],
        remediation: 'Add Django SecurityMiddleware and CsrfViewMiddleware to Django MIDDLEWARE in correct order, enable HTTPS redirects in Django settings',
        examples: {
            vulnerable: 'MIDDLEWARE = ["django.middleware.common.CommonMiddleware"]',
            secure: 'MIDDLEWARE = ["django.middleware.security.SecurityMiddleware", "django.middleware.csrf.CsrfViewMiddleware", ...]'
        }
    },
    {
        id: 'django-broken-auth',
        type: types_js_1.VulnerabilityType.BROKEN_AUTHENTICATION,
        name: 'Django Broken Authentication',
        description: 'Weak authentication patterns and missing validation',
        patterns: {
            regex: [
                /def\s+\w*admin\w*.*?\(.*?request.*?\):(?!.*@login_required)(?!.*request\.user\.is_authenticated)/s,
                /AUTH_PASSWORD_VALIDATORS\s*=\s*\[\s*\]/g,
                /if\s+user\.password\s*==\s*password:/g,
                /if\s+hashlib\.md5\s*\(\s*password\.encode\(\)\s*\)\.hexdigest\(\)\s*==\s*stored_hash:/g,
                /request\.session\[["']user_id["']\]\s*=\s*user\.id(?!.*request\.session\.cycle_key)/g,
                /if\s+password\s*==\s*["']admin123["']:/g,
                /DEFAULT_PASSWORD\s*=\s*["']password["']/g,
                /AUTHENTICATION_BACKENDS\s*=\s*\[.*?["']django\.contrib\.auth\.backends\.AllowAllUsersModelBackend["']/s
            ]
        },
        severity: 'high',
        cweId: 'CWE-287',
        owaspCategory: 'A07:2021 - Identification and Authentication Failures',
        languages: ['python'],
        remediation: 'Use Django built-in authentication system, require Django login decorators, implement Django password validators, avoid hardcoded credentials',
        examples: {
            vulnerable: 'if user.password == password:',
            secure: 'if user.check_password(password):'
        }
    },
    {
        id: 'django-authorization-bypass',
        type: types_js_1.VulnerabilityType.BROKEN_ACCESS_CONTROL,
        name: 'Django Authorization Bypass',
        description: 'Missing or improper authorization checks in views',
        patterns: {
            regex: [
                /def\s+delete_user[\s\S]*?User\.objects\.get\(id=user_id\)\.delete\(\)/,
                /if\s+request\.user\.is_authenticated\(\)/,
                /if\s+request\.user:/,
                /get_object_or_404\s*\(\s*\w+\s*,\s*pk\s*=\s*request\.GET\[["']\w+["']\]/,
                /user\.delete\(\)/,
                /if\s+["']admin["']\s+in\s+request\.GET:/,
                /if\s+request\.GET\.get\s*\(\s*["']force["']\s*\):/,
                /@user_passes_test\s*\(\s*lambda\s+u:\s+True\s*\)/,
                /@permission_required\s*\(\s*["']["']\s*\)/
            ]
        },
        severity: 'high',
        cweId: 'CWE-285',
        owaspCategory: 'A01:2021 - Broken Access Control',
        languages: ['python'],
        remediation: 'Use Django @login_required, @permission_required decorators, implement Django object-level permissions, validate ownership in Django views',
        examples: {
            vulnerable: 'def delete_user(request, user_id):\n    User.objects.get(id=user_id).delete()',
            secure: '@login_required\n@permission_required("auth.delete_user")\ndef delete_user(request, user_id):\n    user = get_object_or_404(User, id=user_id)\n    if user.owner == request.user:\n        user.delete()'
        }
    },
    {
        id: 'django-csrf-bypass',
        type: types_js_1.VulnerabilityType.CSRF,
        name: 'Django CSRF Protection Bypass',
        description: 'Cross-Site Request Forgery protection bypassed or disabled',
        patterns: {
            regex: [
                /@csrf_exempt\s+def\s+transfer_money/g,
                /@csrf_exempt\s+def\s+delete_account/g,
                /@csrf_exempt\s+def\s+change_password/g,
                /if\s+request\.method\s*==\s*["']POST["']:(?!.*csrf)/s,
                /request\.META\.pop\s*\(\s*["']HTTP_X_CSRFTOKEN["']/g,
                /del\s+request\.META\[["']CSRF_COOKIE["']\]/g,
                /<form\s+method\s*=\s*["']post["'](?!.*\{\%\s*csrf_token\s*\%\})/g,
                /\$\.post\s*\(\s*["']/g
            ]
        },
        severity: 'high',
        cweId: 'CWE-352',
        owaspCategory: 'A01:2021 - Broken Access Control',
        languages: ['python'],
        remediation: 'Remove Django @csrf_exempt from sensitive views, include Django {% csrf_token %} in forms, send CSRF token in AJAX requests using Django CSRF middleware',
        examples: {
            vulnerable: '@csrf_exempt\ndef transfer_money(request):',
            secure: 'def transfer_money(request):  # Uses CSRF protection by default'
        }
    },
    {
        id: 'django-clickjacking',
        type: types_js_1.VulnerabilityType.SECURITY_MISCONFIGURATION,
        name: 'Django Clickjacking Vulnerability',
        description: 'Missing or disabled X-Frame-Options protection',
        patterns: {
            regex: [
                /@xframe_options_exempt/g,
                /X_FRAME_OPTIONS\s*=\s*["']ALLOWALL["']/g,
                /X_FRAME_OPTIONS\s*=\s*None/g,
                /response\[["']X-Frame-Options["']\]\s*=\s*["']ALLOWALL["']/g,
                /response\[["']X-Frame-Options["']\]\s*=\s*f["']ALLOW-FROM\s*\{.*?user_\w+/
            ]
        },
        severity: 'medium',
        cweId: 'CWE-1021',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        languages: ['python'],
        remediation: 'Use Django X_FRAME_OPTIONS = "DENY" or "SAMEORIGIN" setting, remove Django @xframe_options_exempt decorator from sensitive views',
        examples: {
            vulnerable: '@xframe_options_exempt\ndef sensitive_view(request):',
            secure: 'def sensitive_view(request):  # Uses X-Frame-Options by default'
        }
    },
    {
        id: 'django-model-injection',
        type: types_js_1.VulnerabilityType.SQL_INJECTION,
        name: 'Django Model Injection',
        description: 'Dynamic model access and method calls with user input',
        patterns: {
            regex: [
                /getattr\s*\(\s*models\s*,\s*request\.GET\[["']\w+["']\]/g,
                /apps\.get_model\s*\(\s*user_\w+\s*,\s*user_\w+/g,
                /eval\s*\(\s*f["']\{.*?model_name.*?\}\.objects\.all\(\)["']/g,
                /User\.objects\.filter\s*\(\s*\*\*\s*\{\s*request\.GET\[["']\w+["']\]:\s*\w+\s*\}/g,
                /setattr\s*\(\s*\w+\s*,\s*request\.POST\[["']\w+["']\]/g,
                /getattr\s*\(\s*\w+\s*,\s*user_\w+/g,
                /getattr\s*\(\s*User\.objects\s*,\s*request\.GET\[["']\w+["']\]/g,
                /eval\s*\(\s*f["']User\.objects\.\{.*?method_name.*?\}\(\)["']/g,
                /type\s*\(\s*model_name\s*,\s*\(\s*models\.Model\s*,\s*\)\s*,\s*user_\w+/
            ]
        },
        severity: 'critical',
        cweId: 'CWE-94',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['python'],
        remediation: 'Avoid dynamic Django model/method access with user input. Use allowlists for safe Django model/field names.',
        examples: {
            vulnerable: 'getattr(models, request.GET["model"]).objects.all()',
            secure: 'allowed_models = {"user": User, "post": Post}\nif request.GET["model"] in allowed_models:\n    allowed_models[request.GET["model"]].objects.all()'
        }
    },
    {
        id: 'django-mass-assignment',
        type: types_js_1.VulnerabilityType.MASS_ASSIGNMENT,
        name: 'Django Mass Assignment',
        description: 'Mass assignment vulnerabilities in Django model operations',
        patterns: {
            regex: [
                /User\.objects\.create\s*\(\s*\*\*\s*request\.POST\s*\)/g,
                /User\s*\(\s*\*\*\s*request\.POST\.dict\(\)\s*\)\.save\(\)/g,
                /User\.objects\.bulk_create\s*\(\s*\[\s*User\s*\(\s*\*\*\s*data\s*\)/g,
                /User\.objects\.filter\s*\(.*?\)\.update\s*\(\s*\*\*\s*request\.POST\s*\)/g,
                /user\.__dict__\.update\s*\(\s*request\.POST\s*\)/g,
                /form\s*=\s*ModelForm\s*\(\s*request\.POST.*?instance\s*=\s*user\s*\)/g,
                /class\s+\w+Form\s*\(\s*ModelForm\s*\):.*?class\s+Meta:.*?model\s*=\s*\w+(?!.*fields)/gs
            ]
        },
        severity: 'high',
        cweId: 'CWE-915',
        owaspCategory: 'A01:2021 - Broken Access Control',
        languages: ['python'],
        remediation: 'Use ModelForm with explicit fields, validate input, implement field whitelisting',
        examples: {
            vulnerable: 'User.objects.create(**request.POST)',
            secure: 'User.objects.create(name=request.POST["name"], email=request.POST["email"])'
        }
    },
    {
        id: 'django-unsafe-url-patterns',
        type: types_js_1.VulnerabilityType.PATH_TRAVERSAL,
        name: 'Unsafe Django URL Patterns',
        description: 'Overly permissive URL patterns allowing path traversal',
        patterns: {
            regex: [
                /path\s*\(\s*["']<path:\w+>["']\s*,\s*views\.\w+/g,
                /path\s*\(\s*["']<str:\w+>["']\s*,\s*views\.render_template/g,
                /re_path\s*\(\s*r["'][\^]files\/\(\.\*\)\$["']/g,
                /re_path\s*\(\s*r["'][\^]admin\/\(\.\+\)\$["']/g,
                /path\s*\(\s*["']<slug:\w+>["']\s*,\s*views\.dynamic_\w+/g,
                /path\s*\(\s*["']<path:file_path>["']\s*,\s*views\.static_serve/g,
                /re_path\s*\(\s*r["'][\^]\(\.\*\)\$["']/g,
                /path\s*\(\s*["']<path:anything>["']\s*,\s*views\.fallback/
            ]
        },
        severity: 'high',
        cweId: 'CWE-22',
        owaspCategory: 'A01:2021 - Broken Access Control',
        languages: ['python'],
        remediation: 'Use specific Django URL patterns, validate path parameters in Django views, restrict file access to safe directories',
        examples: {
            vulnerable: 'path("<path:filename>", views.serve_file)',
            secure: 'path("files/<slug:filename>", views.serve_file)'
        }
    },
    {
        id: 'django-cve-2021-33203',
        type: types_js_1.VulnerabilityType.PATH_TRAVERSAL,
        name: 'CVE-2021-33203 - Directory Traversal in Static Files',
        description: 'Directory traversal vulnerability in Django static file serving',
        patterns: {
            regex: [
                /django\.views\.static\.serve\s*\(\s*request\s*,\s*path\s*=\s*["']\.\.\/.*?\/etc\/passwd["']/g,
                /static\.serve\s*\(\s*request\s*,\s*document_root\s*=\s*["']\/["']/g,
                /serve\s*\(\s*request\s*,\s*path\s*,\s*document_root\s*=\s*settings\.MEDIA_ROOT\s*,\s*show_indexes\s*=\s*True\s*\)/
            ]
        },
        severity: 'high',
        cweId: 'CWE-22',
        owaspCategory: 'A01:2021 - Broken Access Control',
        languages: ['python'],
        remediation: 'Validate file paths, use Django\'s built-in static file handling, avoid serving files with user-controlled paths',
        examples: {
            vulnerable: 'django.views.static.serve(request, path="../../../etc/passwd")',
            secure: 'Use Django\'s STATIC_URL and collectstatic for production'
        }
    },
    {
        id: 'django-cve-2021-33571',
        type: types_js_1.VulnerabilityType.OPEN_REDIRECT,
        name: 'CVE-2021-33571 - URL Validation Bypass',
        description: 'URL validation bypass allowing open redirects',
        patterns: {
            regex: [
                /URLValidator\(\)\s*\(\s*user_\w+/g,
                /django\.core\.validators\.URLValidator\s*\(\s*schemes\s*=\s*\[\s*["']javascript["']\s*\]/g,
                /validate_url\s*\(\s*f["']javascript:\{.*?user_\w+/g,
                /HttpResponseRedirect\s*\(\s*request\.GET\[["']next["']\]/g,
                /redirect\s*\(\s*request\.POST\[["']url["']\]/
            ]
        },
        severity: 'medium',
        cweId: 'CWE-601',
        owaspCategory: 'A01:2021 - Broken Access Control',
        languages: ['python'],
        remediation: 'Validate redirect URLs against allowlist, sanitize URL schemes, use Django is_safe_url() for redirects',
        examples: {
            vulnerable: 'HttpResponseRedirect(request.GET["next"])',
            secure: 'from django.utils.http import is_safe_url\nif is_safe_url(url, allowed_hosts={request.get_host()}):\n    return HttpResponseRedirect(url)'
        }
    },
    {
        id: 'django-cve-2020-13254',
        type: types_js_1.VulnerabilityType.SECURITY_MISCONFIGURATION,
        name: 'CVE-2020-13254 - Cache Poisoning',
        description: 'Cache poisoning through user-controlled cache keys',
        patterns: {
            regex: [
                /cache\.set\s*\(\s*request\.GET\[["']\w+["']\]/g,
                /cache\.get\s*\(\s*f["']user_\{.*?request\.user\.id.*?\}_\{.*?request\.GET\[/g,
                /cache\.set\s*\(\s*f["']page_\{.*?request\.path.*?\}_\{.*?user_\w+/g,
                /cache\.set\s*\(\s*user_\w+\.replace\s*\(\s*["']\\n["']/g,
                /cache\.get\s*\(\s*user_\w+\.replace\s*\(\s*["']\\r["']/
            ]
        },
        severity: 'medium',
        cweId: 'CWE-20',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        languages: ['python'],
        remediation: 'Sanitize Django cache keys, use Django make_key() to generate safe keys, validate user input before caching',
        examples: {
            vulnerable: 'cache.set(request.GET["key"], data)',
            secure: 'from django.core.cache.utils import make_key\nsafe_key = make_key(request.GET["key"])\ncache.set(safe_key, data)'
        }
    },
    {
        id: 'django-cve-2019-14234',
        type: types_js_1.VulnerabilityType.SQL_INJECTION,
        name: 'CVE-2019-14234 - SQL Injection in Key Transforms',
        description: 'SQL injection through JSONField and HStore key transforms',
        patterns: {
            regex: [
                /User\.objects\.filter\s*\(\s*\*\*\s*\{\s*f["']data__\{.*?user_\w+/g,
                /Model\.objects\.filter\s*\(\s*json_field__contains\s*=\s*\{\s*user_\w+:/g,
                /queryset\.filter\s*\(\s*\*\*\s*\{\s*f["']metadata__\{.*?request\.GET\[/g,
                /Model\.objects\.filter\s*\(\s*\*\*\s*\{\s*f["']hstore_field__\{.*?user_\w+/
            ]
        },
        severity: 'high',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['python'],
        remediation: 'Validate Django JSON/HStore field keys against allowlist, avoid dynamic key construction with user input in Django ORM',
        examples: {
            vulnerable: 'User.objects.filter(**{f"data__{user_key}": value})',
            secure: 'allowed_keys = ["name", "email"]\nif user_key in allowed_keys:\n    User.objects.filter(**{f"data__{user_key}": value})'
        }
    },
    {
        id: 'django-cve-2018-14574',
        type: types_js_1.VulnerabilityType.OPEN_REDIRECT,
        name: 'CVE-2018-14574 - CommonMiddleware Open Redirect',
        description: 'Open redirect vulnerability in Django CommonMiddleware',
        patterns: {
            regex: [
                /return\s+HttpResponsePermanentRedirect\s*\(\s*request\.get_full_path\(\)\s*\)/g,
                /return\s+HttpResponseRedirect\s*\(\s*f["']\{request\.scheme\}:\/\/\{request\.get_host\(\)\}\{request\.get_full_path\(\)\}["']\s*\)/g,
                /redirect_to\s*=\s*request\.get_full_path\(\)/g,
                /APPEND_SLASH\s*=\s*True(?=.*user.*controlled.*URLs)/
            ]
        },
        severity: 'medium',
        cweId: 'CWE-601',
        owaspCategory: 'A01:2021 - Broken Access Control',
        languages: ['python'],
        remediation: 'Validate redirect URLs in Django, use absolute URLs instead of Django get_full_path(), implement URL allowlisting',
        examples: {
            vulnerable: 'return HttpResponseRedirect(request.get_full_path())',
            secure: 'return HttpResponseRedirect("/safe-path/")'
        }
    }
];
