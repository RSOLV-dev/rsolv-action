import { describe, it, expect } from 'vitest';
import { PatternRegistry } from '../../patterns.js';
import { VulnerabilityType } from '../../types.js';

describe('Django Security Patterns', () => {
  const registry = new PatternRegistry();

  describe('Django ORM Injection Vulnerabilities', () => {
    it('should detect SQL injection in Django ORM', () => {
      const patterns = registry.getPatterns(VulnerabilityType.SQL_INJECTION);
      const djangoPatterns = patterns.filter(p => 
        p.languages.includes('python') && p.id.includes('django-orm-injection')
      );
      
      expect(djangoPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // String formatting in queries
        'User.objects.filter("name = \'%s\'" % username)',
        'User.objects.extra(where=["name = \'%s\'" % name])',
        'User.objects.raw("SELECT * FROM users WHERE id = %s" % user_id)',
        // f-string injection
        'User.objects.filter(f"name = \'{username}\'")',
        'User.objects.extra(where=[f"age > {min_age}"])',
        // format() injection
        'User.objects.raw("SELECT * FROM users WHERE name = \'{}\'".format(name))',
        'User.objects.extra(select={"custom": "field = \'{}\'".format(value)})',
        // .extra() with user input
        'User.objects.extra(where=[user_condition])',
        'User.objects.extra(tables=[user_table])',
        // Raw SQL with interpolation
        'cursor.execute("SELECT * FROM users WHERE name = \'%s\'" % name)',
        'cursor.execute(f"DELETE FROM posts WHERE id = {post_id}")',
        // QuerySet.extra with dynamic content
        'User.objects.extra(select_related=user_input)',
        'User.objects.extra(order_by=user_order)'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = djangoPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
      
      // Safe parameterized queries should not match
      const safeCodes = [
        'User.objects.filter(name=username)',
        'User.objects.raw("SELECT * FROM users WHERE id = %s", [user_id])',
        'cursor.execute("SELECT * FROM users WHERE name = %s", [name])',
        'User.objects.extra(where=["name = %s"], params=[name])'
      ];
      
      safeCodes.forEach(code => {
        const detected = djangoPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(false, `False positive for: ${code}`);
      });
    });

    it('should detect NoSQL injection in Django', () => {
      const patterns = registry.getPatterns(VulnerabilityType.NOSQL_INJECTION);
      const djangoPatterns = patterns.filter(p => 
        p.languages.includes('python') && p.id.includes('django-nosql-injection')
      );
      
      expect(djangoPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // MongoDB injection through djongo or MongoEngine
        'User.objects.raw({"$where": user_input})',
        'User.objects.mongo_find({"$where": f"this.name == \'{name}\'"})',
        'collection.find({"$where": user_condition})',
        'collection.aggregate([{"$match": eval(user_filter)}])',
        // Elasticsearch injection
        'client.search(body={"query": {"query_string": {"query": user_query}}})',
        'Search().query(user_query)',
        // Redis injection
        'redis_client.eval(user_script)',
        'redis_client.execute_command(user_command)'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = djangoPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });
  });

  describe('Django Template Security Vulnerabilities', () => {
    it('should detect XSS in Django templates', () => {
      const patterns = registry.getPatterns(VulnerabilityType.XSS);
      const djangoPatterns = patterns.filter(p => 
        p.languages.includes('python') && p.id.includes('django-template-xss')
      );
      
      expect(djangoPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // safe filter usage without proper sanitization
        '{{ user_content|safe }}',
        '{{ comment.body|safe }}',
        // mark_safe() without sanitization
        'mark_safe(user_input)',
        'mark_safe(f"<div>{user_content}</div>")',
        // Safestring usage
        'SafeString(user_input)',
        'SafeText(user_content)',
        // format_html with unsafe content
        'format_html("<div>{}</div>", mark_safe(user_content))',
        // JSON script tag without proper escaping
        '{{ data|safe }}',
        // Custom template tags that don\'t escape
        '{% autoescape off %}{{ user_content }}{% endautoescape %}'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = djangoPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
      
      // Safe template usage should not match
      const safeCodes = [
        '{{ user_content }}',
        '{{ user_content|escape }}',
        'format_html("<div>{}</div>", user_content)',
        '{% autoescape on %}{{ user_content }}{% endautoescape %}'
      ];
      
      safeCodes.forEach(code => {
        const detected = djangoPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(false, `False positive for: ${code}`);
      });
    });

    it('should detect template injection vulnerabilities', () => {
      const patterns = registry.getPatterns(VulnerabilityType.TEMPLATE_INJECTION);
      const djangoPatterns = patterns.filter(p => 
        p.languages.includes('python') && p.id.includes('django-template-injection')
      );
      
      expect(djangoPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Template compilation with user input
        'Template(request.GET["template"]).render(context)',
        'Engine().from_string(user_template).render(context)',
        // Dynamic template loading
        'get_template(request.POST["template_name"])',
        'select_template([user_template_name])',
        // render_to_string with user input
        'render_to_string(user_template, context)',
        // Jinja2 template injection
        'jinja2.Template(user_input).render()',
        'Environment().from_string(user_template).render()',
        // Custom template engines
        'custom_engine.compile(user_template)',
        'template_engine.render(user_template_string)'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = djangoPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });
  });

  describe('Django Settings Vulnerabilities', () => {
    it('should detect dangerous debug settings', () => {
      const patterns = registry.getPatterns(VulnerabilityType.DEBUG_MODE);
      const djangoPatterns = patterns.filter(p => 
        p.languages.includes('python') && p.id.includes('django-debug-settings')
      );
      
      expect(djangoPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Debug mode enabled
        'DEBUG = True',
        'DEBUG=True',
        // Development settings in production
        'ALLOWED_HOSTS = []',
        'ALLOWED_HOSTS = ["*"]',
        'SECRET_KEY = "django-insecure-key"',
        // Dangerous middleware order
        'MIDDLEWARE = [\n    "debug_toolbar.middleware.DebugToolbarMiddleware",',
        // Development databases
        'DATABASES = {\n    "default": {\n        "ENGINE": "django.db.backends.sqlite3"',
        // Debug apps in production
        'INSTALLED_APPS = [\n    "debug_toolbar",',
        '"django_extensions"'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = djangoPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });

    it('should detect insecure session configuration', () => {
      const patterns = registry.getPatterns(VulnerabilityType.SECURITY_MISCONFIGURATION);
      const djangoPatterns = patterns.filter(p => 
        p.languages.includes('python') && p.id.includes('django-insecure-session')
      );
      
      expect(djangoPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Insecure session settings
        'SESSION_COOKIE_SECURE = False',
        'SESSION_COOKIE_HTTPONLY = False',
        'SESSION_COOKIE_SAMESITE = None',
        'CSRF_COOKIE_SECURE = False',
        'CSRF_COOKIE_HTTPONLY = False',
        // Weak session configuration
        'SESSION_EXPIRE_AT_BROWSER_CLOSE = False',
        'SESSION_COOKIE_AGE = 31536000',  // 1 year
        'SESSION_SAVE_EVERY_REQUEST = False',
        // Insecure CSRF settings
        'CSRF_COOKIE_SAMESITE = "None"',
        'CSRF_TRUSTED_ORIGINS = ["*"]'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = djangoPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });

    it('should detect missing security middleware', () => {
      const patterns = registry.getPatterns(VulnerabilityType.SECURITY_MISCONFIGURATION);
      const djangoPatterns = patterns.filter(p => 
        p.languages.includes('python') && p.id.includes('django-missing-security-middleware')
      );
      
      expect(djangoPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Missing security middleware in MIDDLEWARE setting
        'MIDDLEWARE = [\n    "django.middleware.common.CommonMiddleware",\n]',
        // Commented out security middleware
        '# "django.middleware.security.SecurityMiddleware",',
        '# "django.middleware.csrf.CsrfViewMiddleware",',
        // Wrong middleware order
        'MIDDLEWARE = [\n    "django.middleware.csrf.CsrfViewMiddleware",\n    "django.middleware.security.SecurityMiddleware"',
        // Missing HTTPS redirect
        'SECURE_SSL_REDIRECT = False',
        'SECURE_HSTS_SECONDS = 0'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = djangoPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });
  });

  describe('Django Authentication & Authorization Issues', () => {
    it('should detect broken authentication patterns', () => {
      const patterns = registry.getPatterns(VulnerabilityType.BROKEN_AUTHENTICATION);
      const djangoPatterns = patterns.filter(p => 
        p.languages.includes('python') && p.id.includes('django-broken-auth')
      );
      
      expect(djangoPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Missing authentication checks
        'def admin_view(request):\n    # No authentication check\n    return render(request, "admin.html")',
        // Weak password validation
        'AUTH_PASSWORD_VALIDATORS = []',
        'if user.password == password:',
        'if hashlib.md5(password.encode()).hexdigest() == stored_hash:',
        // Session without regeneration
        'request.session["user_id"] = user.id',
        // Hardcoded passwords
        'if password == "admin123":',
        'DEFAULT_PASSWORD = "password"',
        // Weak authentication backends
        'AUTHENTICATION_BACKENDS = [\n    "django.contrib.auth.backends.AllowAllUsersModelBackend"'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = djangoPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });

    it('should detect authorization bypass vulnerabilities', () => {
      const patterns = registry.getPatterns(VulnerabilityType.BROKEN_ACCESS_CONTROL);
      const djangoPatterns = patterns.filter(p => 
        p.languages.includes('python') && p.id.includes('django-authorization-bypass')
      );
      
      expect(djangoPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Missing permission checks
        'def delete_user(request, user_id):\n    User.objects.get(id=user_id).delete()',
        // Improper permission checks
        'if request.user.is_authenticated():  # Old Django syntax',
        'if request.user:  # Insufficient check',
        // Object-level permission bypass
        'obj = get_object_or_404(Model, pk=request.GET["id"])',
        'user.delete()  # No ownership check',
        // Admin bypass
        'if "admin" in request.GET:',
        'if request.GET.get("force"):',
        // Permission decorator bypass
        '@user_passes_test(lambda u: True)',
        '@permission_required("")'  // Empty permission
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = djangoPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });
  });

  describe('Django CSRF and Security Middleware Issues', () => {
    it('should detect CSRF protection bypasses', () => {
      const patterns = registry.getPatterns(VulnerabilityType.CSRF);
      const djangoPatterns = patterns.filter(p => 
        p.languages.includes('python') && p.id.includes('django-csrf-bypass')
      );
      
      expect(djangoPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // CSRF exempt on sensitive views
        '@csrf_exempt\ndef transfer_money(request):',
        '@csrf_exempt\ndef delete_account(request):',
        '@csrf_exempt\ndef change_password(request):',
        // Manual CSRF bypass
        'if request.method == "POST":\n    # No CSRF check',
        'request.META.pop("HTTP_X_CSRFTOKEN", None)',
        // CSRF cookie manipulation
        'del request.META["CSRF_COOKIE"]',
        // Form without CSRF token
        '<form method="post">',  // No {% csrf_token %}
        // AJAX without CSRF
        '$.post("/api/transfer", data)'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = djangoPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });

    it('should detect clickjacking vulnerabilities', () => {
      const patterns = registry.getPatterns(VulnerabilityType.SECURITY_MISCONFIGURATION);
      const djangoPatterns = patterns.filter(p => 
        p.languages.includes('python') && p.id.includes('django-clickjacking')
      );
      
      expect(djangoPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Missing X-Frame-Options
        '@xframe_options_exempt',
        'X_FRAME_OPTIONS = "ALLOWALL"',
        'X_FRAME_OPTIONS = None',
        // Dangerous frame options
        'response["X-Frame-Options"] = "ALLOWALL"',
        'response["X-Frame-Options"] = f"ALLOW-FROM {user_domain}"'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = djangoPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });
  });

  describe('Django Model Security Issues', () => {
    it('should detect model injection vulnerabilities', () => {
      const patterns = registry.getPatterns(VulnerabilityType.SQL_INJECTION);
      const djangoPatterns = patterns.filter(p => 
        p.languages.includes('python') && p.id.includes('django-model-injection')
      );
      
      expect(djangoPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Dynamic model access
        'getattr(models, request.GET["model"]).objects.all()',
        'apps.get_model(user_app, user_model)',
        'eval(f"{model_name}.objects.all()")',
        // Dynamic field access
        'User.objects.filter(**{request.GET["field"]: value})',
        'setattr(obj, request.POST["field"], value)',
        'getattr(obj, user_field)',
        // Dynamic method calls
        'getattr(User.objects, request.GET["method"])()',
        'eval(f"User.objects.{method_name}()")',
        // Model metaclass manipulation
        'type(model_name, (models.Model,), user_attrs)'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = djangoPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });

    it('should detect unsafe model operations', () => {
      const patterns = registry.getPatterns(VulnerabilityType.MASS_ASSIGNMENT);
      const djangoPatterns = patterns.filter(p => 
        p.languages.includes('python') && p.id.includes('django-mass-assignment')
      );
      
      expect(djangoPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Mass assignment in model creation
        'User.objects.create(**request.POST)',
        'User(**request.POST.dict()).save()',
        'User.objects.bulk_create([User(**data) for data in user_data])',
        // Update with user data
        'User.objects.filter(id=user_id).update(**request.POST)',
        'user.__dict__.update(request.POST)',
        // Form without field restrictions
        'form = ModelForm(request.POST, instance=user)',
        // Without Meta.fields restriction
        'class UserForm(ModelForm):\n    class Meta:\n        model = User'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = djangoPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });
  });

  describe('Django URL Routing Vulnerabilities', () => {
    it('should detect unsafe URL patterns', () => {
      const patterns = registry.getPatterns(VulnerabilityType.PATH_TRAVERSAL);
      const djangoPatterns = patterns.filter(p => 
        p.languages.includes('python') && p.id.includes('django-unsafe-url-patterns')
      );
      
      expect(djangoPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Overly permissive regex patterns
        'path("<path:filename>", views.serve_file)',
        'path("<str:template>", views.render_template)',
        're_path(r"^files/(.*)$", views.download)',
        're_path(r"^admin/(.+)$", views.admin_action)',
        // Regex without proper validation
        'path("<slug:action>", views.dynamic_action)',
        'path("<path:file_path>", views.static_serve)',
        // Catch-all patterns
        're_path(r"^(.*)$", views.catch_all)',
        'path("<path:anything>", views.fallback)'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = djangoPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });
  });

  describe('Real Django CVE Patterns', () => {
    it('should detect CVE-2021-33203 (Directory Traversal)', () => {
      const patterns = registry.getPatterns(VulnerabilityType.PATH_TRAVERSAL);
      const djangoPatterns = patterns.filter(p => 
        p.languages.includes('python') && p.id.includes('django-cve-2021-33203')
      );
      
      expect(djangoPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Vulnerable static file serving
        'django.views.static.serve(request, path="../../../etc/passwd")',
        'static.serve(request, document_root="/", path=user_path)',
        'serve(request, path, document_root=settings.MEDIA_ROOT, show_indexes=True)'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = djangoPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });

    it('should detect CVE-2021-33571 (URL Validation Bypass)', () => {
      const patterns = registry.getPatterns(VulnerabilityType.OPEN_REDIRECT);
      const djangoPatterns = patterns.filter(p => 
        p.languages.includes('python') && p.id.includes('django-cve-2021-33571')
      );
      
      expect(djangoPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // URLValidator bypass
        'URLValidator()(user_url)',
        'django.core.validators.URLValidator(schemes=["javascript"])',
        'validate_url(f"javascript:{user_input}")',
        // HTTP redirect without validation
        'HttpResponseRedirect(request.GET["next"])',
        'redirect(request.POST["url"])'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = djangoPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });

    it('should detect CVE-2020-13254 (Cache Poisoning)', () => {
      const patterns = registry.getPatterns(VulnerabilityType.SECURITY_MISCONFIGURATION);
      const djangoPatterns = patterns.filter(p => 
        p.languages.includes('python') && p.id.includes('django-cve-2020-13254')
      );
      
      expect(djangoPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // Cache with user-controlled keys
        'cache.set(request.GET["key"], data)',
        'cache.get(f"user_{request.user.id}_{request.GET[\'category\']}")',
        'cache.set(f"page_{request.path}_{user_input}", content)',
        // Memcached injection
        'cache.set(user_key.replace("\\n", ""), value)',
        'cache.get(user_key.replace("\\r", ""))'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = djangoPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });

    it('should detect CVE-2019-14234 (SQL Injection in Key Transforms)', () => {
      const patterns = registry.getPatterns(VulnerabilityType.SQL_INJECTION);
      const djangoPatterns = patterns.filter(p => 
        p.languages.includes('python') && p.id.includes('django-cve-2019-14234')
      );
      
      expect(djangoPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // JSONField key transform injection
        'User.objects.filter(**{f"data__{user_key}": value})',
        'Model.objects.filter(json_field__contains={user_key: "value"})',
        'queryset.filter(**{f"metadata__{request.GET[\'key\']}": "test"})',
        // HStore field injection  
        'Model.objects.filter(**{f"hstore_field__{user_input}": value})'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = djangoPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });

    it('should detect CVE-2018-14574 (Open Redirect)', () => {
      const patterns = registry.getPatterns(VulnerabilityType.OPEN_REDIRECT);
      const djangoPatterns = patterns.filter(p => 
        p.languages.includes('python') && p.id.includes('django-cve-2018-14574')
      );
      
      expect(djangoPatterns).toHaveLength(1);
      
      const vulnerableCodes = [
        // CommonMiddleware redirect vulnerability
        'return HttpResponsePermanentRedirect(request.get_full_path())',
        'return HttpResponseRedirect(f"{request.scheme}://{request.get_host()}{request.get_full_path()}")',
        'redirect_to = request.get_full_path()',
        // APPEND_SLASH redirect
        'APPEND_SLASH = True  // With user-controlled URLs'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = djangoPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true, `Failed to detect: ${code}`);
      });
    });
  });

  it('should have comprehensive Django pattern coverage', () => {
    const djangoPatterns = registry.getPatternsByLanguage('python')
      .filter(p => p.id.includes('django-'));
    
    // Should have Django-specific patterns for major vulnerability types
    expect(djangoPatterns.length).toBeGreaterThanOrEqual(18);
    
    // Check for specific Django vulnerability categories
    const categories = djangoPatterns.map(p => p.type);
    expect(categories).toContain(VulnerabilityType.SQL_INJECTION);
    expect(categories).toContain(VulnerabilityType.NOSQL_INJECTION);
    expect(categories).toContain(VulnerabilityType.XSS);
    expect(categories).toContain(VulnerabilityType.TEMPLATE_INJECTION);
    expect(categories).toContain(VulnerabilityType.DEBUG_MODE);
    expect(categories).toContain(VulnerabilityType.SECURITY_MISCONFIGURATION);
    expect(categories).toContain(VulnerabilityType.BROKEN_AUTHENTICATION);
    expect(categories).toContain(VulnerabilityType.BROKEN_ACCESS_CONTROL);
    expect(categories).toContain(VulnerabilityType.CSRF);
    expect(categories).toContain(VulnerabilityType.MASS_ASSIGNMENT);
    expect(categories).toContain(VulnerabilityType.PATH_TRAVERSAL);
    expect(categories).toContain(VulnerabilityType.OPEN_REDIRECT);
  });

  it('should provide Django-specific remediation guidance', () => {
    const djangoPatterns = registry.getPatternsByLanguage('python')
      .filter(p => p.id.includes('django-'));
    
    djangoPatterns.forEach(pattern => {
      expect(pattern.remediation).toBeTruthy();
      expect(pattern.remediation.length).toBeGreaterThan(20);
      expect(pattern.examples.vulnerable).toBeTruthy();
      expect(pattern.examples.secure).toBeTruthy();
      // Django patterns should mention Django-specific solutions
      expect(
        pattern.remediation.toLowerCase().includes('django') ||
        pattern.remediation.toLowerCase().includes('orm') ||
        pattern.remediation.toLowerCase().includes('middleware') ||
        pattern.remediation.toLowerCase().includes('settings') ||
        pattern.remediation.toLowerCase().includes('template') ||
        pattern.remediation.toLowerCase().includes('csrf') ||
        pattern.remediation.toLowerCase().includes('decorator')
      ).toBe(true);
    });
  });
});