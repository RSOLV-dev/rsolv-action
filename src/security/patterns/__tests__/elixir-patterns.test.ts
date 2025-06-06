import { describe, it, expect } from 'vitest';
import { PatternRegistry } from '../../patterns.js';
import { VulnerabilityType } from '../../types.js';

describe('Elixir Security Patterns', () => {
  const registry = new PatternRegistry();

  it('should detect all Elixir patterns', () => {
    const elixirPatterns = registry.getPatternsByLanguage('elixir');
    expect(elixirPatterns.length).toBeGreaterThan(20); // Expecting comprehensive coverage
  });

  describe('SQL Injection (A03:2021)', () => {
    it('should detect Ecto SQL injection vulnerabilities', () => {
      const patterns = registry.getPatterns(VulnerabilityType.SQL_INJECTION);
      const elixirPatterns = patterns.filter(p => p.languages.includes('elixir'));
      
      expect(elixirPatterns.length).toBeGreaterThan(0);
      
      // Test vulnerable Ecto queries
      const vulnerableCodes = [
        `Repo.query!("SELECT * FROM users WHERE name = '#{name}'")`,
        `from(u in User, where: fragment("email = ?", ^user_input))`,
        `Ecto.Adapters.SQL.query!(Repo, "DELETE FROM users WHERE id = #{id}")`,
        `from(u in "users", where: fragment("status = '#{status}'"))`
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = elixirPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true);
      });
    });

    it('should not flag safe Ecto queries', () => {
      const patterns = registry.getPatterns(VulnerabilityType.SQL_INJECTION);
      const elixirPatterns = patterns.filter(p => p.languages.includes('elixir'));
      
      const safeCodes = [
        'from(u in User, where: u.name == ^name)',
        'Repo.get_by(User, name: name)',
        'User |> where([u], u.email == ^email) |> Repo.one()',
        'Repo.query!("SELECT * FROM users WHERE name = $1", [name])'
      ];
      
      safeCodes.forEach(code => {
        const detected = elixirPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(false);
      });
    });
  });

  describe('Command Injection (A03:2021)', () => {
    it('should detect OS command injection in Elixir', () => {
      const patterns = registry.getPatterns(VulnerabilityType.COMMAND_INJECTION);
      const elixirPatterns = patterns.filter(p => p.languages.includes('elixir'));
      
      expect(elixirPatterns.length).toBeGreaterThan(0);
      
      const vulnerableCodes = [
        `System.cmd("echo", ["#{user_input}"])`,
        `:os.cmd('ls #{directory}')`,
        `Port.open({:spawn, "cat #{file}"}, [:binary])`,
        `System.shell("rm -rf #{path}")`
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = elixirPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true);
      });
    });
  });

  describe('Cross-Site Scripting - XSS (A03:2021)', () => {
    it('should detect XSS vulnerabilities in Phoenix templates', () => {
      const patterns = registry.getPatterns(VulnerabilityType.XSS);
      const elixirPatterns = patterns.filter(p => p.languages.includes('elixir'));
      
      expect(elixirPatterns.length).toBeGreaterThan(0);
      
      const vulnerableCodes = [
        '<%= raw user_content %>',
        '<%= Phoenix.HTML.raw(@user_input) %>',
        `~E"<div>#{@comment}</div>"`,
        'content_tag(:div, raw(user_data))'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = elixirPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true);
      });
    });

    it('should not flag safe Phoenix HTML rendering', () => {
      const patterns = registry.getPatterns(VulnerabilityType.XSS);
      const elixirPatterns = patterns.filter(p => p.languages.includes('elixir'));
      
      const safeCodes = [
        '<%= @user_content %>',
        '<%= html_escape(@comment) %>',
        '<%= content_tag(:div, @user_data) %>',
        `~H"<div><%= @safe_content %></div>"`
      ];
      
      safeCodes.forEach(code => {
        const detected = elixirPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(false);
      });
    });
  });

  describe('Broken Authentication (A07:2021)', () => {
    it('should detect weak password hashing', () => {
      const patterns = registry.getPatterns(VulnerabilityType.BROKEN_AUTHENTICATION);
      const elixirPatterns = patterns.filter(p => p.languages.includes('elixir'));
      
      expect(elixirPatterns.length).toBeGreaterThan(0);
      
      const vulnerableCodes = [
        ':crypto.hash(:md5, password)',
        ':crypto.hash(:sha, password)',
        'Base.encode16(:crypto.hash(:sha256, password))',
        'Bcrypt.hash_pwd_salt(password, log_rounds: 4)' // Too few rounds
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = elixirPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true);
      });
    });
  });

  describe('Sensitive Data Exposure (A02:2021)', () => {
    it('should detect hardcoded secrets and API keys', () => {
      const patterns = registry.getPatterns(VulnerabilityType.HARDCODED_SECRETS);
      const elixirPatterns = patterns.filter(p => p.languages.includes('elixir'));
      
      expect(elixirPatterns.length).toBeGreaterThan(0);
      
      const vulnerableCodes = [
        '@api_key "sk_live_4242424242424242"',
        'config :my_app, api_key: "AKIAIOSFODNN7EXAMPLE"',
        'defp secret_key, do: "hardcoded_secret_key_here"',
        '@jwt_secret "super_secret_jwt_key_123"'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = elixirPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true);
      });
    });

    it('should detect sensitive data in logs', () => {
      const patterns = registry.getPatterns(VulnerabilityType.SENSITIVE_DATA_EXPOSURE);
      const elixirPatterns = patterns.filter(p => p.languages.includes('elixir'));
      
      const vulnerableCodes = [
        'Logger.info("User password: #{password}")',
        'IO.inspect(credit_card_number, label: "CC")',
        'require Logger; Logger.debug("SSN: #{ssn}")'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = elixirPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true);
      });
    });
  });

  describe('Insecure Deserialization (A08:2021)', () => {
    it('should detect unsafe atom creation', () => {
      const patterns = registry.getPatterns(VulnerabilityType.INSECURE_DESERIALIZATION);
      const elixirPatterns = patterns.filter(p => p.languages.includes('elixir'));
      
      expect(elixirPatterns.length).toBeGreaterThan(0);
      
      const vulnerableCodes = [
        'String.to_atom(user_input)',
        `:"#{user_provided_string}"`,
        'List.to_atom(char_list_from_user)',
        ':erlang.binary_to_atom(binary, :utf8)'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = elixirPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true);
      });
    });

    it('should detect unsafe code evaluation', () => {
      const patterns = registry.getPatterns(VulnerabilityType.INSECURE_DESERIALIZATION);
      const elixirPatterns = patterns.filter(p => p.languages.includes('elixir'));
      
      const vulnerableCodes = [
        'Code.eval_string(user_input)',
        '{result, _} = Code.eval_quoted(ast)',
        'apply(module, String.to_atom(function_name), args)'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = elixirPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true);
      });
    });
  });

  describe('Security Misconfiguration (A05:2021)', () => {
    it('should detect CORS misconfigurations', () => {
      const patterns = registry.getPatterns(VulnerabilityType.SECURITY_MISCONFIGURATION);
      const elixirPatterns = patterns.filter(p => p.languages.includes('elixir'));
      
      expect(elixirPatterns.length).toBeGreaterThan(0);
      
      const vulnerableCodes = [
        'plug CORSPlug, origin: "*"',
        'put_resp_header(conn, "access-control-allow-origin", "*")',
        'config :cors_plug, origin: ["*"]'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = elixirPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true);
      });
    });

    it('should detect debug mode in production', () => {
      const patterns = registry.getPatterns(VulnerabilityType.DEBUG_MODE);
      const elixirPatterns = patterns.filter(p => p.languages.includes('elixir'));
      
      expect(elixirPatterns.length).toBeGreaterThan(0);
      
      const vulnerableCodes = [
        'config :my_app, MyApp.Endpoint, debug_errors: true',
        'config :phoenix, :stacktrace_depth, 20',
        'config :logger, level: :debug'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = elixirPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true);
      });
    });
  });

  describe('Server-Side Request Forgery - SSRF (A10:2021)', () => {
    it('should detect SSRF vulnerabilities', () => {
      const patterns = registry.getPatterns(VulnerabilityType.SSRF);
      const elixirPatterns = patterns.filter(p => p.languages.includes('elixir'));
      
      expect(elixirPatterns.length).toBeGreaterThan(0);
      
      const vulnerableCodes = [
        'HTTPoison.get(params["url"])',
        'Tesla.get(user_provided_url)',
        '{:ok, response} = :httpc.request(binary_to_list(url))',
        'Req.get!(params["endpoint"])'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = elixirPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true);
      });
    });
  });

  describe('Weak Cryptography (A02:2021)', () => {
    it('should detect weak random number generation', () => {
      const patterns = registry.getPatterns(VulnerabilityType.WEAK_CRYPTOGRAPHY);
      const elixirPatterns = patterns.filter(p => p.languages.includes('elixir'));
      
      expect(elixirPatterns.length).toBeGreaterThan(0);
      
      const vulnerableCodes = [
        ':rand.uniform(1000000)',
        'Enum.random(1..999999)',
        ':random.uniform()',
        'System.unique_integer([:positive]) |> rem(1000000)'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = elixirPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true);
      });
    });
  });

  describe('CSRF (A01:2021)', () => {
    it('should detect missing CSRF protection', () => {
      const patterns = registry.getPatterns(VulnerabilityType.CSRF);
      const elixirPatterns = patterns.filter(p => p.languages.includes('elixir'));
      
      expect(elixirPatterns.length).toBeGreaterThan(0);
      
      const vulnerableCodes = [
        'plug :protect_from_forgery, except: [:create, :update]',
        '# plug :protect_from_forgery',
        'pipeline :api do\n    plug :accepts, ["json"]\n  end'
      ];
      
      vulnerableCodes.forEach(code => {
        const detected = elixirPatterns.some(pattern => 
          pattern.patterns.regex!.some(regex => regex.test(code))
        );
        expect(detected).toBe(true);
      });
    });
  });

  describe('Real CVE Examples', () => {
    it('should detect CVE-2022-23452 - Ecto SQL injection via fragment', () => {
      const patterns = registry.getPatterns(VulnerabilityType.SQL_INJECTION);
      const elixirPatterns = patterns.filter(p => p.languages.includes('elixir'));
      
      // This CVE involves improper use of fragment with user input
      const vulnerableCode = `from(u in User, where: fragment("? = ANY(?)", ^field, ^values))`;
      
      const detected = elixirPatterns.some(pattern => 
        pattern.patterns.regex!.some(regex => regex.test(vulnerableCode))
      );
      expect(detected).toBe(true);
    });

    it('should detect CVE-2021-22880 - PostgreSQL privilege escalation', () => {
      const patterns = registry.getPatterns(VulnerabilityType.SQL_INJECTION);
      const elixirPatterns = patterns.filter(p => p.languages.includes('elixir'));
      
      const vulnerableCode = `Repo.query!("CREATE FUNCTION #{name}() RETURNS void AS $$ #{code} $$ LANGUAGE plpgsql")`;
      
      const detected = elixirPatterns.some(pattern => 
        pattern.patterns.regex!.some(regex => regex.test(vulnerableCode))
      );
      expect(detected).toBe(true);
    });
  });

  it('should have all OWASP Top 10 2021 categories covered', () => {
    const elixirPatterns = registry.getPatternsByLanguage('elixir');
    const owaspCategories = new Set(
      elixirPatterns.map(p => p.owaspCategory.split(':')[0])
    );
    
    // Should have patterns for all 10 OWASP categories
    expect(owaspCategories.size).toBeGreaterThanOrEqual(10);
  });

  it('should provide Elixir-specific remediation for all patterns', () => {
    const elixirPatterns = registry.getPatternsByLanguage('elixir');
    
    elixirPatterns.forEach(pattern => {
      expect(pattern.remediation).toBeTruthy();
      expect(pattern.remediation.length).toBeGreaterThan(10);
      expect(pattern.remediation).toMatch(/Elixir|Phoenix|Ecto|plug/i);
      expect(pattern.examples.vulnerable).toBeTruthy();
      expect(pattern.examples.secure).toBeTruthy();
    });
  });
});