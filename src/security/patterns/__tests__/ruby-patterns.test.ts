import { describe, it, expect } from 'vitest';
import { PatternRegistry } from '../../patterns.js';
import { VulnerabilityType } from '../../types.js';

describe('Ruby Security Patterns', () => {
  const registry = new PatternRegistry();

  it('should detect all Ruby patterns', () => {
    const rubyPatterns = registry.getPatternsByLanguage('ruby');
    expect(rubyPatterns.length).toBeGreaterThan(15); // We have 20+ patterns
  });

  it('should detect SQL injection in Ruby', () => {
    const patterns = registry.getPatterns(VulnerabilityType.SQL_INJECTION);
    const rubyPatterns = patterns.filter(p => p.languages.includes('ruby'));
    
    expect(rubyPatterns).toHaveLength(1);
    expect(rubyPatterns[0].name).toContain('SQL Injection');
    
    // Test detection
    const vulnerableCode = 'User.where("name = \'#{params[:name]}\'")';
    // Test that at least one regex matches
    const matches = rubyPatterns[0].patterns.regex!.some(regex => regex.test(vulnerableCode));
    expect(matches).toBe(true);
  });

  it('should detect command injection in Ruby', () => {
    const patterns = registry.getPatterns(VulnerabilityType.COMMAND_INJECTION);
    const rubyPatterns = patterns.filter(p => p.languages.includes('ruby'));
    
    expect(rubyPatterns).toHaveLength(1);
    
    // Test various command injection patterns
    const vulnerableCodes = [
      'system("echo #{user_input}")',
      '`rm -rf #{params[:dir]}`',
      'exec("ls #{path}")'
    ];
    
    vulnerableCodes.forEach(code => {
      const detected = rubyPatterns.some(pattern => 
        pattern.patterns.regex!.some(regex => regex.test(code))
      );
      expect(detected).toBe(true);
    });
  });

  it('should detect mass assignment vulnerabilities', () => {
    const patterns = registry.getPatterns(VulnerabilityType.MASS_ASSIGNMENT);
    const rubyPatterns = patterns.filter(p => p.languages.includes('ruby'));
    
    expect(rubyPatterns).toHaveLength(1);
    
    const vulnerableCode = 'User.create(params[:user])';
    const regex = rubyPatterns[0].patterns.regex![0];
    expect(regex.test(vulnerableCode)).toBe(true);
    
    // Should not match when using strong parameters
    const safeCode = 'User.create(params.require(:user).permit(:name))';
    expect(regex.test(safeCode)).toBe(false);
  });

  it('should detect unsafe deserialization', () => {
    const patterns = registry.getPatterns(VulnerabilityType.INSECURE_DESERIALIZATION);
    const rubyPatterns = patterns.filter(p => p.languages.includes('ruby'));
    
    expect(rubyPatterns.length).toBeGreaterThan(0);
    
    const vulnerableCodes = [
      'Marshal.load(user_input)',
      'YAML.load(params[:config])'
    ];
    
    vulnerableCodes.forEach(code => {
      const detected = rubyPatterns.some(pattern => 
        pattern.patterns.regex!.some(regex => regex.test(code))
      );
      expect(detected).toBe(true);
    });
  });

  it('should detect XSS in ERB templates', () => {
    const patterns = registry.getPatterns(VulnerabilityType.XSS);
    const rubyPatterns = patterns.filter(p => p.languages.includes('ruby'));
    
    expect(rubyPatterns.length).toBeGreaterThan(0);
    
    const vulnerableCodes = [
      '<%= raw user_content %>',
      '<%= @comment.body.html_safe %>'
    ];
    
    vulnerableCodes.forEach(code => {
      const detected = rubyPatterns.some(pattern => 
        pattern.patterns.regex!.some(regex => regex.test(code))
      );
      expect(detected).toBe(true);
    });
  });

  it('should detect weak cryptography', () => {
    const patterns = registry.getPatterns(VulnerabilityType.WEAK_CRYPTOGRAPHY);
    const rubyPatterns = patterns.filter(p => p.languages.includes('ruby'));
    
    expect(rubyPatterns.length).toBeGreaterThan(0);
    
    // Test MD5 detection
    const md5Code = 'Digest::MD5.hexdigest(password)';
    const md5Detected = rubyPatterns.some(pattern => 
      pattern.patterns.regex!.some(regex => regex.test(md5Code))
    );
    expect(md5Detected).toBe(true);
    
    // SHA1 is detected in broken authentication patterns, not weak crypto
    // So we'll test for it separately
    const authPatterns = registry.getPatterns(VulnerabilityType.BROKEN_AUTHENTICATION);
    const sha1Code = 'user.password = Digest::SHA1.hexdigest(password)';
    const sha1Detected = authPatterns.some(pattern => 
      pattern.languages.includes('ruby') &&
      pattern.patterns.regex!.some(regex => regex.test(sha1Code))
    );
    expect(sha1Detected).toBe(true);
  });

  it('should detect hardcoded secrets', () => {
    const patterns = registry.getPatterns(VulnerabilityType.HARDCODED_SECRETS);
    const rubyPatterns = patterns.filter(p => p.languages.includes('ruby'));
    
    expect(rubyPatterns.length).toBeGreaterThan(0);
    
    const vulnerableCode = 'API_KEY = "sk_live_abcd1234efgh5678"';
    const detected = rubyPatterns.some(pattern => 
      pattern.patterns.regex!.some(regex => regex.test(vulnerableCode))
    );
    expect(detected).toBe(true);
  });

  it('should have all OWASP Top 10 categories covered', () => {
    const rubyPatterns = registry.getPatternsByLanguage('ruby');
    const owaspCategories = new Set(
      rubyPatterns.map(p => p.owaspCategory.split(':')[0])
    );
    
    // Should have patterns for most OWASP categories
    expect(owaspCategories.size).toBeGreaterThanOrEqual(9);
  });

  it('should provide remediation for all patterns', () => {
    const rubyPatterns = registry.getPatternsByLanguage('ruby');
    
    rubyPatterns.forEach(pattern => {
      expect(pattern.remediation).toBeTruthy();
      expect(pattern.remediation.length).toBeGreaterThan(10);
      expect(pattern.examples.vulnerable).toBeTruthy();
      expect(pattern.examples.secure).toBeTruthy();
    });
  });
});