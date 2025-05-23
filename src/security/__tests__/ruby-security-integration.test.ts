import { describe, it, expect } from 'vitest';
import { SecurityDetector } from '../detector.js';
import { VulnerabilityType } from '../types.js';

describe('Ruby Security Integration', () => {
  const detector = new SecurityDetector();

  it('should detect multiple vulnerabilities in a Ruby file', () => {
    const rubyCode = `
class UsersController < ApplicationController
  # Missing authentication - A01 Broken Access Control
  def admin_panel
    @users = User.all
  end

  # SQL Injection - A03 Injection
  def search
    @users = User.where("name = '#{params[:name]}'")
  end

  # Mass assignment - A01 Broken Access Control
  def create
    @user = User.create(params[:user])
    redirect_to @user
  end

  # Command injection - A03 Injection
  def backup
    system("tar -czf backup.tar.gz #{params[:dir]}")
  end

  # Weak crypto - A02 Cryptographic Failures
  def legacy_login
    password_hash = Digest::MD5.hexdigest(params[:password])
    @user = User.find_by(password_hash: password_hash)
  end

  # Hardcoded secret - A02 Cryptographic Failures
  API_KEY = "sk_live_4242424242424242"

  # Open redirect - A01 Broken Access Control
  def logout
    redirect_to params[:return_to]
  end

  # Unsafe deserialization - A08 Software and Data Integrity Failures
  def import_settings
    settings = Marshal.load(params[:data])
    current_user.update(settings: settings)
  end
end
    `.trim();

    const vulnerabilities = detector.detect(rubyCode, 'ruby');
    
    // Should detect multiple vulnerabilities
    expect(vulnerabilities.length).toBeGreaterThan(5);
    
    // Check for specific vulnerability types
    const vulnTypes = vulnerabilities.map(v => v.type);
    // We should detect most of these types
    const expectedTypes = [
      VulnerabilityType.COMMAND_INJECTION,
      VulnerabilityType.MASS_ASSIGNMENT,
      VulnerabilityType.WEAK_CRYPTOGRAPHY,
      VulnerabilityType.HARDCODED_SECRETS,
      VulnerabilityType.INSECURE_DESERIALIZATION
    ];
    
    const detectedExpected = expectedTypes.filter(type => vulnTypes.includes(type));
    expect(detectedExpected.length).toBeGreaterThanOrEqual(4);
    
    // Check severity levels
    const criticalVulns = vulnerabilities.filter(v => v.severity === 'critical');
    expect(criticalVulns.length).toBeGreaterThan(2); // Command injection, hardcoded secret, deserialization
    
    // Check OWASP categories
    const owaspCategories = new Set(
      vulnerabilities.map(v => v.owaspCategory?.split(':')[0]).filter(Boolean)
    );
    expect(owaspCategories.size).toBeGreaterThan(3); // Should cover multiple OWASP categories
  });

  it('should provide Ruby-specific remediation', () => {
    const sqlInjectionCode = `
      User.where("email = '#{email}'")
    `;
    
    const vulnerabilities = detector.detect(sqlInjectionCode, 'ruby');
    
    expect(vulnerabilities.length).toBe(1);
    const vuln = vulnerabilities[0];
    
    expect(vuln.type).toBe(VulnerabilityType.SQL_INJECTION);
    expect(vuln.remediation).toContain('parameterized');
    expect(vuln.remediation).toContain('?'); // Ruby uses ? for placeholders
  });

  it('should detect Rails-specific vulnerabilities', () => {
    const railsCode = `
# ERB template with XSS
<%= raw user_comment %>
<%= @post.content.html_safe %>

# Debug mode enabled
config.consider_all_requests_local = true

# Insecure cookie
cookies[:auth] = token
    `.trim();
    
    const vulnerabilities = detector.detect(railsCode, 'ruby');
    
    const vulnTypes = vulnerabilities.map(v => v.type);
    expect(vulnTypes).toContain(VulnerabilityType.XSS);
    expect(vulnTypes).toContain(VulnerabilityType.DEBUG_MODE);
    expect(vulnTypes).toContain(VulnerabilityType.SECURITY_MISCONFIGURATION);
  });

  it('should handle Ruby-specific syntax correctly', () => {
    const rubyCode = `
# String interpolation in various contexts
name = "User: #{params[:name]}"  # Safe - not in SQL
User.where(name: params[:name])  # Safe - parameterized
User.where("name = ?", params[:name])  # Safe - parameterized
User.where("name = '#{params[:name]}'")  # Vulnerable!

# Method calls
system("echo", user_input)  # Safe - array form
system("echo #{user_input}")  # Vulnerable!
    `.trim();
    
    const vulnerabilities = detector.detect(rubyCode, 'ruby');
    
    // Should only detect the vulnerable patterns
    expect(vulnerabilities.length).toBeGreaterThanOrEqual(1);
    
    // At least command injection should be detected
    const commandInjections = vulnerabilities.filter(v => 
      v.type === VulnerabilityType.COMMAND_INJECTION
    );
    expect(commandInjections.length).toBeGreaterThan(0);
  });

  it('should rank Ruby vulnerabilities by severity', () => {
    const mixedCode = `
# Low severity
rescue => e
  nil
end

# Medium severity  
password = Digest::MD5.hexdigest(input)

# High severity
User.where("id = #{params[:id]}")

# Critical severity
Marshal.load(params[:data])
system("rm -rf #{params[:path]}")
    `.trim();
    
    const vulnerabilities = detector.detect(mixedCode, 'ruby');
    
    // Group by severity
    const bySeverity = vulnerabilities.reduce((acc, vuln) => {
      acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    
    // Should have at least some critical and high severity issues
    expect(vulnerabilities.length).toBeGreaterThan(0);
    expect(bySeverity.critical || 0).toBeGreaterThanOrEqual(1);
    const totalHighSeverity = (bySeverity.critical || 0) + (bySeverity.high || 0);
    expect(totalHighSeverity).toBeGreaterThanOrEqual(2);
  });
});