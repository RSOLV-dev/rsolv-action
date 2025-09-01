# Tidewave Security Considerations

## Overview
Tidewave is an AI-powered development assistant integrated into the RSOLV platform for development environments only. This document outlines security considerations and best practices.

## Configuration

### Environment Restrictions
- **Development Only**: Tidewave is only included in `:dev` environment via mix.exs
- **Not in Production**: Never deploys to staging or production environments
- **Code Reloading Guard**: Only loaded when `code_reloading?` is true in endpoint.ex

### Network Access Control
- **Local Network Access**: Configured to accept connections from 10.0.0.0/8
- **Allowed Origins**: Limited to `http://localhost:4000` and `http://10.*:4000`
- **Remote Access Flag**: Explicitly enabled for local development network

### API Key Management
- **Environment Variable**: Anthropic API key stored in environment variable, not in code
- **Dev Config File**: .env.dev file is gitignored (added to .gitignore)
- **No Hardcoding**: Never commit API keys to version control

## Security Best Practices

### 1. API Key Protection
- Store API key in environment variables or secure vaults
- Use .env.dev file locally (already in .gitignore)
- Rotate API keys regularly
- Monitor API usage for anomalies

### 2. Network Isolation
- Only enable on development networks
- Use firewall rules to restrict access if needed
- Never expose Tidewave endpoint to public internet
- Monitor access logs during development

### 3. Code Review
- Review all Tidewave-suggested changes before committing
- Understand the security implications of generated code
- Test thoroughly in development before promoting changes
- Use version control to track all changes

### 4. Data Handling
- Tidewave may process sensitive code patterns
- Ensure no production data is accessible in dev environment
- Use anonymized/synthetic data for development
- Clear browser cache/storage after sessions

### 5. Dependencies
- Keep Tidewave package updated for security patches
- Review Tidewave's own dependencies
- Monitor security advisories for the package
- Test updates in isolated environment first

## Risk Mitigation

### Potential Risks
1. **API Key Exposure**: Mitigated by environment variables and .gitignore
2. **Network Access**: Limited to local development network only
3. **Code Generation**: All changes reviewed through version control
4. **Dependency Vulnerabilities**: Regular updates and security monitoring

### Monitoring Recommendations
- Log all Tidewave access attempts
- Monitor API usage and costs
- Review generated code patterns
- Track dependency vulnerabilities

## Incident Response

If security concerns arise:
1. Immediately revoke compromised API keys
2. Review access logs for unauthorized usage
3. Audit recent code changes made via Tidewave
4. Update security configurations as needed
5. Document incident and lessons learned

## Compliance Notes

- Tidewave is a development tool only
- No customer data should be processed
- No production systems should have access
- Regular security reviews recommended

## Configuration Checklist

- [x] Tidewave only in :dev environment
- [x] API key in environment variable
- [x] .env.dev in .gitignore
- [x] Local network access configured
- [x] Not deployed to staging/production
- [x] Code reloading guard in place
- [x] LiveView debug annotations enabled (dev only)

Last Updated: 2025-09-01