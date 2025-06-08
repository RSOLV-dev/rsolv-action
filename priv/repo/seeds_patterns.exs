# Script for creating initial public patterns
alias RsolvApi.Repo
alias RsolvApi.Security.{SecurityPattern, PatternTier}

public_tier = Repo.get_by!(PatternTier, name: "public")

patterns = [
  %{
    name: "DOM XSS via innerHTML",
    description: "Direct assignment to innerHTML with user input can lead to XSS",
    language: "javascript",
    type: "xss",
    severity: "high",
    cwe_id: "CWE-79",
    owasp_category: "A03:2021 – Injection",
    remediation: "Use textContent for plain text or sanitize HTML content before assignment",
    confidence: "high",
    regex_patterns: ["innerHTML\\s*=\\s*[^;]+"],
    safe_usage_patterns: ["textContent\\s*=", "sanitizeHTML\\("],
    is_active: true,
    tier_id: public_tier.id
  },
  %{
    name: "Hardcoded Secret",
    description: "Potential hardcoded secret or API key in source code",
    language: "javascript",
    type: "hardcoded_secret",
    severity: "high",
    cwe_id: "CWE-798",
    owasp_category: "A07:2021 – Identification and Authentication Failures",
    remediation: "Use environment variables or secure configuration management",
    confidence: "medium",
    regex_patterns: ["(api[_-]?key|secret|password|token)\\s*[:=]\\s*[\"'`][^\"'`]{10,}[\"'`]"],
    safe_usage_patterns: ["process\\.env\\.", "config\\.get\\("],
    is_active: true,
    tier_id: public_tier.id
  },
  %{
    name: "SQL Injection via String Concatenation",
    description: "Direct string concatenation in SQL queries can lead to injection",
    language: "javascript",
    type: "sql_injection",
    severity: "critical",
    cwe_id: "CWE-89",
    owasp_category: "A03:2021 – Injection", 
    remediation: "Use parameterized queries or prepared statements",
    confidence: "high",
    regex_patterns: ["query\\s*\\(\\s*[\"'`].*\\+.*[\"'`]", "execute\\s*\\(\\s*[\"'`].*\\$\\{"],
    safe_usage_patterns: ["query\\s*\\(\\s*[\"'`][^\"'`]*\\?[^\"'`]*[\"'`]\\s*,"],
    is_active: true,
    tier_id: public_tier.id
  }
]

Enum.each(patterns, fn attrs ->
  %SecurityPattern{}
  |> SecurityPattern.changeset(attrs)
  |> Repo.insert!()
end)

IO.puts("✅ Seeded #{length(patterns)} public patterns")