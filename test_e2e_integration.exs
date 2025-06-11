#!/usr/bin/env elixir

# End-to-end integration test between RSOLV-api and RSOLV-action pattern format

Mix.install([
  {:httpoison, "~> 2.0"},
  {:jason, "~> 1.4"}
])

defmodule E2EIntegrationTest do
  @api_url "https://api.rsolv.dev/api/v1/patterns"
  
  def run do
    IO.puts("=== E2E Integration Test: RSOLV-api → RSOLV-action ===\n")
    
    # Test JavaScript patterns which RSOLV-action uses heavily
    test_javascript_integration()
    
    # Generate TypeScript interface for RSOLV-action
    generate_typescript_client()
  end
  
  def test_javascript_integration do
    IO.puts("Testing JavaScript pattern integration...")
    
    case fetch_patterns("javascript") do
      {:ok, patterns} ->
        IO.puts("✓ Successfully fetched #{length(patterns)} JavaScript patterns from API")
        
        # Show the structure that RSOLV-action needs to handle
        sample_pattern = List.first(patterns)
        IO.puts("\nSample pattern structure from API:")
        IO.puts(Jason.encode!(sample_pattern, pretty: true))
        
        # Test pattern compatibility
        test_pattern_compatibility(patterns)
        
      {:error, reason} ->
        IO.puts("✗ Failed to fetch patterns: #{reason}")
    end
  end
  
  def test_pattern_compatibility(patterns) do
    IO.puts("\nChecking pattern compatibility...")
    
    issues = []
    
    for pattern <- patterns do
      # Check required fields
      if not Map.has_key?(pattern, "id"), do: issues ++ ["Missing id in pattern"]
      if not Map.has_key?(pattern, "name"), do: issues ++ ["Missing name in pattern"]
      if not Map.has_key?(pattern, "type"), do: issues ++ ["Missing type in pattern"]
      if not Map.has_key?(pattern, "severity"), do: issues ++ ["Missing severity in pattern"]
      
      # Check regex structure
      regex_path = get_in(pattern, ["patterns", "regex"])
      if is_nil(regex_path) do
        IO.puts("⚠ Pattern #{pattern["id"]} has no regex at patterns.regex")
      end
      
      # Check test cases structure
      test_cases = pattern["testCases"] || pattern["test_cases"]
      if is_nil(test_cases) do
        IO.puts("⚠ Pattern #{pattern["id"]} has no test cases")
      end
    end
    
    if Enum.empty?(issues) do
      IO.puts("✓ All patterns have required fields")
    else
      IO.puts("✗ Found #{length(issues)} compatibility issues")
      Enum.each(issues, &IO.puts("  - #{&1}"))
    end
  end
  
  def generate_typescript_client do
    IO.puts("\n=== TypeScript Client Code for RSOLV-action ===\n")
    
    client_code = """
// Pattern API client for RSOLV-action
// This handles the nested structure from RSOLV-api

export interface PatternResponse {
  count: number;
  language: string;
  patterns: PatternData[];
}

export interface PatternData {
  id: string;
  name: string;
  type: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  patterns: {
    regex: string[];
  };
  languages: string[];
  frameworks?: string[];
  recommendation: string;
  cweId: string;
  owaspCategory: string;
  testCases: {
    vulnerable: string[];
    safe: string[];
  };
}

export class PatternAPIClient {
  private apiUrl: string;
  private apiKey?: string;

  constructor(apiUrl: string = 'https://api.rsolv.dev/api/v1/patterns', apiKey?: string) {
    this.apiUrl = apiUrl;
    this.apiKey = apiKey;
  }

  async fetchPatterns(language: string): Promise<PatternData[]> {
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
    };
    
    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    const response = await fetch(`${this.apiUrl}/${language}`, { headers });
    
    if (!response.ok) {
      throw new Error(`Failed to fetch patterns: ${response.statusText}`);
    }

    const data: PatternResponse = await response.json();
    return data.patterns;
  }

  // Convert API pattern to RSOLV-action SecurityPattern format
  convertToSecurityPattern(apiPattern: PatternData): any {
    // Extract regexes from nested structure
    const regexPatterns = apiPattern.patterns.regex.map(r => new RegExp(r));
    
    return {
      id: apiPattern.id,
      name: apiPattern.name,
      type: this.mapVulnerabilityType(apiPattern.type),
      severity: apiPattern.severity,
      description: apiPattern.description,
      patterns: {
        regex: regexPatterns
      },
      languages: apiPattern.languages,
      frameworks: apiPattern.frameworks || [],
      cweId: apiPattern.cweId,
      owaspCategory: apiPattern.owaspCategory,
      remediation: apiPattern.recommendation,
      testCases: apiPattern.testCases
    };
  }

  private mapVulnerabilityType(type: string): string {
    // Map API types to RSOLV-action VulnerabilityType enum
    const typeMap: Record<string, string> = {
      'sql_injection': 'SQL_INJECTION',
      'xss': 'XSS',
      'command_injection': 'COMMAND_INJECTION',
      'path_traversal': 'PATH_TRAVERSAL',
      'xxe': 'XXE',
      'ssrf': 'SSRF',
      'insecure_deserialization': 'INSECURE_DESERIALIZATION',
      'weak_crypto': 'WEAK_CRYPTO',
      'hardcoded_secret': 'HARDCODED_SECRET',
      'insecure_random': 'INSECURE_RANDOM',
      'open_redirect': 'OPEN_REDIRECT',
      'ldap_injection': 'LDAP_INJECTION',
      'xpath_injection': 'XPATH_INJECTION',
      'nosql_injection': 'NOSQL_INJECTION',
      'rce': 'RCE',
      'dos': 'DOS',
      'timing_attack': 'TIMING_ATTACK',
      'csrf': 'CSRF',
      'jwt': 'JWT',
      'debug': 'INFORMATION_DISCLOSURE',
      'cve': 'CVE'
    };
    
    return typeMap[type] || 'UNKNOWN';
  }
}

// Example usage in RSOLV-action
export async function loadPatternsFromAPI(): Promise<void> {
  const client = new PatternAPIClient();
  
  const languages = ['javascript', 'python', 'ruby', 'java', 'php', 'elixir'];
  
  for (const language of languages) {
    try {
      const patterns = await client.fetchPatterns(language);
      console.log(`Loaded ${patterns.length} ${language} patterns from API`);
      
      // Convert and use patterns
      const securityPatterns = patterns.map(p => client.convertToSecurityPattern(p));
      // Add to pattern registry...
    } catch (error) {
      console.error(`Failed to load ${language} patterns:`, error);
    }
  }
}
"""
    
    IO.puts(client_code)
    
    IO.puts("\n=== Integration Notes ===")
    IO.puts("1. RSOLV-api returns patterns under 'patterns.regex' (nested structure)")
    IO.puts("2. Test cases are returned as 'testCases' (camelCase)")
    IO.puts("3. Regex patterns are returned as strings, need to be compiled in TypeScript")
    IO.puts("4. Type mapping required between API and RSOLV-action VulnerabilityType enum")
  end
  
  def fetch_patterns(language) do
    url = "#{@api_url}/#{language}"
    
    case HTTPoison.get(url) do
      {:ok, %{status_code: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, %{"patterns" => patterns}} -> {:ok, patterns}
          {:error, _} -> {:error, "Failed to parse JSON"}
        end
      {:ok, %{status_code: code}} ->
        {:error, "HTTP #{code}"}
      {:error, %{reason: reason}} ->
        {:error, reason}
    end
  end
end

E2EIntegrationTest.run()