defmodule RsolvApi.Security.Patterns.Ruby.SsrfOpenUriTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Ruby.SsrfOpenUri
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = SsrfOpenUri.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "ruby-ssrf-open-uri"
      assert pattern.name == "SSRF via open-uri"
      assert pattern.severity == :high
      assert pattern.type == :ssrf
      assert pattern.languages == ["ruby"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = SsrfOpenUri.pattern()
      
      assert pattern.cwe_id == "CWE-918"
      assert pattern.owasp_category == "A10:2021"
    end
    
    test "has multiple regex patterns" do
      pattern = SsrfOpenUri.pattern()
      
      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 6
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = SsrfOpenUri.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches open-uri with user input", %{pattern: pattern} do
      vulnerable_code = [
        "open(params[:url])",
        "URI.open(params[:file_url])",
        "open(request.parameters[:target])",
        "URI.open(user_input)",
        "open(params['webhook_url'])"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches open with URL parameter variations", %{pattern: pattern} do
      vulnerable_code = [
        "open(params[:config_url])",
        "URI.open(params['api_endpoint'])",
        "open(request.params[:callback_url])",
        "URI.open(params.fetch(:source_url))",
        "open(user_provided_url)"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches Net::HTTP with user input", %{pattern: pattern} do
      vulnerable_code = [
        "Net::HTTP.get(URI(params[:target]))",
        "Net::HTTP.get_response(URI.parse(user_url))",
        "Net::HTTP.start(params[:host], 80)",
        "Net::HTTP.new(params[:server], params[:port])"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches HTTParty with user input", %{pattern: pattern} do
      vulnerable_code = [
        "HTTParty.get(params[:api_url])",
        "HTTParty.post(user_endpoint, body: data)",
        "HTTParty.put(params['webhook'])",
        "HTTParty.request(:get, params[:url])"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches Faraday with user input", %{pattern: pattern} do
      vulnerable_code = [
        "Faraday.get(params[:endpoint])",
        "Faraday.new(url: params[:base_url])",
        "faraday.get(user_path)",
        "connection.get(params[:resource_url])"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches RestClient with user input", %{pattern: pattern} do
      vulnerable_code = [
        "RestClient.get(params[:api_endpoint])",
        "RestClient.post(user_webhook, payload)",
        "RestClient::Request.execute(url: params[:target])",
        "rest_client.get(params['service_url'])"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe HTTP usage", %{pattern: pattern} do
      safe_code = [
        "open('https://api.trusted.com/data')",
        "URI.open('http://localhost:3000/health')",
        "Net::HTTP.get(URI('https://example.com/api'))",
        "HTTParty.get('https://api.github.com/users')",
        "Faraday.get('https://jsonplaceholder.typicode.com/posts')",
        "RestClient.get('https://api.example.com/status')",
        "logger.info \"Opening URL: \#{params[:url]}\""
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should not match: #{code}"
      end
    end
    
    test "documents regex limitations for comment detection", %{pattern: pattern} do
      # Note: Regex patterns have known limitations with comment detection
      # This is acceptable as AST enhancement will handle such cases
      commented_code = "# open(params[:url]) # Commented out SSRF vulnerability"
      
      # This is a known limitation - regex will match commented code
      assert Enum.any?(pattern.regex, &Regex.match?(&1, commented_code)),
             "Regex patterns are expected to match commented code (AST enhancement handles this)"
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = SsrfOpenUri.vulnerability_metadata()
      
      assert metadata.description =~ "SSRF"
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 5
      assert length(metadata.real_world_impact) >= 3
      assert length(metadata.cve_examples) >= 2
    end
    
    test "includes CVE examples from research" do
      metadata = SsrfOpenUri.vulnerability_metadata()
      
      cve_ids = Enum.map(metadata.cve_examples, & &1.id)
      assert Enum.any?(cve_ids, &String.contains?(&1, "CVE-2019-11027"))
      assert Enum.any?(cve_ids, &String.contains?(&1, "CVE-2022-27311"))
    end
    
    test "includes proper security references" do
      metadata = SsrfOpenUri.vulnerability_metadata()
      
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = SsrfOpenUri.ast_enhancement()
      
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.7
    end
    
    test "includes HTTP library analysis" do
      enhancement = SsrfOpenUri.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert enhancement.ast_rules.http_library_analysis.open_uri_methods
      assert enhancement.ast_rules.http_library_analysis.net_http_methods
    end
    
    test "has user input source detection" do
      enhancement = SsrfOpenUri.ast_enhancement()
      
      assert "params" in enhancement.ast_rules.user_input_analysis.input_sources
      assert "request" in enhancement.ast_rules.user_input_analysis.input_sources
      assert "user_input" in enhancement.ast_rules.user_input_analysis.input_sources
    end
    
    test "includes URL validation detection" do
      enhancement = SsrfOpenUri.ast_enhancement()
      
      assert enhancement.ast_rules.url_analysis.check_url_validation
      assert enhancement.ast_rules.url_analysis.allowlist_patterns
      assert enhancement.ast_rules.url_analysis.dangerous_schemes
    end
  end
end