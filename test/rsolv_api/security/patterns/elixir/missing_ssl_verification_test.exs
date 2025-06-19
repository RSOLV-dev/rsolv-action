defmodule RsolvApi.Security.Patterns.Elixir.MissingSslVerificationTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Elixir.MissingSslVerification
  alias RsolvApi.Security.Pattern

  describe "missing_ssl_verification pattern" do
    test "returns correct pattern structure" do
      pattern = MissingSslVerification.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "elixir-missing-ssl-verification"
      assert pattern.name == "Missing SSL Certificate Verification"
      assert pattern.type == :authentication
      assert pattern.severity == :high
      assert pattern.languages == ["elixir"]
      assert pattern.default_tier == :ai
      assert pattern.cwe_id == "CWE-295"
      assert pattern.owasp_category == "A07:2021"
      
      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects HTTPoison with verify_none" do
      pattern = MissingSslVerification.pattern()
      
      test_cases = [
        ~S|HTTPoison.get!(url, [], ssl: [verify: :verify_none])|,
        ~S|HTTPoison.post(url, body, headers, ssl: [verify: :verify_none])|,
        ~S|HTTPoison.put!(url, data, [], ssl: [verify: :verify_none, versions: [:"tlsv1.2"]])|,
        ~S|HTTPoison.request(:get, url, "", [], ssl: [verify: :verify_none])|,
        ~S|HTTPoison.patch!(url, body, headers, ssl: [verify: :verify_none, ciphers: :strong])|
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects Tesla with verify_none" do
      pattern = MissingSslVerification.pattern()
      
      test_cases = [
        ~S|Tesla.get(client, url, opts: [adapter: [ssl_options: [verify: :verify_none]]])|,
        ~S|Tesla.post(client, url, body, opts: [adapter: [ssl_options: [verify: :verify_none]]])|,
        ~S|adapter Tesla.Adapter.Hackney, ssl_options: [verify: :verify_none]|,
        ~S|middleware Tesla.Middleware.BaseUrl, "https://api.example.com", ssl_options: [verify: :verify_none]|,
        ~S|Tesla.client([], {Tesla.Adapter.Hackney, ssl_options: [verify: :verify_none]})|
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects hackney options with verify_none" do
      pattern = MissingSslVerification.pattern()
      
      test_cases = [
        ~S|HTTPoison.get(url, [], hackney: [ssl_options: [verify: :verify_none]])|,
        ~S|HTTPoison.post!(url, body, headers, hackney: [ssl_options: [verify: :verify_none]])|,
        ~S|hackney: [:insecure]|,
        ~S|HTTPoison.get(url, [], hackney: [:insecure])|,
        ~S|HTTPoison.request(:post, url, body, headers, hackney: [:insecure])|
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects multi-line SSL configuration" do
      pattern = MissingSslVerification.pattern()
      
      test_cases = [
        ~S"""
        HTTPoison.get!(
          url,
          [],
          ssl: [
            verify: :verify_none,
            versions: [:"tlsv1.2"]
          ]
        )
        """,
        ~S"""
        opts = [
          ssl: [
            verify: :verify_none
          ]
        ]
        HTTPoison.post(url, body, headers, opts)
        """,
        ~S"""
        config :my_app, :http_client,
          ssl: [
            verify: :verify_none,
            cacerts: :certifi.cacerts()
          ]
        """
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects Req library with verify_none" do
      pattern = MissingSslVerification.pattern()
      
      test_cases = [
        ~S|Req.get!(url, connect_options: [verify: :verify_none])|,
        ~S|Req.post(url, body: data, connect_options: [verify: :verify_none])|,
        ~S|Req.new(base_url: url, connect_options: [verify: :verify_none])|,
        ~S|Req.request!(method: :get, url: url, connect_options: [verify: :verify_none])|,
        ~S|connect_options: [transport_opts: [verify: :verify_none]]|
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "does not detect secure SSL configurations" do
      pattern = MissingSslVerification.pattern()
      
      safe_code = [
        # Default secure configurations
        ~S|HTTPoison.get!(url)|,
        ~S|HTTPoison.post(url, body, headers)|,
        ~S|Tesla.get(client, url)|,
        # Explicit verify_peer
        ~S|HTTPoison.get!(url, [], ssl: [verify: :verify_peer])|,
        ~S|HTTPoison.post(url, body, headers, ssl: [verify: :verify_peer, cacerts: :certifi.cacerts()])|,
        # Other SSL options without verify_none
        ~S|HTTPoison.get!(url, [], ssl: [versions: [:"tlsv1.2", :"tlsv1.3"]])|,
        ~S|ssl: [ciphers: :strong]|,
        # Comments
        ~S|# HTTPoison.get!(url, [], ssl: [verify: :verify_none])|
      ]
      
      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "does not detect comments or documentation" do
      pattern = MissingSslVerification.pattern()
      
      safe_code = [
        ~S|# HTTPoison.get!(url, [], ssl: [verify: :verify_none])|,
        ~S|@doc "Never use ssl: [verify: :verify_none]"|,
        ~S|# TODO: Remove hackney: [:insecure] in production|,
        ~S"""
        # Insecure example:
        # HTTPoison.get!(url, [], hackney: [:insecure])
        """
      ]
      
      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = MissingSslVerification.vulnerability_metadata()
      
      assert metadata.attack_vectors
      assert metadata.business_impact  
      assert metadata.technical_impact
      assert metadata.likelihood
      assert metadata.cve_examples
      assert metadata.compliance_standards
      assert metadata.remediation_steps
      assert metadata.prevention_tips
      assert metadata.detection_methods
      assert metadata.safe_alternatives
    end

    test "vulnerability metadata contains SSL/TLS specific information" do
      metadata = MissingSslVerification.vulnerability_metadata()
      
      assert String.contains?(metadata.attack_vectors, "MITM")
      assert String.contains?(metadata.business_impact, "confidentiality")
      assert String.contains?(metadata.technical_impact, "certificate")
      assert String.contains?(metadata.safe_alternatives, "verify_peer")
      assert String.contains?(metadata.prevention_tips, "production")
    end

    test "includes AST enhancement rules" do
      enhancement = MissingSslVerification.ast_enhancement()
      
      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has SSL specific rules" do
      enhancement = MissingSslVerification.ast_enhancement()
      
      assert enhancement.context_rules.http_libraries
      assert enhancement.context_rules.insecure_options
      assert enhancement.ast_rules.ssl_analysis
      assert enhancement.confidence_rules.adjustments.development_context_penalty
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = MissingSslVerification.enhanced_pattern()
      
      assert enhanced.id == "elixir-missing-ssl-verification"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = MissingSslVerification.pattern()
      
      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end
  end
end