defmodule Rsolv.Security.Patterns.Ruby.UnsafeDeserializationMarshalTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Ruby.UnsafeDeserializationMarshal
  alias Rsolv.Security.Pattern

  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = UnsafeDeserializationMarshal.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "ruby-unsafe-deserialization-marshal"
      assert pattern.name == "Unsafe Deserialization - Marshal"
      assert pattern.severity == :critical
      assert pattern.type == :deserialization
      assert pattern.languages == ["ruby"]
    end

    test "includes CWE and OWASP references" do
      pattern = UnsafeDeserializationMarshal.pattern()

      assert pattern.cwe_id == "CWE-502"
      assert pattern.owasp_category == "A08:2021"
    end

    test "has multiple regex patterns" do
      pattern = UnsafeDeserializationMarshal.pattern()

      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 5
    end
  end

  describe "regex matching" do
    setup do
      pattern = UnsafeDeserializationMarshal.pattern()
      {:ok, pattern: pattern}
    end

    test "matches Marshal.load with params", %{pattern: pattern} do
      vulnerable_code = [
        ~S|data = Marshal.load(params[:data])|,
        ~S|obj = Marshal.load(params["serialized"])|,
        ~S|user = Marshal.load(params[:user_data])|,
        ~S|result = Marshal.load(params.fetch(:payload))|,
        ~S|Marshal.load(params[:token])|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches Marshal.load with request data", %{pattern: pattern} do
      vulnerable_code = [
        ~S|data = Marshal.load(request.body.read)|,
        ~S|obj = Marshal.load(request.headers['X-Data'])|,
        ~S|Marshal.load(request.raw_post)|,
        ~S|session_data = Marshal.load(request.session[:data])|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches Marshal.load with cookies", %{pattern: pattern} do
      vulnerable_code = [
        ~S|data = Marshal.load(cookies[:session])|,
        ~S|obj = Marshal.load(cookies.signed[:data])|,
        ~S|user = Marshal.load(cookies.encrypted[:user])|,
        ~S|Marshal.load(cookies[:auth_token])|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches Marshal.load with Base64 decoding", %{pattern: pattern} do
      vulnerable_code = [
        ~S|data = Marshal.load(Base64.decode64(params[:data]))|,
        ~S|obj = Marshal.load(Base64.strict_decode64(user_input))|,
        ~S|result = Marshal.load(Base64.urlsafe_decode64(params[:payload]))|,
        ~S|Marshal.load(Base64.decode64(cookies[:session]))|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches Marshal.load with user input variables", %{pattern: pattern} do
      vulnerable_code = [
        ~S|data = Marshal.load(user_input)|,
        ~S|obj = Marshal.load(untrusted_data)|,
        ~S|Marshal.load(external_data)|,
        ~S|result = Marshal.load(client_data)|,
        ~S|Marshal.load(uploaded_file.read)|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches ActiveStorage vulnerability patterns", %{pattern: pattern} do
      vulnerable_code = [
        ~S|Marshal.load(URI.decode(signed_blob_id))|,
        ~S|data = Marshal.load(ActiveStorage::Verifier.new.verify(token))|,
        ~S|blob = Marshal.load(Rails.application.message_verifier.verify(params[:blob]))|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "does not match safe Marshal usage", %{pattern: pattern} do
      safe_code = [
        ~S|data = Marshal.load(File.read("safe_file.dat"))|,
        ~S|obj = Marshal.load(TRUSTED_CONSTANT)|,
        ~S|Marshal.dump(user_object)|,
        ~S|JSON.parse(params[:data])|,
        ~S|YAML.safe_load(user_input)|,
        ~S|if params[:data]; Marshal.load(trusted_source); end|
      ]

      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should not match: #{code}"
      end
    end

    test "documents regex limitations for comment detection", %{pattern: pattern} do
      # Note: Regex patterns have known limitations with comment detection
      # This is acceptable as AST enhancement will handle such cases
      commented_code = ~S|# Marshal.load(params[:data]) # Vulnerable but commented|

      # This is a known limitation - regex will match commented code
      assert Enum.any?(pattern.regex, &Regex.match?(&1, commented_code)),
             "Regex patterns are expected to match commented code (AST enhancement handles this)"
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = UnsafeDeserializationMarshal.vulnerability_metadata()

      assert metadata.description =~ "Marshal"
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 5
      assert length(metadata.real_world_impact) >= 3
      assert length(metadata.cve_examples) >= 3
    end

    test "includes CVE examples from research" do
      metadata = UnsafeDeserializationMarshal.vulnerability_metadata()

      cve_ids = Enum.map(metadata.cve_examples, & &1.id)
      assert Enum.any?(cve_ids, &String.contains?(&1, "CVE-2019-5420"))
      assert Enum.any?(cve_ids, &String.contains?(&1, "CVE-2020-8165"))
    end

    test "includes proper references" do
      metadata = UnsafeDeserializationMarshal.vulnerability_metadata()

      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = UnsafeDeserializationMarshal.ast_enhancement()

      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)

      assert enhancement.min_confidence >= 0.8
    end

    test "includes Marshal-specific AST rules" do
      enhancement = UnsafeDeserializationMarshal.ast_enhancement()

      assert enhancement.ast_rules.node_type == "CallExpression"
      assert enhancement.ast_rules.method_analysis.method_name == "load"
      assert enhancement.ast_rules.receiver_analysis.object_name == "Marshal"
    end

    test "has user input source detection" do
      enhancement = UnsafeDeserializationMarshal.ast_enhancement()

      assert "params" in enhancement.ast_rules.user_input_analysis.input_sources
      assert "request" in enhancement.ast_rules.user_input_analysis.input_sources
      assert "cookies" in enhancement.ast_rules.user_input_analysis.input_sources
    end

    test "includes gadget chain detection rules" do
      enhancement = UnsafeDeserializationMarshal.ast_enhancement()

      assert enhancement.ast_rules.gadget_analysis.check_known_gadgets
      assert enhancement.ast_rules.gadget_analysis.universal_gadget_patterns
    end
  end
end
