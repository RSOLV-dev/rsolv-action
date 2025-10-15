defmodule Rsolv.Security.Patterns.Java.UnsafeDeserializationTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Java.UnsafeDeserialization
  alias Rsolv.Security.Pattern

  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = UnsafeDeserialization.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "java-unsafe-deserialization"
      assert pattern.name == "Insecure Deserialization"
      assert pattern.severity == :critical
      assert pattern.type == :deserialization
      assert pattern.languages == ["java"]
    end

    test "includes CWE and OWASP references" do
      pattern = UnsafeDeserialization.pattern()

      assert pattern.cwe_id == "CWE-502"
      assert pattern.owasp_category == "A08:2021"
    end

    test "has multiple regex patterns" do
      pattern = UnsafeDeserialization.pattern()

      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 4
    end
  end

  describe "regex matching" do
    setup do
      pattern = UnsafeDeserialization.pattern()
      {:ok, pattern: pattern}
    end

    test "matches ObjectInputStream.readObject()", %{pattern: pattern} do
      vulnerable_code = [
        ~S|ObjectInputStream ois = new ObjectInputStream(input);
Object obj = ois.readObject();|,
        ~S|return new ObjectInputStream(fileInputStream).readObject();|,
        ~S|Object data = objectInputStream.readObject();|,
        ~S|ois.readObject()|,
        ~S|((ObjectInputStream) stream).readObject()|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches readUnshared() usage", %{pattern: pattern} do
      vulnerable_code = [
        ~S|Object obj = ois.readUnshared();|,
        ~S|return objectInputStream.readUnshared();|,
        ~S|data = ((ObjectInputStream) input).readUnshared();|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches XMLDecoder readObject", %{pattern: pattern} do
      vulnerable_code = [
        ~S|XMLDecoder decoder = new XMLDecoder(inputStream);
Object obj = decoder.readObject();|,
        ~S|return xmlDecoder.readObject();|,
        ~S|XMLDecoder d = new XMLDecoder(new BufferedInputStream(stream));
d.readObject();|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches Externalizable.readExternal", %{pattern: pattern} do
      vulnerable_code = [
        ~S|public void readExternal(ObjectInput in) throws IOException {
    this.data = in.readObject();
}|,
        ~S|externalizable.readExternal(objectInput);|,
        ~S|obj.readExternal(new ObjectInputStream(stream));|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "does not match safe alternatives", %{pattern: pattern} do
      safe_code = [
        ~S|// Use JSON deserialization instead
ObjectMapper mapper = new ObjectMapper();
User user = mapper.readValue(jsonString, User.class);|,
        ~S|// Comment about readObject|,
        ~S|logger.info("readObject called")|,
        ~S|String method = "readObject"|,
        ~S|// Implement custom validation
private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
    ois.defaultReadObject();
    validateState();
}|
      ]

      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should not match: #{code}"
      end
    end

    test "matches deserialization with class loading", %{pattern: pattern} do
      vulnerable_code = [
        ~S|Class<?> clazz = Class.forName(className);
ObjectInputStream ois = new ObjectInputStream(input);
Object obj = ois.readObject();|,
        ~S|ois.readObject(); // After dynamic class loading|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = UnsafeDeserialization.vulnerability_metadata()

      assert metadata.description =~ "deserialization"
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 5
      assert length(metadata.real_world_impact) >= 4
      assert length(metadata.cve_examples) >= 5
    end

    test "includes CVE examples from research" do
      metadata = UnsafeDeserialization.vulnerability_metadata()

      cve_ids = Enum.map(metadata.cve_examples, & &1.id)
      assert Enum.any?(cve_ids, &String.contains?(&1, "CVE-"))
      # Should include recent CVEs from research
      assert Enum.any?(cve_ids, fn id ->
               String.contains?(id, "2023") || String.contains?(id, "2024")
             end)
    end

    test "includes proper security references" do
      metadata = UnsafeDeserialization.vulnerability_metadata()

      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end

    test "includes gadget chain information" do
      metadata = UnsafeDeserialization.vulnerability_metadata()

      assert Enum.any?(metadata.attack_vectors, &String.contains?(&1, "gadget"))
      assert metadata.additional_context.gadget_chains
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = UnsafeDeserialization.ast_enhancement()

      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)

      assert enhancement.min_confidence >= 0.7
    end

    test "includes deserialization method analysis" do
      enhancement = UnsafeDeserialization.ast_enhancement()

      assert enhancement.ast_rules.node_type == "MethodInvocation"
      assert enhancement.ast_rules.deserialization_analysis.check_method_name
      assert enhancement.ast_rules.deserialization_analysis.unsafe_methods
      assert enhancement.ast_rules.deserialization_analysis.check_receiver_type
    end

    test "has input source tracking" do
      enhancement = UnsafeDeserialization.ast_enhancement()

      assert enhancement.ast_rules.input_tracking.check_data_source
      assert enhancement.ast_rules.input_tracking.untrusted_sources
      assert enhancement.ast_rules.input_tracking.safe_sources
    end

    test "includes validation detection" do
      enhancement = UnsafeDeserialization.ast_enhancement()

      assert enhancement.context_rules.check_custom_readobject
      assert enhancement.context_rules.check_input_filtering
      assert enhancement.context_rules.safe_patterns
    end
  end
end
