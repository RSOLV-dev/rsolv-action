defmodule RsolvApi.Security.Patterns.Python.UnsafePickleTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Python.UnsafePickle
  alias RsolvApi.Security.Pattern
  
  describe "pattern structure" do
    test "returns correct pattern structure with all required fields" do
      pattern = UnsafePickle.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "python-unsafe-pickle"
      assert pattern.name == "Insecure Deserialization via pickle"
      assert pattern.type == :deserialization
      assert pattern.severity == :critical
      assert pattern.languages == ["python"]
      assert pattern.cwe_id == "CWE-502"
      assert pattern.owasp_category == "A08:2021"
      assert is_binary(pattern.recommendation)
      assert is_map(pattern.test_cases)
    end
  end
  
  describe "vulnerability detection" do
    test "detects pickle.loads with various inputs" do
      pattern = UnsafePickle.pattern()
      
      vulnerable_code = [
        ~S|data = pickle.loads(user_data)|,
        ~S|pickle.loads(request.data)|,
        ~S|result = pickle.loads(base64.b64decode(encoded_data))|,
        ~S|obj = pickle.loads(bytes_data)|,
        ~S|pickle.loads(input_bytes)|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
          "Should match vulnerable code: #{code}"
      end
    end
    
    test "detects pickle.load from file operations" do
      pattern = UnsafePickle.pattern()
      
      vulnerable_code = [
        ~S|with open('data.pkl', 'rb') as f: obj = pickle.load(f)|,
        ~S|pickle.load(file_handle)|,
        ~S|data = pickle.load(open('user.pkl', 'rb'))|,
        ~S|result = pickle.load(fp)|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
          "Should match vulnerable code: #{code}"
      end
    end
    
    test "detects various pickle module usages" do
      pattern = UnsafePickle.pattern()
      
      vulnerable_code = [
        ~S|import pickle; data = pickle.loads(input)|,
        ~S|from pickle import loads; result = loads(data)|,
        ~S|import cPickle; obj = cPickle.loads(serialized)|,
        ~S|unpickled = pickle.Unpickler(file).load()|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
          "Should match vulnerable code: #{code}"
      end
    end
    
    test "ignores safe serialization methods" do
      pattern = UnsafePickle.pattern()
      
      safe_code = [
        ~S|data = json.loads(user_data)|,
        ~S|with open('data.json', 'r') as f: obj = json.load(f)|,
        ~S|result = yaml.safe_load(content)|,
        ~S|import msgpack; data = msgpack.loads(bytes_data)|,
        ~S|# pickle.loads is dangerous - use json instead|
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
          "Should NOT match safe code: #{code}"
      end
    end
  end
  
  describe "vulnerability metadata" do
    test "provides comprehensive metadata" do
      metadata = UnsafePickle.vulnerability_metadata()
      
      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert is_list(metadata.references)
      assert is_list(metadata.attack_vectors)
      assert is_list(metadata.real_world_impact)
      assert is_list(metadata.safe_alternatives)
      assert is_list(metadata.cve_examples)
      assert length(metadata.cve_examples) >= 3
    end
  end
  
  describe "AST enhancement" do
    test "returns correct AST enhancement structure" do
      enhancement = UnsafePickle.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.ast_rules.node_type == "Call"
      assert is_number(enhancement.min_confidence)
    end
    
    test "AST rules identify pickle usage" do
      enhancement = UnsafePickle.ast_enhancement()
      
      assert is_list(enhancement.ast_rules.function_names)
      assert "pickle.loads" in enhancement.ast_rules.function_names
      assert "pickle.load" in enhancement.ast_rules.function_names
    end
    
    test "context rules exclude test files" do
      enhancement = UnsafePickle.ast_enhancement()
      
      assert is_list(enhancement.context_rules.exclude_paths)
      assert ~r/test/ in enhancement.context_rules.exclude_paths
    end
    
    test "confidence scoring adjusts for context" do
      enhancement = UnsafePickle.ast_enhancement()
      adjustments = enhancement.confidence_rules.adjustments
      
      assert adjustments["user_controlled_input"] > 0
      assert adjustments["hardcoded_data"] < 0
      assert adjustments["test_code"] < 0
    end
  end
  
  describe "file applicability" do
    test "applies to Python files" do
      assert UnsafePickle.applies_to_file?("script.py", nil)
      assert UnsafePickle.applies_to_file?("module.pyw", nil)
      assert UnsafePickle.applies_to_file?("app.py", nil)
      
      refute UnsafePickle.applies_to_file?("script.js", nil)
      refute UnsafePickle.applies_to_file?("config.json", nil)
    end
  end
end