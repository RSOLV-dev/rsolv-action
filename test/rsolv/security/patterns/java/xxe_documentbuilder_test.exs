defmodule Rsolv.Security.Patterns.Java.XxeDocumentbuilderTest do
  use ExUnit.Case, async: true
  
  alias Rsolv.Security.Patterns.Java.XxeDocumentbuilder
  alias Rsolv.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = XxeDocumentbuilder.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "java-xxe-documentbuilder"
      assert pattern.name == "XXE via DocumentBuilder"
      assert pattern.severity == :high
      assert pattern.type == :xxe
      assert pattern.languages == ["java"]
      assert pattern.cwe_id == "CWE-611"
      assert pattern.owasp_category == "A05:2021"
      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 3
      assert Enum.all?(pattern.regex, &is_struct(&1, Regex))
    end
    
    test "includes comprehensive test cases" do
      pattern = XxeDocumentbuilder.pattern()
      
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
      assert is_list(pattern.test_cases.vulnerable)
      assert is_list(pattern.test_cases.safe)
      assert length(pattern.test_cases.vulnerable) >= 2
      assert length(pattern.test_cases.safe) >= 2
    end
    
    test "has appropriate recommendation" do
      pattern = XxeDocumentbuilder.pattern()
      
      assert String.contains?(String.downcase(pattern.recommendation), "secure") and
             String.contains?(String.downcase(pattern.recommendation), "processing")
      assert String.contains?(String.downcase(pattern.recommendation), "disable") or
             String.contains?(String.downcase(pattern.recommendation), "entity")
    end
  end
  
  describe "regex matching" do
    test "detects DocumentBuilderFactory without secure processing" do
      pattern = XxeDocumentbuilder.pattern()
      
      vulnerable_code = [
        "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance(); DocumentBuilder db = dbf.newDocumentBuilder();",
        "DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();",
        "DocumentBuilderFactory.newInstance().newDocumentBuilder();",
        "DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();",
        "factory.newDocumentBuilder().parse(inputStream);",
        "DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();\nDocumentBuilder dBuilder = dbFactory.newDocumentBuilder();\nDocument doc = dBuilder.parse(xmlFile);",
        "DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();\nDocument document = builder.parse(new File(\"test.xml\"));"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects insecure DocumentBuilder patterns" do
      pattern = XxeDocumentbuilder.pattern()
      
      vulnerable_code = [
        "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\nDocumentBuilder db = dbf.newDocumentBuilder();\nDocument doc = db.parse(xmlString);",
        "final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfinal DocumentBuilder builder = factory.newDocumentBuilder();",
        "DocumentBuilder parser = DocumentBuilderFactory.newInstance().newDocumentBuilder();",
        "DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocument doc = factory.newDocumentBuilder().parse(inputStream);",
        "DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(xmlFile);",
        "private DocumentBuilder getDocumentBuilder() {\n  return DocumentBuilderFactory.newInstance().newDocumentBuilder();\n}",
        "DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();\nreturn db.parse(new InputSource(new StringReader(xml)));"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects various DocumentBuilderFactory instantiation patterns" do
      pattern = XxeDocumentbuilder.pattern()
      
      vulnerable_code = [
        "DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();\ndbFactory.newDocumentBuilder();",
        "DocumentBuilderFactory factory;\nfactory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();",
        "var factory = DocumentBuilderFactory.newInstance();\nvar builder = factory.newDocumentBuilder();",
        "final var dbf = DocumentBuilderFactory.newInstance();\nfinal var db = dbf.newDocumentBuilder();",
        "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\nif (condition) {\n  DocumentBuilder db = dbf.newDocumentBuilder();\n}",
        "try {\n  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n  DocumentBuilder db = dbf.newDocumentBuilder();\n} catch (Exception e) {}",
        "DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();\nDocument document = builder.parse(inputStream);"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects DocumentBuilder usage without secure configuration" do
      pattern = XxeDocumentbuilder.pattern()
      
      vulnerable_code = [
        "DocumentBuilder documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();",
        "DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(xmlContent);",
        "DocumentBuilder db = factory.newDocumentBuilder();\nDocument doc = db.parse(xmlFile);",
        "DocumentBuilder builder = dbFactory.newDocumentBuilder();\nbuilder.parse(inputStream);",
        "factory.newDocumentBuilder().parse(new InputSource(reader));",
        "DocumentBuilder parser = DocumentBuilderFactory.newInstance().newDocumentBuilder();\nparser.setErrorHandler(errorHandler);",
        "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = dbf.newDocumentBuilder();\nbuilder.setEntityResolver(resolver);"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "does not match secure DocumentBuilder configurations" do
      pattern = XxeDocumentbuilder.pattern()
      
      safe_code = [
        "// DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();",
        "// DocumentBuilder db = dbf.newDocumentBuilder();", 
        "String comment = \"Use DocumentBuilderFactory.newInstance() carefully\";"
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should not match: #{code}"
      end
    end
    
    test "detects method chaining patterns" do
      pattern = XxeDocumentbuilder.pattern()
      
      vulnerable_code = [
        "Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(xmlFile);",
        "Node node = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(inputStream).getDocumentElement();",
        "DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(xmlString).normalize();",
        "return DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(source);",
        "Element root = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file).getDocumentElement();",
        "DocumentBuilderFactory.newInstance().newDocumentBuilder().setErrorHandler(handler);",
        "var result = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(inputSource);"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = XxeDocumentbuilder.vulnerability_metadata()
      
      assert String.contains?(String.downcase(metadata.description), "xxe") or
             String.contains?(String.downcase(metadata.description), "external entity")
      assert String.contains?(String.downcase(metadata.description), "documentbuilder")
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 4
      assert length(metadata.real_world_impact) >= 4
      assert length(metadata.cve_examples) >= 2
    end
    
    test "includes XXE-specific information" do
      metadata = XxeDocumentbuilder.vulnerability_metadata()
      
      assert String.contains?(metadata.description, "XXE") or String.contains?(metadata.description, "External Entity")
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "setFeature"))
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "SECURE_PROCESSING")) or
             Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "XMLConstants"))
    end
    
    test "includes proper security references" do
      metadata = XxeDocumentbuilder.vulnerability_metadata()
      
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
    
    test "includes OWASP Top 10 information" do
      metadata = XxeDocumentbuilder.vulnerability_metadata()
      
      assert Enum.any?(metadata.attack_vectors, fn vector -> 
        String.contains?(String.downcase(vector), "owasp") or
        String.contains?(String.downcase(vector), "top 10") or
        String.contains?(String.downcase(vector), "a05")
      end) or
      Enum.any?(metadata.references, fn ref ->
        String.contains?(String.downcase(ref.title), "owasp") and 
        String.contains?(String.downcase(ref.title), "a05")
      end)
    end
    
    test "includes CVE examples with proper structure" do
      metadata = XxeDocumentbuilder.vulnerability_metadata()
      
      for cve <- metadata.cve_examples do
        assert Map.has_key?(cve, :id)
        assert Map.has_key?(cve, :description)
        assert Map.has_key?(cve, :severity)
        assert Map.has_key?(cve, :cvss)
        assert is_number(cve.cvss)
        assert cve.cvss > 0
      end
    end
    
    test "includes DocumentBuilder-specific information" do
      metadata = XxeDocumentbuilder.vulnerability_metadata()
      
      assert Enum.any?(metadata.additional_context.secure_patterns, fn pattern ->
        String.contains?(String.downcase(pattern), "documentbuilderfactory") or
        String.contains?(String.downcase(pattern), "secure processing") or
        String.contains?(String.downcase(pattern), "setfeature")
      end)
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = XxeDocumentbuilder.ast_enhancement()
      
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.7
    end
    
    test "includes DocumentBuilder analysis" do
      enhancement = XxeDocumentbuilder.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "MethodInvocation"
      assert enhancement.ast_rules.xml_analysis.check_documentbuilder_usage
      assert enhancement.ast_rules.xml_analysis.documentbuilder_methods
      assert enhancement.ast_rules.xml_analysis.check_secure_processing
    end
    
    test "has factory detection rules" do
      enhancement = XxeDocumentbuilder.ast_enhancement()
      
      assert enhancement.ast_rules.factory_analysis.check_factory_instantiation
      assert enhancement.ast_rules.factory_analysis.documentbuilder_factory_methods
      assert enhancement.ast_rules.factory_analysis.check_feature_configuration
    end
    
    test "includes XML parsing analysis" do
      enhancement = XxeDocumentbuilder.ast_enhancement()
      
      assert enhancement.ast_rules.parsing_analysis.check_parse_methods
      assert enhancement.ast_rules.parsing_analysis.parse_methods
      assert enhancement.ast_rules.parsing_analysis.check_input_sources
    end
    
    test "includes context-based filtering" do
      enhancement = XxeDocumentbuilder.ast_enhancement()
      
      assert enhancement.context_rules.check_secure_configuration
      assert enhancement.context_rules.secure_features
      assert enhancement.context_rules.xxe_prevention_patterns
    end
    
    test "has proper confidence scoring" do
      enhancement = XxeDocumentbuilder.ast_enhancement()
      
      adjustments = enhancement.confidence_rules.adjustments
      assert Map.has_key?(adjustments, "has_secure_processing")
      assert Map.has_key?(adjustments, "has_external_entity_disabled")
      assert Map.has_key?(adjustments, "in_xml_processing_context")
      assert Map.has_key?(adjustments, "in_test_code")
    end
  end
end