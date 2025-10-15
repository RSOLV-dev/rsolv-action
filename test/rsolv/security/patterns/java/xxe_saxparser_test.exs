defmodule Rsolv.Security.Patterns.Java.XxeSaxparserTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Java.XxeSaxparser
  alias Rsolv.Security.Pattern

  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = XxeSaxparser.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "java-xxe-saxparser"
      assert pattern.name == "XXE via SAXParser"
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
      pattern = XxeSaxparser.pattern()

      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
      assert is_list(pattern.test_cases.vulnerable)
      assert is_list(pattern.test_cases.safe)
      assert length(pattern.test_cases.vulnerable) >= 2
      assert length(pattern.test_cases.safe) >= 2
    end

    test "has appropriate recommendation" do
      pattern = XxeSaxparser.pattern()

      assert String.contains?(String.downcase(pattern.recommendation), "secure") and
               String.contains?(String.downcase(pattern.recommendation), "processing")

      assert String.contains?(String.downcase(pattern.recommendation), "disable") or
               String.contains?(String.downcase(pattern.recommendation), "entity")
    end
  end

  describe "regex matching" do
    test "detects SAXParserFactory without secure processing" do
      pattern = XxeSaxparser.pattern()

      vulnerable_code = [
        "SAXParserFactory spf = SAXParserFactory.newInstance(); SAXParser parser = spf.newSAXParser();",
        "SAXParserFactory factory = SAXParserFactory.newInstance();\nSAXParser parser = factory.newSAXParser();",
        "SAXParserFactory.newInstance().newSAXParser();",
        "SAXParser parser = SAXParserFactory.newInstance().newSAXParser();",
        "factory.newSAXParser().parse(inputStream, handler);",
        "SAXParserFactory spFactory = SAXParserFactory.newInstance();\nSAXParser saxParser = spFactory.newSAXParser();\nsaxParser.parse(xmlFile, handler);",
        "SAXParser parser = SAXParserFactory.newInstance().newSAXParser();\nparser.parse(new File(\"test.xml\"), defaultHandler);"
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end

    test "detects insecure SAXParser instantiation patterns" do
      pattern = XxeSaxparser.pattern()

      vulnerable_code = [
        "SAXParserFactory spf = SAXParserFactory.newInstance();\nSAXParser sp = spf.newSAXParser();\nsp.parse(xmlString, handler);",
        "final SAXParserFactory factory = SAXParserFactory.newInstance();\nfinal SAXParser parser = factory.newSAXParser();",
        "SAXParser saxParser = SAXParserFactory.newInstance().newSAXParser();",
        "SAXParserFactory factory = SAXParserFactory.newInstance();\nSAXParser parser = factory.newSAXParser();\nparser.parse(inputStream, saxHandler);",
        "SAXParserFactory.newInstance().newSAXParser().parse(xmlFile, handler);",
        "private SAXParser getSAXParser() {\n  return SAXParserFactory.newInstance().newSAXParser();\n}",
        "SAXParser sp = SAXParserFactory.newInstance().newSAXParser();\nreturn sp.parse(new InputSource(new StringReader(xml)), handler);"
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end

    test "detects various SAXParserFactory instantiation patterns" do
      pattern = XxeSaxparser.pattern()

      vulnerable_code = [
        "SAXParserFactory spFactory = SAXParserFactory.newInstance();\nspFactory.newSAXParser();",
        "SAXParserFactory factory;\nfactory = SAXParserFactory.newInstance();\nSAXParser parser = factory.newSAXParser();",
        "var factory = SAXParserFactory.newInstance();\nvar parser = factory.newSAXParser();",
        "final var spf = SAXParserFactory.newInstance();\nfinal var sp = spf.newSAXParser();",
        "SAXParserFactory spf = SAXParserFactory.newInstance();\nif (condition) {\n  SAXParser sp = spf.newSAXParser();\n}",
        "try {\n  SAXParserFactory spf = SAXParserFactory.newInstance();\n  SAXParser sp = spf.newSAXParser();\n} catch (Exception e) {}",
        "SAXParserFactory factory = SAXParserFactory.newInstance();\nSAXParser parser = factory.newSAXParser();\nparser.parse(inputStream, defaultHandler);"
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end

    test "detects SAXParser usage without secure configuration" do
      pattern = XxeSaxparser.pattern()

      vulnerable_code = [
        "SAXParser saxParser = SAXParserFactory.newInstance().newSAXParser();",
        "SAXParserFactory.newInstance().newSAXParser().parse(xmlContent, handler);",
        "SAXParser sp = factory.newSAXParser();\nsp.parse(xmlFile, saxHandler);",
        "SAXParser parser = spFactory.newSAXParser();\nparser.parse(inputStream, defaultHandler);",
        "factory.newSAXParser().parse(new InputSource(reader), handler);",
        "SAXParser parser = SAXParserFactory.newInstance().newSAXParser();\nparser.setProperty(property, value);",
        "SAXParserFactory spf = SAXParserFactory.newInstance();\nSAXParser parser = spf.newSAXParser();\nXMLReader xmlReader = parser.getXMLReader();"
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end

    test "does not match secure SAXParser configurations" do
      pattern = XxeSaxparser.pattern()

      safe_code = [
        "// SAXParserFactory spf = SAXParserFactory.newInstance();",
        "// SAXParser sp = spf.newSAXParser();",
        "String comment = \"Use SAXParserFactory.newInstance() carefully\";"
      ]

      for code <- safe_code do
        refute Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should not match: #{code}"
      end
    end

    test "detects method chaining patterns" do
      pattern = XxeSaxparser.pattern()

      vulnerable_code = [
        "SAXParserFactory.newInstance().newSAXParser().parse(xmlFile, handler);",
        "Node node = SAXParserFactory.newInstance().newSAXParser().getXMLReader();",
        "SAXParserFactory.newInstance().newSAXParser().setProperty(property, value);",
        "return SAXParserFactory.newInstance().newSAXParser();",
        "XMLReader reader = SAXParserFactory.newInstance().newSAXParser().getXMLReader();",
        "SAXParserFactory.newInstance().newSAXParser().parse(inputSource, saxHandler);",
        "var result = SAXParserFactory.newInstance().newSAXParser().parse(inputStream, handler);"
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = XxeSaxparser.vulnerability_metadata()

      assert String.contains?(String.downcase(metadata.description), "xxe") or
               String.contains?(String.downcase(metadata.description), "external entity")

      assert String.contains?(String.downcase(metadata.description), "saxparser")
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 4
      assert length(metadata.real_world_impact) >= 4
      assert length(metadata.cve_examples) >= 2
    end

    test "includes XXE-specific information" do
      metadata = XxeSaxparser.vulnerability_metadata()

      assert String.contains?(metadata.description, "XXE") or
               String.contains?(metadata.description, "External Entity")

      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "setFeature"))

      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "SECURE_PROCESSING")) or
               Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "XMLConstants"))
    end

    test "includes proper security references" do
      metadata = XxeSaxparser.vulnerability_metadata()

      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end

    test "includes OWASP Top 10 information" do
      metadata = XxeSaxparser.vulnerability_metadata()

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
      metadata = XxeSaxparser.vulnerability_metadata()

      for cve <- metadata.cve_examples do
        assert Map.has_key?(cve, :id)
        assert Map.has_key?(cve, :description)
        assert Map.has_key?(cve, :severity)
        assert Map.has_key?(cve, :cvss)
        assert is_number(cve.cvss)
        assert cve.cvss > 0
      end
    end

    test "includes SAXParser-specific information" do
      metadata = XxeSaxparser.vulnerability_metadata()

      assert Enum.any?(metadata.additional_context.secure_patterns, fn pattern ->
               String.contains?(String.downcase(pattern), "saxparserfactory") or
                 String.contains?(String.downcase(pattern), "secure processing") or
                 String.contains?(String.downcase(pattern), "setfeature")
             end)
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = XxeSaxparser.ast_enhancement()

      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)

      assert enhancement.min_confidence >= 0.7
    end

    test "includes SAXParser analysis" do
      enhancement = XxeSaxparser.ast_enhancement()

      assert enhancement.ast_rules.node_type == "MethodInvocation"
      assert enhancement.ast_rules.xml_analysis.check_saxparser_usage
      assert enhancement.ast_rules.xml_analysis.saxparser_methods
      assert enhancement.ast_rules.xml_analysis.check_secure_processing
    end

    test "has factory detection rules" do
      enhancement = XxeSaxparser.ast_enhancement()

      assert enhancement.ast_rules.factory_analysis.check_factory_instantiation
      assert enhancement.ast_rules.factory_analysis.saxparser_factory_methods
      assert enhancement.ast_rules.factory_analysis.check_feature_configuration
    end

    test "includes XML parsing analysis" do
      enhancement = XxeSaxparser.ast_enhancement()

      assert enhancement.ast_rules.parsing_analysis.check_parse_methods
      assert enhancement.ast_rules.parsing_analysis.parse_methods
      assert enhancement.ast_rules.parsing_analysis.check_input_sources
    end

    test "includes XMLReader analysis" do
      enhancement = XxeSaxparser.ast_enhancement()

      assert enhancement.ast_rules.xmlreader_analysis.check_xmlreader_usage
      assert enhancement.ast_rules.xmlreader_analysis.xmlreader_methods
      assert enhancement.ast_rules.xmlreader_analysis.check_xmlreader_features
    end

    test "includes context-based filtering" do
      enhancement = XxeSaxparser.ast_enhancement()

      assert enhancement.context_rules.check_secure_configuration
      assert enhancement.context_rules.secure_features
      assert enhancement.context_rules.xxe_prevention_patterns
    end

    test "has proper confidence scoring" do
      enhancement = XxeSaxparser.ast_enhancement()

      adjustments = enhancement.confidence_rules.adjustments
      assert Map.has_key?(adjustments, "has_secure_processing")
      assert Map.has_key?(adjustments, "has_external_entity_disabled")
      assert Map.has_key?(adjustments, "in_xml_processing_context")
      assert Map.has_key?(adjustments, "in_test_code")
    end
  end
end
