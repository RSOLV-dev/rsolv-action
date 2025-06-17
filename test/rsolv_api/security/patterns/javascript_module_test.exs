defmodule RsolvApi.Security.Patterns.JavascriptModuleTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Javascript
  alias RsolvApi.Security.Pattern
  
  describe "updated Javascript module" do
    test "sql_injection_concat delegates to SqlInjectionConcat module" do
      pattern = Javascript.sql_injection_concat()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-sql-injection-concat"
      assert pattern.name == "SQL Injection via String Concatenation"
      assert pattern.description =~ "string concatenation"
    end
    
    test "sql_injection_interpolation delegates to SqlInjectionInterpolation module" do
      pattern = Javascript.sql_injection_interpolation()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-sql-injection-interpolation"
      assert pattern.name == "SQL Injection via String Interpolation"
      assert pattern.description =~ "Template literal"
    end
    
    test "xss_innerhtml delegates to XssInnerhtml module" do
      pattern = Javascript.xss_innerhtml()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-xss-innerhtml"
      assert pattern.name == "Cross-Site Scripting (XSS) via innerHTML"
      assert pattern.description =~ "innerHTML"
    end
    
    test "xss_document_write delegates to XssDocumentWrite module" do
      pattern = Javascript.xss_document_write()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-xss-document-write"
      assert pattern.name == "Cross-Site Scripting (XSS) via document.write"
      assert pattern.description =~ "document.write"
    end
    
    test "command_injection_exec delegates to CommandInjectionExec module" do
      pattern = Javascript.command_injection_exec()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-command-injection-exec"
      assert pattern.name == "Command Injection via exec"
      assert pattern.description =~ "exec"
    end
    
    test "all/0 includes patterns from new modules" do
      patterns = Javascript.all()
      pattern_ids = Enum.map(patterns, & &1.id)
      
      # Check migrated patterns are included
      assert "js-sql-injection-concat" in pattern_ids
      assert "js-sql-injection-interpolation" in pattern_ids
      assert "js-xss-innerhtml" in pattern_ids
      assert "js-xss-document-write" in pattern_ids
      assert "js-command-injection-exec" in pattern_ids
      
      # Check total count is 30
      assert length(patterns) == 30
    end
  end
end