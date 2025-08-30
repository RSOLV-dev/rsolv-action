defmodule Rsolv.AST.WeakCryptoPatternTest do
  use ExUnit.Case, async: false
  
  alias Rsolv.AST.{SessionManager, AnalysisService}
  
  setup do
    {:ok, session} = SessionManager.create_session("test")
    # Session cleanup is handled automatically by the manager
    {:ok, session: session}
  end
  
  describe "weak crypto pattern matching" do
    test "detects crypto.createHash('md5') calls", %{session: _session} do
      code = """
      const crypto = require('crypto');
      const hash = crypto.createHash('md5');
      """
      
      file = %{
        path: "test.js",
        language: "javascript", 
        content: code
      }
      
      {:ok, findings} = AnalysisService.analyze_file(file, %{"includeSecurityPatterns" => true})
      
      # Should find MD5 usage
      assert length(findings) > 0
      assert Enum.any?(findings, fn f -> f.type == "js-weak-crypto-md5" end)
    end
    
    test "does NOT detect console.log as weak crypto", %{session: _session} do
      code = """
      const message = "User selected option: SELECT * FROM menu";
      console.log(message + userChoice);
      """
      
      file = %{
        path: "test.js",
        language: "javascript",
        content: code
      }
      
      {:ok, findings} = AnalysisService.analyze_file(file, %{"includeSecurityPatterns" => true})
      
      # Should NOT find weak crypto in console.log
      refute Enum.any?(findings, fn f -> 
        f.type in ["js-weak-crypto-md5", "js-weak-crypto-sha1"]
      end)
    end
    
    test "detects crypto.createHash('sha1') calls", %{session: _session} do
      code = """
      const crypto = require('crypto');
      const hash = crypto.createHash('sha1');
      """
      
      file = %{
        path: "test.js",
        language: "javascript",
        content: code
      }
      
      {:ok, findings} = AnalysisService.analyze_file(file, %{"includeSecurityPatterns" => true})
      
      # Should find SHA1 usage
      assert length(findings) > 0
      assert Enum.any?(findings, fn f -> f.type == "js-weak-crypto-sha1" end)
    end
    
    test "does NOT detect other crypto methods as weak", %{session: _session} do
      code = """
      const crypto = require('crypto');
      const hash = crypto.createHash('sha256');  // Strong algorithm
      const random = crypto.randomBytes(32);     // Not createHash
      """
      
      file = %{
        path: "test.js",
        language: "javascript",
        content: code
      }
      
      {:ok, findings} = AnalysisService.analyze_file(file, %{"includeSecurityPatterns" => true})
      
      # Should NOT find weak crypto for SHA256 or randomBytes
      refute Enum.any?(findings, fn f -> 
        f.type in ["js-weak-crypto-md5", "js-weak-crypto-sha1"]
      end)
    end
  end
end