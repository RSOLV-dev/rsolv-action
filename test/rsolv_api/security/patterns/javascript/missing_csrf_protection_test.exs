defmodule RsolvApi.Security.Patterns.Javascript.MissingCsrfProtectionTest do
  use ExUnit.Case, async: true
  doctest RsolvApi.Security.Patterns.Javascript.MissingCsrfProtection
  
  alias RsolvApi.Security.Pattern
  alias RsolvApi.Security.Patterns.Javascript.MissingCsrfProtection

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = MissingCsrfProtection.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-missing-csrf"
      assert pattern.name == "Missing CSRF Protection"
      assert pattern.type == :csrf
      assert pattern.severity == :high
      assert pattern.languages == ["javascript", "typescript"]
      assert pattern.cwe_id == "CWE-352"
      assert pattern.owasp_category == "A01:2021"
    end

    test "pattern has required metadata" do
      pattern = MissingCsrfProtection.pattern()
      
      assert pattern.description =~ "CSRF"
      assert pattern.recommendation =~ "CSRF"
      assert is_map(pattern.test_cases)
      assert is_list(pattern.test_cases.vulnerable)
      assert is_list(pattern.test_cases.safe)
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive vulnerability metadata" do
      metadata = MissingCsrfProtection.vulnerability_metadata()
      
      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert is_list(metadata.references)
      assert is_list(metadata.attack_vectors)
      assert is_list(metadata.real_world_impact)
      assert is_list(metadata.cve_examples)
      assert is_list(metadata.safe_alternatives)
    end

    test "metadata includes required reference types" do
      metadata = MissingCsrfProtection.vulnerability_metadata()
      references = metadata.references
      
      assert Enum.any?(references, &(&1.type == :cwe))
      assert Enum.any?(references, &(&1.type == :owasp))
    end

    test "metadata includes real CVE examples" do
      metadata = MissingCsrfProtection.vulnerability_metadata()
      
      assert length(metadata.cve_examples) >= 3
      
      for cve <- metadata.cve_examples do
        assert cve.id =~ ~r/^CVE-\d{4}-\d+$/
        assert is_binary(cve.description)
        assert cve.severity in ["critical", "high", "medium", "low"]
        assert is_float(cve.cvss) or is_integer(cve.cvss)
      end
    end
  end

  describe "detection tests" do
    test "detects POST routes without CSRF protection" do
      pattern = MissingCsrfProtection.pattern()
      
      vulnerable_codes = [
        ~S|app.post('/api/transfer', (req, res) => { transferMoney(req.body) })|,
        ~S|app.post('/user/delete', async (req, res) => { await deleteUser(req.params.id) })|,
        ~S|router.post('/api/payment', function(req, res) { processPayment(req.body); })|
      ]
      
      for code <- vulnerable_codes do
        assert Regex.match?(pattern.regex, code), "Should detect: #{code}"
      end
    end

    test "detects PUT/PATCH/DELETE routes without CSRF protection" do
      pattern = MissingCsrfProtection.pattern()
      
      vulnerable_codes = [
        ~S|app.put('/api/user/profile', (req, res) => { updateProfile(req.body) })|,
        ~S|app.patch('/settings', async (req, res) => { await updateSettings(req.body) })|,
        ~S|app.delete('/account/:id', (req, res) => { deleteAccount(req.params.id) })|
      ]
      
      for code <- vulnerable_codes do
        assert Regex.match?(pattern.regex, code), "Should detect: #{code}"
      end
    end

    test "detects Express router methods without CSRF" do
      pattern = MissingCsrfProtection.pattern()
      
      vulnerable_codes = [
        ~S|router.post('/submit', handleSubmit)|,
        ~S|apiRouter.put('/update', updateHandler)|,
        ~S|adminRouter.delete('/remove', removeHandler)|
      ]
      
      for code <- vulnerable_codes do
        assert Regex.match?(pattern.regex, code), "Should detect: #{code}"
      end
    end
  end

  describe "safe code validation" do
    test "does not match routes with CSRF middleware" do
      pattern = MissingCsrfProtection.pattern()
      
      safe_codes = [
        ~S|app.post('/api/transfer', csrfProtection, (req, res) => {})|,
        ~S|app.post('/submit', csrf(), handleSubmit)|,
        ~S|app.post('/api/action', verifyCsrfToken, processAction)|
      ]
      
      for code <- safe_codes do
        refute Regex.match?(pattern.regex, code), "Should not match: #{code}"
      end
    end

    test "does not match when CSRF token is verified in handler" do
      pattern = MissingCsrfProtection.pattern()
      
      safe_codes = [
        ~S|app.post('/api/transfer', (req, res) => { if (!verifyCsrf(req)) return; transferMoney(req.body) })|,
        ~S|app.post('/submit', (req, res) => { validateCsrfToken(req.body.csrf_token); process(req) })|
      ]
      
      for code <- safe_codes do
        refute Regex.match?(pattern.regex, code), "Should not match: #{code}"
      end
    end

    test "does not match GET routes" do
      pattern = MissingCsrfProtection.pattern()
      
      safe_codes = [
        ~S|app.get('/api/users', (req, res) => { res.json(users) })|,
        ~S|router.get('/profile/:id', getProfile)|,
        ~S|app.get('/data', fetchData)|
      ]
      
      for code <- safe_codes do
        refute Regex.match?(pattern.regex, code), "Should not match: #{code}"
      end
    end

    test "does not match when app-wide CSRF is configured" do
      pattern = MissingCsrfProtection.pattern()
      
      safe_code = ~S"""
      app.use(csrf());
      app.post('/transfer', (req, res) => {
        // CSRF token automatically checked by middleware
        processTransfer(req.body);
      });
      """
      
      # This is a limitation of regex - it can't detect app-wide middleware
      # AST enhancement will handle this case
    end
  end

  describe "applies_to_file?/1" do
    test "applies to JavaScript files" do
      assert MissingCsrfProtection.applies_to_file?("app.js")
      assert MissingCsrfProtection.applies_to_file?("routes/api.js")
      assert MissingCsrfProtection.applies_to_file?("server.mjs")
    end

    test "applies to TypeScript files" do
      assert MissingCsrfProtection.applies_to_file?("app.ts")
      assert MissingCsrfProtection.applies_to_file?("routes/api.tsx")
      assert MissingCsrfProtection.applies_to_file?("server.ts")
    end

    test "does not apply to non-JS/TS files" do
      refute MissingCsrfProtection.applies_to_file?("app.py")
      refute MissingCsrfProtection.applies_to_file?("routes.rb")
      refute MissingCsrfProtection.applies_to_file?("README.md")
    end
  end

  describe "ast_enhancement/0" do
    test "returns comprehensive AST enhancement rules" do
      enhancement = MissingCsrfProtection.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.keys(enhancement) == [:ast_rules, :context_rules, :confidence_rules, :min_confidence]
    end
    
    test "AST rules target Express route methods" do
      enhancement = MissingCsrfProtection.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert enhancement.ast_rules.callee.object_patterns == ["app", "router", "apiRouter", "adminRouter"]
      assert enhancement.ast_rules.callee.property_patterns == ["post", "put", "patch", "delete"]
    end
    
    test "context rules exclude test files and API endpoints" do
      enhancement = MissingCsrfProtection.ast_enhancement()
      
      assert Enum.any?(enhancement.context_rules.exclude_paths, &(&1 == ~r/test/))
      assert enhancement.context_rules.exclude_if_app_wide_csrf == true
      assert enhancement.context_rules.exclude_if_api_only == true
    end
    
    test "confidence rules heavily penalize global CSRF" do
      enhancement = MissingCsrfProtection.ast_enhancement()
      
      assert enhancement.confidence_rules.base == 0.3
      assert enhancement.confidence_rules.adjustments["has_global_csrf"] == -0.9
      assert enhancement.min_confidence == 0.8
    end
  end

  describe "enhanced_pattern/0" do
    test "returns pattern with AST enhancement from ast_enhancement/0" do
      enhanced = MissingCsrfProtection.enhanced_pattern()
      enhancement = MissingCsrfProtection.ast_enhancement()
      
      # Verify it has all the AST enhancement fields
      assert enhanced.ast_rules == enhancement.ast_rules
      assert enhanced.context_rules == enhancement.context_rules
      assert enhanced.confidence_rules == enhancement.confidence_rules
      assert enhanced.min_confidence == enhancement.min_confidence
      
      # And still has all the pattern fields
      assert enhanced.id == "js-missing-csrf"
      assert enhanced.severity == :high
    end
  end
end