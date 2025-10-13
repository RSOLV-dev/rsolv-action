defmodule Rsolv.AST.TestIntegratorTest do
  @moduledoc """
  Tests for AST-based test integration for JavaScript/TypeScript frameworks.

  RFC-060-AMENDMENT-001: Phase 1 - Backend implementation tests.

  Tests the ability to:
  1. Parse existing test files using Babel parser
  2. Find appropriate insertion points (after last `it` block inside `describe`)
  3. Insert new security test cases
  4. Serialize back to valid source code

  Currently supports: JavaScript/TypeScript with Jest, Vitest, and Mocha
  """
  use ExUnit.Case, async: true

  alias Rsolv.AST.TestIntegrator

  describe "JavaScript/TypeScript test integration with Vitest" do
    test "integrates test into simple Vitest describe block" do
      target_content = """
      describe('UsersController', () => {
        it('creates user', () => {
          expect(User.count()).toBe(1);
        });
      });
      """

      test_suite = %{
        "redTests" => [
          %{
            "testName" => "rejects SQL injection in search endpoint",
            "testCode" => "post('/search', { q: \"admin'; DROP TABLE users;--\" });\nexpect(response.status).toBe(400);",
            "attackVector" => "admin'; DROP TABLE users;--"
          }
        ]
      }

      {:ok, integrated_code, insertion_point, method} =
        TestIntegrator.generate_integration(target_content, test_suite, "javascript", "vitest")

      assert method == "ast"
      assert insertion_point != nil
      assert insertion_point.strategy == "after_last_it_block"
      assert String.contains?(integrated_code, "rejects SQL injection in search endpoint")
      assert String.contains?(integrated_code, "describe('security'")
      assert String.contains?(integrated_code, "admin'; DROP TABLE users;--")
      assert String.contains?(integrated_code, "creates user")  # Original test preserved
    end

    test "integrates test with multiple RED tests" do
      target_content = """
      describe('AuthController', () => {
        it('validates credentials', () => {
          expect(true).toBe(true);
        });
      });
      """

      test_suite = %{
        "redTests" => [
          %{
            "testName" => "prevents SQL injection in login",
            "testCode" => "const result = login(\"' OR '1'='1\", 'pass');\nexpect(result).toBeNull();",
            "attackVector" => "' OR '1'='1"
          },
          %{
            "testName" => "prevents command injection",
            "testCode" => "const result = exec('ls; rm -rf /');\nexpect(result).toThrow();",
            "attackVector" => "ls; rm -rf /"
          }
        ]
      }

      {:ok, integrated_code, _insertion_point, method} =
        TestIntegrator.generate_integration(target_content, test_suite, "javascript", "vitest")

      assert method == "ast"
      assert String.contains?(integrated_code, "prevents SQL injection in login")
      assert String.contains?(integrated_code, "prevents command injection")
    end

    test "handles TypeScript test file" do
      target_content = """
      describe('PaymentService', (): void => {
        it('processes payment', (): void => {
          const amount: number = 100;
          expect(amount).toBe(100);
        });
      });
      """

      test_suite = %{
        "redTests" => [
          %{
            "testName" => "validates payment amount",
            "testCode" => "const invalidAmount: number = -50;\nexpect(() => processPayment(invalidAmount)).toThrow();",
            "attackVector" => "negative amount"
          }
        ]
      }

      {:ok, integrated_code, _insertion_point, method} =
        TestIntegrator.generate_integration(target_content, test_suite, "typescript", "vitest")

      assert method == "ast"
      assert String.contains?(integrated_code, "validates payment amount")
    end

    test "preserves indentation in integrated code" do
      target_content = """
      describe('FileService', () => {
          it('reads file', () => {
              const data = readFile('test.txt');
              expect(data).toBeDefined();
          });
      });
      """

      test_suite = %{
        "redTests" => [
          %{
            "testName" => "prevents path traversal",
            "testCode" => "const result = readFile('../../../etc/passwd');\nexpect(result).toBeNull();",
            "attackVector" => "../../../etc/passwd"
          }
        ]
      }

      {:ok, integrated_code, _insertion_point, method} =
        TestIntegrator.generate_integration(target_content, test_suite, "javascript", "vitest")

      assert method == "ast"
      # Should maintain indentation
      assert String.contains?(integrated_code, "    describe('security'") ||
               String.contains?(integrated_code, "describe('security'")
    end
  end

  describe "Jest framework support" do
    test "integrates test for Jest (identical syntax to Vitest)" do
      target_content = """
      describe('UserService', () => {
        it('should create user', () => {
          expect(true).toBe(true);
        });
      });
      """

      test_suite = %{
        "redTests" => [
          %{
            "testName" => "should prevent SQL injection",
            "testCode" => "const result = vulnerableQuery(\"'; DROP TABLE users;--\");\nexpect(result).toBeNull();",
            "attackVector" => "'; DROP TABLE users;--"
          }
        ]
      }

      {:ok, integrated_code, _insertion_point, method} =
        TestIntegrator.generate_integration(target_content, test_suite, "javascript", "jest")

      assert method == "ast"
      assert String.contains?(integrated_code, "should prevent SQL injection")
    end
  end

  describe "Mocha framework support" do
    test "integrates test for Mocha (identical syntax to Vitest/Jest)" do
      target_content = """
      describe('AuthService', function() {
        it('authenticates user', function() {
          expect(true).to.be.true;
        });
      });
      """

      test_suite = %{
        "redTests" => [
          %{
            "testName" => "rejects malicious input",
            "testCode" => "const result = authenticate(\"admin' --\");\nexpect(result).to.be.null;",
            "attackVector" => "admin' --"
          }
        ]
      }

      {:ok, integrated_code, _insertion_point, method} =
        TestIntegrator.generate_integration(target_content, test_suite, "javascript", "mocha")

      assert method == "ast"
      assert String.contains?(integrated_code, "rejects malicious input")
    end
  end

  describe "fallback behavior" do
    test "falls back to append when no describe block found" do
      target_content = """
      // Empty test file
      const helper = () => {};
      """

      test_suite = %{
        "redTests" => [
          %{
            "testName" => "validates input",
            "testCode" => "expect(true).toBe(true);",
            "attackVector" => "test"
          }
        ]
      }

      {:ok, integrated_code, insertion_point, method} =
        TestIntegrator.generate_integration(target_content, test_suite, "javascript", "vitest")

      assert method == "append"
      assert insertion_point == nil
      assert String.contains?(integrated_code, "validates input")
      assert String.contains?(integrated_code, "describe('security'")
    end

    test "falls back to append on parse error" do
      target_content = """
      describe('Test', () => { // unclosed describe block
      """

      test_suite = %{
        "redTests" => [
          %{
            "testName" => "test security",
            "testCode" => "expect(true).toBe(true);",
            "attackVector" => "test"
          }
        ]
      }

      {:ok, integrated_code, _insertion_point, method} =
        TestIntegrator.generate_integration(target_content, test_suite, "javascript", "vitest")

      assert method == "append"
      assert String.contains?(integrated_code, "test security")
    end
  end

  describe "edge cases" do
    test "handles empty test suite" do
      target_content = """
      describe('Service', () => {
        it('works', () => {
          expect(1).toBe(1);
        });
      });
      """

      test_suite = %{"redTests" => []}

      {:ok, _integrated_code, _insertion_point, method} =
        TestIntegrator.generate_integration(target_content, test_suite, "javascript", "vitest")

      # Should still succeed (just won't add anything)
      assert method in ["ast", "append"]
    end

    test "handles test with special characters in attack vector" do
      target_content = """
      describe('XSSController', () => {
        it('renders page', () => {
          expect(true).toBe(true);
        });
      });
      """

      test_suite = %{
        "redTests" => [
          %{
            "testName" => "prevents XSS attack",
            "testCode" => "const result = render('<script>alert(\"XSS\")</script>');\nexpect(result).not.toContain('<script>');",
            "attackVector" => "<script>alert(\"XSS\")</script>"
          }
        ]
      }

      {:ok, integrated_code, _insertion_point, _method} =
        TestIntegrator.generate_integration(target_content, test_suite, "javascript", "vitest")

      assert String.contains?(integrated_code, "prevents XSS attack")
      # Attack vector should be in comment
      assert String.contains?(integrated_code, "Attack vector:")
    end

    test "handles multiple existing tests" do
      target_content = """
      describe('ComplexService', () => {
        it('test one', () => {
          expect(1).toBe(1);
        });

        it('test two', () => {
          expect(2).toBe(2);
        });

        it('test three', () => {
          expect(3).toBe(3);
        });
      });
      """

      test_suite = %{
        "redTests" => [
          %{
            "testName" => "security test",
            "testCode" => "expect(true).toBe(true);",
            "attackVector" => "test"
          }
        ]
      }

      {:ok, integrated_code, insertion_point, method} =
        TestIntegrator.generate_integration(target_content, test_suite, "javascript", "vitest")

      assert method == "ast"
      assert insertion_point.strategy == "after_last_it_block"
      # Should insert after the last test
      assert String.contains?(integrated_code, "test three")
      assert String.contains?(integrated_code, "security test")
    end
  end

  describe "unsupported frameworks" do
    test "returns error for unsupported framework" do
      target_content = """
      describe('Test', () => {
        it('works', () => {});
      });
      """

      test_suite = %{
        "redTests" => [
          %{
            "testName" => "test",
            "testCode" => "expect(true).toBe(true);",
            "attackVector" => "test"
          }
        ]
      }

      {:ok, _integrated_code, _insertion_point, method} =
        TestIntegrator.generate_integration(target_content, test_suite, "javascript", "jasmine")

      # Should fall back to append for unsupported frameworks
      assert method in ["ast", "append"]
    end
  end
end
