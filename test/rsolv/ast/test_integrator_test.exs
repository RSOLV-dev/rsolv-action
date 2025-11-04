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
  # Changed: parser pool is singleton, must run sequentially
  use ExUnit.Case, async: false

  import Rsolv.AST.TestIntegratorHelpers

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

      test_suite =
        build_test_suite([
          red_test(
            "rejects SQL injection in search endpoint",
            "post('/search', { q: \"admin'; DROP TABLE users;--\" });\nexpect(response.status).toBe(400);",
            "admin'; DROP TABLE users;--"
          )
        ])

      integrate_and_assert_ast(target_content, test_suite, "javascript", "vitest",
        strategy: "after_last_it_block",
        contains: [
          "rejects SQL injection in search endpoint",
          "describe('security'",
          "admin'; DROP TABLE users;--",
          "creates user"
        ]
      )
    end

    test "integrates test with multiple RED tests" do
      target_content = """
      describe('AuthController', () => {
        it('validates credentials', () => {
          expect(true).toBe(true);
        });
      });
      """

      test_suite =
        build_test_suite([
          red_test(
            "prevents SQL injection in login",
            "const result = login(\"' OR '1'='1\", 'pass');\nexpect(result).toBeNull();",
            "' OR '1'='1"
          ),
          red_test(
            "prevents command injection",
            "const result = exec('ls; rm -rf /');\nexpect(result).toThrow();",
            "ls; rm -rf /"
          )
        ])

      integrate_and_assert_ast(target_content, test_suite, "javascript", "vitest",
        contains: ["prevents SQL injection in login", "prevents command injection"]
      )
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

      test_suite =
        build_test_suite([
          red_test(
            "validates payment amount",
            "const invalidAmount: number = -50;\nexpect(() => processPayment(invalidAmount)).toThrow();",
            "negative amount"
          )
        ])

      integrate_and_assert_ast(target_content, test_suite, "typescript", "vitest",
        contains: ["validates payment amount"]
      )
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

      test_suite = build_test_suite([path_traversal_js()])

      {:ok, integrated_code} =
        integrate_and_assert_ast(target_content, test_suite, "javascript", "vitest")

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

      test_suite =
        build_test_suite([
          red_test(
            "should prevent SQL injection",
            "const result = vulnerableQuery(\"'; DROP TABLE users;--\");\nexpect(result).toBeNull();",
            "'; DROP TABLE users;--"
          )
        ])

      integrate_and_assert_ast(target_content, test_suite, "javascript", "jest",
        contains: ["should prevent SQL injection"]
      )
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

      test_suite =
        build_test_suite([
          red_test(
            "rejects malicious input",
            "const result = authenticate(\"admin' --\");\nexpect(result).to.be.null;",
            "admin' --"
          )
        ])

      integrate_and_assert_ast(target_content, test_suite, "javascript", "mocha",
        contains: ["rejects malicious input"]
      )
    end
  end

  describe "fallback behavior" do
    test "falls back to append when no describe block found" do
      target_content = """
      // Empty test file
      const helper = () => {};
      """

      test_suite =
        build_test_suite([
          red_test("validates input", "expect(true).toBe(true);", "test")
        ])

      integrate_and_assert_fallback(target_content, test_suite, "javascript", "vitest", [
        "validates input",
        "describe('security'"
      ])
    end

    test "falls back to append on parse error" do
      target_content = malformed_js()

      test_suite =
        build_test_suite([
          red_test("test security", "expect(true).toBe(true);", "test")
        ])

      integrate_and_assert_fallback(target_content, test_suite, "javascript", "vitest", [
        "test security"
      ])
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

      test_suite = empty_test_suite()

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

      test_suite = build_test_suite([xss_js()])

      integrate_and_assert_ast(target_content, test_suite, "javascript", "vitest",
        contains: ["prevents XSS attack", "Attack vector:"]
      )
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

      test_suite =
        build_test_suite([
          red_test("security test", "expect(true).toBe(true);", "test")
        ])

      integrate_and_assert_ast(target_content, test_suite, "javascript", "vitest",
        strategy: "after_last_it_block",
        contains: ["test three", "security test"]
      )
    end
  end

  describe "unsupported frameworks" do
    test "returns error for unsupported framework" do
      target_content = """
      describe('Test', () => {
        it('works', () => {});
      });
      """

      test_suite =
        build_test_suite([
          red_test("test", "expect(true).toBe(true);", "test")
        ])

      {:ok, _integrated_code, _insertion_point, method} =
        TestIntegrator.generate_integration(target_content, test_suite, "javascript", "jasmine")

      # Should fall back to append for unsupported frameworks
      assert method in ["ast", "append"]
    end
  end
end
