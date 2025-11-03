defmodule Rsolv.AST.TestIntegratorRubyPythonTest do
  @moduledoc """
  TDD tests for Ruby (RSpec) and Python (pytest) AST integration.

  These tests verify that the TestIntegrator correctly:
  1. Parses Ruby RSpec files using the actual Ruby parser AST structure
  2. Finds RSpec describe/context blocks (block nodes with send children)
  3. Finds last it/specify/example blocks within describe
  4. Parses Python pytest files using the actual Python AST structure
  5. Finds pytest TestClass definitions (ClassDef nodes)
  6. Finds last test_* functions within classes

  RFC-060-AMENDMENT-001: Phase 1 - Ruby and Python parser integration

  NOTE: async: false is required because these tests share parser pool state
  via the "test-integrator" session in SessionManager. Running tests in parallel
  causes race conditions where one test's parser state affects another,
  leading to CI failures in Shard 1 even though tests pass locally.
  """
  use ExUnit.Case, async: false

  import Rsolv.AST.TestIntegratorHelpers

  alias Rsolv.AST.TestIntegrator

  describe "Ruby RSpec test integration" do
    test "integrates test into simple RSpec describe block" do
      target_content = """
      require 'rails_helper'

      RSpec.describe UsersController do
        it 'creates user' do
          expect(User.count).to eq(1)
        end
      end
      """

      test_suite =
        build_test_suite([
          red_test(
            "rejects SQL injection in search endpoint",
            "post '/search', params: { q: \"admin'; DROP TABLE users;--\" }\nexpect(response.status).to eq(400)",
            "admin'; DROP TABLE users;--"
          )
        ])

      integrate_and_assert_ast(target_content, test_suite, "ruby", "rspec",
        strategy: "after_last_it_block",
        contains: [
          "rejects SQL injection in search endpoint",
          "describe 'security'",
          "admin'; DROP TABLE users;--",
          "creates user"
        ]
      )
    end

    test "integrates test with multiple RED tests in RSpec" do
      target_content = """
      require 'rails_helper'

      RSpec.describe AuthController do
        it 'validates credentials' do
          expect(true).to be true
        end
      end
      """

      test_suite =
        build_test_suite([
          red_test(
            "prevents SQL injection in login",
            "result = login(\"' OR '1'='1\", 'pass')\nexpect(result).to be_nil",
            "' OR '1'='1"
          ),
          red_test(
            "prevents command injection",
            "expect { exec_command('ls; rm -rf /') }.to raise_error",
            "ls; rm -rf /"
          )
        ])

      integrate_and_assert_ast(target_content, test_suite, "ruby", "rspec",
        contains: ["prevents SQL injection in login", "prevents command injection"]
      )
    end

    test "handles RSpec context blocks" do
      target_content = """
      require 'rails_helper'

      RSpec.describe PaymentService do
        context 'when processing payment' do
          it 'charges card' do
            expect(charge_amount).to eq(100)
          end
        end
      end
      """

      test_suite =
        build_test_suite([
          red_test(
            "validates payment amount",
            "expect { process_payment(-50) }.to raise_error",
            "negative amount"
          )
        ])

      integrate_and_assert_ast(target_content, test_suite, "ruby", "rspec",
        contains: ["validates payment amount"]
      )
    end

    test "preserves indentation in Ruby code" do
      target_content = """
      require 'rails_helper'

      RSpec.describe FileService do
          it 'reads file' do
              data = read_file('test.txt')
              expect(data).not_to be_nil
          end
      end
      """

      test_suite = build_test_suite([path_traversal_ruby()])

      integrate_and_assert_ast(target_content, test_suite, "ruby", "rspec",
        contains: ["describe 'security'"]
      )
    end
  end

  describe "Python pytest test integration" do
    test "integrates test into simple pytest class" do
      target_content = """
      import pytest

      class TestUsers:
          def test_create_user(self):
              assert User.objects.count() == 1
      """

      test_suite = %{
        "redTests" => [
          %{
            "testName" => "rejects SQL injection in search",
            "testCode" =>
              "response = client.post('/search', {'q': \"admin'; DROP TABLE users;--\"})\nassert response.status_code == 400",
            "attackVector" => "admin'; DROP TABLE users;--"
          }
        ]
      }

      {:ok, integrated_code, insertion_point, method} =
        TestIntegrator.generate_integration(target_content, test_suite, "python", "pytest")

      assert method == "ast", "Should use AST method for Python pytest integration"
      assert insertion_point != nil, "Should find insertion point"
      assert insertion_point.strategy == "after_last_test_function"
      assert String.contains?(integrated_code, "test_rejects_sql_injection_in_search")

      assert String.contains?(integrated_code, "class TestUsers"),
             "Should integrate into existing class"

      assert String.contains?(integrated_code, "admin'; DROP TABLE users;--")

      assert String.contains?(integrated_code, "test_create_user"),
             "Should preserve original test"
    end

    test "integrates test with multiple RED tests in pytest" do
      target_content = """
      import pytest

      class TestAuth:
          def test_validates_credentials(self):
              assert True
      """

      test_suite = %{
        "redTests" => [
          %{
            "testName" => "prevents SQL injection in login",
            "testCode" => "result = login(\"' OR '1'='1\", 'pass')\nassert result is None",
            "attackVector" => "' OR '1'='1"
          },
          %{
            "testName" => "prevents command injection",
            "testCode" => "with pytest.raises(SecurityError):\n    exec_command('ls; rm -rf /')",
            "attackVector" => "ls; rm -rf /"
          }
        ]
      }

      {:ok, integrated_code, _insertion_point, method} =
        TestIntegrator.generate_integration(target_content, test_suite, "python", "pytest")

      assert method == "ast"
      assert String.contains?(integrated_code, "test_prevents_sql_injection_in_login")
      assert String.contains?(integrated_code, "test_prevents_command_injection")
    end

    test "handles module-level pytest functions" do
      target_content = """
      import pytest

      def test_something():
          assert True
      """

      test_suite = %{
        "redTests" => [
          %{
            "testName" => "validates input",
            "testCode" => "assert validate_input('test') is True",
            "attackVector" => "test"
          }
        ]
      }

      {:ok, integrated_code, _insertion_point, method} =
        TestIntegrator.generate_integration(target_content, test_suite, "python", "pytest")

      assert method == "ast"
      assert String.contains?(integrated_code, "test_validates_input")
    end

    test "preserves indentation in Python code" do
      target_content = """
      import pytest

      class TestFileService:
          def test_reads_file(self):
              data = read_file('test.txt')
              assert data is not None
      """

      test_suite = %{
        "redTests" => [
          %{
            "testName" => "prevents path traversal",
            "testCode" => "result = read_file('../../../etc/passwd')\nassert result is None",
            "attackVector" => "../../../etc/passwd"
          }
        ]
      }

      {:ok, integrated_code, _insertion_point, method} =
        TestIntegrator.generate_integration(target_content, test_suite, "python", "pytest")

      assert method == "ast"
      # Should integrate into existing class
      assert String.contains?(integrated_code, "class TestFileService")
      assert String.contains?(integrated_code, "test_prevents_path_traversal")
    end
  end

  describe "fallback behavior for Ruby and Python" do
    test "falls back to append when no describe block found in Ruby" do
      target_content = """
      # Empty Ruby file
      require 'rails_helper'
      """

      test_suite = %{
        "redTests" => [
          %{
            "testName" => "validates input",
            "testCode" => "expect(true).to be true",
            "attackVector" => "test"
          }
        ]
      }

      {:ok, integrated_code, insertion_point, method} =
        TestIntegrator.generate_integration(target_content, test_suite, "ruby", "rspec")

      assert method == "append"
      assert insertion_point == nil
      assert String.contains?(integrated_code, "validates input")
      assert String.contains?(integrated_code, "describe 'security'")
    end

    test "falls back to append when no test class found in Python" do
      target_content = """
      # Empty Python file
      import pytest
      """

      test_suite = %{
        "redTests" => [
          %{
            "testName" => "validates input",
            "testCode" => "assert True",
            "attackVector" => "test"
          }
        ]
      }

      {:ok, integrated_code, insertion_point, method} =
        TestIntegrator.generate_integration(target_content, test_suite, "python", "pytest")

      assert method == "append"
      assert insertion_point == nil
      assert String.contains?(integrated_code, "test_validates_input")
      assert String.contains?(integrated_code, "class TestSecurity")
    end

    test "falls back to append on Ruby parse error" do
      target_content = malformed_ruby()

      test_suite =
        build_test_suite([
          red_test("test security", "expect(true).to be true", "test")
        ])

      integrate_and_assert_fallback(target_content, test_suite, "ruby", "rspec", [
        "test security"
      ])
    end

    test "falls back to append on Python parse error" do
      target_content = malformed_python()

      test_suite =
        build_test_suite([
          red_test("test security", "assert True", "test")
        ])

      integrate_and_assert_fallback(target_content, test_suite, "python", "pytest", [
        "test_security"
      ])
    end
  end

  describe "edge cases for Ruby and Python" do
    test "handles empty test suite for Ruby" do
      target_content = """
      RSpec.describe Service do
        it 'works' do
          expect(1).to eq(1)
        end
      end
      """

      test_suite = %{"redTests" => []}

      {:ok, _integrated_code, _insertion_point, method} =
        TestIntegrator.generate_integration(target_content, test_suite, "ruby", "rspec")

      # Should still succeed (just won't add anything)
      assert method in ["ast", "append"]
    end

    test "handles empty test suite for Python" do
      target_content = """
      class TestService:
          def test_works(self):
              assert 1 == 1
      """

      test_suite = %{"redTests" => []}

      {:ok, _integrated_code, _insertion_point, method} =
        TestIntegrator.generate_integration(target_content, test_suite, "python", "pytest")

      # Should still succeed (just won't add anything)
      assert method in ["ast", "append"]
    end

    test "handles Ruby test with special characters in attack vector" do
      target_content = """
      RSpec.describe XSSController do
        it 'renders page' do
          expect(true).to be true
        end
      end
      """

      test_suite = %{
        "redTests" => [
          %{
            "testName" => "prevents XSS attack",
            "testCode" =>
              "result = render('<script>alert(\"XSS\")</script>')\nexpect(result).not_to include('<script>')",
            "attackVector" => "<script>alert(\"XSS\")</script>"
          }
        ]
      }

      {:ok, integrated_code, _insertion_point, _method} =
        TestIntegrator.generate_integration(target_content, test_suite, "ruby", "rspec")

      assert String.contains?(integrated_code, "prevents XSS attack")
      # Attack vector should be in comment
      assert String.contains?(integrated_code, "Attack vector:")
    end

    test "handles Python test with special characters in attack vector" do
      target_content = """
      class TestXSSController:
          def test_renders_page(self):
              assert True
      """

      test_suite = %{
        "redTests" => [
          %{
            "testName" => "prevents XSS attack",
            "testCode" =>
              "result = render('<script>alert(\"XSS\")</script>')\nassert '<script>' not in result",
            "attackVector" => "<script>alert(\"XSS\")</script>"
          }
        ]
      }

      {:ok, integrated_code, _insertion_point, _method} =
        TestIntegrator.generate_integration(target_content, test_suite, "python", "pytest")

      assert String.contains?(integrated_code, "test_prevents_xss_attack")
      # Attack vector should be in docstring
      assert String.contains?(integrated_code, "Attack vector:")
    end

    test "handles multiple existing tests in Ruby" do
      target_content = """
      RSpec.describe ComplexService do
        it 'test one' do
          expect(1).to eq(1)
        end

        it 'test two' do
          expect(2).to eq(2)
        end

        it 'test three' do
          expect(3).to eq(3)
        end
      end
      """

      test_suite = %{
        "redTests" => [
          %{
            "testName" => "security test",
            "testCode" => "expect(true).to be true",
            "attackVector" => "test"
          }
        ]
      }

      {:ok, integrated_code, insertion_point, method} =
        TestIntegrator.generate_integration(target_content, test_suite, "ruby", "rspec")

      assert method == "ast"
      assert insertion_point.strategy == "after_last_it_block"
      # Should insert after the last test
      assert String.contains?(integrated_code, "test three")
      assert String.contains?(integrated_code, "security test")
    end

    test "handles multiple existing tests in Python" do
      target_content = """
      class TestComplexService:
          def test_one(self):
              assert 1 == 1

          def test_two(self):
              assert 2 == 2

          def test_three(self):
              assert 3 == 3
      """

      test_suite = %{
        "redTests" => [
          %{
            "testName" => "security test",
            "testCode" => "assert True",
            "attackVector" => "test"
          }
        ]
      }

      {:ok, integrated_code, insertion_point, method} =
        TestIntegrator.generate_integration(target_content, test_suite, "python", "pytest")

      assert method == "ast"
      assert insertion_point.strategy == "after_last_test_function"
      # Should insert after the last test
      assert String.contains?(integrated_code, "test_three")
      assert String.contains?(integrated_code, "test_security_test")
    end
  end
end
