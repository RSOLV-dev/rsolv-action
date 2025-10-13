defmodule Rsolv.AST.TestIntegratorTest do
  @moduledoc """
  Tests for AST-based test integration across JavaScript/TypeScript, Ruby, and Python.

  RFC-060-AMENDMENT-001: Phase 0 - RED tests written before implementation.

  Tests the ability to:
  1. Parse existing test files
  2. Find appropriate insertion points (describe/context blocks, test classes)
  3. Insert new test cases
  4. Serialize back to valid source code
  """
  use ExUnit.Case, async: true

  alias Rsolv.AST.TestIntegrator

  # JavaScript/TypeScript Tests (5 tests)
  describe "JavaScript/TypeScript integration" do
    test "parses JavaScript test file and finds describe block" do
      test_code = """
      describe('UserService', () => {
        it('should create user', () => {
          expect(true).toBe(true);
        });
      });
      """

      {:ok, ast} = TestIntegrator.parse(test_code, :javascript)
      insertion_point = TestIntegrator.find_insertion_point(ast, "UserService")

      assert insertion_point != nil
      assert insertion_point.type == :describe_block
      assert insertion_point.name == "UserService"
    end

    test "inserts test into JavaScript describe block" do
      test_code = """
      describe('AuthController', () => {
        it('validates credentials', () => {
          expect(true).toBe(true);
        });
      });
      """

      new_test = """
        it('should prevent SQL injection in login', () => {
          const result = vulnerableLogin("' OR '1'='1");
          expect(result).toBeNull();
        });
      """

      {:ok, updated_code} = TestIntegrator.insert_test(test_code, new_test, :javascript)

      assert String.contains?(updated_code, "should prevent SQL injection in login")
      assert String.contains?(updated_code, "validates credentials")
      # Verify it's still valid JavaScript
      assert {:ok, _ast} = TestIntegrator.parse(updated_code, :javascript)
    end

    test "handles TypeScript test file with type annotations" do
      test_code = """
      describe('PaymentService', (): void => {
        it('processes payment', (): void => {
          const amount: number = 100;
          expect(amount).toBe(100);
        });
      });
      """

      new_test = """
        it('validates payment amount', (): void => {
          const invalidAmount: number = -50;
          expect(() => processPayment(invalidAmount)).toThrow();
        });
      """

      {:ok, updated_code} = TestIntegrator.insert_test(test_code, new_test, :typescript)

      assert String.contains?(updated_code, "validates payment amount")
      assert String.contains?(updated_code, "number")
    end

    test "returns error when no insertion point found in JavaScript" do
      test_code = """
      // Empty test file
      const helper = () => {};
      """

      new_test = """
        it('should validate input', () => {
          expect(true).toBe(true);
        });
      """

      result = TestIntegrator.insert_test(test_code, new_test, :javascript)

      assert {:error, :no_insertion_point} = result
    end

    test "preserves formatting and indentation in JavaScript" do
      test_code = """
      describe('FileService', () => {
          it('reads file', () => {
              const data = readFile('test.txt');
              expect(data).toBeDefined();
          });
      });
      """

      new_test = """
          it('prevents path traversal', () => {
              const result = readFile('../../../etc/passwd');
              expect(result).toBeNull();
          });
      """

      {:ok, updated_code} = TestIntegrator.insert_test(test_code, new_test, :javascript)

      # Should maintain 4-space indentation
      assert String.contains?(updated_code, "    it('prevents path traversal'")
    end
  end

  # Ruby Tests (5 tests)
  describe "Ruby RSpec integration" do
    test "parses Ruby test file and finds RSpec describe block" do
      test_code = """
      RSpec.describe UserService do
        it 'creates a user' do
          expect(true).to be true
        end
      end
      """

      {:ok, ast} = TestIntegrator.parse(test_code, :ruby)
      insertion_point = TestIntegrator.find_insertion_point(ast, "UserService")

      assert insertion_point != nil
      assert insertion_point.type == :rspec_describe
      assert insertion_point.name == "UserService"
    end

    test "inserts test into Ruby RSpec describe block" do
      test_code = """
      RSpec.describe AuthController do
        it 'authenticates valid user' do
          expect(authenticate('user')).to be_truthy
        end
      end
      """

      new_test = """
        it 'prevents SQL injection in authentication' do
          result = authenticate("admin' OR '1'='1")
          expect(result).to be_nil
        end
      """

      {:ok, updated_code} = TestIntegrator.insert_test(test_code, new_test, :ruby)

      assert String.contains?(updated_code, "prevents SQL injection")
      assert String.contains?(updated_code, "authenticates valid user")
      # Verify it's still valid Ruby
      assert {:ok, _ast} = TestIntegrator.parse(updated_code, :ruby)
    end

    test "handles Ruby context blocks" do
      test_code = """
      RSpec.describe PaymentProcessor do
        context 'with valid payment' do
          it 'processes successfully' do
            expect(true).to be true
          end
        end
      end
      """

      new_test = """
          it 'validates amount is positive' do
            expect { process_payment(-100) }.to raise_error(ArgumentError)
          end
      """

      {:ok, updated_code} = TestIntegrator.insert_test(test_code, new_test, :ruby)

      assert String.contains?(updated_code, "validates amount is positive")
    end

    test "returns error when no RSpec block found in Ruby" do
      test_code = """
      # Just a helper module
      module TestHelper
        def setup_test
        end
      end
      """

      new_test = """
        it 'validates input' do
          expect(true).to be true
        end
      """

      result = TestIntegrator.insert_test(test_code, new_test, :ruby)

      assert {:error, :no_insertion_point} = result
    end

    test "preserves Ruby formatting with 2-space indentation" do
      test_code = """
      RSpec.describe FileReader do
        it 'reads file contents' do
          content = read_file('test.txt')
          expect(content).not_to be_empty
        end
      end
      """

      new_test = """
        it 'prevents directory traversal' do
          expect { read_file('../../secret.txt') }.to raise_error(SecurityError)
        end
      """

      {:ok, updated_code} = TestIntegrator.insert_test(test_code, new_test, :ruby)

      # Should maintain 2-space indentation (Ruby convention)
      assert String.contains?(updated_code, "  it 'prevents directory traversal'")
    end
  end

  # Python Tests (5 tests)
  describe "Python pytest/unittest integration" do
    test "parses Python test file and finds test class" do
      test_code = """
      import pytest

      class TestUserService:
          def test_create_user(self):
              assert True
      """

      {:ok, ast} = TestIntegrator.parse(test_code, :python)
      insertion_point = TestIntegrator.find_insertion_point(ast, "TestUserService")

      assert insertion_point != nil
      assert insertion_point.type == :test_class
      assert insertion_point.name == "TestUserService"
    end

    test "inserts test into Python test class" do
      test_code = """
      import unittest

      class TestAuthController(unittest.TestCase):
          def test_valid_login(self):
              self.assertTrue(login('user', 'pass'))
      """

      new_test = """
          def test_sql_injection_prevention(self):
              result = login("admin' OR '1'='1", "password")
              self.assertIsNone(result)
      """

      {:ok, updated_code} = TestIntegrator.insert_test(test_code, new_test, :python)

      assert String.contains?(updated_code, "test_sql_injection_prevention")
      assert String.contains?(updated_code, "test_valid_login")
      # Verify it's still valid Python
      assert {:ok, _ast} = TestIntegrator.parse(updated_code, :python)
    end

    test "handles pytest-style function-based tests" do
      test_code = """
      import pytest

      def test_payment_processing():
          assert process_payment(100) == True
      """

      new_test = """
      def test_payment_validation():
          with pytest.raises(ValueError):
              process_payment(-50)
      """

      {:ok, updated_code} = TestIntegrator.insert_test(test_code, new_test, :python)

      assert String.contains?(updated_code, "test_payment_validation")
      assert String.contains?(updated_code, "test_payment_processing")
    end

    test "returns error when no test class or function found in Python" do
      test_code = """
      # Just a helper module
      def helper_function():
          return True
      """

      new_test = """
          def test_validation(self):
              assert True
      """

      result = TestIntegrator.insert_test(test_code, new_test, :python)

      assert {:error, :no_insertion_point} = result
    end

    test "preserves Python formatting with 4-space indentation" do
      test_code = """
      import pytest

      class TestFileReader:
          def test_read_file(self):
              content = read_file('test.txt')
              assert content is not None
      """

      new_test = """
          def test_path_traversal_prevention(self):
              with pytest.raises(SecurityError):
                  read_file('../../etc/passwd')
      """

      {:ok, updated_code} = TestIntegrator.insert_test(test_code, new_test, :python)

      # Should maintain 4-space indentation (PEP 8)
      assert String.contains?(updated_code, "    def test_path_traversal_prevention")
      assert String.contains?(updated_code, "        with pytest.raises")
    end
  end

  # Edge Cases (cross-language)
  describe "edge cases and error handling" do
    test "handles empty test file gracefully" do
      test_code = ""
      new_test = "it('test', () => {});"

      result = TestIntegrator.insert_test(test_code, new_test, :javascript)

      assert {:error, :empty_file} = result
    end

    test "handles malformed AST" do
      test_code = "describe('Test', () => { // unclosed"
      new_test = "it('test', () => {});"

      result = TestIntegrator.insert_test(test_code, new_test, :javascript)

      assert {:error, :parse_error} = result
    end

    test "serializes AST back to valid source code" do
      test_code = """
      describe('Service', () => {
        it('works', () => {
          expect(1).toBe(1);
        });
      });
      """

      {:ok, ast} = TestIntegrator.parse(test_code, :javascript)
      {:ok, serialized} = TestIntegrator.serialize(ast, :javascript)

      # Should be able to parse the serialized code
      assert {:ok, _} = TestIntegrator.parse(serialized, :javascript)
    end
  end
end
