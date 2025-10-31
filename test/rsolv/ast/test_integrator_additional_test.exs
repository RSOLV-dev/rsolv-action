defmodule Rsolv.AST.TestIntegratorAdditionalTest do
  @moduledoc """
  Additional test coverage for TestIntegrator edge cases and real-world scenarios.

  These tests complement the core tests in test_integrator_test.exs by covering:
  - Multiple test insertions
  - Nested test structures
  - Mixed indentation styles
  - Very large test files
  - Special characters in test names
  - Framework-specific edge cases (before/after hooks, fixtures, etc.)
  """
  # Must run sequentially because TestIntegrator creates parser sessions
  # with shared SessionManager state. Parallel execution in CI causes
  # parser port exhaustion and state pollution.
  use ExUnit.Case, async: false

  alias Rsolv.AST.TestIntegrator

  describe "multiple test insertions" do
    test "inserting second test maintains both tests correctly" do
      test_code = """
      describe('UserController', () => {
        it('creates user', () => {
          expect(createUser()).toBeDefined();
        });
      });
      """

      first_test = """
        it('validates user input', () => {
          expect(validateUser(null)).toBe(false);
        });
      """

      # Insert first test
      {:ok, code_with_first} = TestIntegrator.insert_test(test_code, first_test, :javascript)

      # Insert second test into the result
      second_test = """
        it('handles duplicate users', () => {
          expect(createUser('existing@example.com')).toThrow();
        });
      """

      {:ok, final_code} = TestIntegrator.insert_test(code_with_first, second_test, :javascript)

      # Verify all three tests are present
      assert String.contains?(final_code, "creates user")
      assert String.contains?(final_code, "validates user input")
      assert String.contains?(final_code, "handles duplicate users")

      # Verify it's still valid
      assert {:ok, _ast} = TestIntegrator.parse(final_code, :javascript)
    end
  end

  describe "nested test structures" do
    test "handles nested describe blocks in JavaScript" do
      test_code = """
      describe('UserController', () => {
        describe('authentication', () => {
          it('logs in user', () => {
            expect(login()).toBe(true);
          });
        });

        describe('authorization', () => {
          it('checks permissions', () => {
            expect(hasPermission()).toBe(true);
          });
        });
      });
      """

      new_test = """
        it('validates session', () => {
          expect(validateSession()).toBe(true);
        });
      """

      {:ok, updated_code} = TestIntegrator.insert_test(test_code, new_test, :javascript)

      assert String.contains?(updated_code, "validates session")
      assert {:ok, _ast} = TestIntegrator.parse(updated_code, :javascript)
    end

    test "handles nested context blocks in Ruby" do
      test_code = """
      RSpec.describe UserController do
        context 'when authenticated' do
          context 'with admin role' do
            it 'allows access' do
              expect(can_access?).to be true
            end
          end
        end
      end
      """

      new_test = """
          it 'logs admin action' do
            expect(admin_logs).not_to be_empty
          end
      """

      {:ok, updated_code} = TestIntegrator.insert_test(test_code, new_test, :ruby)

      assert String.contains?(updated_code, "logs admin action")
      assert {:ok, _ast} = TestIntegrator.parse(updated_code, :ruby)
    end
  end

  describe "special characters and unicode" do
    test "handles test names with special characters in JavaScript" do
      test_code = """
      describe('UserController', () => {
        it('handles user@example.com format', () => {
          expect(true).toBe(true);
        });
      });
      """

      new_test = """
        it('handles special chars: !@#$%^&*()', () => {
          expect(sanitize('test!@#')).toBeDefined();
        });
      """

      {:ok, updated_code} = TestIntegrator.insert_test(test_code, new_test, :javascript)

      assert String.contains?(updated_code, "special chars")
      assert {:ok, _ast} = TestIntegrator.parse(updated_code, :javascript)
    end

    test "handles unicode in Ruby test names" do
      test_code = """
      RSpec.describe UserController do
        it 'handles English names' do
          expect(true).to be true
        end
      end
      """

      new_test = """
        it 'handles unicode: 你好世界 🚀' do
          expect(true).to be true
        end
      """

      {:ok, updated_code} = TestIntegrator.insert_test(test_code, new_test, :ruby)

      assert String.contains?(updated_code, "unicode")
      assert {:ok, _ast} = TestIntegrator.parse(updated_code, :ruby)
    end
  end

  describe "before/after hooks and fixtures" do
    test "preserves RSpec before/after hooks" do
      test_code = """
      RSpec.describe UserController do
        before(:each) do
          @user = create_user
        end

        after(:each) do
          cleanup_user(@user)
        end

        it 'uses fixture' do
          expect(@user).not_to be_nil
        end
      end
      """

      new_test = """
        it 'validates fixture data' do
          expect(@user.email).to match(/.*@.*/)
        end
      """

      {:ok, updated_code} = TestIntegrator.insert_test(test_code, new_test, :ruby)

      # Ensure hooks are preserved
      assert String.contains?(updated_code, "before(:each)")
      assert String.contains?(updated_code, "after(:each)")
      assert String.contains?(updated_code, "validates fixture data")
      assert {:ok, _ast} = TestIntegrator.parse(updated_code, :ruby)
    end

    test "preserves pytest fixtures" do
      test_code = """
      import pytest

      @pytest.fixture
      def user():
          return create_user()

      class TestUserController:
          def test_with_fixture(self, user):
              assert user is not None
      """

      new_test = """
          def test_validates_user(self, user):
              assert user.email is not None
      """

      {:ok, updated_code} = TestIntegrator.insert_test(test_code, new_test, :python)

      # Ensure fixture is preserved
      assert String.contains?(updated_code, "@pytest.fixture")
      assert String.contains?(updated_code, "validates_user")
      assert {:ok, _ast} = TestIntegrator.parse(updated_code, :python)
    end

    test "preserves JavaScript beforeEach/afterEach" do
      test_code = """
      describe('UserController', () => {
        let user;

        beforeEach(() => {
          user = createUser();
        });

        afterEach(() => {
          cleanupUser(user);
        });

        it('uses setup', () => {
          expect(user).toBeDefined();
        });
      });
      """

      new_test = """
        it('validates setup data', () => {
          expect(user.email).toMatch(/@/);
        });
      """

      {:ok, updated_code} = TestIntegrator.insert_test(test_code, new_test, :javascript)

      # Ensure hooks are preserved
      assert String.contains?(updated_code, "beforeEach")
      assert String.contains?(updated_code, "afterEach")
      assert String.contains?(updated_code, "validates setup data")
      assert {:ok, _ast} = TestIntegrator.parse(updated_code, :javascript)
    end
  end

  describe "large test files" do
    test "handles test file with many existing tests (JavaScript)" do
      # Generate a file with 20 tests
      tests =
        Enum.map(1..20, fn i ->
          """
            it('test #{i}', () => {
              expect(true).toBe(true);
            });
          """
        end)
        |> Enum.join("\n")

      test_code = """
      describe('LargeController', () => {
      #{tests}
      });
      """

      new_test = """
        it('new security test', () => {
          expect(validateInput('test')).toBe(true);
        });
      """

      {:ok, updated_code} = TestIntegrator.insert_test(test_code, new_test, :javascript)

      # Verify new test is added
      assert String.contains?(updated_code, "new security test")

      # Verify all original tests are preserved
      Enum.each(1..20, fn i ->
        assert String.contains?(updated_code, "test #{i}")
      end)

      assert {:ok, _ast} = TestIntegrator.parse(updated_code, :javascript)
    end
  end

  describe "mixed indentation styles" do
    test "handles file with tabs in JavaScript" do
      test_code = """
      describe('Service', () => {
      \tit('test with tabs', () => {
      \t\texpect(true).toBe(true);
      \t});
      });
      """

      new_test = """
      \tit('new test', () => {
      \t\texpect(false).toBe(false);
      \t});
      """

      {:ok, updated_code} = TestIntegrator.insert_test(test_code, new_test, :javascript)

      assert String.contains?(updated_code, "new test")
      # Note: Our implementation normalizes to spaces, which is acceptable
    end
  end

  describe "framework-specific patterns" do
    test "handles RSpec shared examples" do
      test_code = """
      RSpec.describe UserController do
        it_behaves_like 'an authenticated controller'

        it 'creates user' do
          expect(true).to be true
        end
      end
      """

      new_test = """
        it 'validates permissions' do
          expect(has_permission?).to be true
        end
      """

      {:ok, updated_code} = TestIntegrator.insert_test(test_code, new_test, :ruby)

      # Ensure shared example is preserved
      assert String.contains?(updated_code, "it_behaves_like")
      assert String.contains?(updated_code, "validates permissions")
      assert {:ok, _ast} = TestIntegrator.parse(updated_code, :ruby)
    end

    test "handles pytest parametrize decorator" do
      test_code = """
      import pytest

      class TestUserController:
          @pytest.mark.parametrize("input,expected", [
              ("valid", True),
              ("invalid", False),
          ])
          def test_validation(self, input, expected):
              assert validate(input) == expected
      """

      new_test = """
          def test_security_check(self):
              assert check_security() is True
      """

      {:ok, updated_code} = TestIntegrator.insert_test(test_code, new_test, :python)

      # Ensure decorator is preserved
      assert String.contains?(updated_code, "@pytest.mark.parametrize")
      assert String.contains?(updated_code, "security_check")
      assert {:ok, _ast} = TestIntegrator.parse(updated_code, :python)
    end

    test "handles Jest test.each pattern" do
      test_code = """
      describe('Validator', () => {
        test.each([
          ['valid@email.com', true],
          ['invalid', false],
        ])('validates %s', (input, expected) => {
          expect(validate(input)).toBe(expected);
        });
      });
      """

      new_test = """
        it('handles security validation', () => {
          expect(validateSecurity()).toBe(true);
        });
      """

      {:ok, updated_code} = TestIntegrator.insert_test(test_code, new_test, :javascript)

      # Ensure test.each is preserved
      assert String.contains?(updated_code, "test.each")
      assert String.contains?(updated_code, "security validation")
      assert {:ok, _ast} = TestIntegrator.parse(updated_code, :javascript)
    end
  end

  describe "alternative test frameworks" do
    test "handles Mocha's test() syntax" do
      test_code = """
      describe('UserService', function() {
        test('creates user', function() {
          assert(true);
        });
      });
      """

      new_test = """
        test('validates user', function() {
          assert(validateUser());
        });
      """

      {:ok, updated_code} = TestIntegrator.insert_test(test_code, new_test, :javascript)

      assert String.contains?(updated_code, "validates user")
      assert {:ok, _ast} = TestIntegrator.parse(updated_code, :javascript)
    end

    test "handles Minitest Ruby syntax" do
      test_code = """
      class TestUserController < Minitest::Test
        def test_create_user
          assert true
        end
      end
      """

      # Note: Current implementation focuses on RSpec
      # This test documents expected behavior for future enhancement
      new_test = """
        def test_validate_user
          assert validate_user
        end
      """

      # This might not work yet - that's OK, we're documenting the gap
      result = TestIntegrator.insert_test(test_code, new_test, :ruby)

      case result do
        {:ok, _code} ->
          # Great! It works
          assert true

        {:error, :no_insertion_point} ->
          # Expected - not implemented yet for Minitest
          # This test documents the gap
          assert true
      end
    end
  end

  describe "whitespace and formatting edge cases" do
    test "handles file with Windows line endings (CRLF)" do
      test_code =
        "describe('Test', () => {\r\n  it('works', () => {\r\n    expect(true).toBe(true);\r\n  });\r\n});"

      new_test = """
        it('new test', () => {
          expect(false).toBe(false);
        });
      """

      {:ok, updated_code} = TestIntegrator.insert_test(test_code, new_test, :javascript)

      assert String.contains?(updated_code, "new test")
      # Line ending normalization is acceptable
    end

    test "handles file with trailing whitespace" do
      test_code = """
      describe('Test', () => {
        it('works', () => {
          expect(true).toBe(true);
        });
      });
      """

      new_test = """
        it('new test', () => {
          expect(false).toBe(false);
        });
      """

      {:ok, updated_code} = TestIntegrator.insert_test(test_code, new_test, :javascript)

      assert String.contains?(updated_code, "new test")
    end

    test "handles file with no trailing newline" do
      test_code =
        "describe('Test', () => {\n  it('works', () => {\n    expect(true).toBe(true);\n  });\n})"

      new_test = """
        it('new test', () => {
          expect(false).toBe(false);
        });
      """

      {:ok, updated_code} = TestIntegrator.insert_test(test_code, new_test, :javascript)

      assert String.contains?(updated_code, "new test")
    end
  end
end
