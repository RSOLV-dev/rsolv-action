defmodule Rsolv.AST.TestScorerTest do
  @moduledoc """
  Tests for path similarity scoring used to find the best test file
  for inserting validation tests.

  RFC-060-AMENDMENT-001: Phase 0 - RED tests written before implementation.
  """
  use ExUnit.Case, async: true

  alias Rsolv.AST.TestScorer

  describe "path_similarity_score/2" do
    test "returns 1.0 for identical paths" do
      vulnerable_file = "lib/app/services/user_service.ex"
      candidate_test = "test/app/services/user_service_test.exs"

      score = TestScorer.path_similarity_score(vulnerable_file, candidate_test)

      assert score == 1.0
    end

    test "scores high for matching directory structure" do
      vulnerable_file = "src/controllers/api/v1/users_controller.js"
      candidate_test = "test/controllers/api/v1/users_controller.test.js"

      score = TestScorer.path_similarity_score(vulnerable_file, candidate_test)

      assert score >= 0.8
      assert score < 1.0
    end

    test "scores medium for same module but different structure" do
      vulnerable_file = "app/services/authentication.rb"
      candidate_test = "spec/unit/authentication_spec.rb"

      score = TestScorer.path_similarity_score(vulnerable_file, candidate_test)

      assert score >= 0.5
      assert score < 0.8
    end

    test "scores low for completely different paths" do
      vulnerable_file = "src/database/connection.py"
      candidate_test = "tests/api/test_endpoints.py"

      score = TestScorer.path_similarity_score(vulnerable_file, candidate_test)

      assert score < 0.5
    end

    test "handles paths with no common segments" do
      vulnerable_file = "alpha/beta/gamma.js"
      candidate_test = "tests/zeta/omega.test.js"

      score = TestScorer.path_similarity_score(vulnerable_file, candidate_test)

      assert score >= 0.0
      assert score <= 0.3
    end
  end

  describe "same_module?/2" do
    test "returns true when file names match (ignoring extensions)" do
      vulnerable_file = "lib/services/payment.ex"
      candidate_test = "test/services/payment_test.exs"

      assert TestScorer.same_module?(vulnerable_file, candidate_test) == true
    end

    test "returns true when file names match with test suffix patterns" do
      vulnerable_file = "src/utils/validator.js"
      candidate_test = "test/utils/validator.spec.js"

      assert TestScorer.same_module?(vulnerable_file, candidate_test) == true
    end

    test "returns false when file names differ" do
      vulnerable_file = "app/models/user.rb"
      candidate_test = "spec/models/account_spec.rb"

      assert TestScorer.same_module?(vulnerable_file, candidate_test) == false
    end

    test "handles edge case of empty file names" do
      vulnerable_file = "app/"
      candidate_test = "test/.test.js"

      assert TestScorer.same_module?(vulnerable_file, candidate_test) == false
    end
  end

  describe "same_directory_structure?/2" do
    test "returns true for matching directory hierarchies" do
      vulnerable_file = "src/api/v2/handlers/auth.ts"
      candidate_test = "test/api/v2/handlers/auth.test.ts"

      assert TestScorer.same_directory_structure?(vulnerable_file, candidate_test) == true
    end

    test "returns false when directory depth differs" do
      vulnerable_file = "lib/services/user.ex"
      candidate_test = "test/unit/services/integration/user_test.exs"

      assert TestScorer.same_directory_structure?(vulnerable_file, candidate_test) == false
    end

    test "returns false for completely different structures" do
      vulnerable_file = "app/controllers/admin.rb"
      candidate_test = "spec/requests/api_spec.rb"

      assert TestScorer.same_directory_structure?(vulnerable_file, candidate_test) == false
    end
  end

  describe "calculate_score/2 - full scoring with bonuses" do
    test "combines base score with same module bonus" do
      vulnerable_file = "lib/app/auth.ex"
      candidate_test = "test/app/auth_test.exs"

      score = TestScorer.calculate_score(vulnerable_file, candidate_test)

      # Should have high base score + same module bonus
      assert score > 1.0
    end

    test "applies directory structure bonus" do
      vulnerable_file = "src/api/v1/users.js"
      candidate_test = "test/api/v1/different_module.test.js"

      score = TestScorer.calculate_score(vulnerable_file, candidate_test)

      # Should have directory bonus but not module bonus
      assert score >= 0.5
      assert score < 1.5
    end

    test "returns base score when no bonuses apply" do
      vulnerable_file = "app/models/user.rb"
      candidate_test = "spec/controllers/admin_spec.rb"

      score = TestScorer.calculate_score(vulnerable_file, candidate_test)

      # Should only have base path similarity
      assert score >= 0.0
      assert score <= 1.0
    end
  end

  describe "find_best_test_file/2" do
    test "selects test file with highest score" do
      vulnerable_file = "src/services/payment.js"

      candidate_tests = [
        "test/services/payment.test.js",
        "test/api/endpoints.test.js",
        "test/unit/other.test.js"
      ]

      best = TestScorer.find_best_test_file(vulnerable_file, candidate_tests)

      assert best == "test/services/payment.test.js"
    end

    test "returns nil when candidate list is empty" do
      vulnerable_file = "src/app.js"
      candidate_tests = []

      best = TestScorer.find_best_test_file(vulnerable_file, candidate_tests)

      assert best == nil
    end

    test "handles ties by returning first matching candidate" do
      vulnerable_file = "lib/utils.ex"
      # Two tests with identical scores (same distance)
      candidate_tests = [
        "test/unit/helpers.exs",
        "test/integration/workers.exs"
      ]

      best = TestScorer.find_best_test_file(vulnerable_file, candidate_tests)

      # Should return one of them consistently
      assert best in candidate_tests
    end
  end
end
