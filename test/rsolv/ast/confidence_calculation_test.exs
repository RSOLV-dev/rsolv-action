defmodule Rsolv.AST.ConfidenceCalculationTest do
  use ExUnit.Case, async: false

  alias Rsolv.AST.ConfidenceCalculator

  describe "confidence calculation for object.property patterns" do
    test "gives high confidence boost for exact object.property match" do
      # Pattern with callee_object and callee_property
      pattern = %{
        "_callee_object" => "crypto",
        "_callee_property" => "createHash",
        "type" => "CallExpression"
      }

      # Node that matches exactly
      node = %{
        "type" => "CallExpression",
        "callee" => %{
          "type" => "MemberExpression",
          "object" => %{"name" => "crypto"},
          "property" => %{"name" => "createHash"}
        }
      }

      context = %{parent_type: "VariableDeclarator", depth: 4}

      confidence =
        ConfidenceCalculator.calculate_confidence(
          pattern,
          node,
          context,
          %{base: 0.5, adjustments: %{}}
        )

      # Should get significant boost for exact match
      assert confidence >= 0.8
    end

    test "gives lower confidence when object.property doesn't match" do
      pattern = %{
        "_callee_object" => "crypto",
        "_callee_property" => "createHash",
        "type" => "CallExpression"
      }

      # Node with different object/property
      node = %{
        "type" => "CallExpression",
        "callee" => %{
          "type" => "MemberExpression",
          "object" => %{"name" => "console"},
          "property" => %{"name" => "log"}
        }
      }

      context = %{parent_type: "ExpressionStatement", depth: 3}

      confidence =
        ConfidenceCalculator.calculate_confidence(
          pattern,
          node,
          context,
          %{base: 0.5, adjustments: %{}}
        )

      # Should have much lower confidence
      assert confidence < 0.3
    end

    test "applies confidence rules from pattern definition" do
      pattern = %{
        "_callee_object" => "crypto",
        "_callee_property" => "createHash",
        "type" => "CallExpression"
      }

      node = %{
        "type" => "CallExpression",
        "callee" => %{
          "type" => "MemberExpression",
          "object" => %{"name" => "crypto"},
          "property" => %{"name" => "createHash"}
        },
        "arguments" => [
          %{"type" => "Literal", "value" => "md5"}
        ]
      }

      context = %{
        parent_type: "VariableDeclarator",
        depth: 4,
        in_test_file: false
      }

      confidence_rules = %{
        base: 0.5,
        adjustments: %{
          # Big boost for exact match
          "exact_object_property_match" => 0.4,
          # Additional boost for MD5/SHA1
          "has_weak_algorithm" => 0.2,
          # Penalty for test files
          "in_test_code" => -0.6
        }
      }

      confidence =
        ConfidenceCalculator.calculate_confidence(
          pattern,
          node,
          context,
          confidence_rules
        )

      # Base 0.5 + exact match 0.4 = 0.9 minimum
      assert confidence >= 0.9
    end
  end
end
