defmodule Rsolv.Integration.ASTValidationComprehensiveTest do
  use RsolvWeb.ConnCase, async: true
  import Rsolv.APITestHelpers

  setup do
    setup_api_auth()
  end

  describe "Comment Detection Tests" do
    test "detects single-line JavaScript comments", %{
      conn: conn,
      customer: customer,
      api_key: api_key
    } do
      test_cases = [
        # Basic single-line comment
        %{
          code: "// eval(userInput)",
          line: 1,
          content: "// eval(userInput)\nconsole.log('safe');",
          should_reject: true
        },
        # Comment at end of line
        %{
          code: "eval(userInput); // TODO: fix this",
          line: 1,
          content: "const x = 5; // eval(userInput); // TODO: fix this",
          should_reject: true
        },
        # Not a comment - real vulnerability (but no clear user input source)
        %{
          code: "eval(userInput)",
          line: 2,
          content: "// This is safe\neval(userInput);\n// Another comment",
          should_reject: false,
          # Lower confidence without clear user input flow
          expected_min_confidence: 0.6
        }
      ]

      for test_case <- test_cases do
        result = validate_vulnerability(conn, customer, api_key, test_case)

        if test_case.should_reject do
          assert result["isValid"] == false
          assert result["confidence"] <= 0.1
          assert result["reason"] =~ "comment"
        else
          assert result["isValid"] == true
          min_confidence = Map.get(test_case, :expected_min_confidence, 0.8)
          assert result["confidence"] >= min_confidence
        end
      end
    end

    test "detects multi-line JavaScript comments", %{
      conn: conn,
      customer: customer,
      api_key: api_key
    } do
      test_cases = [
        # Basic multi-line comment
        %{
          code: "eval(userInput)",
          line: 2,
          content: "/*\n eval(userInput)\n*/\nconsole.log('safe');",
          should_reject: true
        },
        # Complex multi-line with asterisks
        %{
          code: "* eval(userInput)",
          line: 3,
          content: "/**\n * This is bad:\n * eval(userInput)\n */",
          should_reject: true
        }
      ]

      for test_case <- test_cases do
        result = validate_vulnerability(conn, customer, api_key, test_case)
        assert result["isValid"] == false
        assert result["reason"] =~ "comment"
      end
    end

    test "detects Python comments", %{conn: conn, customer: customer, api_key: api_key} do
      test_cases = [
        # Single-line Python comment
        %{
          code: "# exec(user_input)",
          line: 1,
          content: "# exec(user_input)\nprint('safe')",
          should_reject: true
        },
        # Triple-quote docstring
        %{
          code: "exec(user_input)",
          line: 3,
          content: "\"\"\"\nDangerous:\nexec(user_input)\n\"\"\"\nprint('safe')",
          should_reject: true
        }
      ]

      for test_case <- test_cases do
        result = validate_vulnerability(conn, customer, api_key, test_case)
        assert result["isValid"] == false
        assert result["reason"] =~ "comment"
      end
    end

    test "detects Ruby comments", %{conn: conn, customer: customer, api_key: api_key} do
      test_cases = [
        # Single-line Ruby comment
        %{
          code: "# eval(user_input)",
          line: 1,
          content: "# eval(user_input)\nputs 'safe'",
          should_reject: true
        },
        # Multi-line Ruby comment
        %{
          code: "eval(user_input)",
          line: 3,
          content: "=begin\nDon't do this:\neval(user_input)\n=end\nputs 'safe'",
          should_reject: true
        }
      ]

      for test_case <- test_cases do
        result = validate_vulnerability(conn, customer, api_key, test_case)
        assert result["isValid"] == false
        assert result["reason"] =~ "comment"
      end
    end
  end

  describe "String Literal Detection Tests" do
    test "detects JavaScript string literals", %{conn: conn, customer: customer, api_key: api_key} do
      test_cases = [
        # Single quotes
        %{
          code: "const warning = 'Never use eval()'",
          line: 1,
          content: "const warning = 'Never use eval()';",
          should_reject: true
        },
        # Double quotes
        %{
          code: "const msg = \"eval() is dangerous\"",
          line: 1,
          content: "const msg = \"eval() is dangerous\";",
          should_reject: true
        },
        # Template literals
        %{
          code: "const template = `Don't use eval()`",
          line: 1,
          content: "const template = `Don't use eval()`;",
          should_reject: true
        },
        # Not in string - real vulnerability (but no clear user input source)
        %{
          code: "eval(userInput)",
          line: 1,
          content: "const result = eval(userInput);",
          should_reject: false,
          # Lower confidence without clear user input flow
          expected_min_confidence: 0.6
        }
      ]

      for test_case <- test_cases do
        result = validate_vulnerability(conn, customer, api_key, test_case)

        if test_case.should_reject do
          assert result["isValid"] == false
          assert result["confidence"] <= 0.1
          assert result["reason"] =~ "string literal"
        else
          assert result["isValid"] == true
          min_confidence = Map.get(test_case, :expected_min_confidence, 0.8)
          assert result["confidence"] >= min_confidence
        end
      end
    end

    test "detects Python string literals", %{conn: conn, customer: customer, api_key: api_key} do
      test_cases = [
        # Single quotes
        %{
          code: "message = 'exec() is bad'",
          line: 1,
          content: "message = 'exec() is bad'",
          should_reject: true
        },
        # Triple quotes
        %{
          code: "doc = '''exec(user_input)'''",
          line: 1,
          content: "doc = '''exec(user_input)'''",
          should_reject: true
        }
      ]

      for test_case <- test_cases do
        result = validate_vulnerability(conn, customer, api_key, test_case)
        assert result["isValid"] == false
        assert result["reason"] =~ "string literal"
      end
    end
  end

  describe "User Input Flow Detection Tests" do
    test "detects direct user input usage", %{conn: conn, customer: customer, api_key: api_key} do
      test_cases = [
        # Direct request parameter
        %{
          code: "eval(req.body.expression)",
          line: 5,
          content: """
          app.post('/calc', (req, res) => {
            const result = eval(req.body.expression);
            res.json({result});
          });
          """,
          should_have_high_confidence: true
        },
        # User input through variable (indirect taint - slightly lower confidence)
        %{
          code: "eval(userExpression)",
          line: 3,
          content: """
          const userExpression = req.query.expr;
          // Process user input
          const result = eval(userExpression);
          """,
          should_have_high_confidence: true,
          # Indirect taint has slightly lower confidence
          expected_min_confidence: 0.85
        },
        # No user input - hardcoded
        %{
          code: "eval('2 + 2')",
          line: 1,
          content: "const four = eval('2 + 2');",
          should_have_high_confidence: false
        }
      ]

      for test_case <- test_cases do
        result = validate_vulnerability(conn, customer, api_key, test_case)

        assert result["isValid"] == true

        if test_case.should_have_high_confidence do
          # Use custom confidence threshold if specified, otherwise default to 0.9
          min_confidence = Map.get(test_case, :expected_min_confidence, 0.9)
          assert result["confidence"] >= min_confidence
          assert result["astContext"]["inUserInputFlow"] == true
        else
          assert result["confidence"] < 0.9
          assert result["astContext"]["inUserInputFlow"] == false
        end
      end
    end
  end

  describe "Edge Cases and Error Handling" do
    test "handles malformed code gracefully", %{conn: conn, customer: customer, api_key: api_key} do
      test_cases = [
        # Incomplete code
        %{
          code: "eval(",
          line: 1,
          content: "function broken() { eval(",
          should_validate: true
        },
        # Special characters
        %{
          code: "eval(user\\nInput)",
          line: 1,
          content: "eval(user\\nInput);",
          should_validate: true
        },
        # Unicode
        %{
          code: "eval('🚀')",
          line: 1,
          content: "const rocket = eval('🚀');",
          should_validate: true
        }
      ]

      for test_case <- test_cases do
        result = validate_vulnerability(conn, customer, api_key, test_case)

        # Should not crash - should return a result
        assert Map.has_key?(result, "isValid")
        assert Map.has_key?(result, "confidence")
      end
    end

    test "handles very large files efficiently", %{
      conn: conn,
      customer: customer,
      api_key: api_key
    } do
      # Generate a large file with vulnerability near the end
      large_content =
        Enum.map(1..10000, fn i ->
          "console.log('Line #{i}');"
        end)
        |> Enum.join("\n")

      vulnerable_line = 10001
      large_content = large_content <> "\neval(userInput); // Line #{vulnerable_line}"

      result =
        validate_vulnerability(conn, customer, api_key, %{
          code: "eval(userInput)",
          line: vulnerable_line,
          content: large_content,
          should_reject: false
        })

      assert result["isValid"] == true
      # Lower confidence without clear user input flow context
      assert result["confidence"] >= 0.6
    end
  end

  describe "Performance and Batch Processing" do
    test "processes large batches efficiently", %{
      conn: conn,
      customer: customer,
      api_key: api_key
    } do
      # Create 100 vulnerabilities
      vulnerabilities =
        Enum.map(1..100, fn i ->
          %{
            "id" => "vuln-#{i}",
            "patternId" => "js-eval-injection",
            "filePath" => "file#{i}.js",
            "line" => 1,
            "code" => if(rem(i, 2) == 0, do: "// eval(x)", else: "eval(x)"),
            "severity" => "critical"
          }
        end)

      files =
        Enum.reduce(1..100, %{}, fn i, acc ->
          content = if(rem(i, 2) == 0, do: "// eval(x)", else: "eval(x);")
          Map.put(acc, "file#{i}.js", content)
        end)

      request_data = %{
        "vulnerabilities" => vulnerabilities,
        "files" => files
      }

      start_time = System.monotonic_time(:millisecond)

      conn =
        conn
        |> put_req_header("x-api-key", api_key.key)
        |> put_req_header("content-type", "application/json")
        |> post("/api/v1/vulnerabilities/validate", request_data)

      response = json_response(conn, 200)

      end_time = System.monotonic_time(:millisecond)
      duration = end_time - start_time

      # Should process 100 vulnerabilities in under 10 seconds
      # Note: Increased from 5s to account for test environment variability
      # while still ensuring reasonable performance
      assert duration < 10000

      # Verify results
      assert length(response["validated"]) == 100
      assert response["stats"]["total"] == 100
      # Half are real
      assert response["stats"]["validated"] == 50
      # Half are in comments
      assert response["stats"]["rejected"] == 50
    end
  end

  describe "Different Language Support" do
    test "validates PHP vulnerabilities", %{conn: conn, customer: customer, api_key: api_key} do
      result =
        validate_vulnerability(conn, customer, api_key, %{
          code: "eval($_POST['code'])",
          line: 5,
          content: """
          <?php
          if (isset($_POST['code'])) {
              $result = eval($_POST['code']);
              echo $result;
          }
          ?>
          """,
          should_reject: false
        })

      assert result["isValid"] == true
      assert result["confidence"] >= 0.9
    end

    test "validates Ruby vulnerabilities", %{conn: conn, customer: customer, api_key: api_key} do
      result =
        validate_vulnerability(conn, customer, api_key, %{
          code: "eval(params[:code])",
          line: 3,
          content: """
          def execute
            result = eval(params[:code])
            render json: { result: result }
          end
          """,
          should_reject: false
        })

      assert result["isValid"] == true
      assert result["confidence"] >= 0.9
    end

    test "validates Python vulnerabilities", %{conn: conn, customer: customer, api_key: api_key} do
      result =
        validate_vulnerability(conn, customer, api_key, %{
          code: "exec(request.form['code'])",
          line: 4,
          content: """
          @app.route('/execute', methods=['POST'])
          def execute():
              code = request.form['code']
              exec(code)
              return 'OK'
          """,
          should_reject: false
        })

      assert result["isValid"] == true
      assert result["confidence"] >= 0.9
    end
  end

  # Helper function to validate a single vulnerability
  defp validate_vulnerability(conn, _customer, api_key, test_case) do
    # Use app.js instead of test.js to avoid test file confidence reduction
    file_path = Map.get(test_case, :file_path, "app.js")

    request_data = %{
      "vulnerabilities" => [
        %{
          "id" => "test-vuln",
          "patternId" => "eval-injection",
          "filePath" => file_path,
          "line" => test_case.line,
          "code" => test_case.code,
          "severity" => "critical"
        }
      ],
      "files" => %{
        file_path => test_case.content
      }
    }

    conn =
      conn
      |> put_req_header("x-api-key", api_key.key)
      |> put_req_header("content-type", "application/json")
      |> post("/api/v1/vulnerabilities/validate", request_data)

    response = json_response(conn, 200)
    hd(response["validated"])
  end
end
