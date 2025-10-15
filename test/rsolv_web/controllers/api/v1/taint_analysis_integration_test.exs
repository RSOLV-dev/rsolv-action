defmodule RsolvWeb.Api.V1.TaintAnalysisIntegrationTest do
  use RsolvWeb.ConnCase, async: false

  import Mock

  alias Rsolv.Accounts
  alias Rsolv.Cache.ValidationCache

  setup do
    # Clear cache before each test
    ValidationCache.clear()

    # Mock customer for testing
    customer = %{
      id: "test_customer_1",
      name: "Test Customer",
      email: "test@example.com",
      subscription_plan: "trial",
      tier: "enterprise",
      flags: ["ai_access", "enterprise_access"],
      monthly_limit: 100,
      current_usage: 15,
      active: true,
      trial: true,
      created_at: DateTime.utc_now()
    }

    {:ok, customer: customer}
  end

  describe "taint analysis integration" do
    test "detects direct user input with high confidence", %{conn: conn, customer: customer} do
      with_mock Accounts, get_customer_by_api_key: fn "test_api_key_123" -> customer end do
        request_body = %{
          "vulnerabilities" => [
            %{
              "id" => "taint-1",
              "type" => "code_injection",
              "filePath" => "/app/routes.js",
              "line" => 3,
              "code" => "eval(req.body.code)"
            }
          ],
          "files" => %{
            "/app/routes.js" => """
            app.post('/execute', (req, res) => {
              // Direct user input to eval
              eval(req.body.code);
              res.json({status: 'executed'});
            });
            """
          }
        }

        conn =
          conn
          |> put_req_header("x-api-key", "test_api_key_123")
          |> put_req_header("content-type", "application/json")
          |> post("/api/v1/vulnerabilities/validate", request_body)

        response = json_response(conn, 200)

        assert length(response["validated"]) == 1
        vuln = hd(response["validated"])
        assert vuln["isValid"] == true
        # Direct input gets 95% confidence
        assert vuln["confidence"] == 0.95
        assert vuln["astContext"]["directInput"] == true
        assert vuln["astContext"]["taintLevel"] == 1
      end
    end

    test "detects single-hop tainted flow", %{conn: conn, customer: customer} do
      with_mock Accounts, get_customer_by_api_key: fn "test_api_key_123" -> customer end do
        request_body = %{
          "vulnerabilities" => [
            %{
              "id" => "taint-2",
              "type" => "code_injection",
              "filePath" => "/app/controller.js",
              "line" => 4,
              "code" => "eval(userCode)"
            }
          ],
          "files" => %{
            "/app/controller.js" => """
            app.post('/run', (req, res) => {
              const userCode = req.body.script;
              // Single hop taint
              eval(userCode);
              res.json({done: true});
            });
            """
          }
        }

        conn =
          conn
          |> put_req_header("x-api-key", "test_api_key_123")
          |> put_req_header("content-type", "application/json")
          |> post("/api/v1/vulnerabilities/validate", request_body)

        response = json_response(conn, 200)

        assert length(response["validated"]) == 1
        vuln = hd(response["validated"])
        assert vuln["isValid"] == true
        # Single-hop gets 85% confidence
        assert vuln["confidence"] == 0.85
        assert vuln["astContext"]["taintedFlow"] == true
        assert vuln["astContext"]["taintLevel"] == 2
        assert vuln["astContext"]["taintHops"] == 0
      end
    end

    test "detects multi-hop tainted flow with reduced confidence", %{
      conn: conn,
      customer: customer
    } do
      with_mock Accounts, get_customer_by_api_key: fn "test_api_key_123" -> customer end do
        request_body = %{
          "vulnerabilities" => [
            %{
              "id" => "taint-3",
              "type" => "code_injection",
              "filePath" => "/app/processor.js",
              "line" => 4,
              "code" => "eval(final)"
            }
          ],
          "files" => %{
            "/app/processor.js" => """
            const input = req.query.data;
            const processed = input;
            const final = processed;
            eval(final);
            """
          }
        }

        conn =
          conn
          |> put_req_header("x-api-key", "test_api_key_123")
          |> put_req_header("content-type", "application/json")
          |> post("/api/v1/vulnerabilities/validate", request_body)

        response = json_response(conn, 200)

        assert length(response["validated"]) == 1
        vuln = hd(response["validated"])
        assert vuln["isValid"] == true
        # Multi-hop gets 75% confidence
        assert vuln["confidence"] == 0.75
        assert vuln["astContext"]["taintedFlow"] == true
        assert vuln["astContext"]["taintLevel"] == 3
      end
    end

    test "detects suspicious variable names", %{conn: conn, customer: customer} do
      with_mock Accounts, get_customer_by_api_key: fn "test_api_key_123" -> customer end do
        request_body = %{
          "vulnerabilities" => [
            %{
              "id" => "taint-4",
              "type" => "code_injection",
              "filePath" => "/app/handler.js",
              "line" => 2,
              "code" => "eval(userExpression)"
            }
          ],
          "files" => %{
            "/app/handler.js" => """
            const config = loadConfig();
            eval(userExpression);
            """
          }
        }

        conn =
          conn
          |> put_req_header("x-api-key", "test_api_key_123")
          |> put_req_header("content-type", "application/json")
          |> post("/api/v1/vulnerabilities/validate", request_body)

        response = json_response(conn, 200)

        assert length(response["validated"]) == 1
        vuln = hd(response["validated"])
        assert vuln["isValid"] == true
        # Suspicious name gets 60% confidence
        assert vuln["confidence"] == 0.60
        assert vuln["astContext"]["suspiciousName"] == true
        assert vuln["astContext"]["taintLevel"] == 3
      end
    end

    test "reduces confidence when sanitization is detected", %{conn: conn, customer: customer} do
      with_mock Accounts, get_customer_by_api_key: fn "test_api_key_123" -> customer end do
        request_body = %{
          "vulnerabilities" => [
            %{
              "id" => "taint-5",
              "type" => "code_injection",
              "filePath" => "/app/secure.js",
              "line" => 4,
              "code" => "eval(cleaned)"
            }
          ],
          "files" => %{
            "/app/secure.js" => """
            app.post('/safe', (req, res) => {
              const input = req.body.code;
              const cleaned = sanitize(input);
              eval(cleaned);
            });
            """
          }
        }

        conn =
          conn
          |> put_req_header("x-api-key", "test_api_key_123")
          |> put_req_header("content-type", "application/json")
          |> post("/api/v1/vulnerabilities/validate", request_body)

        response = json_response(conn, 200)

        assert length(response["validated"]) == 1
        vuln = hd(response["validated"])
        # Confidence should be reduced by 50% due to sanitization
        # Base confidence would be 0.85 (single-hop), reduced to 0.425
        assert vuln["confidence"] == 0.425
        assert vuln["astContext"]["hasSanitization"] == true
      end
    end

    test "gives low confidence for unknown sources", %{conn: conn, customer: customer} do
      with_mock Accounts, get_customer_by_api_key: fn "test_api_key_123" -> customer end do
        request_body = %{
          "vulnerabilities" => [
            %{
              "id" => "taint-6",
              "type" => "code_injection",
              "filePath" => "/app/mystery.js",
              "line" => 2,
              "code" => "eval(config)"
            }
          ],
          "files" => %{
            "/app/mystery.js" => """
            const config = loadConfiguration();
            eval(config);
            """
          }
        }

        conn =
          conn
          |> put_req_header("x-api-key", "test_api_key_123")
          |> put_req_header("content-type", "application/json")
          |> post("/api/v1/vulnerabilities/validate", request_body)

        response = json_response(conn, 200)

        assert length(response["validated"]) == 1
        vuln = hd(response["validated"])
        # Unknown source gets 40% confidence
        assert vuln["confidence"] == 0.40
        assert vuln["astContext"]["taintLevel"] == 4
        assert vuln["astContext"]["directInput"] == false
        assert vuln["astContext"]["taintedFlow"] == false
        assert vuln["astContext"]["suspiciousName"] == false
      end
    end

    test "taint analysis with file path multipliers", %{conn: conn, customer: customer} do
      with_mock Accounts, get_customer_by_api_key: fn "test_api_key_123" -> customer end do
        request_body = %{
          "vulnerabilities" => [
            %{
              "id" => "taint-7",
              "type" => "code_injection",
              "filePath" => "/vendor/lib/processor.js",
              "line" => 2,
              "code" => "eval(req.body.code)"
            }
          ],
          "files" => %{
            "/vendor/lib/processor.js" => """
            // Vendor file with direct user input
            eval(req.body.code);
            """
          }
        }

        conn =
          conn
          |> put_req_header("x-api-key", "test_api_key_123")
          |> put_req_header("content-type", "application/json")
          |> post("/api/v1/vulnerabilities/validate", request_body)

        response = json_response(conn, 200)

        assert length(response["validated"]) == 1
        vuln = hd(response["validated"])
        # Direct input (0.95) * vendor multiplier (0.1) = 0.095
        # Should be filtered because vendor + low confidence
        assert vuln["isValid"] == false
        assert vuln["confidence"] == 0.095
        assert vuln["reason"] =~ "vendor"
      end
    end

    test "NodeGoat-style eval vulnerability detection", %{conn: conn, customer: customer} do
      with_mock Accounts, get_customer_by_api_key: fn "test_api_key_123" -> customer end do
        # This mimics the actual NodeGoat vulnerability
        request_body = %{
          "vulnerabilities" => [
            %{
              "id" => "nodegoat-eval",
              "type" => "code_injection",
              "filePath" => "/app/routes/contributions.js",
              "line" => 8,
              "code" => "eval(preTax)"
            }
          ],
          "files" => %{
            "/app/routes/contributions.js" => """
            app.post('/contributions', isLoggedIn, (req, res) => {
              const preTax = req.body.preTax;
              const afterTax = req.body.afterTax;
              const roth = req.body.roth;
              
              // Vulnerable: Server-side JavaScript injection
              const preTaxTotal = eval(preTax);
              const afterTaxTotal = eval(afterTax);
              const rothTotal = eval(roth);
              
              res.json({
                preTax: preTaxTotal,
                afterTax: afterTaxTotal,
                roth: rothTotal
              });
            });
            """
          }
        }

        conn =
          conn
          |> put_req_header("x-api-key", "test_api_key_123")
          |> put_req_header("content-type", "application/json")
          |> post("/api/v1/vulnerabilities/validate", request_body)

        response = json_response(conn, 200)

        assert length(response["validated"]) == 1
        vuln = hd(response["validated"])
        assert vuln["isValid"] == true
        # Single-hop from req.body.preTax
        assert vuln["confidence"] == 0.85
        assert vuln["astContext"]["taintedFlow"] == true
        assert vuln["astContext"]["inUserInputFlow"] == true
      end
    end
  end
end
