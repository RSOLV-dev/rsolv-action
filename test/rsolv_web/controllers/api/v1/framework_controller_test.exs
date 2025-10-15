defmodule RsolvWeb.Api.V1.FrameworkControllerTest do
  use RsolvWeb.ConnCase, async: true

  describe "POST /api/v1/framework/detect" do
    test "detects Vitest from package.json", %{conn: conn} do
      request_body = %{
        "packageJson" => %{
          "devDependencies" => %{
            "vitest" => "^1.0.0"
          }
        },
        "gemfile" => nil,
        "requirementsTxt" => nil
      }

      conn = post(conn, ~p"/api/v1/framework/detect", request_body)

      assert json_response(conn, 200) == %{
               "framework" => "vitest",
               "version" => "1.0.0",
               "testDir" => "test/",
               "compatibleWith" => []
             }
    end

    test "detects Jest from package.json", %{conn: conn} do
      request_body = %{
        "packageJson" => %{
          "devDependencies" => %{
            "jest" => "^29.0.0"
          }
        },
        "gemfile" => nil,
        "requirementsTxt" => nil
      }

      conn = post(conn, ~p"/api/v1/framework/detect", request_body)

      assert json_response(conn, 200) == %{
               "framework" => "jest",
               "version" => "29.0.0",
               "testDir" => "__tests__/",
               "compatibleWith" => []
             }
    end

    test "detects Mocha from package.json", %{conn: conn} do
      request_body = %{
        "packageJson" => %{
          "devDependencies" => %{
            "mocha" => "^10.0.0"
          }
        },
        "gemfile" => nil,
        "requirementsTxt" => nil
      }

      conn = post(conn, ~p"/api/v1/framework/detect", request_body)

      assert json_response(conn, 200) == %{
               "framework" => "mocha",
               "version" => "10.0.0",
               "testDir" => "test/",
               "compatibleWith" => []
             }
    end

    test "prioritizes Vitest when multiple frameworks present", %{conn: conn} do
      request_body = %{
        "packageJson" => %{
          "devDependencies" => %{
            "vitest" => "^1.0.0",
            "jest" => "^29.0.0"
          }
        },
        "gemfile" => nil,
        "requirementsTxt" => nil
      }

      conn = post(conn, ~p"/api/v1/framework/detect", request_body)

      response = json_response(conn, 200)
      assert response["framework"] == "vitest"
      assert response["version"] == "1.0.0"
      assert "jest" in response["compatibleWith"]
    end

    test "detects RSpec from Gemfile", %{conn: conn} do
      request_body = %{
        "packageJson" => nil,
        "gemfile" => """
        source 'https://rubygems.org'
        gem 'rspec', '~> 3.0'
        """,
        "requirementsTxt" => nil
      }

      conn = post(conn, ~p"/api/v1/framework/detect", request_body)

      assert json_response(conn, 200) == %{
               "framework" => "rspec",
               "version" => "~> 3.0",
               "testDir" => "spec/",
               "compatibleWith" => []
             }
    end

    test "detects Minitest from Gemfile", %{conn: conn} do
      request_body = %{
        "packageJson" => nil,
        "gemfile" => """
        source 'https://rubygems.org'
        gem 'minitest', '~> 5.0'
        """,
        "requirementsTxt" => nil
      }

      conn = post(conn, ~p"/api/v1/framework/detect", request_body)

      assert json_response(conn, 200) == %{
               "framework" => "minitest",
               "version" => "~> 5.0",
               "testDir" => "test/",
               "compatibleWith" => []
             }
    end

    test "detects pytest from requirements.txt", %{conn: conn} do
      request_body = %{
        "packageJson" => nil,
        "gemfile" => nil,
        "requirementsTxt" => """
        django==4.0.0
        pytest==7.0.0
        pytest-cov==3.0.0
        """
      }

      conn = post(conn, ~p"/api/v1/framework/detect", request_body)

      assert json_response(conn, 200) == %{
               "framework" => "pytest",
               "version" => "7.0.0",
               "testDir" => "tests/",
               "compatibleWith" => []
             }
    end

    test "detects framework from config files", %{conn: conn} do
      request_body = %{
        "packageJson" => nil,
        "gemfile" => nil,
        "requirementsTxt" => nil,
        "configFiles" => ["vitest.config.ts", "package.json"]
      }

      conn = post(conn, ~p"/api/v1/framework/detect", request_body)

      assert json_response(conn, 200) == %{
               "framework" => "vitest",
               "version" => nil,
               "testDir" => "test/",
               "compatibleWith" => []
             }
    end

    test "combines package.json and config files", %{conn: conn} do
      request_body = %{
        "packageJson" => %{
          "devDependencies" => %{
            "vitest" => "^1.0.0"
          }
        },
        "gemfile" => nil,
        "requirementsTxt" => nil,
        "configFiles" => ["vitest.config.ts"]
      }

      conn = post(conn, ~p"/api/v1/framework/detect", request_body)

      response = json_response(conn, 200)
      assert response["framework"] == "vitest"
      assert response["version"] == "1.0.0"
      assert response["testDir"] == "test/"
    end

    test "returns error when no frameworks detected", %{conn: conn} do
      request_body = %{
        "packageJson" => %{
          "devDependencies" => %{
            "typescript" => "^5.0.0"
          }
        },
        "gemfile" => nil,
        "requirementsTxt" => nil
      }

      conn = post(conn, ~p"/api/v1/framework/detect", request_body)

      assert json_response(conn, 422) == %{
               "error" => "No test framework detected",
               "details" => "Could not detect test framework from provided files"
             }
    end

    test "returns error when all inputs are nil", %{conn: conn} do
      request_body = %{
        "packageJson" => nil,
        "gemfile" => nil,
        "requirementsTxt" => nil
      }

      conn = post(conn, ~p"/api/v1/framework/detect", request_body)

      assert json_response(conn, 400) == %{
               "error" => "At least one package file must be provided",
               "details" => "Provide packageJson, gemfile, requirementsTxt, or configFiles"
             }
    end

    test "returns error when all inputs are empty", %{conn: conn} do
      request_body = %{
        "packageJson" => nil,
        "gemfile" => "",
        "requirementsTxt" => "",
        "configFiles" => []
      }

      conn = post(conn, ~p"/api/v1/framework/detect", request_body)

      assert json_response(conn, 400) == %{
               "error" => "At least one package file must be provided",
               "details" => "Provide packageJson, gemfile, requirementsTxt, or configFiles"
             }
    end

    test "handles malformed JSON gracefully", %{conn: conn} do
      # Phoenix will handle JSON parsing errors before reaching our controller
      # It raises Plug.Parsers.ParseError for malformed JSON
      assert_raise Plug.Parsers.ParseError, fn ->
        conn
        |> put_req_header("content-type", "application/json")
        |> post(~p"/api/v1/framework/detect", "{invalid json")
      end
    end

    test "extracts custom test directory from package.json config", %{conn: conn} do
      request_body = %{
        "packageJson" => %{
          "devDependencies" => %{
            "vitest" => "^1.0.0"
          },
          "vitest" => %{
            "include" => ["src/**/*.test.ts"]
          }
        },
        "gemfile" => nil,
        "requirementsTxt" => nil
      }

      conn = post(conn, ~p"/api/v1/framework/detect", request_body)

      response = json_response(conn, 200)
      assert response["framework"] == "vitest"
      assert response["testDir"] == "src/"
    end

    test "handles empty package.json devDependencies", %{conn: conn} do
      request_body = %{
        "packageJson" => %{
          "devDependencies" => %{}
        },
        "gemfile" => nil,
        "requirementsTxt" => nil
      }

      conn = post(conn, ~p"/api/v1/framework/detect", request_body)

      assert json_response(conn, 422) == %{
               "error" => "No test framework detected",
               "details" => "Could not detect test framework from provided files"
             }
    end

    test "handles package.json without devDependencies", %{conn: conn} do
      request_body = %{
        "packageJson" => %{
          "name" => "my-package"
        },
        "gemfile" => nil,
        "requirementsTxt" => nil
      }

      conn = post(conn, ~p"/api/v1/framework/detect", request_body)

      assert json_response(conn, 422) == %{
               "error" => "No test framework detected",
               "details" => "Could not detect test framework from provided files"
             }
    end
  end
end
