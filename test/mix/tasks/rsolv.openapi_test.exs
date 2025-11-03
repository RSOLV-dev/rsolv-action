defmodule Mix.Tasks.Rsolv.OpenapiTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  @test_output_file "test/tmp/test_openapi.json"

  setup do
    # Ensure test directory exists
    File.mkdir_p!("test/tmp")

    # Clean up any existing test file
    File.rm(@test_output_file)

    on_exit(fn ->
      File.rm(@test_output_file)
    end)

    :ok
  end

  describe "run/1" do
    test "generates OpenAPI spec to default location" do
      # Run the task and capture output
      output =
        capture_io(fn ->
          Mix.Tasks.Rsolv.Openapi.run([])
        end)

      # Verify success message
      assert output =~ "OpenAPI spec written to priv/static/openapi.json"
      assert output =~ "✓ OpenAPI spec validation passed"

      # Verify file was created
      assert File.exists?("priv/static/openapi.json")

      # Verify it's valid JSON
      {:ok, spec} = File.read!("priv/static/openapi.json") |> JSON.decode()

      assert spec["info"]["title"] == "RSOLV API"
      assert spec["info"]["version"] == "1.0.0"
      assert spec["openapi"] == "3.0.0"
    end

    test "generates OpenAPI spec to custom location" do
      output =
        capture_io(fn ->
          Mix.Tasks.Rsolv.Openapi.run([@test_output_file])
        end)

      assert output =~ "OpenAPI spec written to #{@test_output_file}"
      assert output =~ "✓ OpenAPI spec validation passed"

      # Verify file was created at custom location
      assert File.exists?(@test_output_file)

      # Verify it's valid JSON
      {:ok, spec} = File.read!(@test_output_file) |> JSON.decode()

      assert spec["info"]["title"] == "RSOLV API"
    end

    test "validates spec and reports metadata" do
      output =
        capture_io(fn ->
          Mix.Tasks.Rsolv.Openapi.run([@test_output_file])
        end)

      # Verify validation output includes metadata
      assert output =~ "Title: RSOLV API"
      assert output =~ "Version: 1.0.0"
      assert output =~ "Paths:"
      assert output =~ "Tags:"
    end

    test "generates spec with multiple server configurations" do
      capture_io(fn ->
        Mix.Tasks.Rsolv.Openapi.run([@test_output_file])
      end)

      {:ok, spec} = File.read!(@test_output_file) |> JSON.decode()

      # Should have at least one server configured
      assert is_list(spec["servers"])
      assert length(spec["servers"]) >= 1

      # Verify server structure
      server = hd(spec["servers"])
      assert server["url"]
      assert is_binary(server["url"])
    end

    test "generates spec with security schemes" do
      capture_io(fn ->
        Mix.Tasks.Rsolv.Openapi.run([@test_output_file])
      end)

      {:ok, spec} = File.read!(@test_output_file) |> JSON.decode()

      assert spec["components"]["securitySchemes"]
      assert spec["components"]["securitySchemes"]["ApiKeyAuth"]
    end

    test "generates spec with API paths" do
      capture_io(fn ->
        Mix.Tasks.Rsolv.Openapi.run([@test_output_file])
      end)

      {:ok, spec} = File.read!(@test_output_file) |> JSON.decode()

      # Should have paths defined
      assert is_map(spec["paths"])
      assert map_size(spec["paths"]) > 0
    end
  end
end
