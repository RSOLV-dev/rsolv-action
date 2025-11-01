defmodule RsolvWeb.ApiSpecTest do
  use ExUnit.Case, async: true

  alias RsolvWeb.ApiSpec

  describe "spec/0" do
    test "returns OpenAPI spec with required fields" do
      spec = ApiSpec.spec()

      assert spec.info.title == "RSOLV API"
      assert spec.info.version == "1.0.0"
      assert is_list(spec.servers)
      assert length(spec.servers) > 0
      assert spec.paths
      assert spec.components
    end

    test "includes multiple server configurations" do
      spec = ApiSpec.spec()

      # Should have production, staging, and local servers
      assert length(spec.servers) >= 1

      # Check that servers have required fields
      for server <- spec.servers do
        assert server.url
        assert is_binary(server.url)
      end
    end

    test "includes security schemes" do
      spec = ApiSpec.spec()

      assert spec.components.securitySchemes
      assert spec.components.securitySchemes["ApiKeyAuth"]
      assert spec.components.securitySchemes["ApiKeyAuth"].type == "http"
    end

    test "includes API documentation tags" do
      spec = ApiSpec.spec()

      assert is_list(spec.tags)
      assert length(spec.tags) > 0

      tag_names = Enum.map(spec.tags, & &1.name)
      assert "Patterns" in tag_names
      assert "AST" in tag_names
      assert "Vulnerabilities" in tag_names
    end

    test "spec is valid OpenAPI structure" do
      spec = ApiSpec.spec()

      # Verify it's an OpenApiSpex.OpenApi struct
      assert %OpenApiSpex.OpenApi{} = spec

      # Verify required top-level fields
      assert spec.openapi == "3.0.0"
      assert spec.info
      assert spec.paths
    end
  end
end
