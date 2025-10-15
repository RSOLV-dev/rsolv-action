defmodule RsolvWeb.PatternInterpolationMetadataTest do
  use RsolvWeb.ConnCase

  describe "GET /api/v1/patterns/:id/metadata for SQL injection interpolation" do
    test "returns vulnerability metadata for js-sql-injection-interpolation", %{conn: conn} do
      conn = get(conn, "/api/v1/patterns/js-sql-injection-interpolation/metadata")

      assert json = json_response(conn, 200)
      assert json["pattern_id"] == "js-sql-injection-interpolation"
      assert json["description"] =~ "template literal"

      # Check references
      assert length(json["references"]) >= 5
      ref_types = Enum.map(json["references"], & &1["type"])
      assert "cwe" in ref_types
      assert "stackoverflow" in ref_types

      # Check attack vectors mention template literals
      attack_vector_text = Enum.join(json["attack_vectors"], " ")
      assert attack_vector_text =~ "${"

      # Check for additional context about common mistakes
      assert Map.has_key?(json, "additional_context")
    end
  end
end
