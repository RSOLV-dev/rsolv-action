defmodule RsolvWeb.PatternDocumentWriteMetadataTest do
  use RsolvWeb.ConnCase

  describe "GET /api/v1/patterns/:id/metadata for XSS document.write" do
    test "returns vulnerability metadata for js-xss-document-write", %{conn: conn} do
      conn = get(conn, "/api/v1/patterns/js-xss-document-write/metadata")

      assert json = json_response(conn, 200)
      assert json["pattern_id"] == "js-xss-document-write"
      assert json["description"] =~ "document.write"
      assert json["description"] =~ "DOM XSS sink"

      # Check references
      assert length(json["references"]) >= 5
      ref_types = Enum.map(json["references"], & &1["type"])
      assert "cwe" in ref_types
      assert "mdn" in ref_types
      # Chrome intervention
      assert "google" in ref_types

      # Check attack vectors
      attack_vector_text = Enum.join(json["attack_vectors"], " ")
      assert attack_vector_text =~ "script"
      assert attack_vector_text =~ "onerror"

      # Check for parser blocking warnings
      assert Map.has_key?(json, "additional_context")
      assert Map.has_key?(json["additional_context"], "parser_blocking")
      assert is_list(json["additional_context"]["parser_blocking"])
    end
  end
end
