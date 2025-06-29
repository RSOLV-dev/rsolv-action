defmodule RsolvApi.JsonEncoders do
  @moduledoc """
  Custom JSON encoders for types that don't have built-in JSON encoding.
  Note: We now use JSONSerializer for proper regex handling instead of this.
  """
  
  # This module is kept for compatibility but is no longer used
  # The native JSON module in Elixir 1.18+ doesn't support custom encoders
  # in the same way as Jason. Use RSOLVApi.Security.Patterns.JSONSerializer instead.
end