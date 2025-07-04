defmodule Rsolv.TestActor do
  @moduledoc """
  A simple actor implementation for FunWithFlags testing.
  """
  
  defstruct [:id]
  
  def new(id), do: %__MODULE__{id: id}
end

# Implement the FunWithFlags.Actor protocol
defimpl FunWithFlags.Actor, for: Rsolv.TestActor do
  def id(%{id: id}), do: id
end