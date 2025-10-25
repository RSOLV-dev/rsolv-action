defmodule Rsolv.Cldr do
  @moduledoc """
  CLDR backend for RSOLV application.

  Used by ex_money for currency formatting and localization.
  """

  use Cldr,
    locales: ["en"],
    default_locale: "en",
    providers: [Cldr.Number, Money]
end
