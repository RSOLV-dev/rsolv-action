defmodule Rsolv.Mailer do
  @moduledoc """
  Mailer module for sending emails via Bamboo and Postmark.
  """
  use Bamboo.Mailer, otp_app: :rsolv
end
