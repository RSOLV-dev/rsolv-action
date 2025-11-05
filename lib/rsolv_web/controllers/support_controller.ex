defmodule RsolvWeb.SupportController do
  use RsolvWeb, :controller

  @moduledoc """
  Customer support documentation controller for support.rsolv.dev

  Serves comprehensive customer support documentation including:
  - Customer onboarding guide
  - Billing FAQ
  - API key management
  - Credit system explanation
  - Payment method troubleshooting
  """

  def index(conn, _params) do
    render(conn, :index, page_title: "Customer Support - RSOLV")
  end

  def onboarding(conn, _params) do
    render(conn, :onboarding, page_title: "Customer Onboarding Guide - RSOLV")
  end

  def billing_faq(conn, _params) do
    render(conn, :billing_faq, page_title: "Billing FAQ - RSOLV")
  end

  def api_keys(conn, _params) do
    render(conn, :api_keys, page_title: "API Key Management - RSOLV")
  end

  def credits(conn, _params) do
    render(conn, :credits, page_title: "Credit System Guide - RSOLV")
  end

  def payment_troubleshooting(conn, _params) do
    render(conn, :payment_troubleshooting, page_title: "Payment Troubleshooting - RSOLV")
  end
end
