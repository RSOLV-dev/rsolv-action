defmodule RsolvWeb.DocsController do
  use RsolvWeb, :controller

  @moduledoc """
  Documentation site controller for docs.rsolv.dev and docs.rsolv-staging.com

  Serves comprehensive documentation for RSOLV GitHub Action including:
  - Installation guide
  - Getting started tutorial
  - Troubleshooting
  - API reference
  - FAQ
  """

  def index(conn, _params) do
    render(conn, :index, page_title: "RSOLV Documentation")
  end

  def installation(conn, _params) do
    render(conn, :installation, page_title: "Installation Guide - RSOLV")
  end

  def getting_started(conn, _params) do
    render(conn, :getting_started, page_title: "Getting Started - RSOLV")
  end

  def troubleshooting(conn, _params) do
    render(conn, :troubleshooting, page_title: "Troubleshooting - RSOLV")
  end

  def api_reference(conn, _params) do
    render(conn, :api_reference, page_title: "API Reference - RSOLV")
  end

  def faq(conn, _params) do
    render(conn, :faq, page_title: "FAQ - RSOLV")
  end

  def workflows(conn, _params) do
    render(conn, :workflows, page_title: "Workflow Templates - RSOLV")
  end

  def configuration(conn, _params) do
    render(conn, :configuration, page_title: "Configuration - RSOLV")
  end

  def example_new_layout(conn, _params) do
    render(conn, :example_new_layout, page_title: "Component Example - RSOLV Documentation")
  end
end
