defmodule RsolvWeb.Email.TemplateLoader do
  @moduledoc """
  Helper module for loading email templates from the filesystem.

  Provides production-safe file path resolution using `Application.app_dir/2`
  which works correctly in both development and release builds.

  ## Examples

      iex> RsolvWeb.Email.TemplateLoader.load_template("welcome")
      {:ok, "<html>...</html>"}

      iex> RsolvWeb.Email.TemplateLoader.load_template!("welcome")
      "<html>...</html>"

      iex> RsolvWeb.Email.TemplateLoader.template_path("welcome")
      "/path/to/app/lib/rsolv_web/components/templates/email/welcome.html"
  """

  @app_name :rsolv
  @template_dir "lib/rsolv_web/components/templates/email"

  @doc """
  Returns the full path to an email template file.

  Uses `Application.app_dir/2` for production-safe path resolution.

  ## Parameters

    * `template_name` - The template name without extension (e.g., "welcome", "payment_failed")

  ## Examples

      iex> RsolvWeb.Email.TemplateLoader.template_path("welcome")
      "/path/to/rsolv/lib/rsolv_web/components/templates/email/welcome.html"
  """
  @spec template_path(String.t() | atom()) :: String.t()
  def template_path(template_name) when is_atom(template_name) do
    template_path(Atom.to_string(template_name))
  end

  def template_path(template_name) when is_binary(template_name) do
    filename = "#{template_name}.html"
    Application.app_dir(@app_name, Path.join(@template_dir, filename))
  end

  @doc """
  Loads an email template from the filesystem.

  Returns `{:ok, content}` on success or `{:error, reason}` on failure.

  ## Parameters

    * `template_name` - The template name without extension

  ## Examples

      iex> RsolvWeb.Email.TemplateLoader.load_template("welcome")
      {:ok, "<html>...</html>"}

      iex> RsolvWeb.Email.TemplateLoader.load_template("nonexistent")
      {:error, :enoent}
  """
  @spec load_template(String.t() | atom()) :: {:ok, String.t()} | {:error, File.posix()}
  def load_template(template_name) do
    path = template_path(template_name)

    case File.read(path) do
      {:ok, content} -> {:ok, content}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Loads an email template from the filesystem, raising on error.

  Raises `File.Error` if the template cannot be read.

  ## Parameters

    * `template_name` - The template name without extension

  ## Examples

      iex> RsolvWeb.Email.TemplateLoader.load_template!("welcome")
      "<html>...</html>"

      iex> RsolvWeb.Email.TemplateLoader.load_template!("nonexistent")
      ** (File.Error) could not read file ...
  """
  @spec load_template!(String.t() | atom()) :: String.t()
  def load_template!(template_name) do
    path = template_path(template_name)
    File.read!(path)
  end

  @doc """
  Checks if a template file exists.

  ## Parameters

    * `template_name` - The template name without extension

  ## Examples

      iex> RsolvWeb.Email.TemplateLoader.template_exists?("welcome")
      true

      iex> RsolvWeb.Email.TemplateLoader.template_exists?("nonexistent")
      false
  """
  @spec template_exists?(String.t() | atom()) :: boolean()
  def template_exists?(template_name) do
    path = template_path(template_name)
    File.exists?(path)
  end

  @doc """
  Lists all available email templates.

  Returns a list of template names (atoms) without the .html extension.

  ## Examples

      iex> RsolvWeb.Email.TemplateLoader.list_templates()
      [:early_access_guide, :early_access_welcome, :feature_deep_dive, ...]
  """
  @spec list_templates() :: [atom()]
  def list_templates do
    template_dir_path = Application.app_dir(@app_name, @template_dir)

    case File.ls(template_dir_path) do
      {:ok, files} ->
        files
        |> Enum.filter(&String.ends_with?(&1, ".html"))
        |> Enum.map(&String.replace_suffix(&1, ".html", ""))
        |> Enum.map(&String.to_atom/1)
        |> Enum.sort()

      {:error, _} ->
        []
    end
  end
end
