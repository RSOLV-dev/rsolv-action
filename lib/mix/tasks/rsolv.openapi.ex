defmodule Mix.Tasks.Rsolv.Openapi do
  @moduledoc """
  Generates RSOLV OpenAPI specification as a JSON file.

  ## Usage

      mix rsolv.openapi [output_file]

  If no output file is specified, the spec will be written to `priv/static/openapi.json`.

  ## Examples

      # Generate to default location
      mix rsolv.openapi

      # Generate to specific file
      mix rsolv.openapi docs/api-spec.json
  """

  use Mix.Task

  @shortdoc "Generates RSOLV OpenAPI specification JSON file"

  @impl Mix.Task
  def run(args) do
    # Parse args - use --spec flag to specify the spec module
    {opts, remaining_args} = OptionParser.parse!(args, strict: [spec: :string])

    spec_module = opts[:spec] || "RsolvWeb.ApiSpec"

    output_file =
      case remaining_args do
        [file] -> file
        [] -> "priv/static/openapi.json"
      end

    # Start the application to load all modules
    Mix.Task.run("app.start")

    # Ensure the directory exists
    output_file
    |> Path.dirname()
    |> File.mkdir_p!()

    # Get the spec module
    spec_mod = Module.concat([spec_module])

    unless Code.ensure_loaded?(spec_mod) do
      Mix.raise("Spec module #{spec_module} not found")
    end

    # Generate the spec
    spec = spec_mod.spec()

    # Encode to JSON
    json =
      spec
      |> Jason.encode!(pretty: true)

    # Write to file
    File.write!(output_file, json)

    Mix.shell().info("OpenAPI spec written to #{output_file}")

    # Validate the spec
    validate_spec(spec)
  end

  defp validate_spec(spec) do
    # Basic validation
    errors = []

    errors =
      if is_nil(spec.info) || is_nil(spec.info.title) || is_nil(spec.info.version) do
        ["Missing required info.title or info.version" | errors]
      else
        errors
      end

    errors =
      if map_size(spec.paths || %{}) == 0 do
        ["No paths defined in specification" | errors]
      else
        errors
      end

    case errors do
      [] ->
        Mix.shell().info("✓ OpenAPI spec validation passed")
        Mix.shell().info("  - Title: #{spec.info.title}")
        Mix.shell().info("  - Version: #{spec.info.version}")
        Mix.shell().info("  - Paths: #{map_size(spec.paths || %{})}")
        Mix.shell().info("  - Tags: #{length(spec.tags || [])}")

      errors ->
        Mix.shell().error("✗ OpenAPI spec validation failed:")

        Enum.each(errors, fn error ->
          Mix.shell().error("  - #{error}")
        end)

        Mix.raise("OpenAPI spec validation failed")
    end
  end
end
