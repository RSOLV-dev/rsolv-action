defmodule Rsolv.Frameworks.Detector do
  @moduledoc """
  Test framework detection from package files and configuration.

  Detects test frameworks across multiple languages:
  - JavaScript/TypeScript: Vitest, Jest, Mocha
  - Ruby: RSpec, Minitest
  - Python: pytest, unittest

  ## Detection Strategy

  1. Check package.json devDependencies (JS/TS)
  2. Check config files (vitest.config.ts, jest.config.js, etc.)
  3. Check Gemfile (Ruby)
  4. Check requirements.txt (Python)

  ## Priority Order

  For JavaScript/TypeScript:
  - Vitest (priority 1)
  - Jest (priority 2)
  - Mocha (priority 3)

  When multiple frameworks are detected, returns the highest priority framework
  as the primary, with others listed in `compatible_with`.

  ## Examples

      iex> Rsolv.Frameworks.Detector.detect(%{
      ...>   package_json: %{"devDependencies" => %{"vitest" => "^1.0.0"}},
      ...>   gemfile: nil,
      ...>   requirements_txt: nil
      ...> })
      {:ok, %{
        framework: "vitest",
        version: "1.0.0",
        test_dir: "test/",
        compatible_with: []
      }}

      iex> Rsolv.Frameworks.Detector.detect(%{
      ...>   package_json: %{"devDependencies" => %{"jest" => "^29.0.0", "vitest" => "^1.0.0"}},
      ...>   gemfile: nil,
      ...>   requirements_txt: nil
      ...> })
      {:ok, %{
        framework: "vitest",
        version: "1.0.0",
        test_dir: "test/",
        compatible_with: ["jest"]
      }}

  """

  require Logger

  @type package_files :: %{
    optional(:package_json) => map() | nil,
    optional(:gemfile) => String.t() | nil,
    optional(:requirements_txt) => String.t() | nil,
    optional(:config_files) => list(String.t())
  }

  @type detection_result :: %{
    framework: String.t(),
    version: String.t() | nil,
    test_dir: String.t(),
    compatible_with: list(String.t())
  }

  # Framework priorities (lower number = higher priority)
  @js_framework_priority %{
    "vitest" => 1,
    "jest" => 2,
    "mocha" => 3
  }

  # Default test directories by framework
  @framework_test_dirs %{
    "vitest" => "test/",
    "jest" => "__tests__/",
    "mocha" => "test/",
    "rspec" => "spec/",
    "minitest" => "test/",
    "pytest" => "tests/",
    "unittest" => "tests/"
  }

  # Config file patterns
  @config_patterns %{
    "vitest" => ["vitest.config.ts", "vitest.config.js", "vitest.config.mjs"],
    "jest" => ["jest.config.js", "jest.config.ts", "jest.config.json"],
    "mocha" => [".mocharc.json", ".mocharc.js", "mocha.opts"],
    "pytest" => ["pytest.ini", "pyproject.toml", "setup.cfg"],
    "rspec" => [".rspec", "spec/spec_helper.rb"]
  }

  @doc """
  Detects test framework from package files and configuration.

  ## Parameters

  - `package_files`: Map containing package file contents:
    - `:package_json` - Parsed package.json (JavaScript/TypeScript)
    - `:gemfile` - Gemfile content as string (Ruby)
    - `:requirements_txt` - requirements.txt content as string (Python)
    - `:config_files` - List of config file names found in the repo (optional)

  ## Returns

  - `{:ok, result}` - Successfully detected framework
  - `{:error, reason}` - Detection failed

  The result map contains:
  - `framework` - Primary framework name
  - `version` - Framework version if available
  - `test_dir` - Default test directory for the framework
  - `compatible_with` - List of other compatible frameworks detected

  ## Examples

      # Detect Jest with version cleaning
      iex> Rsolv.Frameworks.Detector.detect(%{
      ...>   package_json: %{"devDependencies" => %{"jest" => "~29.0.0"}}
      ...> })
      {:ok, %{
        framework: "jest",
        version: "29.0.0",
        test_dir: "__tests__/",
        compatible_with: []
      }}

      # Detect Mocha
      iex> Rsolv.Frameworks.Detector.detect(%{
      ...>   package_json: %{"devDependencies" => %{"mocha" => "^10.0.0"}}
      ...> })
      {:ok, %{
        framework: "mocha",
        version: "10.0.0",
        test_dir: "test/",
        compatible_with: []
      }}

      # Detect RSpec from Gemfile
      iex> Rsolv.Frameworks.Detector.detect(%{
      ...>   gemfile: "gem 'rspec', '~> 3.0'"
      ...> })
      {:ok, %{
        framework: "rspec",
        version: "~> 3.0",
        test_dir: "spec/",
        compatible_with: []
      }}

      # Detect pytest from requirements.txt
      iex> Rsolv.Frameworks.Detector.detect(%{
      ...>   requirements_txt: "pytest==7.0.0"
      ...> })
      {:ok, %{
        framework: "pytest",
        version: "7.0.0",
        test_dir: "tests/",
        compatible_with: []
      }}

      # Detect from config files
      iex> Rsolv.Frameworks.Detector.detect(%{
      ...>   config_files: ["jest.config.js"]
      ...> })
      {:ok, %{
        framework: "jest",
        version: nil,
        test_dir: "__tests__/",
        compatible_with: []
      }}

      # No framework detected
      iex> Rsolv.Frameworks.Detector.detect(%{
      ...>   package_json: %{"devDependencies" => %{"typescript" => "^5.0.0"}}
      ...> })
      {:error, "No test framework detected"}

      # Empty input
      iex> Rsolv.Frameworks.Detector.detect(%{})
      {:error, "No test framework detected"}
  """
  @spec detect(package_files()) :: {:ok, detection_result()} | {:error, String.t()}
  def detect(package_files) when is_map(package_files) do
    Logger.debug("Detecting framework from package files: #{inspect(Map.keys(package_files))}")

    # Detect all frameworks present
    detected_frameworks = detect_all_frameworks(package_files)

    Logger.debug("Detected frameworks: #{inspect(detected_frameworks)}")

    case detected_frameworks do
      [] ->
        {:error, "No test framework detected"}

      frameworks ->
        # Sort by priority and select primary
        primary = select_primary_framework(frameworks)
        others = Enum.reject(frameworks, fn f -> f.name == primary.name end)

        result = %{
          framework: primary.name,
          version: primary.version,
          test_dir: get_test_dir(primary.name, package_files),
          compatible_with: Enum.map(others, & &1.name)
        }

        Logger.info("Selected framework: #{primary.name}")
        {:ok, result}
    end
  end

  # Detect all frameworks across all package files
  defp detect_all_frameworks(package_files) do
    [
      detect_from_package_json(package_files[:package_json]),
      detect_from_gemfile(package_files[:gemfile]),
      detect_from_requirements_txt(package_files[:requirements_txt]),
      detect_from_config_files(package_files[:config_files])
    ]
    |> List.flatten()
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq_by(& &1.name)
  end

  # Detect JavaScript/TypeScript frameworks from package.json
  defp detect_from_package_json(nil), do: []
  defp detect_from_package_json(package_json) when is_map(package_json) do
    dev_deps = Map.get(package_json, "devDependencies", %{})

    ["vitest", "jest", "mocha"]
    |> Enum.map(fn framework ->
      case Map.get(dev_deps, framework) do
        nil -> nil
        version_spec ->
          %{
            name: framework,
            version: clean_version(version_spec),
            source: "package.json"
          }
      end
    end)
    |> Enum.reject(&is_nil/1)
  end

  # Detect Ruby frameworks from Gemfile
  defp detect_from_gemfile(nil), do: []
  defp detect_from_gemfile(gemfile_content) when is_binary(gemfile_content) do
    [
      detect_gem(gemfile_content, "rspec"),
      detect_gem(gemfile_content, "minitest")
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp detect_gem(gemfile_content, gem_name) do
    # Match patterns like: gem 'rspec', '~> 3.0'
    regex = ~r/gem\s+['"]#{gem_name}['"](?:\s*,\s*['"]([^'"]+)['"])?/

    case Regex.run(regex, gemfile_content) do
      [_, version] -> %{name: gem_name, version: version, source: "Gemfile"}
      [_] -> %{name: gem_name, version: nil, source: "Gemfile"}
      nil -> nil
    end
  end

  # Detect Python frameworks from requirements.txt
  defp detect_from_requirements_txt(nil), do: []
  defp detect_from_requirements_txt(requirements_content) when is_binary(requirements_content) do
    [
      detect_requirement(requirements_content, "pytest"),
      detect_requirement(requirements_content, "unittest")
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp detect_requirement(requirements_content, package_name) do
    # Match patterns like: pytest==7.0.0 or pytest>=7.0.0
    # Use word boundary \b to ensure exact package name match
    regex = ~r/^#{package_name}\b(?:==|>=|<=|~=)([^\s]+)/m

    case Regex.run(regex, requirements_content) do
      [_, version] -> %{name: package_name, version: version, source: "requirements.txt"}
      nil ->
        # Also check for package name without version, using word boundary
        standalone_regex = ~r/^#{package_name}\b\s*$/m
        if Regex.match?(standalone_regex, requirements_content) do
          %{name: package_name, version: nil, source: "requirements.txt"}
        else
          nil
        end
    end
  end

  # Detect frameworks from config files
  defp detect_from_config_files(nil), do: []
  defp detect_from_config_files(config_files) when is_list(config_files) do
    @config_patterns
    |> Enum.flat_map(fn {framework, patterns} ->
      if Enum.any?(patterns, fn pattern -> pattern in config_files end) do
        [%{name: framework, version: nil, source: "config file"}]
      else
        []
      end
    end)
  end

  # Select primary framework based on priority
  defp select_primary_framework(frameworks) do
    frameworks
    |> Enum.sort_by(fn framework ->
      # JS frameworks use defined priority, others use order of detection
      Map.get(@js_framework_priority, framework.name, 999)
    end)
    |> List.first()
  end

  # Get test directory for framework, with config file override
  defp get_test_dir(framework_name, package_files) do
    # Check for custom test dir in package.json config
    custom_dir = get_custom_test_dir(framework_name, package_files[:package_json])

    custom_dir || Map.get(@framework_test_dirs, framework_name, "test/")
  end

  # Extract custom test directory from package.json config
  defp get_custom_test_dir("vitest", package_json) when is_map(package_json) do
    get_in(package_json, ["vitest", "include"])
    |> extract_test_dir()
  end

  defp get_custom_test_dir("jest", package_json) when is_map(package_json) do
    get_in(package_json, ["jest", "testMatch"])
    |> extract_test_dir()
  end

  defp get_custom_test_dir(_framework, _package_json), do: nil

  defp extract_test_dir(nil), do: nil
  defp extract_test_dir(paths) when is_list(paths) do
    # Extract directory from patterns like ["test/**/*.test.ts"]
    paths
    |> List.first()
    |> extract_test_dir()
  end
  defp extract_test_dir(path) when is_binary(path) do
    case Regex.run(~r/^([^*]+)/, path) do
      [_, dir] -> String.trim(dir)
      _ -> nil
    end
  end

  # Clean version string (remove ^ ~ = etc.)
  defp clean_version(version_spec) when is_binary(version_spec) do
    String.replace(version_spec, ~r/^[\^~=><!]+/, "")
  end
  defp clean_version(nil), do: nil
end
