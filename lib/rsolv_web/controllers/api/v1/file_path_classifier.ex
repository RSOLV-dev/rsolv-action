defmodule RsolvWeb.Api.V1.FilePathClassifier do
  @moduledoc """
  Classifies file paths to determine if they are vendor, test, config, or application code.
  Part of RFC-042: AST False Positive Reduction Enhancement.
  
  This module helps reduce false positives by identifying files that are less likely
  to contain real security vulnerabilities (vendor libraries, test files, etc).
  
  ## Classification Types
  
  - `:vendor` - Third-party libraries, minified files, build outputs
  - `:test` - Test files, specs, fixtures, mocks
  - `:config` - Configuration files, build configs
  - `:application` - Application source code (default)
  
  ## Confidence Impact
  
  - Vendor files: 0.1x multiplier (90% reduction)
  - Test files: 0.2x multiplier (80% reduction)
  - Config files: 0.5x multiplier (50% reduction)
  - Application files: 1.0x multiplier (no reduction)
  """
  
  # Pattern definitions moved to helper functions to avoid compilation issues
  # with regex module attributes in production builds
  
  # Confidence multipliers by classification
  @confidence_multipliers %{
    vendor: 0.1,
    test: 0.2,
    config: 0.5,
    application: 1.0
  }
  
  # Filtering thresholds by classification
  @filter_thresholds %{
    vendor: 0.3,
    test: 0.4
  }
  
  @doc """
  Classifies a file path as :vendor, :test, :config, or :application.
  
  ## Examples
  
      iex> FilePathClassifier.classify("/node_modules/react/index.js")
      :vendor
      
      iex> FilePathClassifier.classify("/test/unit/app_test.js")
      :test
      
      iex> FilePathClassifier.classify("/app/routes/index.js")
      :application
  """
  def classify(nil), do: :application
  def classify(""), do: :application
  def classify("/"), do: :application
  
  def classify(file_path) when is_binary(file_path) do
    cond do
      matches_any?(get_vendor_patterns(), file_path) -> :vendor
      matches_any?(get_test_patterns(), file_path) -> :test
      matches_any?(get_config_patterns(), file_path) -> :config
      true -> :application
    end
  end
  
  defp get_vendor_patterns do
    [
      ~r|/vendor/|,           # Common vendor directory
      ~r|/node_modules/|,     # NPM packages
      ~r|/bower_components/|, # Bower packages
      ~r|/assets/vendor/|,    # Asset vendor directory
      ~r|/lib/third-party/|,  # Third-party libraries
      ~r|/public/vendor/|,    # Public vendor assets
      ~r|/static/vendor/|,    # Static vendor assets
      ~r|\.min\.js$|,         # Minified JavaScript
      ~r|\.min\.css$|,        # Minified CSS
      ~r|-min\.js$|,          # Alternative minified naming
      ~r|/dist/|,             # Distribution builds
      ~r|/build/|             # Build outputs
    ]
  end
  
  defp get_test_patterns do
    [
      ~r|/test/|,         # Test directory
      ~r|/tests/|,        # Tests directory
      ~r|/spec/|,         # Specification tests
      ~r|/__tests__/|,    # Jest convention
      ~r|/__test__/|,     # Alternative Jest
      ~r|\.test\.|,       # Test file suffix
      ~r|\.spec\.|,       # Spec file suffix
      ~r|_test\.|,        # Underscore test suffix
      ~r|_spec\.|,        # Underscore spec suffix
      ~r|/e2e/|,          # End-to-end tests
      ~r|/integration/|,  # Integration tests
      ~r|/fixtures/|,     # Test fixtures
      ~r|/mocks/|,        # Mock objects
      ~r|/stubs/|         # Test stubs
    ]
  end
  
  defp get_config_patterns do
    [
      ~r|/config/|,       # Config directory
      ~r|\.config\.|,     # Config file suffix
      ~r|webpack\.|,      # Webpack config
      ~r|rollup\.|,       # Rollup config
      ~r|gulpfile|,       # Gulp config
      ~r|Gruntfile|,      # Grunt config
      ~r|\.eslintrc|,     # ESLint config
      ~r|\.babelrc|,      # Babel config
      ~r|tsconfig\.|,     # TypeScript config
      ~r|jest\.config|    # Jest config
    ]
  end
  
  @doc """
  Returns the confidence multiplier for a given file classification.
  
  This multiplier is applied to the base confidence score to reduce
  confidence for files that are less likely to contain real vulnerabilities.
  
  ## Examples
  
      iex> FilePathClassifier.confidence_multiplier(:vendor)
      0.1
      
      iex> FilePathClassifier.confidence_multiplier(:application)
      1.0
  """
  def confidence_multiplier(classification) do
    Map.get(@confidence_multipliers, classification, 1.0)
  end
  
  @doc """
  Determines if a vulnerability should be filtered based on file classification and confidence.
  
  Filtering is applied when confidence is below the threshold for a given classification.
  Only vendor and test files have filtering thresholds; config and application files
  are never filtered.
  
  ## Examples
  
      iex> FilePathClassifier.should_filter?(:vendor, 0.25)
      true
      
      iex> FilePathClassifier.should_filter?(:vendor, 0.35)
      false
      
      iex> FilePathClassifier.should_filter?(:application, 0.1)
      false
  """
  def should_filter?(classification, confidence) do
    case Map.get(@filter_thresholds, classification) do
      nil -> false
      threshold -> confidence < threshold
    end
  end
  
  # Private functions
  
  defp matches_any?(patterns, file_path) do
    Enum.any?(patterns, &Regex.match?(&1, file_path))
  end
end