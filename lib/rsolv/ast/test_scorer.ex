defmodule Rsolv.AST.TestScorer do
  @moduledoc """
  Scores test files for integration suitability based on path similarity,
  module matching, and directory structure.

  RFC-060-AMENDMENT-001: Scoring algorithm to find the best test file
  for inserting validation tests.

  ## Scoring Algorithm

  Base score (0.0-1.0): Path similarity using Jaccard similarity
  Module bonus (+0.3): Same module name (ignoring test suffixes)
  Directory bonus (+0.2): Same directory structure

  Total range: 0.0-1.5

  ## Examples

      iex> Rsolv.AST.TestScorer.score_test_files(
      ...>   "app/controllers/users_controller.rb",
      ...>   ["spec/controllers/users_controller_spec.rb", "spec/models/user_spec.rb"],
      ...>   "rspec"
      ...> )
      %{
        recommendations: [
          %{
            path: "spec/controllers/users_controller_spec.rb",
            score: 1.5,
            reason: "Exact match: controller test for controller file"
          },
          %{
            path: "spec/models/user_spec.rb",
            score: 0.4,
            reason: "Related: tests user model"
          }
        ],
        fallback: %{
          path: "spec/security/users_controller_security_spec.rb",
          reason: "Generated security-specific test file"
        }
      }
  """

  @doc """
  Scores multiple test files and returns sorted recommendations plus fallback path.

  ## Parameters

    - vulnerable_file: Path to the vulnerable source file
    - candidate_files: List of candidate test file paths
    - framework: Testing framework (e.g., "rspec", "vitest", "pytest")

  ## Returns

  Map with:
    - `recommendations`: List of scored candidates sorted by score (descending)
    - `fallback`: Suggested new test file path if no good match exists

  ## Examples

      iex> score_test_files("app/models/user.rb", ["spec/models/user_spec.rb"], "rspec")
      %{
        recommendations: [%{path: "spec/models/user_spec.rb", score: 1.5, reason: _}],
        fallback: %{path: "spec/security/user_security_spec.rb", reason: _}
      }
  """
  def score_test_files(vulnerable_file, candidate_files, framework) do
    candidates =
      candidate_files
      |> Enum.map(fn file ->
        %{
          path: file,
          score: calculate_score(vulnerable_file, file),
          reason: explain_score(vulnerable_file, file)
        }
      end)
      |> Enum.sort_by(& &1.score, :desc)

    %{
      recommendations: candidates,
      fallback: generate_fallback_path(vulnerable_file, framework)
    }
  end

  @doc """
  Finds the best matching test file from a list of candidates.

  Returns the path with the highest score, or nil if no candidates.

  ## Examples

      iex> find_best_test_file("src/app.js", ["test/app.test.js", "test/other.test.js"])
      "test/app.test.js"

      iex> find_best_test_file("src/app.js", [])
      nil
  """
  def find_best_test_file(_vulnerable_file, []), do: nil

  def find_best_test_file(vulnerable_file, candidate_files) do
    candidate_files
    |> Enum.map(fn file -> {file, calculate_score(vulnerable_file, file)} end)
    |> Enum.max_by(fn {_file, score} -> score end)
    |> elem(0)
  end

  @doc """
  Calculates total score for a test file candidate.

  Combines base path similarity with bonuses for module and directory matching.

  ## Range: 0.0-1.5

  - Base: 0.0-1.0 (path similarity)
  - Module bonus: +0.3
  - Directory bonus: +0.2

  ## Examples

      iex> calculate_score("lib/app/auth.ex", "test/app/auth_test.exs")
      1.5  # Perfect match with both bonuses

      iex> calculate_score("app/models/user.rb", "spec/controllers/admin_spec.rb")
      0.2  # Low similarity, no bonuses
  """
  def calculate_score(vulnerable_file, test_file) do
    base = path_similarity_score(vulnerable_file, test_file)
    module_bonus = if same_module?(vulnerable_file, test_file), do: 0.3, else: 0.0
    directory_bonus = if same_directory_structure?(vulnerable_file, test_file), do: 0.2, else: 0.0

    base + module_bonus + directory_bonus
  end

  @doc """
  Calculates path similarity score between two file paths.

  Uses Jaccard similarity on normalized path segments (filename + directories).

  ## Range: 0.0-1.0

  - 1.0: Identical normalized paths with strongly-paired prefixes (lib/test, spec/test)
  - 0.99: Identical normalized paths with different prefixes (src/test)
  - 0.5-0.8: Similar paths
  - <0.5: Different paths

  ## Examples

      iex> path_similarity_score("lib/services/user.ex", "test/services/user_test.exs")
      1.0  # Identical structure with strongly-paired prefixes

      iex> path_similarity_score("src/api/v1/users.js", "test/api/v1/users.test.js")
      0.99  # Identical structure with different prefixes

      iex> path_similarity_score("app/models/user.rb", "spec/controllers/admin_spec.rb")
      0.2  # Very different
  """
  def path_similarity_score(file1, file2) do
    # Normalize paths: extract segments without file extensions
    segments1 = normalize_path(file1)
    segments2 = normalize_path(file2)

    # Calculate similarity based on matching segments
    calculate_segment_similarity(segments1, segments2)
  end

  @doc """
  Checks if two files test the same module (ignoring test suffixes).

  ## Examples

      iex> same_module?("lib/services/payment.ex", "test/services/payment_test.exs")
      true

      iex> same_module?("src/utils/validator.js", "test/utils/validator.spec.js")
      true

      iex> same_module?("app/models/user.rb", "spec/models/account_spec.rb")
      false
  """
  def same_module?(file1, file2) do
    module1 = extract_module_name(file1)
    module2 = extract_module_name(file2)

    module1 != "" and module2 != "" and module1 == module2
  end

  @doc """
  Checks if two files have the same directory structure.

  Compares directory hierarchies, ignoring top-level source/test directories.

  ## Examples

      iex> same_directory_structure?("src/api/v2/handlers/auth.ts", "test/api/v2/handlers/auth.test.ts")
      true

      iex> same_directory_structure?("lib/services/user.ex", "test/unit/services/integration/user_test.exs")
      false

      iex> same_directory_structure?("app/controllers/admin.rb", "spec/requests/api_spec.rb")
      false
  """
  def same_directory_structure?(file1, file2) do
    dirs1 = extract_directory_structure(file1)
    dirs2 = extract_directory_structure(file2)

    dirs1 == dirs2 and dirs1 != []
  end

  # Private helper functions

  defp normalize_path(path) do
    path
    |> String.split("/")
    |> Enum.reject(&(&1 == "" or &1 in [".", ".."]))
  end

  defp remove_test_affixes(segment) do
    segment
    |> String.replace(~r/^test_/, "")
    |> String.replace(~r/_test$/, "")
    |> String.replace(~r/_spec$/, "")
    |> String.replace(~r/\.test$/, "")
    |> String.replace(~r/\.spec$/, "")
    |> String.replace(~r/Spec$/, "")
    |> String.replace(~r/Test$/, "")
  end

  defp remove_extension(segment) do
    segment
    |> Path.rootname()
    # Handle .test.js, .spec.ts, etc.
    |> Path.rootname()
  end

  # Strongly-paired prefixes (Ruby/Elixir conventions) get no penalty
  @strong_pairs [{"lib", "test"}, {"test", "lib"}, {"spec", "test"}, {"test", "spec"}]
  @all_prefixes ["lib", "test", "spec", "src", "__tests__", "tests"]

  defp calculate_segment_similarity(segments1, segments2) do
    # Normalize: remove extensions and test affixes
    norm1 = Enum.map(segments1, &normalize_segment/1)
    norm2 = Enum.map(segments2, &normalize_segment/1)

    # Split directories from filename
    {dirs1, file1} = split_dirs_and_file(norm1)
    {dirs2, file2} = split_dirs_and_file(norm2)

    # File match score (0.5 weight)
    file_score = calculate_file_similarity(file1, file2, dirs1, dirs2)

    # Directory match score (0.5 weight)
    dir_score = score_directory_similarity(dirs1, dirs2)

    file_score + dir_score
  end

  defp normalize_segment(segment) do
    segment |> remove_extension() |> remove_test_affixes()
  end

  # Calculate file similarity with enhanced Python test pattern matching
  defp calculate_file_similarity(file1, file2, dirs1, _dirs2) do
    cond do
      # Exact match - highest score
      file1 == file2 and file1 != "" ->
        0.5

      # Test file name matches a directory component in source path
      # e.g., test_dao.py matches sqli/dao/student.py
      # This is a strong signal that the test is for that module/layer
      file2 != "" and file2 in dirs1 ->
        0.5

      # Fuzzy match for singular/plural and common patterns
      fuzzy_match?(file1, file2) ->
        0.4

      # Check if test file relates to any directory in source
      # e.g., "dao" in dirs1 and "dao" in file2
      has_directory_overlap?(file2, dirs1) ->
        0.3

      true ->
        0.0
    end
  end

  # Check if two filenames are fuzzy matches (singular/plural, etc.)
  defp fuzzy_match?(file1, file2) when file1 == "" or file2 == "", do: false

  defp fuzzy_match?(file1, file2) do
    # Remove common suffixes
    base1 = String.replace(file1, ~r/(s|es|ies)$/, "")
    base2 = String.replace(file2, ~r/(s|es|ies)$/, "")

    # Check if one is the singular/plural of the other
    String.jaro_distance(base1, base2) > 0.85 or
      file1 == base2 or
      file2 == base1 or
      String.starts_with?(file1, file2) or
      String.starts_with?(file2, file1)
  end

  # Check if test filename component appears in any source directory
  defp has_directory_overlap?(_file, []), do: false

  defp has_directory_overlap?(file, dirs) do
    Enum.any?(dirs, fn dir ->
      String.contains?(file, dir) or String.contains?(dir, file)
    end)
  end

  defp score_directory_similarity(dirs1, dirs2) do
    # Remove known prefixes for comparison
    norm1 = remove_first_if_prefix(dirs1)
    norm2 = remove_first_if_prefix(dirs2)

    # Calculate Jaccard similarity
    base_score = directory_base_score(norm1, norm2)

    # Apply penalty if prefixes differ (except for strongly-paired prefixes)
    penalty = prefix_mismatch_penalty(dirs1, dirs2, norm1, norm2)

    # Boost score if there's any directory overlap even after normalization
    overlap_bonus = if has_any_directory_overlap?(norm1, norm2), do: 0.2, else: 0.0

    base_score - penalty + overlap_bonus
  end

  defp directory_base_score([], []), do: 0.5
  defp directory_base_score(dirs1, dirs2), do: jaccard_similarity(dirs1, dirs2) * 0.5

  # Check if there's any overlap between two directory lists
  defp has_any_directory_overlap?([], _), do: false
  defp has_any_directory_overlap?(_, []), do: false

  defp has_any_directory_overlap?(dirs1, dirs2) do
    set1 = MapSet.new(dirs1)
    set2 = MapSet.new(dirs2)
    MapSet.intersection(set1, set2) |> MapSet.size() > 0
  end

  defp jaccard_similarity(list1, list2) do
    set1 = MapSet.new(list1)
    set2 = MapSet.new(list2)
    intersection_size = MapSet.intersection(set1, set2) |> MapSet.size()
    union_size = MapSet.union(set1, set2) |> MapSet.size()

    if union_size == 0, do: 0.0, else: intersection_size / union_size
  end

  defp prefix_mismatch_penalty(dirs1, dirs2, norm1, norm2) do
    # No penalty if directories don't match perfectly after normalization
    if norm1 != norm2, do: 0.0, else: prefix_penalty(dirs1, dirs2)
  end

  defp prefix_penalty([first1 | _], [first2 | _])
       when first1 in @all_prefixes and first2 in @all_prefixes do
    if {first1, first2} in @strong_pairs, do: 0.0, else: 0.01
  end

  defp prefix_penalty(_, _), do: 0.0

  defp remove_first_if_prefix([first | rest]) when first in @all_prefixes, do: rest
  defp remove_first_if_prefix(segments), do: segments

  defp split_dirs_and_file([]), do: {[], ""}

  defp split_dirs_and_file(segments) do
    {Enum.drop(segments, -1), List.last(segments)}
  end

  defp extract_module_name(path) do
    path
    |> Path.basename()
    |> remove_extension()
    |> remove_test_affixes()
  end

  defp extract_directory_structure(path) do
    path
    |> Path.dirname()
    |> String.split("/")
    |> Enum.reject(&(&1 == "" or &1 == "."))
    # Remove common test/source prefixes
    |> Enum.reject(&(&1 in ["lib", "test", "spec", "src", "app", "__tests__", "tests"]))
  end

  defp explain_score(vulnerable_file, test_file) do
    score = calculate_score(vulnerable_file, test_file)
    has_module_match = same_module?(vulnerable_file, test_file)
    has_dir_match = same_directory_structure?(vulnerable_file, test_file)

    cond do
      score >= 1.5 and has_module_match and has_dir_match ->
        "Exact match: same module and directory structure"

      score >= 1.2 and has_module_match ->
        "Direct unit test for vulnerable file"

      score >= 1.0 and has_dir_match ->
        "Test in same directory structure"

      score >= 0.7 ->
        "Related test file with similar path"

      score >= 0.4 ->
        "Possibly related test file"

      true ->
        "Distant match"
    end
  end

  # Framework configuration for test file generation
  @framework_config %{
    "rspec" => %{extension: "_spec.rb", directory: "spec"},
    "vitest" => %{extension: ".test.ts", directory: "test"},
    "jest" => %{extension: ".test.js", directory: "test"},
    "pytest" => %{extension: "_test.py", directory: "tests"},
    "mocha" => %{extension: ".test.js", directory: "test"},
    "minitest" => %{extension: "_test.rb", directory: "test"}
  }
  @default_config %{extension: ".test.js", directory: "test"}

  defp generate_fallback_path(vulnerable_file, framework) do
    # Extract base name and directory
    base_name = Path.basename(vulnerable_file, Path.extname(vulnerable_file))
    dir_structure = extract_directory_structure(vulnerable_file)

    # Get framework-specific configuration
    config = Map.get(@framework_config, framework, @default_config)

    # Build fallback path: test_dir/security/dir_structure/base_name_security.ext
    fallback_segments =
      [config.directory, "security"] ++
        dir_structure ++ ["#{base_name}_security#{config.extension}"]

    fallback_path = Path.join(fallback_segments)

    %{
      path: fallback_path,
      reason: "No existing test found - suggest creating new security test file"
    }
  end
end
