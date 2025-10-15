defmodule Rsolv.Security.Patterns.Elixir.UnsafeAtomCreation do
  @moduledoc """
  Detects unsafe atom creation from user input in Elixir.

  This pattern identifies dynamic atom creation using String.to_atom/1, :erlang.binary_to_atom/2,
  or List.to_atom/1 with user-provided data. These operations can lead to atom table exhaustion
  attacks since atoms are never garbage collected in the BEAM VM.

  ## Vulnerability Details

  The BEAM VM (Erlang/Elixir runtime) has a finite atom table that stores all atoms created
  during the lifetime of the VM. By default, this table is limited to about 1 million atoms.
  Once exhausted, the VM crashes. Atoms are never garbage collected, making dynamic atom
  creation from user input a serious denial-of-service vulnerability.

  ### Attack Example

  Vulnerable code:
  ```elixir
  # Controller accepting user input
  def process(conn, %{"action" => action}) do
    atom_action = String.to_atom(action)  # VULNERABLE!
    apply(__MODULE__, atom_action, [conn])
  end
  ```

  An attacker can send millions of requests with different action values, exhausting the atom table.

  ### Safe Alternative

  Safe code:
  ```elixir
  # Use String.to_existing_atom/1 or pattern matching
  def process(conn, %{"action" => action}) do
    case action do
      "create" -> create(conn)
      "update" -> update(conn)
      "delete" -> delete(conn)
      _ -> {:error, :invalid_action}
    end
  end
  ```
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @impl true
  def pattern do
    %Pattern{
      id: "elixir-unsafe-atom-creation",
      name: "Unsafe Atom Creation",
      description: "Dynamic atom creation from user input can exhaust the atom table",
      type: :denial_of_service,
      severity: :high,
      languages: ["elixir"],
      regex: [
        # String.to_atom with any input
        ~r/String\.to_atom\s*\(/,
        # :erlang.binary_to_atom usage
        ~r/:erlang\.binary_to_atom\s*\(/,
        # List.to_atom usage
        ~r/List\.to_atom\s*\(/,
        # Pipe to String.to_atom
        ~r/\|>\s*String\.to_atom/,
        # Dynamic atom interpolation (less common but possible)
        ~r/:"#\{[^}]*(?:params|user|input|data)[^}]*\}"/i
      ],
      cwe_id: "CWE-400",
      owasp_category: "A05:2021",
      recommendation:
        "Use String.to_existing_atom/1 or pattern matching instead of dynamic atom creation",
      test_cases: %{
        vulnerable: [
          ~S|String.to_atom(params["key"])|,
          ~S|String.to_atom(user_input)|,
          ~S|:erlang.binary_to_atom(data, :utf8)|,
          ~S|List.to_atom(char_list)|,
          "params[\"action\"] |> String.to_atom()",
          ~S|:"#{user_provided_string}"|
        ],
        safe: [
          ~S|String.to_existing_atom(params["key"])|,
          ~S|:erlang.binary_to_existing_atom(data, :utf8)|,
          ~S|case user_input do
  "create" -> :create
  "update" -> :update
  _ -> :unknown
end|,
          ~S|Map.get(data, :key)|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Unsafe atom creation in Elixir occurs when developers use String.to_atom/1,
      :erlang.binary_to_atom/2, or List.to_atom/1 with user-controlled input. The BEAM VM
      stores all atoms in a global atom table that has a finite size (default ~1M atoms) and
      atoms are never garbage collected. An attacker can exhaust this table by sending
      requests with unique values, causing the entire VM to crash with an 'atom table full'
      error. This is a particularly severe DoS vulnerability because it affects the entire
      Erlang node, not just a single process.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-400",
          title: "Uncontrolled Resource Consumption",
          url: "https://cwe.mitre.org/data/definitions/400.html"
        },
        %{
          type: :owasp,
          id: "A05:2021",
          title: "OWASP Top 10 2021 - A05 Security Misconfiguration",
          url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
        },
        %{
          type: :research,
          id: "erlang_atom_dos",
          title: "Preventing Atom DoS Attacks in Elixir",
          url: "https://paraxial.io/blog/atom-dos"
        },
        %{
          type: :research,
          id: "beam_atom_exhaustion",
          title: "Understanding Atom Exhaustion in BEAM",
          url: "https://www.erlang-solutions.com/blog/avoiding-atom-exhaustion-in-elixir/"
        }
      ],
      attack_vectors: [
        "HTTP parameter manipulation: Sending millions of unique parameter values",
        "WebSocket message flooding: Rapid unique message types to exhaust atoms",
        "JSON key injection: Providing JSON with millions of unique keys when parsed with atom keys",
        "GraphQL field injection: Dynamic field names converted to atoms",
        "Configuration injection: User-provided config values converted to atoms"
      ],
      real_world_impact: [
        "Complete node crash requiring restart (affects all applications on the node)",
        "Service unavailability until manual intervention",
        "Potential data loss if in-memory state not persisted",
        "Cascading failures in distributed systems when nodes crash",
        "Extended downtime if atom limit needs to be increased and redeployed"
      ],
      cve_examples: [
        %{
          id: "CVE-2022-24795",
          description: "yajl-ruby gem allows remote DoS via atom exhaustion",
          severity: "high",
          cvss: 7.5,
          note: "Demonstrates how JSON parsing with atom keys can lead to atom exhaustion"
        },
        %{
          id: "CVE-2013-4164",
          description: "Ruby on Rails atom DoS vulnerability",
          severity: "high",
          cvss: 7.5,
          note: "Similar vulnerability showing impact of converting user input to symbols/atoms"
        }
      ],
      detection_notes: """
      This pattern detects various forms of unsafe atom creation:
      - Direct String.to_atom/1 calls
      - Erlang's binary_to_atom/2 function
      - List.to_atom/1 for character lists
      - Piped operations to to_atom
      - Dynamic atom interpolation with user data
      """,
      safe_alternatives: [
        "Use String.to_existing_atom/1 - only creates atom if it already exists",
        "Use pattern matching with known atoms instead of dynamic creation",
        "Use strings as map keys instead of atoms for user data",
        "Create a whitelist of allowed atoms and validate before conversion",
        "Use GenServer calls with predefined message atoms rather than dynamic ones"
      ],
      additional_context: %{
        common_mistakes: [
          "Thinking atoms are garbage collected like other data types",
          "Using String.to_atom for user-provided action/command routing",
          "Converting JSON keys to atoms without validation",
          "Not understanding that atom table is VM-wide, not per-process"
        ],
        secure_patterns: [
          "Always use to_existing_atom variants for user input",
          "Define all possible atoms at compile time",
          "Use strings or binaries for dynamic user data",
          "Implement explicit pattern matching for routing"
        ]
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual vulnerabilities and false positives
  by analyzing context and usage patterns.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Elixir.UnsafeAtomCreation.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]

      iex> enhancement = Rsolv.Security.Patterns.Elixir.UnsafeAtomCreation.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        atom_analysis: %{
          check_atom_creation: true,
          dangerous_functions: ["String.to_atom", ":erlang.binary_to_atom", "List.to_atom"],
          safe_functions: ["String.to_existing_atom", ":erlang.binary_to_existing_atom"],
          check_input_source: true
        },
        input_analysis: %{
          user_input_indicators: [
            "params",
            "conn.params",
            "user",
            "input",
            "data",
            "request",
            "body"
          ],
          check_variable_flow: true,
          check_function_arguments: true
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/_test\.exs$/],
        user_input_sources: [
          "params",
          "conn.params",
          "conn.body_params",
          "socket.assigns",
          "args",
          "input"
        ],
        safe_contexts: ["migration", "seed", "config", "compile"],
        exclude_hardcoded_strings: true
      },
      confidence_rules: %{
        base: 0.6,
        adjustments: %{
          "has_user_input" => 0.4,
          "uses_existing_atom" => -0.9,
          "in_test_code" => -1.0,
          "hardcoded_string" => -0.8,
          "in_safe_context" => -0.7
        }
      },
      min_confidence: 0.7
    }
  end
end
