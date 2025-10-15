defmodule Rsolv.Security.Patterns.Elixir.DeserializationErlang do
  @moduledoc """
  Detects unsafe Erlang term deserialization vulnerabilities in Elixir.

  This pattern identifies the use of :erlang.binary_to_term/1 and :erlang.binary_to_term/2
  which can lead to remote code execution when deserializing untrusted data. Even when
  using the [:safe] option, the function can still execute anonymous functions embedded
  in the serialized data.

  ## Vulnerability Details

  The External Term Format (ETF) used by Erlang can represent any Erlang/Elixir term,
  including functions. When binary_to_term deserializes data containing functions,
  those functions can be executed. This poses a severe security risk when processing
  untrusted input, as attackers can embed malicious code.

  ### Attack Example

  Vulnerable code:
  ```elixir
  # Web handler deserializing user data
  def handle_request(conn, %{"data" => encoded_data}) do
    binary = Base.decode64!(encoded_data)
    result = :erlang.binary_to_term(binary)  # CRITICAL VULNERABILITY!
    # Attacker can execute arbitrary code
  end
  ```

  An attacker can serialize malicious functions and execute them on the server.

  ### Safe Alternative

  Safe code:
  ```elixir
  # Use JSON for data exchange
  def handle_request(conn, %{"data" => json_data}) do
    case Jason.decode(json_data) do
      {:ok, data} -> process_safe_data(data)
      {:error, _} -> {:error, "Invalid JSON"}
    end
  end

  # Or if ETF is required, use [:safe] and validate no functions
  def deserialize_safe(binary) do
    try do
      # [:safe] prevents atom creation but NOT function execution!
      term = :erlang.binary_to_term(binary, [:safe])
      if contains_function?(term) do
        {:error, "Functions not allowed"}
      else
        {:ok, term}
      end
    rescue
      _ -> {:error, "Invalid data"}
    end
  end
  ```
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @impl true
  def pattern do
    %Pattern{
      id: "elixir-deserialization-erlang",
      name: "Unsafe Erlang Term Deserialization",
      description: "binary_to_term can execute arbitrary code when deserializing untrusted data",
      type: :deserialization,
      severity: :critical,
      languages: ["elixir"],
      regex: [
        # Direct binary_to_term calls (exclude comments)
        ~r/^(?!\s*#).*:erlang\.binary_to_term\s*\(/m,
        # With safe option (still vulnerable to function execution)
        ~r/^(?!\s*#).*:erlang\.binary_to_term\s*\([^,)]+,\s*\[.*:safe/m,
        # Piped to binary_to_term
        ~r/^(?!\s*#).*\|>\s*:erlang\.binary_to_term/m,
        # Variable assignment
        ~r/^(?!\s*#).*=\s*:erlang\.binary_to_term\s*\(/m,
        # In function calls
        ~r/^(?!\s*#).*apply\s*\(\s*:erlang\s*,\s*:binary_to_term/m
      ],
      cwe_id: "CWE-502",
      owasp_category: "A08:2021",
      recommendation:
        "Use JSON for data serialization or validate deserialized data contains no functions",
      test_cases: %{
        vulnerable: [
          ~S|:erlang.binary_to_term(user_data)|,
          ~S|data = :erlang.binary_to_term(Base.decode64!(encoded))|,
          ~S|:erlang.binary_to_term(user_data, [:safe])|
        ],
        safe: [
          ~S|Jason.decode!(user_data)|,
          ~S|:erlang.term_to_binary(data)|,
          ~S|# :erlang.binary_to_term(data) - commented out|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Unsafe deserialization of Erlang External Term Format (ETF) is a critical vulnerability that
      occurs when :erlang.binary_to_term/1 or :erlang.binary_to_term/2 is used with untrusted
      input. The ETF format can encode any Erlang/Elixir term, including anonymous functions.
      When these functions are deserialized, they can be executed, leading to remote code execution.

      Even the [:safe] option only prevents atom exhaustion attacks - it does NOT prevent function
      execution. This makes binary_to_term inherently unsafe for untrusted data, regardless of
      options used. Attackers can craft malicious payloads that execute arbitrary code with the
      privileges of the application process.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-502",
          title: "Deserialization of Untrusted Data",
          url: "https://cwe.mitre.org/data/definitions/502.html"
        },
        %{
          type: :owasp,
          id: "A08:2021",
          title: "OWASP Top 10 2021 - A08 Software and Data Integrity Failures",
          url: "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
        },
        %{
          type: :research,
          id: "erlef_serialization",
          title: "ErlEF Security WG - Serialisation and Deserialisation",
          url:
            "https://security.erlef.org/secure_coding_and_deployment_hardening/serialisation.html"
        },
        %{
          type: :research,
          id: "paraxial_rce",
          title: "Elixir/Phoenix Security: Remote Code Execution and Serialisation",
          url: "https://paraxial.io/blog/elixir-rce"
        }
      ],
      attack_vectors: [
        "Embedding anonymous functions in ETF that execute on deserialization",
        "Using fun references to call arbitrary module functions",
        "Chaining function calls to achieve code execution",
        "Exploiting process dictionary or ETS table access",
        "Atom exhaustion attacks (mitigated by [:safe] option)",
        "Denial of service through large or complex terms",
        "Data exfiltration through function side effects"
      ],
      real_world_impact: [
        "Complete server compromise with application privileges",
        "Data theft including database credentials and API keys",
        "Installation of backdoors and persistent access",
        "Lateral movement to other services in the cluster",
        "Cryptocurrency mining using server resources",
        "Destruction of data or service availability",
        "Supply chain attacks by modifying application behavior"
      ],
      cve_examples: [
        %{
          id: "CVE-2020-15150",
          description: "RCE in Elixir Paginator library via binary_to_term",
          severity: "critical",
          cvss: 9.8,
          note: "Paginator used binary_to_term on user input allowing arbitrary code execution"
        }
      ],
      detection_notes: """
      This pattern detects:
      - Direct calls to :erlang.binary_to_term with any arguments
      - Usage with [:safe] option (still vulnerable to function execution)
      - Piped operations to binary_to_term
      - Variable assignments from binary_to_term results
      - Dynamic calls via apply/3
      """,
      safe_alternatives: [
        "Use JSON (Jason) for data serialization between untrusted parties",
        "Use Protocol Buffers or MessagePack for binary serialization",
        "If ETF is required, implement strict validation to reject functions",
        "Use :erlang.binary_to_term(data, [:safe]) AND check for functions",
        "Implement a whitelist of allowed term structures",
        "Run deserialization in an isolated process with restricted permissions"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing [:safe] option prevents all attacks (it doesn't prevent RCE)",
          "Using binary_to_term for caching without considering cache poisoning",
          "Deserializing data from cookies or client-side storage",
          "Not validating the structure of deserialized terms"
        ],
        secure_patterns: [
          "Always use JSON for client-server communication",
          "Validate all deserialized data against expected schemas",
          "Never deserialize data from untrusted sources",
          "Use cryptographic signatures to verify data integrity"
        ]
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual vulnerabilities and false positives
  by analyzing context and usage patterns.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Elixir.DeserializationErlang.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Elixir.DeserializationErlang.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        deserialization_analysis: %{
          check_binary_to_term: true,
          dangerous_functions: [":erlang.binary_to_term"],
          check_safe_option: true,
          check_input_source: true
        },
        input_analysis: %{
          user_input_indicators: [
            "params",
            "conn",
            "socket",
            "request",
            "body",
            "data",
            "encoded",
            "payload",
            "input",
            "user",
            "client"
          ],
          check_base64_decode: true,
          check_network_sources: true
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/_test\.exs$/, ~r/fixture/],
        user_input_sources: [
          "params",
          "conn.params",
          "conn.body_params",
          "socket.assigns",
          "request",
          "Base.decode64!",
          "File.read!",
          "HTTPoison.get!"
        ],
        safe_sources: ["Application.get_env", "Config.get", ":ets.lookup"],
        exclude_if_trusted_source: true
      },
      confidence_rules: %{
        base: 0.7,
        adjustments: %{
          "has_user_input" => 0.3,
          # Still vulnerable but slightly lower confidence
          "uses_safe_option" => -0.2,
          "from_trusted_source" => -0.8,
          "in_test_code" => -1.0,
          "has_validation" => -0.3
        }
      },
      min_confidence: 0.8
    }
  end
end
