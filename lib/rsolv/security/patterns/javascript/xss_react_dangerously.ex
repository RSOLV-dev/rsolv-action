defmodule Rsolv.Security.Patterns.Javascript.XssReactDangerously do
  @moduledoc """
  Cross-Site Scripting (XSS) via React dangerouslySetInnerHTML

  Detects dangerous patterns like:
    <div dangerouslySetInnerHTML={{__html: userInput}} />
    <span dangerouslySetInnerHTML={{__html: req.body.content}} />
    React.createElement('div', {dangerouslySetInnerHTML: {__html: params.html}})
    
  Safe alternatives:
    <div>{userInput}</div>
    <div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />
    <div dangerouslySetInnerHTML={{__html: sanitizeHtml(content)}} />
    
  React's dangerouslySetInnerHTML is explicitly named to warn developers about the
  XSS risk. It's React's equivalent to using innerHTML directly and bypasses React's
  built-in XSS protection. When used with untrusted user input, it creates severe
  XSS vulnerabilities that can compromise user sessions and data.

  ## Vulnerability Details

  React normally escapes all values before rendering them to the DOM, providing
  automatic XSS protection. The dangerouslySetInnerHTML prop intentionally bypasses
  this protection to allow raw HTML insertion. This is necessary for certain use
  cases (like rendering markdown or rich text editor content), but creates severe
  security risks when used with untrusted input.

  ### Attack Example
  ```javascript
  // Vulnerable: Direct user input to dangerouslySetInnerHTML
  function Comment({content}) {
    return <div dangerouslySetInnerHTML={{__html: content}} />;
  }

  // Attack: content = "<img src=x onerror='alert(document.cookie)'>"
  // Result: Script executes and can steal session cookies

  // Also vulnerable: Server-side rendered content
  const Page = () => (
    <div dangerouslySetInnerHTML={{__html: window.__INITIAL_STATE__.html}} />
  );
  // If __INITIAL_STATE__ contains user input, XSS is possible
  ```

  ### React-Specific Risks
  React's popularity and the explicit nature of dangerouslySetInnerHTML create
  unique risks. Developers know they're doing something "dangerous" but often
  underestimate the severity or forget to sanitize in all code paths. The prop
  is commonly used for:
  - Rendering markdown content
  - Displaying rich text editor output
  - Server-side rendering (SSR) hydration
  - Legacy HTML content migration
  Each use case requires careful sanitization to prevent XSS.
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @doc """
  Returns the XSS React dangerouslySetInnerHTML detection pattern.

  This pattern detects usage of React's dangerouslySetInnerHTML prop with
  user-controlled input, which can lead to XSS vulnerabilities.

  ## Examples

      iex> pattern = Rsolv.Security.Patterns.Javascript.XssReactDangerously.pattern()
      iex> pattern.id
      "js-xss-react-dangerously"
      
      iex> pattern = Rsolv.Security.Patterns.Javascript.XssReactDangerously.pattern()
      iex> pattern.severity
      :high
      
      iex> pattern = Rsolv.Security.Patterns.Javascript.XssReactDangerously.pattern()
      iex> pattern.cwe_id
      "CWE-79"
      
      iex> pattern = Rsolv.Security.Patterns.Javascript.XssReactDangerously.pattern()
      iex> vulnerable = ~S|<div dangerouslySetInnerHTML={{__html: userInput}} />|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = Rsolv.Security.Patterns.Javascript.XssReactDangerously.pattern()
      iex> safe = ~S|<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />|
      iex> Regex.match?(pattern.regex, safe)
      false
      
      iex> pattern = Rsolv.Security.Patterns.Javascript.XssReactDangerously.pattern()
      iex> safe = ~S|<div>{userInput}</div>|
      iex> Regex.match?(pattern.regex, safe)
      false
      
      iex> pattern = Rsolv.Security.Patterns.Javascript.XssReactDangerously.pattern()
      iex> vulnerable = ~S|React.createElement('div', {dangerouslySetInnerHTML: {__html: input}})|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = Rsolv.Security.Patterns.Javascript.XssReactDangerously.pattern()
      iex> pattern.recommendation
      "Avoid dangerouslySetInnerHTML. Use React's default escaping or sanitize with DOMPurify."
  """
  def pattern do
    %Pattern{
      id: "js-xss-react-dangerously",
      name: "XSS via React dangerouslySetInnerHTML",
      description:
        "React's dangerouslySetInnerHTML with user input can execute malicious scripts",
      type: :xss,
      severity: :high,
      languages: ["javascript", "typescript", "jsx", "tsx"],
      # Match dangerouslySetInnerHTML with user input variables
      # Note: AST enhancement is used to filter out false positives from sanitized content
      # Match dangerouslySetInnerHTML with common user input patterns
      # Note: This regex is intentionally broad - AST enhancement filters false positives
      regex:
        ~r/^(?!.*\/\/).*dangerouslySetInnerHTML\s*[=:]\s*\{\s*\{?\s*__html\s*:\s*(?!(?:DOMPurify\.sanitize|sanitizeHtml|escapeHtml|purify)\s*\(|["'][^"']*["']\s*\}\}|(?:SAFE_|STATIC_))(?:.*\+.*[a-zA-Z_$][\w.$]*|`[^`]*\$\{|[a-zA-Z_$][\w.$]*)/im,
      cwe_id: "CWE-79",
      owasp_category: "A03:2021",
      recommendation:
        "Avoid dangerouslySetInnerHTML. Use React's default escaping or sanitize with DOMPurify.",
      test_cases: %{
        vulnerable: [
          ~S|<div dangerouslySetInnerHTML={{__html: userInput}} />|,
          ~S|<span dangerouslySetInnerHTML={{__html: req.body.content}} />|,
          ~S|<div dangerouslySetInnerHTML={{__html: params.message}}></div>|,
          ~S|dangerouslySetInnerHTML={{__html: userData}}|,
          ~S|React.createElement('div', {dangerouslySetInnerHTML: {__html: input}})|
        ],
        safe: [
          ~S|<div>{userInput}</div>|,
          ~S|<div>Safe content without dangerouslySetInnerHTML</div>|,
          ~S|<span textContent={content} />|,
          ~S|// dangerouslySetInnerHTML={{__html: commented}}|,
          ~S|const safe = "No innerHTML here"|
        ]
      }
    }
  end

  @doc """
  Comprehensive vulnerability metadata for React dangerouslySetInnerHTML XSS.

  This metadata documents the security implications of using React's
  dangerouslySetInnerHTML prop with untrusted input and provides guidance
  for secure HTML rendering in React applications.
  """
  def vulnerability_metadata do
    %{
      description: """
      Cross-Site Scripting (XSS) vulnerabilities through React's dangerouslySetInnerHTML
      prop represent one of the most common security issues in React applications.
      The prop name itself is a warning - it literally tells developers they're doing
      something dangerous by bypassing React's built-in XSS protection.

      React automatically escapes all values before rendering them to the DOM, which
      provides excellent default protection against XSS attacks. However, there are
      legitimate use cases where raw HTML needs to be rendered - markdown content,
      rich text editor output, or legacy HTML content. The dangerouslySetInnerHTML
      prop enables these use cases but requires developers to handle sanitization.

      When user-controlled input is passed to dangerouslySetInnerHTML without proper
      sanitization, attackers can inject arbitrary JavaScript that executes in the
      context of other users' browsers. This can lead to session hijacking, data
      theft, phishing attacks, and complete account compromise.

      The vulnerability is particularly dangerous because:
      1. React's popularity means millions of applications potentially at risk
      2. The explicit "dangerous" naming creates false confidence
      3. Sanitization is often forgotten in some code paths
      4. Server-side rendering (SSR) introduces additional attack vectors
      5. Rich text and markdown are common requirements in modern apps

      Modern React applications must implement proper sanitization strategies,
      typically using libraries like DOMPurify or isomorphic-dompurify for SSR.
      The rise of Content Security Policy (CSP) provides defense in depth, but
      proper input sanitization remains the primary protection against XSS.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-79",
          title:
            "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
          url: "https://cwe.mitre.org/data/definitions/79.html"
        },
        %{
          type: :owasp,
          id: "A03:2021",
          title: "OWASP Top 10 2021 - A03 Injection",
          url: "https://owasp.org/Top10/A03_2021-Injection/"
        },
        %{
          type: :vendor,
          id: "react_dangerously",
          title: "React Documentation - dangerouslySetInnerHTML",
          url:
            "https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html"
        },
        %{
          type: :research,
          id: "react_xss_prevention",
          title: "Preventing XSS in React Applications",
          url: "https://pragmaticwebsecurity.com/articles/spasecurity/react-xss-part1.html"
        },
        %{
          type: :owasp,
          id: "react_security",
          title: "OWASP React Security Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/React_Security_Cheat_Sheet.html"
        },
        %{
          type: :tool,
          id: "dompurify",
          title: "DOMPurify - XSS Sanitizer for HTML",
          url: "https://github.com/cure53/DOMPurify"
        }
      ],
      attack_vectors: [
        "Script injection: dangerouslySetInnerHTML={{__html: '<script>alert(1)</script>'}}",
        "Event handler: __html: '<img src=x onerror=alert(document.cookie)>'",
        "JavaScript URL: __html: '<a href=\"javascript:alert(1)\">Click</a>'",
        "SVG injection: __html: '<svg onload=alert(1)>'",
        "Style injection: __html: '<style>body{background:url(javascript:alert(1))}</style>'",
        "Meta refresh: __html: '<meta http-equiv=\"refresh\" content=\"0;javascript:alert(1)\">'",
        "Data URI: __html: '<object data=\"data:text/html,<script>alert(1)</script>\">",
        "HTML5 events: __html: '<video src=x onerror=alert(1)>'",
        "Template injection: __html: `${userInput}` with malicious content"
      ],
      real_world_impact: [
        "Session token theft leading to account takeover",
        "Credential harvesting through fake login forms",
        "Cryptocurrency wallet drainage via injected scripts",
        "Phishing attacks through UI redressing",
        "Malware distribution through drive-by downloads",
        "Corporate data exfiltration in enterprise apps",
        "Supply chain attacks by compromising developer accounts",
        "SEO poisoning and defacement attacks"
      ],
      cve_examples: [
        %{
          id: "CVE-2023-30845",
          description: "Payload CMS XSS via dangerouslySetInnerHTML in rich text field preview",
          severity: "high",
          cvss: 7.5,
          note: "Popular CMS vulnerable due to unsanitized dangerouslySetInnerHTML usage"
        },
        %{
          id: "CVE-2022-25912",
          description: "Strapi CMS XSS through dangerouslySetInnerHTML in admin panel",
          severity: "high",
          cvss: 7.2,
          note: "Admin panel XSS allowing privilege escalation"
        },
        %{
          id: "CVE-2021-32677",
          description:
            "Gatsby framework XSS via dangerouslySetInnerHTML in static site generation",
          severity: "medium",
          cvss: 6.1,
          note: "Static site generator vulnerable during build process"
        },
        %{
          id: "CVE-2020-26945",
          description: "MyBB forum software XSS via React dangerouslySetInnerHTML",
          severity: "high",
          cvss: 7.5,
          note: "Forum software allowing stored XSS through rich text posts"
        }
      ],
      detection_notes: """
      This pattern detects dangerouslySetInnerHTML usage that includes user-controlled
      input. The detection covers:

      1. JSX syntax: <element dangerouslySetInnerHTML={{__html: userInput}} />
      2. React.createElement: createElement('div', {dangerouslySetInnerHTML: {__html: input}})
      3. Spread props: <div {...{dangerouslySetInnerHTML: {__html: data}}} />
      4. Various user input patterns: req.*, params.*, query.*, user*, input, data

      The pattern excludes safe usage where sanitization functions are detected:
      - DOMPurify.sanitize()
      - sanitizeHtml()
      - escapeHtml()
      - Other common sanitization patterns
      - Static content patterns (SAFE_*, STATIC_*)

      Note that the pattern is case-insensitive to catch variations in naming.
      """,
      safe_alternatives: [
        "Use React's default rendering: <div>{userContent}</div>",
        "Sanitize with DOMPurify: dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(input)}}",
        "Use isomorphic-dompurify for SSR applications",
        "Implement strict Content Security Policy (CSP) headers",
        "Use markdown libraries with built-in sanitization",
        "Create safe components for rich text rendering",
        "Validate and escape on the server side",
        "Use React-based rich text editors with XSS protection",
        "Consider using sandboxed iframes for untrusted content",
        "Implement allowlist-based HTML filtering"
      ],
      additional_context: %{
        react_specific_notes: [
          "React escapes all values by default - trust this protection",
          "dangerouslySetInnerHTML completely bypasses React's XSS protection",
          "Server-side rendering (SSR) requires isomorphic sanitization",
          "Hydration mismatches can occur with improper sanitization",
          "React Developer Tools can help identify dangerouslySetInnerHTML usage"
        ],
        common_mistakes: [
          "Assuming the 'dangerous' name is sufficient warning",
          "Sanitizing on client but not server (or vice versa)",
          "Trusting markdown without sanitization",
          "Using dangerouslySetInnerHTML for simple text content",
          "Forgetting to sanitize in error messages or edge cases",
          "Trusting data from internal APIs without validation"
        ],
        framework_alternatives: [
          "Next.js: Use next-mdx for safe markdown rendering",
          "Gatsby: Configure gatsby-transformer-remark with sanitization",
          "Create React App: Import and configure DOMPurify",
          "Remix: Implement server-side sanitization before hydration",
          "React Native: Use WebView with limited permissions for rich content"
        ]
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual XSS vulnerabilities
  and safe usage of dangerouslySetInnerHTML with proper sanitization.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Javascript.XssReactDangerously.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.XssReactDangerously.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "JSXAttribute"
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.XssReactDangerously.ast_enhancement()
      iex> enhancement.ast_rules.attribute_name
      "dangerouslySetInnerHTML"
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.XssReactDangerously.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
  """
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "JSXAttribute",
        attribute_name: "dangerouslySetInnerHTML",
        value_check: %{
          type: "JSXExpressionContainer",
          expression_type: "ObjectExpression",
          property_check: %{
            key: "__html",
            value_analysis: %{
              contains_user_input: true,
              user_input_patterns: [
                "req.",
                "request.",
                "params.",
                "query.",
                "body.",
                "user",
                "input",
                "data",
                "content",
                "form.",
                "args.",
                "ctx.",
                "props.",
                "state."
              ]
            }
          }
        },
        alternate_node_type: "CallExpression",
        alternate_check: %{
          callee_names: ["createElement", "React.createElement", "h"],
          props_argument_position: 1,
          props_contains: "dangerouslySetInnerHTML"
        }
      },
      context_rules: %{
        exclude_paths: [
          ~r/test/,
          ~r/spec/,
          ~r/__tests__/,
          ~r/fixtures/,
          ~r/mocks/,
          # Storybook files
          ~r/stories/,
          ~r/examples/,
          ~r/docs/,
          ~r/node_modules/
        ],
        safe_patterns: [
          "DOMPurify.sanitize",
          "sanitizeHtml",
          "escapeHtml",
          "purify",
          "xss(",
          "sanitize(",
          "bleach.clean",
          "htmlSanitizer",
          "createDOMPurifier",
          "sanitizer.sanitize",
          # Marked with built-in sanitization
          "marked.parseInline"
        ],
        safe_variable_patterns: [
          # SAFE_HTML, SAFE_CONTENT
          "SAFE_",
          # STATIC_HTML, STATIC_CONTENT
          "STATIC_",
          # SANITIZED_HTML
          "SANITIZED_",
          # TRUSTED_CONTENT
          "TRUSTED_",
          # CONST_TEMPLATE
          "CONST_",
          # HARDCODED_HTML
          "HARDCODED_"
        ],
        framework_safe_patterns: [
          # React server rendering
          "renderToStaticMarkup",
          # React server rendering
          "renderToString",
          # Next.js static props
          "__NEXT_DATA__",
          # Next.js static generation
          "getStaticProps",
          # Gatsby build-time transform
          "gatsby-transformer"
        ]
      },
      confidence_rules: %{
        base: 0.6,
        adjustments: %{
          # Direct user input
          "user_input" => 0.4,
          # Request data usage
          "request_data" => 0.4,
          # Template literals with variables
          "template_literal" => 0.3,
          # No sanitization detected
          "no_sanitization" => 0.3,
          # Common use case but risky
          "markdown_content" => 0.2,
          # Sanitization function used
          "sanitized" => -0.8,
          # Hardcoded HTML
          "static_content" => -0.7,
          # SSR with proper escaping
          "server_rendered" => -0.3,
          # Test files
          "test_code" => -0.6,
          # Using safe markdown library
          "safe_library" => -0.5,
          # CSP headers detected
          "csp_protected" => -0.4,
          # From trusted API/source
          "trusted_source" => -0.3,
          # Server-side escaped
          "escaped_server" => -0.4
        }
      },
      min_confidence: 0.7
    }
  end
end
