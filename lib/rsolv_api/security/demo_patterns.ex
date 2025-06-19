defmodule RsolvApi.Security.DemoPatterns do
  @moduledoc """
  Demo patterns available without an API key.
  
  These patterns demonstrate RSOLV's capabilities and encourage users to upgrade
  for access to the full set of 172+ security patterns.
  """
  
  alias RsolvApi.Security.Pattern
  
  @doc """
  Returns a curated set of demo patterns for users without an API key.
  
  The demo patterns are chosen to:
  - Show high-impact vulnerabilities (SQL injection, XSS, etc.)
  - Cover multiple languages
  - Demonstrate the value of the full pattern set
  - Encourage users to get an API key
  """
  def get_demo_patterns(language \\ nil) do
    all_demo_patterns()
    |> filter_by_language(language)
  end
  
  defp all_demo_patterns do
    [
      # JavaScript patterns (5)
      %Pattern{
        id: "js-sql-injection-concat",
        name: "SQL Injection via String Concatenation",
        description: "Detects SQL injection vulnerabilities from string concatenation",
        type: :sql_injection,
        severity: :critical,
        languages: ["javascript", "typescript"],
        regex: ~r/query\s*=.*["'`].*\s*\+\s*[^"'`]+(?:WHERE|FROM|SELECT|INSERT|UPDATE|DELETE)/i,
        cwe_id: "CWE-89",
        owasp_category: "A03:2021",
        recommendation: "Use parameterized queries or prepared statements",
        test_cases: %{
          vulnerable: [
            ~s|query = "SELECT * FROM users WHERE id = " + userId|,
            ~s|sql = 'DELETE FROM items WHERE id = ' + itemId|
          ],
          safe: [
            ~s|query = "SELECT * FROM users WHERE id = ?"|,
            ~s|db.query('SELECT * FROM users WHERE id = ?', [userId])|
          ]
        }
      },
      %Pattern{
        id: "js-xss-innerhtml",
        name: "Cross-Site Scripting via innerHTML",
        description: "Detects XSS vulnerabilities from innerHTML assignments",
        type: :xss,
        severity: :high,
        languages: ["javascript", "typescript"],
        regex: ~r/\.innerHTML\s*=\s*[^"'`]+(?:\+|`[^`]*\$\{)/,
        cwe_id: "CWE-79",
        owasp_category: "A03:2021",
        recommendation: "Use textContent or sanitize HTML content",
        test_cases: %{
          vulnerable: [
            ~s|element.innerHTML = userInput|,
            ~s|div.innerHTML = "<p>" + data + "</p>"|
          ],
          safe: [
            ~s|element.textContent = userInput|,
            ~s|element.innerHTML = DOMPurify.sanitize(userInput)|
          ]
        }
      },
      %Pattern{
        id: "js-command-injection-exec",
        name: "Command Injection via exec",
        description: "Detects command injection through child_process.exec",
        type: :command_injection,
        severity: :critical,
        languages: ["javascript", "typescript"],
        regex: ~r/(?:exec|execSync)\s*\(\s*["`']?[^"'`]*?\$\{|(?:exec|execSync)\s*\(\s*[^)]*?\+/,
        cwe_id: "CWE-78",
        owasp_category: "A03:2021",
        recommendation: "Use execFile with argument array instead",
        test_cases: %{
          vulnerable: [
            ~s|exec('ls ' + userPath)|,
            ~s|exec(`rm -rf ${directory}`)|
          ],
          safe: [
            ~s|execFile('ls', [userPath])|,
            ~s|spawn('rm', ['-rf', directory])|
          ]
        }
      },
      %Pattern{
        id: "js-weak-crypto-md5",
        name: "Weak Cryptography - MD5",
        description: "Detects usage of weak MD5 hashing",
        type: :crypto,
        severity: :medium,
        languages: ["javascript", "typescript"],
        regex: ~r/crypto\.createHash\s*\(\s*["']md5["']\s*\)|\.md5\s*\(/,
        cwe_id: "CWE-327",
        owasp_category: "A02:2021",
        recommendation: "Use SHA-256 or stronger algorithms",
        test_cases: %{
          vulnerable: [
            ~s|crypto.createHash('md5')|,
            ~s|hash.md5(password)|
          ],
          safe: [
            ~s|crypto.createHash('sha256')|,
            ~s|bcrypt.hash(password, 10)|
          ]
        }
      },
      %Pattern{
        id: "js-hardcoded-secret-api-key",
        name: "Hardcoded API Key",
        description: "Detects hardcoded API keys in source code",
        type: :hardcoded_secret,
        severity: :high,
        languages: ["javascript", "typescript"],
        regex: ~r/(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["'][\w-]{20,}/i,
        cwe_id: "CWE-798",
        owasp_category: "A07:2021",
        recommendation: "Use environment variables or secure key management",
        test_cases: %{
          vulnerable: [
            ~s|const API_KEY = "sk_live_abcd1234efgh5678"|,
            ~s|apiKey: "1234567890abcdef"|
          ],
          safe: [
            ~s|const API_KEY = process.env.API_KEY|,
            ~s|apiKey: config.get('apiKey')|
          ]
        }
      },
      
      # Python patterns (4)
      %Pattern{
        id: "python-sql-injection-format",
        name: "SQL Injection via % Formatting",
        description: "Detects SQL injection through string formatting",
        type: :sql_injection,
        severity: :critical,
        languages: ["python"],
        regex: ~r/(?:cursor\.execute|db\.execute|execute)\s*\(\s*["'].*%[sd].*["']\s*%/,
        cwe_id: "CWE-89",
        owasp_category: "A03:2021",
        recommendation: "Use parameterized queries",
        test_cases: %{
          vulnerable: [
            ~s|cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)|,
            ~s|db.execute("DELETE FROM items WHERE name = '%s'" % name)|
          ],
          safe: [
            ~s|cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))|,
            ~s|db.execute("DELETE FROM items WHERE name = ?", [name])|
          ]
        }
      },
      %Pattern{
        id: "python-command-injection-os-system",
        name: "Command Injection via os.system",
        description: "Detects command injection through os.system",
        type: :command_injection,
        severity: :critical,
        languages: ["python"],
        regex: ~r/os\.system\s*\(\s*[^)]*?(?:\+|%|\.format|f["'])/,
        cwe_id: "CWE-78",
        owasp_category: "A03:2021",
        recommendation: "Use subprocess with argument list",
        test_cases: %{
          vulnerable: [
            ~s|os.system("ls " + directory)|,
            ~s|os.system(f"rm {filename}")|
          ],
          safe: [
            ~s|subprocess.run(["ls", directory])|,
            ~s|subprocess.run(["rm", filename], check=True)|
          ]
        }
      },
      %Pattern{
        id: "python-unsafe-pickle",
        name: "Insecure Deserialization via pickle",
        description: "Detects unsafe pickle deserialization",
        type: :deserialization,
        severity: :critical,
        languages: ["python"],
        regex: ~r/pickle\.load[s]?\s*\(|pickle\.Unpickler/,
        cwe_id: "CWE-502",
        owasp_category: "A08:2021",
        recommendation: "Use JSON or other safe formats",
        test_cases: %{
          vulnerable: [
            ~s|data = pickle.loads(user_input)|,
            ~s|obj = pickle.load(file)|
          ],
          safe: [
            ~s|data = json.loads(user_input)|,
            ~s|obj = json.load(file)|
          ]
        }
      },
      %Pattern{
        id: "python-weak-hash-md5",
        name: "Weak Cryptographic Hash - MD5",
        description: "Detects usage of weak MD5 hashing",
        type: :crypto,
        severity: :medium,
        languages: ["python"],
        regex: ~r/hashlib\.md5\s*\(|md5\.new\s*\(/,
        cwe_id: "CWE-327",
        owasp_category: "A02:2021",
        recommendation: "Use SHA-256 or bcrypt for passwords",
        test_cases: %{
          vulnerable: [
            ~s|hashlib.md5(password.encode())|,
            ~s|md5.new(data)|
          ],
          safe: [
            ~s|hashlib.sha256(data.encode())|,
            ~s|bcrypt.hashpw(password.encode(), bcrypt.gensalt())|
          ]
        }
      },
      
      # Ruby patterns (3)
      %Pattern{
        id: "ruby-sql-injection-interpolation",
        name: "SQL Injection via String Interpolation",
        description: "Detects SQL injection through string interpolation",
        type: :sql_injection,
        severity: :critical,
        languages: ["ruby"],
        regex: ~r/(?:find_by_sql|where|execute)\s*\(\s*["'`].*#\{/,
        cwe_id: "CWE-89",
        owasp_category: "A03:2021",
        recommendation: "Use parameterized queries or ActiveRecord methods",
        test_cases: %{
          vulnerable: [
            ~s|User.where("name = '\#{params[:name]}'")|,
            ~s|execute("SELECT * FROM users WHERE id = \#{id}")|
          ],
          safe: [
            ~s|User.where(name: params[:name])|,
            ~s|User.where(["name = ?", params[:name]])|
          ]
        }
      },
      %Pattern{
        id: "ruby-mass-assignment",
        name: "Mass Assignment Vulnerability",
        description: "Detects potential mass assignment issues",
        type: :mass_assignment,
        severity: :high,
        languages: ["ruby"],
        regex: ~r/params\.require\s*\(\s*:\w+\s*\)(?!\.permit)/,
        cwe_id: "CWE-915",
        owasp_category: "A08:2021",
        recommendation: "Use strong parameters with permit",
        test_cases: %{
          vulnerable: [
            ~s|User.create(params.require(:user))|,
            ~s|@user.update(params[:user])|
          ],
          safe: [
            ~s|User.create(user_params)|,
            ~s|@user.update(params.require(:user).permit(:name, :email))|
          ]
        }
      },
      %Pattern{
        id: "ruby-command-injection",
        name: "Command Injection",
        description: "Detects command injection vulnerabilities",
        type: :command_injection,
        severity: :critical,
        languages: ["ruby"],
        regex: ~r/(?:system|exec|`)\s*\(?\s*["'`]?.*#\{|(?:system|exec)\s*\(?\s*[^,\)]*?\+/,
        cwe_id: "CWE-78",
        owasp_category: "A03:2021",
        recommendation: "Use array form of system/exec or Open3",
        test_cases: %{
          vulnerable: [
            ~s|system("ls \#{directory}")|,
            ~s|`rm \#{file}`|
          ],
          safe: [
            ~s|system("ls", directory)|,
            ~s|Open3.capture3("rm", file)|
          ]
        }
      },
      
      # Java patterns (3)
      %Pattern{
        id: "java-sql-injection-statement",
        name: "SQL Injection via Statement",
        description: "Detects SQL injection through Statement concatenation",
        type: :sql_injection,
        severity: :critical,
        languages: ["java"],
        regex: ~r/(?:createStatement|executeQuery|executeUpdate)\s*\([^)]*?\+|".*(?:SELECT|INSERT|UPDATE|DELETE).*"\s*\+/,
        cwe_id: "CWE-89",
        owasp_category: "A03:2021",
        recommendation: "Use PreparedStatement with parameters",
        test_cases: %{
          vulnerable: [
            ~s|stmt.executeQuery("SELECT * FROM users WHERE id = " + userId)|,
            ~s|String sql = "DELETE FROM items WHERE name = '" + name + "'":|
          ],
          safe: [
            ~s|PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?")|,
            ~s|ps.setInt(1, userId)|
          ]
        }
      },
      %Pattern{
        id: "java-xxe-documentbuilder",
        name: "XXE via DocumentBuilder",
        description: "Detects XXE vulnerability in XML parsing",
        type: :xxe,
        severity: :high,
        languages: ["java"],
        regex: ~r/DocumentBuilderFactory\.newInstance\s*\(\s*\)(?![\s\S]*?setFeature.*?FEATURE_SECURE_PROCESSING)/,
        cwe_id: "CWE-611",
        owasp_category: "A05:2021",
        recommendation: "Disable external entities in XML parser",
        test_cases: %{
          vulnerable: [
            ~s|DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance()|
          ],
          safe: [
            ~s|DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\ndbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)|
          ]
        }
      },
      %Pattern{
        id: "java-weak-random",
        name: "Weak Random Number Generation",
        description: "Detects use of java.util.Random for security",
        type: :crypto,
        severity: :medium,
        languages: ["java"],
        regex: ~r/new\s+Random\s*\(\s*\)|Math\.random\s*\(\s*\)/,
        cwe_id: "CWE-330",
        owasp_category: "A02:2021",
        recommendation: "Use SecureRandom for security-sensitive operations",
        test_cases: %{
          vulnerable: [
            ~s|Random rand = new Random()|,
            ~s|int token = (int)(Math.random() * 1000000)|
          ],
          safe: [
            ~s|SecureRandom random = new SecureRandom()|,
            ~s|byte[] token = new byte[16]; random.nextBytes(token)|
          ]
        }
      },
      
      # PHP patterns (3)
      %Pattern{
        id: "php-sql-injection-concat",
        name: "SQL Injection via Concatenation",
        description: "Detects SQL injection through string concatenation",
        type: :sql_injection,
        severity: :critical,
        languages: ["php"],
        regex: ~r/(?:mysql_query|mysqli_query|query)\s*\(\s*["'].*(?:SELECT|INSERT|UPDATE|DELETE).*["']\s*\./,
        cwe_id: "CWE-89",
        owasp_category: "A03:2021",
        recommendation: "Use prepared statements with PDO or mysqli",
        test_cases: %{
          vulnerable: [
            ~s|$sql = "SELECT * FROM users WHERE id = " . $_GET['id']|,
            ~s|mysql_query("DELETE FROM items WHERE name = '" . $name . "'")|
          ],
          safe: [
            ~s|$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?")|,
            ~s|$stmt->bind_param("i", $_GET['id'])|
          ]
        }
      },
      %Pattern{
        id: "php-xss-echo",
        name: "XSS via echo",
        description: "Detects XSS through unescaped echo",
        type: :xss,
        severity: :high,
        languages: ["php"],
        regex: ~r/echo\s+\$_(?:GET|POST|REQUEST|COOKIE)|<?=\s*\$_(?:GET|POST|REQUEST|COOKIE)/,
        cwe_id: "CWE-79",
        owasp_category: "A03:2021",
        recommendation: "Use htmlspecialchars() or htmlentities()",
        test_cases: %{
          vulnerable: [
            ~s|echo $_GET['name']|,
            ~s|<?= $_POST['comment'] ?>|
          ],
          safe: [
            ~s|echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8')|,
            ~s|<?= htmlentities($_POST['comment']) ?>|
          ]
        }
      },
      %Pattern{
        id: "php-file-inclusion",
        name: "File Inclusion Vulnerability",
        description: "Detects file inclusion vulnerabilities",
        type: :file_inclusion,
        severity: :critical,
        languages: ["php"],
        regex: ~r/(?:include|require|include_once|require_once)\s*\(?\s*\$_(?:GET|POST|REQUEST)/,
        cwe_id: "CWE-98",
        owasp_category: "A03:2021",
        recommendation: "Validate and whitelist file paths",
        test_cases: %{
          vulnerable: [
            ~s|include($_GET['page'])|,
            ~s|require_once($_POST['module'] . '.php')|
          ],
          safe: [
            ~s|$allowed = ['home', 'about']; if (in_array($_GET['page'], $allowed)) include($_GET['page'] . '.php')|,
            ~s|include(__DIR__ . '/templates/' . basename($_GET['page']) . '.php')|
          ]
        }
      },
      
      # Elixir pattern (1) 
      %Pattern{
        id: "elixir-sql-injection-interpolation",
        name: "Ecto SQL Injection via String Interpolation",
        description: "Detects SQL injection in Ecto queries through string interpolation",
        type: :sql_injection,
        severity: :critical,
        languages: ["elixir"],
        regex: ~r/Ecto\.Query\.API\.fragment\s*\(\s*["'].*#\{|Repo\.query[!]?\s*\(\s*["'].*#\{/,
        cwe_id: "CWE-89",
        owasp_category: "A03:2021",
        recommendation: "Use parameterized Ecto queries or fragment with parameters",
        test_cases: %{
          vulnerable: [
            ~s|from(u in User, where: fragment("name = '\#{name}'"))|,
            ~s|Repo.query("SELECT * FROM users WHERE id = \#{user_id}")|
          ],
          safe: [
            ~s|from(u in User, where: u.name == ^name)|,
            ~s|from(u in User, where: fragment("name = ?", ^name))|
          ]
        }
      }
    ]
  end
  
  defp filter_by_language(patterns, nil), do: patterns
  defp filter_by_language(patterns, language) do
    Enum.filter(patterns, fn pattern ->
      language in pattern.languages
    end)
  end
end