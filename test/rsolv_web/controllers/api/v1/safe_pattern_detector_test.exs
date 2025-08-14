defmodule RsolvWeb.Api.V1.SafePatternDetectorTest do
  use ExUnit.Case, async: true
  
  alias RsolvWeb.Api.V1.SafePatternDetector
  
  describe "is_safe_pattern?/3 for timing attacks" do
    test "recognizes safe constant comparisons" do
      # JavaScript/TypeScript patterns
      assert SafePatternDetector.is_safe_pattern?(
        :timing_attack,
        "if (error.code === DOMException.QUOTA_EXCEEDED_ERR)",
        %{language: "javascript"}
      ) == true
      
      assert SafePatternDetector.is_safe_pattern?(
        :timing_attack,
        "status === HttpStatus.OK",
        %{language: "javascript"}
      ) == true
      
      assert SafePatternDetector.is_safe_pattern?(
        :timing_attack,
        "type === CONSTANTS.USER_TYPE",
        %{language: "javascript"}
      ) == true
      
      # Python patterns
      assert SafePatternDetector.is_safe_pattern?(
        :timing_attack,
        "if error_code == errno.EACCES:",
        %{language: "python"}
      ) == true
      
      # Ruby patterns
      assert SafePatternDetector.is_safe_pattern?(
        :timing_attack,
        "status == Net::HTTPSuccess",
        %{language: "ruby"}
      ) == true
    end
    
    test "identifies unsafe timing comparisons" do
      assert SafePatternDetector.is_safe_pattern?(
        :timing_attack,
        "if (password === userInput)",
        %{language: "javascript"}
      ) == false
      
      assert SafePatternDetector.is_safe_pattern?(
        :timing_attack,
        "token === req.body.token",
        %{language: "javascript"}
      ) == false
      
      assert SafePatternDetector.is_safe_pattern?(
        :timing_attack,
        "apiKey == user_provided_key",
        %{language: "python"}
      ) == false
    end
  end
  
  describe "is_safe_pattern?/3 for SQL injection" do
    test "recognizes parameterized queries" do
      # PostgreSQL style
      assert SafePatternDetector.is_safe_pattern?(
        :sql_injection,
        "db.query('SELECT * FROM users WHERE id = $1', [userId])",
        %{language: "javascript"}
      ) == true
      
      # MySQL style
      assert SafePatternDetector.is_safe_pattern?(
        :sql_injection,
        "connection.execute('SELECT * FROM users WHERE id = ?', [userId])",
        %{language: "javascript"}
      ) == true
      
      # Named parameters
      assert SafePatternDetector.is_safe_pattern?(
        :sql_injection,
        "db.query('SELECT * FROM users WHERE id = :userId', {userId: id})",
        %{language: "javascript"}
      ) == true
      
      # Python patterns
      assert SafePatternDetector.is_safe_pattern?(
        :sql_injection,
        "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        %{language: "python"}
      ) == true
      
      # Ruby/Rails patterns
      assert SafePatternDetector.is_safe_pattern?(
        :sql_injection,
        "User.where('id = ?', params[:id])",
        %{language: "ruby"}
      ) == true
      
      # PHP PDO
      assert SafePatternDetector.is_safe_pattern?(
        :sql_injection,
        "$stmt->execute(['id' => $userId])",
        %{language: "php"}
      ) == true
    end
    
    test "identifies unsafe SQL concatenation" do
      assert SafePatternDetector.is_safe_pattern?(
        :sql_injection,
        "db.query('SELECT * FROM users WHERE id = ' + userId)",
        %{language: "javascript"}
      ) == false
      
      assert SafePatternDetector.is_safe_pattern?(
        :sql_injection,
        "query = \"SELECT * FROM users WHERE name = '\" + userName + \"'\"",
        %{language: "python"}
      ) == false
      
      assert SafePatternDetector.is_safe_pattern?(
        :sql_injection,
        "$query = \"SELECT * FROM users WHERE id = $userId\"",
        %{language: "php"}
      ) == false
    end
  end
  
  describe "is_safe_pattern?/3 for NoSQL injection" do
    test "recognizes safe MongoDB queries" do
      assert SafePatternDetector.is_safe_pattern?(
        :nosql_injection,
        "collection.find({ userId: id })",
        %{language: "javascript"}
      ) == true
      
      assert SafePatternDetector.is_safe_pattern?(
        :nosql_injection,
        "users.findOne({ email: userEmail })",
        %{language: "javascript"}
      ) == true
      
      assert SafePatternDetector.is_safe_pattern?(
        :nosql_injection,
        "db.users.findById(userId)",
        %{language: "javascript"}
      ) == true
      
      assert SafePatternDetector.is_safe_pattern?(
        :nosql_injection,
        "collection.updateOne({ _id: id }, { $set: { name: newName } })",
        %{language: "javascript"}
      ) == true
    end
    
    test "identifies unsafe MongoDB queries with $where" do
      assert SafePatternDetector.is_safe_pattern?(
        :nosql_injection,
        "collection.find({ $where: 'this.userId == ' + userId })",
        %{language: "javascript"}
      ) == false
      
      assert SafePatternDetector.is_safe_pattern?(
        :nosql_injection,
        "users.find({ $where: userProvidedFunction })",
        %{language: "javascript"}
      ) == false
      
      assert SafePatternDetector.is_safe_pattern?(
        :nosql_injection,
        "db.collection.find({ $query: userInput })",
        %{language: "javascript"}
      ) == false
    end
  end
  
  describe "is_safe_pattern?/3 for XSS" do
    test "recognizes safe template rendering" do
      # Express with template engines
      assert SafePatternDetector.is_safe_pattern?(
        :xss,
        "res.render('template', { data: userInput })",
        %{language: "javascript"}
      ) == true
      
      # React JSX
      assert SafePatternDetector.is_safe_pattern?(
        :xss,
        "<div>{userInput}</div>",
        %{language: "javascript"}
      ) == true
      
      # Vue templates
      assert SafePatternDetector.is_safe_pattern?(
        :xss,
        "{{ message }}",
        %{language: "javascript"}
      ) == true
      
      # Angular templates
      assert SafePatternDetector.is_safe_pattern?(
        :xss,
        "<p>{{ userContent }}</p>",
        %{language: "javascript"}
      ) == true
      
      # Django templates
      assert SafePatternDetector.is_safe_pattern?(
        :xss,
        "{{ user_input|escape }}",
        %{language: "python"}
      ) == true
      
      # Rails ERB with escaping
      assert SafePatternDetector.is_safe_pattern?(
        :xss,
        "<%= h user_input %>",
        %{language: "ruby"}
      ) == true
    end
    
    test "identifies unsafe HTML insertion" do
      assert SafePatternDetector.is_safe_pattern?(
        :xss,
        "element.innerHTML = userInput",
        %{language: "javascript"}
      ) == false
      
      assert SafePatternDetector.is_safe_pattern?(
        :xss,
        "document.write(userContent)",
        %{language: "javascript"}
      ) == false
      
      assert SafePatternDetector.is_safe_pattern?(
        :xss,
        "$('#div').html(userInput)",
        %{language: "javascript"}
      ) == false
      
      assert SafePatternDetector.is_safe_pattern?(
        :xss,
        "element.outerHTML = content",
        %{language: "javascript"}
      ) == false
      
      # Rails raw output
      assert SafePatternDetector.is_safe_pattern?(
        :xss,
        "<%= raw user_input %>",
        %{language: "ruby"}
      ) == false
    end
  end
  
  describe "is_safe_pattern?/3 for command injection" do
    test "recognizes safe command execution" do
      # Using arrays for arguments (safe)
      assert SafePatternDetector.is_safe_pattern?(
        :command_injection,
        "spawn('ls', ['-la', userPath])",
        %{language: "javascript"}
      ) == true
      
      assert SafePatternDetector.is_safe_pattern?(
        :command_injection,
        "subprocess.run(['ls', '-la', user_path])",
        %{language: "python"}
      ) == true
      
      assert SafePatternDetector.is_safe_pattern?(
        :command_injection,
        "system('ls', '-la', user_path)",
        %{language: "ruby"}
      ) == true
      
      # PHP escapeshellarg
      assert SafePatternDetector.is_safe_pattern?(
        :command_injection,
        "exec('ls ' . escapeshellarg($userPath))",
        %{language: "php"}
      ) == true
    end
    
    test "identifies unsafe command execution" do
      assert SafePatternDetector.is_safe_pattern?(
        :command_injection,
        "exec('ls ' + userInput)",
        %{language: "javascript"}
      ) == false
      
      assert SafePatternDetector.is_safe_pattern?(
        :command_injection,
        "os.system('ls ' + user_path)",
        %{language: "python"}
      ) == false
      
      assert SafePatternDetector.is_safe_pattern?(
        :command_injection,
        "`ls ${userPath}`",
        %{language: "ruby"}
      ) == false
      
      assert SafePatternDetector.is_safe_pattern?(
        :command_injection,
        "shell_exec(\"ls $userPath\")",
        %{language: "php"}
      ) == false
    end
  end
  
  describe "is_safe_pattern?/3 for path traversal" do
    test "recognizes safe path handling" do
      assert SafePatternDetector.is_safe_pattern?(
        :path_traversal,
        "path.join(__dirname, 'uploads', fileName)",
        %{language: "javascript"}
      ) == true
      
      assert SafePatternDetector.is_safe_pattern?(
        :path_traversal,
        "os.path.join(BASE_DIR, 'uploads', filename)",
        %{language: "python"}
      ) == true
      
      assert SafePatternDetector.is_safe_pattern?(
        :path_traversal,
        "File.join(Rails.root, 'uploads', filename)",
        %{language: "ruby"}
      ) == true
      
      assert SafePatternDetector.is_safe_pattern?(
        :path_traversal,
        "realpath($uploadDir . '/' . basename($filename))",
        %{language: "php"}
      ) == true
    end
    
    test "identifies unsafe path handling" do
      assert SafePatternDetector.is_safe_pattern?(
        :path_traversal,
        "'uploads/' + userFileName",
        %{language: "javascript"}
      ) == false
      
      assert SafePatternDetector.is_safe_pattern?(
        :path_traversal,
        "open('/var/data/' + user_file)",
        %{language: "python"}
      ) == false
      
      assert SafePatternDetector.is_safe_pattern?(
        :path_traversal,
        "File.read(\"uploads/\" + params[:file])",
        %{language: "ruby"}
      ) == false
    end
  end
  
  describe "is_safe_pattern?/3 for eval/code injection" do
    test "recognizes safe alternatives to eval" do
      # JSON parsing instead of eval
      assert SafePatternDetector.is_safe_pattern?(
        :code_injection,
        "JSON.parse(userInput)",
        %{language: "javascript"}
      ) == true
      
      assert SafePatternDetector.is_safe_pattern?(
        :code_injection,
        "json.loads(user_input)",
        %{language: "python"}
      ) == true
      
      # Safe function calls
      assert SafePatternDetector.is_safe_pattern?(
        :code_injection,
        "allowedFunctions[functionName]()",
        %{language: "javascript"}
      ) == true
    end
    
    test "identifies unsafe eval usage" do
      assert SafePatternDetector.is_safe_pattern?(
        :code_injection,
        "eval(userInput)",
        %{language: "javascript"}
      ) == false
      
      assert SafePatternDetector.is_safe_pattern?(
        :code_injection,
        "new Function(userCode)",
        %{language: "javascript"}
      ) == false
      
      assert SafePatternDetector.is_safe_pattern?(
        :code_injection,
        "exec(user_code)",
        %{language: "python"}
      ) == false
      
      assert SafePatternDetector.is_safe_pattern?(
        :code_injection,
        "eval(params[:code])",
        %{language: "ruby"}
      ) == false
    end
  end
  
  describe "detect_all_safe_patterns/2" do
    test "detects multiple safe patterns in code" do
      code = """
      db.query('SELECT * FROM users WHERE id = $1', [userId]);
      res.render('template', { data: userInput });
      path.join(__dirname, 'uploads', fileName);
      """
      
      patterns = SafePatternDetector.detect_all_safe_patterns(code, %{language: "javascript"})
      
      assert :sql_injection in patterns
      assert :xss in patterns
      assert :path_traversal in patterns
    end
    
    test "returns empty list when no safe patterns found" do
      code = """
      eval(userInput);
      element.innerHTML = userContent;
      exec('ls ' + userPath);
      """
      
      patterns = SafePatternDetector.detect_all_safe_patterns(code, %{language: "javascript"})
      
      assert patterns == []
    end
  end
  
  describe "explain_safe_pattern/3" do
    test "provides explanation for safe patterns" do
      explanation = SafePatternDetector.explain_safe_pattern(
        :sql_injection,
        "db.query('SELECT * FROM users WHERE id = $1', [userId])",
        %{language: "javascript"}
      )
      
      assert explanation.safe == true
      assert explanation.reason =~ "parameterized"
      assert explanation.recommendation == nil
    end
    
    test "provides recommendation for unsafe patterns" do
      explanation = SafePatternDetector.explain_safe_pattern(
        :sql_injection,
        "db.query('SELECT * FROM users WHERE id = ' + userId)",
        %{language: "javascript"}
      )
      
      assert explanation.safe == false
      assert explanation.reason =~ "concatenation"
      assert explanation.recommendation =~ "parameterized"
    end
  end
end