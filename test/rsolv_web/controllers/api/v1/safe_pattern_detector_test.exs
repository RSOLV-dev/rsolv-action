defmodule RsolvWeb.Api.V1.SafePatternDetectorTest do
  use ExUnit.Case
  alias RsolvWeb.Api.V1.SafePatternDetector
  
  describe "SQL Injection Detection" do
    test "detects unsafe string concatenation with user input" do
      unsafe_patterns = [
        {"db.query(\"SELECT * FROM users WHERE id = \" + req.params.id)", "javascript"},
        {"db.query(\"SELECT * FROM users WHERE name = '\" + userName + \"'\")", "javascript"},
        {"connection.execute(\"DELETE FROM posts WHERE id = \" + postId)", "javascript"},
        {"mysql.query(\"UPDATE users SET role = 'admin' WHERE id = \" + userId)", "javascript"},
        {"pg.query(\"SELECT * FROM \" + tableName)", "javascript"},
        {"db.run(f\"SELECT * FROM users WHERE id = {user_id}\")", "python"},
        {"cursor.execute(\"SELECT * FROM users WHERE name = '%s'\" % name)", "python"},
        {"DB.exec(\"SELECT * FROM users WHERE id = \" + params[:id])", "ruby"},
        {"$pdo->query(\"SELECT * FROM users WHERE id = \" . $_GET['id'])", "php"},
        {"mysqli_query($conn, \"SELECT * FROM users WHERE id = \" . $userId)", "php"},
      ]
      
      for {code, language} <- unsafe_patterns do
        refute SafePatternDetector.is_safe_pattern?(:sql_injection, code, %{language: language}),
               "Should detect unsafe SQL: #{code}"
      end
    end
    
    test "recognizes safe parameterized queries" do
      safe_patterns = [
        {"db.query(\"SELECT * FROM users WHERE id = $1\", [userId])", "javascript"},
        {"db.query(\"SELECT * FROM users WHERE id = ?\", [userId])", "javascript"},
        {"connection.execute(\"SELECT * FROM users WHERE id = :id\", {id: userId})", "javascript"},
        {"db.prepare(\"SELECT * FROM users WHERE id = ?\")", "javascript"},
        {"cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))", "python"},
        {"cursor.execute(\"SELECT * FROM users WHERE id = ?\", [user_id])", "python"},
        {"DB.exec(\"SELECT * FROM users WHERE id = ?\", params[:id])", "ruby"},
        {"User.where(id: params[:id])", "ruby"},
        {"$stmt = $pdo->prepare(\"SELECT * FROM users WHERE id = ?\")", "php"},
        {"$stmt->bind_param(\"i\", $userId)", "php"},
      ]
      
      for {code, language} <- safe_patterns do
        assert SafePatternDetector.is_safe_pattern?(:sql_injection, code, %{language: language}),
               "Should recognize safe SQL: #{code}"
      end
    end
    
    test "detects SQL in test fixtures as safe" do
      test_patterns = [
        {"db.query(\"SELECT * FROM users WHERE id = 1\")", "javascript"},
        {"connection.execute(\"INSERT INTO test_users VALUES (1, 'test')\")", "javascript"},
        {"cursor.execute(\"CREATE TABLE test_table (id INT)\")", "python"},
      ]
      
      # Note: These might need special handling for test files
      # For now, they're marked as unsafe unless in test directories
      for {code, language} <- test_patterns do
        refute SafePatternDetector.is_safe_pattern?(:sql_injection, code, %{language: language}),
               "Static SQL without params should be unsafe: #{code}"
      end
    end
  end
  
  describe "XSS Detection" do
    test "detects unsafe innerHTML and document.write" do
      unsafe_patterns = [
        {"element.innerHTML = userInput", "javascript"},
        {"div.innerHTML = req.body.comment", "javascript"},
        {"document.write(userContent)", "javascript"},
        {"el.outerHTML = data", "javascript"},
        {"$('#content').html(userInput)", "javascript"},
        {"dangerouslySetInnerHTML={{__html: content}}", "javascript"},
        {"v-html=\"userContent\"", "javascript"},
      ]
      
      for {code, language} <- unsafe_patterns do
        refute SafePatternDetector.is_safe_pattern?(:xss, code, %{language: language}),
               "Should detect unsafe XSS: #{code}"
      end
    end
    
    test "recognizes safe text content methods" do
      safe_patterns = [
        {"element.textContent = userInput", "javascript"},
        {"element.innerText = userInput", "javascript"},
        {"document.createTextNode(userInput)", "javascript"},
        {"$('#content').text(userInput)", "javascript"},
        {"React.createElement('div', null, userInput)", "javascript"},
        {"dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(content)}}", "javascript"},
        {"element.innerHTML = escapeHtml(userInput)", "javascript"},
      ]
      
      for {code, language} <- safe_patterns do
        assert SafePatternDetector.is_safe_pattern?(:xss, code, %{language: language}),
               "Should recognize safe XSS prevention: #{code}"
      end
    end
  end
  
  describe "Command Injection Detection" do
    test "detects unsafe command execution with user input" do
      unsafe_patterns = [
        {"exec(\"ls \" + userInput)", "javascript"},
        {"exec(`rm -rf ${userPath}`)", "javascript"},
        {"child_process.exec(\"convert \" + req.body.filename + \" output.pdf\")", "javascript"},
        {"os.system(\"ping \" + hostname)", "python"},
        {"subprocess.call(\"echo \" + user_message, shell=True)", "python"},
        {"system(\"cat \" + params[:file])", "ruby"},
        {"exec($_GET['cmd'])", "php"},
        {"shell_exec(\"tar -xf \" . $filename)", "php"},
      ]
      
      for {code, language} <- unsafe_patterns do
        refute SafePatternDetector.is_safe_pattern?(:command_injection, code, %{language: language}),
               "Should detect unsafe command: #{code}"
      end
    end
    
    test "recognizes safe command execution" do
      safe_patterns = [
        {"execFile('ls', ['-la', userDir])", "javascript"},
        {"spawn('git', ['clone', repoUrl])", "javascript"},
        {"exec('npm run build')", "javascript"},
        {"subprocess.run(['ls', '-la', user_dir], check=True)", "python"},
        {"os.execv('/bin/ls', ['ls', '-la'])", "python"},
        {"system('rake db:migrate')", "ruby"},
        {"exec('composer install')", "php"},
      ]
      
      for {code, language} <- safe_patterns do
        assert SafePatternDetector.is_safe_pattern?(:command_injection, code, %{language: language}),
               "Should recognize safe command: #{code}"
      end
    end
  end
  
  describe "Path Traversal Detection" do
    test "detects unsafe path operations" do
      unsafe_patterns = [
        {"fs.readFile(req.query.file)", "javascript"},
        {"fs.readFile('../' + userPath)", "javascript"},
        {"require(userModule)", "javascript"},
        {"open(user_file, 'r')", "python"},
        {"os.path.join('/var/www', user_path)", "python"},
        {"File.read(params[:path])", "ruby"},
        {"include($_GET['page'])", "php"},
        {"file_get_contents($userFile)", "php"},
      ]
      
      for {code, language} <- unsafe_patterns do
        refute SafePatternDetector.is_safe_pattern?(:path_traversal, code, %{language: language}),
               "Should detect unsafe path traversal: #{code}"
      end
    end
    
    test "recognizes safe path operations" do
      safe_patterns = [
        {"path.join(__dirname, 'static', 'index.html')", "javascript"},
        {"fs.readFile(path.resolve('./config.json'))", "javascript"},
        {"path.normalize(userPath)", "javascript"},
        {"os.path.join(BASE_DIR, 'templates', 'index.html')", "python"},
        {"pathlib.Path(user_path).resolve()", "python"},
        {"Rails.root.join('public', 'uploads')", "ruby"},
        {"basename($_GET['file'])", "php"},
        {"realpath($userPath)", "php"},
      ]
      
      for {code, language} <- safe_patterns do
        assert SafePatternDetector.is_safe_pattern?(:path_traversal, code, %{language: language}),
               "Should recognize safe path handling: #{code}"
      end
    end
  end
  
  describe "NoSQL Injection Detection" do
    test "detects unsafe NoSQL queries" do
      unsafe_patterns = [
        {"db.find({$where: userInput})", "javascript"},
        {"collection.find({username: req.body.username})", "javascript"},
        {"db.users.find({age: {$gt: req.query.age}})", "javascript"},
        {"collection.find(json.loads(user_query))", "python"},
      ]
      
      for {code, language} <- unsafe_patterns do
        refute SafePatternDetector.is_safe_pattern?(:nosql_injection, code, %{language: language}),
               "Should detect unsafe NoSQL: #{code}"
      end
    end
    
    test "recognizes safe NoSQL queries" do
      safe_patterns = [
        {"db.find({username: 'admin'})", "javascript"},
        {"collection.findById(userId)", "javascript"},
        {"db.users.findOne({_id: ObjectId(id)})", "javascript"},
        {"collection.find({'username': username})", "python"},
      ]
      
      for {code, language} <- safe_patterns do
        assert SafePatternDetector.is_safe_pattern?(:nosql_injection, code, %{language: language}),
               "Should recognize safe NoSQL: #{code}"
      end
    end
  end
  
  describe "SSRF Detection" do
    test "detects unsafe URL fetching" do
      unsafe_patterns = [
        {"axios.get(req.body.url)", "javascript"},
        {"fetch(userProvidedUrl)", "javascript"},
        {"request(req.query.webhook)", "javascript"},
        {"urllib.request.urlopen(user_url)", "python"},
        {"requests.get(params['url'])", "python"},
        {"Net::HTTP.get(URI(params[:url]))", "ruby"},
        {"file_get_contents($_POST['url'])", "php"},
        {"curl_init($_GET['endpoint'])", "php"},
      ]
      
      for {code, language} <- unsafe_patterns do
        refute SafePatternDetector.is_safe_pattern?(:ssrf, code, %{language: language}),
               "Should detect unsafe SSRF: #{code}"
      end
    end
    
    test "recognizes safe URL operations" do
      safe_patterns = [
        {"axios.get('https://api.example.com/data')", "javascript"},
        {"fetch(`${API_BASE}/users`)", "javascript"},
        {"request.get('http://localhost:3000/health')", "javascript"},
        {"urllib.request.urlopen('https://api.example.com')", "python"},
        {"requests.get(f'{BASE_URL}/api/v1/users')", "python"},
      ]
      
      for {code, language} <- safe_patterns do
        assert SafePatternDetector.is_safe_pattern?(:ssrf, code, %{language: language}),
               "Should recognize safe URL fetching: #{code}"
      end
    end
  end
  
  describe "Timing Attack Detection" do
    test "detects unsafe string comparisons for secrets" do
      unsafe_patterns = [
        {"password === userInput", "javascript"},
        {"apiKey == req.headers.authorization", "javascript"},
        {"token !== expectedToken", "javascript"},
        {"secret == user_secret", "python"},
        {"password == params[:password]", "ruby"},
        {"$password === $_POST['password']", "php"},
      ]
      
      for {code, language} <- unsafe_patterns do
        refute SafePatternDetector.is_safe_pattern?(:timing_attack, code, %{language: language}),
               "Should detect timing attack vulnerability: #{code}"
      end
    end
    
    test "recognizes safe constant comparisons" do
      safe_patterns = [
        {"error.code === PERMISSION_DENIED", "javascript"},
        {"status === 200", "javascript"},
        {"response.status === HttpStatus.OK", "javascript"},
        {"e.code === DOMException.QUOTA_EXCEEDED_ERR", "javascript"},
        {"error.errno == errno.ENOENT", "python"},
        {"response.status_code == 404", "python"},
      ]
      
      for {code, language} <- safe_patterns do
        assert SafePatternDetector.is_safe_pattern?(:timing_attack, code, %{language: language}),
               "Should recognize safe comparison: #{code}"
      end
    end
  end
  
  describe "Edge Cases and Complex Patterns" do
    test "handles mixed safe and unsafe patterns correctly" do
      # Safe query with unsafe comparison
      code = "db.query('SELECT * FROM users WHERE id = ?', [userId]) && password === userPassword"
      refute SafePatternDetector.is_safe_pattern?(:sql_injection, code, %{language: "javascript"})
      
      # Template literal with partial safety
      code = "db.query(`SELECT * FROM ${TABLE_NAME} WHERE id = ${userId}`)"
      refute SafePatternDetector.is_safe_pattern?(:sql_injection, code, %{language: "javascript"})
    end
    
    test "handles framework-specific patterns" do
      # Rails ActiveRecord (safe)
      assert SafePatternDetector.is_safe_pattern?(
        :sql_injection,
        "User.where(email: params[:email]).first",
        %{language: "ruby"}
      )
      
      # Django ORM (safe)
      assert SafePatternDetector.is_safe_pattern?(
        :sql_injection,
        "User.objects.filter(email=request.POST['email'])",
        %{language: "python"}
      )
      
      # React with DOMPurify (safe)
      assert SafePatternDetector.is_safe_pattern?(
        :xss,
        "dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userContent)}}",
        %{language: "javascript"}
      )
    end
    
    test "correctly identifies build scripts and CI/CD as safer contexts" do
      # Build scripts with static commands
      assert SafePatternDetector.is_safe_pattern?(
        :command_injection,
        "exec('webpack --mode production')",
        %{language: "javascript"}
      )
      
      # But not if they include variables
      refute SafePatternDetector.is_safe_pattern?(
        :command_injection,
        "exec(`webpack --mode ${process.env.MODE}`)",
        %{language: "javascript"}
      )
    end
  end
  
  describe "explain_safety/3" do
    test "provides appropriate explanations for safe patterns" do
      explanation = SafePatternDetector.explain_safety(
        :sql_injection,
        "db.query('SELECT * FROM users WHERE id = ?', [userId])",
        %{language: "javascript"}
      )
      assert explanation =~ "parameterized"
      
      explanation = SafePatternDetector.explain_safety(
        :xss,
        "element.textContent = userInput",
        %{language: "javascript"}
      )
      assert explanation =~ "escaping" or explanation =~ "safe"
    end
    
    test "provides appropriate explanations for unsafe patterns" do
      explanation = SafePatternDetector.explain_safety(
        :sql_injection,
        "db.query('SELECT * FROM users WHERE id = ' + userId)",
        %{language: "javascript"}
      )
      assert explanation =~ "injection" or explanation =~ "unsafe"
      
      explanation = SafePatternDetector.explain_safety(
        :xss,
        "element.innerHTML = userInput",
        %{language: "javascript"}
      )
      assert explanation =~ "XSS" or explanation =~ "escape"
    end
  end
end