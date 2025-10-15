defmodule RsolvWeb.Api.V1.TaintAnalyzerTest do
  use ExUnit.Case, async: true

  alias RsolvWeb.Api.V1.TaintAnalyzer

  describe "analyze/3 for direct user input" do
    test "detects direct user input from request objects" do
      # JavaScript request patterns
      assert TaintAnalyzer.analyze("eval(req.body.code)", "", 1) == %{
               direct_input: true,
               tainted_flow: false,
               suspicious_name: false,
               has_sanitization: false,
               confidence: 0.95,
               taint_level: 1
             }

      assert TaintAnalyzer.analyze("exec(req.params.command)", "", 1) == %{
               direct_input: true,
               tainted_flow: false,
               suspicious_name: false,
               has_sanitization: false,
               confidence: 0.95,
               taint_level: 1
             }

      assert TaintAnalyzer.analyze(
               "db.query('SELECT * FROM users WHERE id = ' + req.query.id)",
               "",
               1
             ) == %{
               direct_input: true,
               tainted_flow: false,
               suspicious_name: false,
               has_sanitization: false,
               confidence: 0.95,
               taint_level: 1
             }

      # Python patterns
      assert TaintAnalyzer.analyze("eval(request.form['code'])", "", 1) == %{
               direct_input: true,
               tainted_flow: false,
               suspicious_name: false,
               has_sanitization: false,
               confidence: 0.95,
               taint_level: 1
             }

      # PHP patterns
      assert TaintAnalyzer.analyze("eval($_POST['code'])", "", 1) == %{
               direct_input: true,
               tainted_flow: false,
               suspicious_name: false,
               has_sanitization: false,
               confidence: 0.95,
               taint_level: 1
             }
    end

    test "does not flag non-user input as direct" do
      assert TaintAnalyzer.analyze("eval(config.defaultCode)", "", 1) == %{
               direct_input: false,
               tainted_flow: false,
               suspicious_name: false,
               has_sanitization: false,
               confidence: 0.40,
               taint_level: 4
             }
    end
  end

  describe "analyze/3 for tainted variable flow" do
    test "detects single-level tainted flow" do
      file_content = """
      const userCode = req.body.code;
      eval(userCode);
      """

      result = TaintAnalyzer.analyze("eval(userCode)", file_content, 2)
      assert result.tainted_flow == true
      assert result.confidence == 0.85
      assert result.taint_level == 2
    end

    test "detects multi-level tainted flow" do
      file_content = """
      const input = req.body.data;
      const processed = processData(input);
      const final = transformData(processed);
      eval(final);
      """

      result = TaintAnalyzer.analyze("eval(final)", file_content, 4)
      assert result.tainted_flow == true
      # Reduced confidence for multi-level
      assert result.confidence == 0.75
      assert result.taint_level == 3
    end

    test "traces taint through function parameters" do
      file_content = """
      function dangerous(code) {
        eval(code);
      }

      app.post('/execute', (req, res) => {
        dangerous(req.body.userCode);
      });
      """

      result = TaintAnalyzer.analyze("eval(code)", file_content, 2)
      assert result.tainted_flow == true
      assert result.confidence == 0.85
      assert result.taint_level == 2
    end
  end

  describe "analyze/3 for suspicious variable names" do
    test "detects suspicious variable names" do
      suspicious_names = [
        "userInput",
        "userCode",
        "userQuery",
        "inputData",
        "userExpression",
        "untrustedData",
        "externalInput"
      ]

      Enum.each(suspicious_names, fn name ->
        result = TaintAnalyzer.analyze("eval(#{name})", "", 1)
        assert result.suspicious_name == true
        assert result.confidence == 0.60
        assert result.taint_level == 3
      end)
    end

    test "does not flag safe variable names" do
      safe_names = [
        "config",
        "settings",
        "defaultValue",
        "template",
        "constant"
      ]

      Enum.each(safe_names, fn name ->
        result = TaintAnalyzer.analyze("eval(#{name})", "", 1)
        assert result.suspicious_name == false
        assert result.confidence == 0.40
        assert result.taint_level == 4
      end)
    end
  end

  describe "analyze/3 for sanitization detection" do
    test "detects nearby sanitization" do
      file_content = """
      const userInput = req.body.code;
      const sanitized = sanitize(userInput);
      eval(sanitized);
      """

      result = TaintAnalyzer.analyze("eval(sanitized)", file_content, 3)
      assert result.has_sanitization == true
      # 0.85 * 0.5 due to sanitization
      assert result.confidence == 0.425
    end

    test "detects validation checks" do
      file_content = """
      const userInput = req.body.id;
      if (!isValidId(userInput)) {
        throw new Error("Invalid ID");
      }
      db.query('SELECT * FROM users WHERE id = ' + userInput);
      """

      result =
        TaintAnalyzer.analyze(
          "db.query('SELECT * FROM users WHERE id = ' + userInput)",
          file_content,
          5
        )

      assert result.has_sanitization == true
      # Reduced due to validation
      assert result.confidence < 0.95
    end

    test "detects escaping functions" do
      file_content = """
      const userHtml = req.body.html;
      const escaped = escapeHtml(userHtml);
      element.innerHTML = escaped;
      """

      result = TaintAnalyzer.analyze("element.innerHTML = escaped", file_content, 3)
      assert result.has_sanitization == true
    end
  end

  describe "calculate_confidence/1" do
    test "calculates confidence based on taint level" do
      assert TaintAnalyzer.calculate_confidence(%{
               direct_input: true,
               tainted_flow: false,
               suspicious_name: false,
               has_sanitization: false
             }) == 0.95

      assert TaintAnalyzer.calculate_confidence(%{
               direct_input: false,
               tainted_flow: true,
               suspicious_name: false,
               has_sanitization: false
             }) == 0.85

      assert TaintAnalyzer.calculate_confidence(%{
               direct_input: false,
               tainted_flow: false,
               suspicious_name: true,
               has_sanitization: false
             }) == 0.60

      assert TaintAnalyzer.calculate_confidence(%{
               direct_input: false,
               tainted_flow: false,
               suspicious_name: false,
               has_sanitization: false
             }) == 0.40
    end

    test "reduces confidence when sanitization is present" do
      # 0.95 * 0.5
      assert TaintAnalyzer.calculate_confidence(%{
               direct_input: true,
               tainted_flow: false,
               suspicious_name: false,
               has_sanitization: true
             }) == 0.475

      # 0.85 * 0.5
      assert TaintAnalyzer.calculate_confidence(%{
               direct_input: false,
               tainted_flow: true,
               suspicious_name: false,
               has_sanitization: true
             }) == 0.425
    end
  end

  describe "trace_taint_flow/3" do
    test "traces variable assignment from user input" do
      file_content = """
      const data = req.body.input;
      const processed = transform(data);
      """

      assert TaintAnalyzer.trace_taint_flow("processed", file_content, 2) == %{
               is_tainted: true,
               source: "req.body.input",
               hops: 1
             }
    end

    test "traces through multiple assignments" do
      file_content = """
      const a = req.params.value;
      const b = a;
      const c = b;
      const d = c;
      eval(d);
      """

      assert TaintAnalyzer.trace_taint_flow("d", file_content, 5) == %{
               is_tainted: true,
               source: "req.params.value",
               hops: 3
             }
    end

    test "returns not tainted for safe sources" do
      file_content = """
      const data = loadConfig();
      eval(data);
      """

      assert TaintAnalyzer.trace_taint_flow("data", file_content, 2) == %{
               is_tainted: false,
               source: nil,
               hops: 0
             }
    end
  end

  describe "integration scenarios" do
    test "properly analyzes NodeGoat eval vulnerability" do
      file_content = """
      app.post('/contributions', (req, res) => {
        const preTax = req.body.preTax;
        const afterTax = req.body.afterTax;
        const roth = req.body.roth;
        
        // Vulnerable line
        const result = eval(preTax);
        
        res.json({ result });
      });
      """

      result = TaintAnalyzer.analyze("eval(preTax)", file_content, 7)
      assert result.direct_input == false
      assert result.tainted_flow == true
      assert result.confidence >= 0.85
      assert result.taint_level == 2
    end

    test "analyzes MongoDB $where injection" do
      file_content = """
      function findByUserId(userId, callback) {
        const query = {
          $where: "this.userId == '" + userId + "'"
        };
        db.collection.find(query, callback);
      }
      """

      result =
        TaintAnalyzer.analyze("$where: \"this.userId == '\" + userId + \"'\"", file_content, 3)

      assert result.suspicious_name == true or result.tainted_flow == true
      assert result.confidence >= 0.60
    end
  end
end
