defmodule RsolvApi.Security.Patterns.Rails.Cve20195418Test do
  use ExUnit.Case, async: true

  alias RsolvApi.Security.Pattern
  alias RsolvApi.Security.Patterns.Rails.Cve20195418

  describe "pattern/0" do
    test "returns valid pattern structure" do
      pattern = Cve20195418.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "rails-cve-2019-5418"
      assert pattern.name == "CVE-2019-5418 - File Content Disclosure"
      assert pattern.description == "Path traversal vulnerability in render file allowing arbitrary file disclosure"
      assert pattern.type == :path_traversal
      assert pattern.severity == :critical
      assert pattern.languages == ["ruby"]
      assert pattern.frameworks == ["rails"]
      assert pattern.cwe_id == "CWE-22"
      assert pattern.owasp_category == "A01:2021"
      assert is_list(pattern.regex)
      assert Enum.all?(pattern.regex, &match?(%Regex{}, &1))
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = Cve20195418.vulnerability_metadata()
      
      assert is_map(metadata)
      assert Map.has_key?(metadata, :description)
      assert Map.has_key?(metadata, :attack_vectors)
      assert Map.has_key?(metadata, :technical_impact)
      assert Map.has_key?(metadata, :business_impact)
      assert Map.has_key?(metadata, :cve_details)
      assert Map.has_key?(metadata, :safe_alternatives)
      assert Map.has_key?(metadata, :remediation_steps)
      assert Map.has_key?(metadata, :detection_methods)
      assert Map.has_key?(metadata, :prevention_tips)
      
      assert String.contains?(metadata.description, "CVE-2019-5418")
      assert String.contains?(metadata.description, "file content disclosure")
      assert String.contains?(metadata.cve_details, "CVSS")
      assert String.contains?(metadata.safe_alternatives, "whitelist")
    end
  end

  describe "ast_enhancement/0" do
    test "returns AST enhancement configuration" do
      ast = Cve20195418.ast_enhancement()
      
      assert is_map(ast)
      assert Map.has_key?(ast, :context_rules)
      assert Map.has_key?(ast, :confidence_rules)
      assert Map.has_key?(ast, :ast_rules)
      
      # Check context rules
      assert is_map(ast.context_rules)
      assert is_list(ast.context_rules.render_methods)
      assert "render" in ast.context_rules.render_methods
      
      # Check confidence rules
      assert is_map(ast.confidence_rules)
      assert is_map(ast.confidence_rules.adjustments)
      assert ast.confidence_rules.adjustments.params_in_file_path == +0.7
      
      # Check AST rules
      assert is_map(ast.ast_rules)
      assert ast.ast_rules.render_analysis.detect_file_option == true
    end
  end

  describe "enhanced_pattern/0" do
    test "includes AST enhancement in pattern" do
      pattern = Cve20195418.enhanced_pattern()
      
      assert %Pattern{} = pattern
      assert Map.has_key?(pattern, :ast_enhancement)
      assert pattern.ast_enhancement == Cve20195418.ast_enhancement()
    end
  end

  describe "vulnerability detection" do
    test "detects render file with params vulnerability" do
      vulnerable_code = """
      class ReportsController < ApplicationController
        def show
          render file: params[:template]
        end
      end
      """
      
      pattern = Cve20195418.pattern()
      
      assert Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, vulnerable_code)
      end)
    end

    test "detects render file with Rails.root and params interpolation" do
      vulnerable_code = """
      class DocumentsController < ApplicationController
        def download
          file_path = "\#{Rails.root}/public/\#{params[:file]}"
          render file: file_path
        end
      end
      """
      
      pattern = Cve20195418.pattern()
      
      assert Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, vulnerable_code)
      end)
    end

    test "detects render template with params path" do
      vulnerable_code = """
      def display
        template_name = params[:template_path]
        render template: template_name
      end
      """
      
      pattern = Cve20195418.pattern()
      
      assert Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, vulnerable_code)
      end)
    end

    test "detects render partial with directory traversal" do
      vulnerable_code = """
      class ViewsController < ApplicationController
        def show_partial
          partial_path = "../\#{params[:dir]}/\#{params[:partial]}"
          render partial: partial_path
        end
      end
      """
      
      pattern = Cve20195418.pattern()
      
      assert Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, vulnerable_code)
      end)
    end

    test "detects complex path construction" do
      vulnerable_code = """
      def report
        base_path = "\#{Rails.root}/reports"
        user_path = params[:report_type]
        full_path = File.join(base_path, user_path)
        render file: full_path
      end
      """
      
      pattern = Cve20195418.pattern()
      
      assert Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, vulnerable_code)
      end)
    end
  end

  describe "safe code validation" do
    test "does not flag safe render with static file" do
      safe_code = """
      class ReportsController < ApplicationController
        def annual_report
          render file: Rails.root.join('app', 'views', 'reports', 'annual.html.erb')
        end
      end
      """
      
      pattern = Cve20195418.pattern()
      
      refute Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, safe_code)
      end)
    end

    test "does not flag render with whitelisted templates" do
      safe_code = """
      class TemplatesController < ApplicationController
        ALLOWED_TEMPLATES = %w[user admin guest].freeze
        
        def show
          template = params[:type]
          if ALLOWED_TEMPLATES.include?(template)
            render template: "templates/\#{template}"
          else
            render template: "templates/default"
          end
        end
      end
      """
      
      pattern = Cve20195418.pattern()
      
      refute Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, safe_code)
      end)
    end

    test "does not flag render without file option" do
      safe_code = """
      class UsersController < ApplicationController
        def show
          @user = User.find(params[:id])
          render :show
        end
        
        def index
          @users = User.all
          render
        end
      end
      """
      
      pattern = Cve20195418.pattern()
      
      refute Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, safe_code)
      end)
    end

    test "does not flag commented vulnerable code" do
      safe_code = """
      class SecureController < ApplicationController
        def display
          # DEPRECATED: This was vulnerable to CVE-2019-5418
          # render file: params[:template]
          
          # Now using safe approach
          render :display
        end
      end
      """
      
      pattern = Cve20195418.pattern()
      
      refute Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, safe_code)
      end)
    end

    test "does not flag render json or other safe formats" do
      safe_code = """
      class ApiController < ApplicationController
        def data
          render json: { status: params[:status] }
        end
        
        def xml_data
          render xml: @data.to_xml
        end
        
        def plain_text
          render plain: "Hello World"
        end
      end
      """
      
      pattern = Cve20195418.pattern()
      
      refute Enum.any?(pattern.regex, fn regex ->
        Regex.match?(regex, safe_code)
      end)
    end
  end

  describe "applies_to_file?/2" do
    test "applies to Rails controller files" do
      assert Cve20195418.applies_to_file?("app/controllers/reports_controller.rb", ["rails"])
      assert Cve20195418.applies_to_file?("app/controllers/admin/documents_controller.rb", ["rails"])
      assert Cve20195418.applies_to_file?("app/controllers/api/v1/files_controller.rb", ["rails"])
    end

    test "applies to Rails view files" do
      assert Cve20195418.applies_to_file?("app/views/layouts/application.html.erb", ["rails"])
      assert Cve20195418.applies_to_file?("app/views/users/show.html.haml", ["rails"])
    end

    test "applies to Rails helper files" do
      assert Cve20195418.applies_to_file?("app/helpers/application_helper.rb", ["rails"])
      assert Cve20195418.applies_to_file?("app/helpers/rendering_helper.rb", ["rails"])
    end

    test "infers Rails from file paths" do
      assert Cve20195418.applies_to_file?("app/controllers/users_controller.rb", [])
      assert Cve20195418.applies_to_file?("app/views/posts/index.html.erb", [])
    end

    test "does not apply to non-rendering files" do
      refute Cve20195418.applies_to_file?("app/models/user.rb", ["rails"])
      refute Cve20195418.applies_to_file?("config/routes.rb", ["rails"])
      refute Cve20195418.applies_to_file?("db/migrate/create_users.rb", ["rails"])
      refute Cve20195418.applies_to_file?("test/controllers/users_controller_test.rb", ["rails"])
    end
  end
end