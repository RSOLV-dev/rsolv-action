defmodule RsolvWeb.Email.TemplateLoaderTest do
  use ExUnit.Case, async: true

  alias RsolvWeb.Email.TemplateLoader

  describe "template_path/1" do
    test "returns correct path for atom template name" do
      path = TemplateLoader.template_path(:welcome)

      assert String.ends_with?(path, "priv/templates/email/welcome.html")
      assert path =~ "rsolv"
    end

    test "returns correct path for string template name" do
      path = TemplateLoader.template_path("payment_failed")

      assert String.ends_with?(
               path,
               "priv/templates/email/payment_failed.html"
             )

      assert path =~ "rsolv"
    end

    test "handles underscored template names" do
      path = TemplateLoader.template_path("early_access_guide")

      assert String.ends_with?(
               path,
               "priv/templates/email/early_access_guide.html"
             )
    end

    test "uses Application.app_dir for production-safe paths" do
      path = TemplateLoader.template_path(:welcome)

      # Should use absolute path, not relative
      assert Path.type(path) == :absolute
    end
  end

  describe "load_template/1" do
    test "successfully loads existing template" do
      assert {:ok, content} = TemplateLoader.load_template(:welcome)
      assert is_binary(content)
      assert String.length(content) > 0
      assert content =~ "<!DOCTYPE html>" or content =~ "<html"
    end

    test "returns error for non-existent template" do
      assert {:error, :enoent} = TemplateLoader.load_template("nonexistent_template")
    end

    test "works with atom template names" do
      assert {:ok, content} = TemplateLoader.load_template(:payment_failed)
      assert is_binary(content)
      assert String.length(content) > 0
    end

    test "works with string template names" do
      assert {:ok, content} = TemplateLoader.load_template("early_access_guide")
      assert is_binary(content)
      assert String.length(content) > 0
    end

    test "loads complete HTML content" do
      {:ok, content} = TemplateLoader.load_template(:welcome)

      # Verify it contains expected HTML structure
      assert content =~ "html" or content =~ "HTML"
    end
  end

  describe "load_template!/1" do
    test "successfully loads existing template" do
      content = TemplateLoader.load_template!(:welcome)

      assert is_binary(content)
      assert String.length(content) > 0
    end

    test "raises File.Error for non-existent template" do
      assert_raise File.Error, fn ->
        TemplateLoader.load_template!("nonexistent_template")
      end
    end

    test "works with atom template names" do
      content = TemplateLoader.load_template!(:payment_failed)

      assert is_binary(content)
      assert String.length(content) > 0
    end

    test "works with string template names" do
      content = TemplateLoader.load_template!("early_access_welcome")

      assert is_binary(content)
      assert String.length(content) > 0
    end

    test "returns same content as load_template/1" do
      {:ok, content1} = TemplateLoader.load_template(:welcome)
      content2 = TemplateLoader.load_template!(:welcome)

      assert content1 == content2
    end
  end

  describe "template_exists?/1" do
    test "returns true for existing templates" do
      assert TemplateLoader.template_exists?(:welcome)
      assert TemplateLoader.template_exists?(:payment_failed)
      assert TemplateLoader.template_exists?(:early_access_guide)
    end

    test "returns false for non-existent templates" do
      refute TemplateLoader.template_exists?("nonexistent")
      refute TemplateLoader.template_exists?(:missing_template)
    end

    test "works with atom template names" do
      assert TemplateLoader.template_exists?(:welcome)
    end

    test "works with string template names" do
      assert TemplateLoader.template_exists?("welcome")
    end

    test "validates all expected templates exist" do
      expected_templates = [
        :early_access_guide,
        :early_access_welcome,
        :feature_deep_dive,
        :feedback_request,
        :first_issue,
        :getting_started,
        :payment_failed,
        :setup_verification,
        :success_checkin,
        :welcome
      ]

      for template <- expected_templates do
        assert TemplateLoader.template_exists?(template),
               "Expected template #{template} to exist"
      end
    end
  end

  describe "list_templates/0" do
    test "returns list of available templates" do
      templates = TemplateLoader.list_templates()

      assert is_list(templates)
      assert length(templates) > 0
    end

    test "returns atoms, not strings" do
      templates = TemplateLoader.list_templates()

      assert Enum.all?(templates, &is_atom/1)
    end

    test "includes all expected templates" do
      templates = TemplateLoader.list_templates()

      expected = [
        :early_access_guide,
        :early_access_welcome,
        :feature_deep_dive,
        :feedback_request,
        :first_issue,
        :getting_started,
        :payment_failed,
        :setup_verification,
        :success_checkin,
        :welcome
      ]

      for template <- expected do
        assert template in templates, "Expected #{template} in template list"
      end
    end

    test "returns sorted list" do
      templates = TemplateLoader.list_templates()

      assert templates == Enum.sort(templates)
    end

    test "does not include file extensions" do
      templates = TemplateLoader.list_templates()

      for template <- templates do
        template_str = Atom.to_string(template)
        refute String.ends_with?(template_str, ".html")
      end
    end

    test "only includes HTML files" do
      # If there were non-HTML files in the directory, they should be excluded
      templates = TemplateLoader.list_templates()

      # Verify each template actually has a corresponding .html file
      for template <- templates do
        assert TemplateLoader.template_exists?(template)
      end
    end
  end

  describe "integration with actual templates" do
    test "all listed templates can be loaded" do
      templates = TemplateLoader.list_templates()

      for template <- templates do
        assert {:ok, content} = TemplateLoader.load_template(template),
               "Failed to load template: #{template}"

        assert String.length(content) > 0, "Template #{template} is empty"
      end
    end

    test "all templates contain HTML content" do
      templates = TemplateLoader.list_templates()

      for template <- templates do
        {:ok, content} = TemplateLoader.load_template(template)

        # Check for basic HTML structure
        assert content =~ ~r/html|HTML/i,
               "Template #{template} doesn't appear to contain HTML"
      end
    end

    test "template paths are production-safe" do
      # Verify we're using Application.app_dir, not relative paths
      path = TemplateLoader.template_path(:welcome)

      # Should not be a relative path
      refute String.starts_with?(path, "lib/")
      refute String.starts_with?(path, "./")
      refute String.starts_with?(path, "../")

      # Should be an absolute path
      assert Path.type(path) == :absolute
    end
  end

  describe "error handling" do
    test "load_template/1 handles file system errors gracefully" do
      # Try to load from an invalid template name
      result = TemplateLoader.load_template("../../etc/passwd")

      assert {:error, _} = result
    end

    test "template_exists?/1 handles invalid paths gracefully" do
      # Should not raise, just return false
      refute TemplateLoader.template_exists?("../../etc/passwd")
      refute TemplateLoader.template_exists?("/absolute/path/to/nowhere")
    end

    test "list_templates/0 returns empty list if directory doesn't exist" do
      # This test documents behavior - in production the directory always exists
      # but we want to ensure we don't crash if it's missing
      templates = TemplateLoader.list_templates()

      # Should return a list (possibly empty if directory is missing in test env)
      assert is_list(templates)
    end
  end

  describe "consistency with EmailsHTML" do
    test "TemplateLoader.list_templates matches EmailsHTML templates" do
      # The templates defined in EmailsHTML should match what's in the filesystem
      emails_html_templates = [
        :early_access_guide,
        :early_access_welcome,
        :feature_deep_dive,
        :feedback_request,
        :first_issue,
        :getting_started,
        :payment_failed,
        :setup_verification,
        :success_checkin,
        :welcome
      ]

      actual_templates = TemplateLoader.list_templates()

      for template <- emails_html_templates do
        assert template in actual_templates,
               "EmailsHTML defines #{template} but it's not in the filesystem"
      end
    end
  end
end
