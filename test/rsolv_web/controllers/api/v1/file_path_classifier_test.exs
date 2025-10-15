defmodule RsolvWeb.Api.V1.FilePathClassifierTest do
  use ExUnit.Case, async: true

  alias RsolvWeb.Api.V1.FilePathClassifier

  describe "classify/1" do
    test "classifies vendor files correctly" do
      assert FilePathClassifier.classify("/vendor/jquery.js") == :vendor
      assert FilePathClassifier.classify("/node_modules/react/index.js") == :vendor
      assert FilePathClassifier.classify("/bower_components/angular.js") == :vendor
      assert FilePathClassifier.classify("/assets/vendor/bootstrap.js") == :vendor
      assert FilePathClassifier.classify("/lib/third-party/library.js") == :vendor
      assert FilePathClassifier.classify("/public/vendor/chart.js") == :vendor
      assert FilePathClassifier.classify("/static/vendor/datepicker.js") == :vendor
      assert FilePathClassifier.classify("/app/assets/vendor/bootstrap/bootstrap.js") == :vendor
      assert FilePathClassifier.classify("/dist/bundle.js") == :vendor
      assert FilePathClassifier.classify("/build/app.js") == :vendor
    end

    test "classifies minified files as vendor" do
      assert FilePathClassifier.classify("/js/app.min.js") == :vendor
      assert FilePathClassifier.classify("/css/styles.min.css") == :vendor
      assert FilePathClassifier.classify("/scripts/jquery-3.6.0.min.js") == :vendor
      assert FilePathClassifier.classify("/assets/vendor/chart/morris-0.4.3.min.js") == :vendor
    end

    test "classifies test files correctly" do
      assert FilePathClassifier.classify("/test/unit/app_test.js") == :test
      assert FilePathClassifier.classify("/tests/integration/api_test.js") == :test
      assert FilePathClassifier.classify("/spec/models/user_spec.js") == :test
      assert FilePathClassifier.classify("/__tests__/component.test.js") == :test
      assert FilePathClassifier.classify("/__test__/utils.test.js") == :test
      assert FilePathClassifier.classify("/src/app.test.js") == :test
      assert FilePathClassifier.classify("/src/app.spec.js") == :test
      assert FilePathClassifier.classify("/src/user_test.js") == :test
      assert FilePathClassifier.classify("/src/user_spec.rb") == :test
      assert FilePathClassifier.classify("/e2e/scenarios/login.js") == :test
      assert FilePathClassifier.classify("/integration/api/users.js") == :test
      assert FilePathClassifier.classify("/fixtures/data.js") == :test
      assert FilePathClassifier.classify("/mocks/api.js") == :test
      assert FilePathClassifier.classify("/stubs/service.js") == :test
    end

    test "classifies config files correctly" do
      assert FilePathClassifier.classify("/config/database.js") == :config
      assert FilePathClassifier.classify("/webpack.config.js") == :config
      assert FilePathClassifier.classify("/rollup.config.js") == :config
      assert FilePathClassifier.classify("/gulpfile.js") == :config
      assert FilePathClassifier.classify("/Gruntfile.js") == :config
      assert FilePathClassifier.classify("/.eslintrc.js") == :config
      assert FilePathClassifier.classify("/.babelrc") == :config
      assert FilePathClassifier.classify("/tsconfig.json") == :config
      assert FilePathClassifier.classify("/jest.config.js") == :config
    end

    test "classifies application files correctly" do
      assert FilePathClassifier.classify("/app/routes/index.js") == :application
      assert FilePathClassifier.classify("/src/controllers/user.js") == :application
      assert FilePathClassifier.classify("/lib/services/auth.js") == :application
      assert FilePathClassifier.classify("/app/data/user-dao.js") == :application
      assert FilePathClassifier.classify("/app/data/allocations-dao.js") == :application
    end

    test "handles edge cases" do
      assert FilePathClassifier.classify("") == :application
      assert FilePathClassifier.classify("/") == :application
      assert FilePathClassifier.classify("app.js") == :application
      assert FilePathClassifier.classify(nil) == :application
    end
  end

  describe "confidence_multiplier/1" do
    test "returns correct confidence multipliers" do
      assert FilePathClassifier.confidence_multiplier(:vendor) == 0.1
      assert FilePathClassifier.confidence_multiplier(:test) == 0.2
      assert FilePathClassifier.confidence_multiplier(:config) == 0.5
      assert FilePathClassifier.confidence_multiplier(:application) == 1.0
    end

    test "defaults to 1.0 for unknown classifications" do
      assert FilePathClassifier.confidence_multiplier(:unknown) == 1.0
      assert FilePathClassifier.confidence_multiplier(nil) == 1.0
    end
  end

  describe "should_filter?/2" do
    test "filters vendor files with low confidence" do
      assert FilePathClassifier.should_filter?(:vendor, 0.29) == true
      assert FilePathClassifier.should_filter?(:vendor, 0.30) == false
      assert FilePathClassifier.should_filter?(:vendor, 0.5) == false
    end

    test "filters test files with low confidence" do
      assert FilePathClassifier.should_filter?(:test, 0.39) == true
      assert FilePathClassifier.should_filter?(:test, 0.40) == false
      assert FilePathClassifier.should_filter?(:test, 0.6) == false
    end

    test "never filters config files" do
      assert FilePathClassifier.should_filter?(:config, 0.1) == false
      assert FilePathClassifier.should_filter?(:config, 0.5) == false
      assert FilePathClassifier.should_filter?(:config, 0.9) == false
    end

    test "never filters application files" do
      assert FilePathClassifier.should_filter?(:application, 0.1) == false
      assert FilePathClassifier.should_filter?(:application, 0.5) == false
      assert FilePathClassifier.should_filter?(:application, 0.9) == false
    end
  end
end
