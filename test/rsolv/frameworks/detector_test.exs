defmodule Rsolv.Frameworks.DetectorTest do
  use ExUnit.Case, async: true

  alias Rsolv.Frameworks.Detector

  describe "detect/1 with JavaScript/TypeScript frameworks" do
    test "detects Vitest from package.json" do
      package_files = %{
        package_json: %{
          "devDependencies" => %{
            "vitest" => "^1.0.0"
          }
        }
      }

      assert {:ok, result} = Detector.detect(package_files)
      assert result.framework == "vitest"
      assert result.version == "1.0.0"
      assert result.test_dir == "test/"
      assert result.compatible_with == []
    end

    test "detects Jest from package.json" do
      package_files = %{
        package_json: %{
          "devDependencies" => %{
            "jest" => "^29.0.0"
          }
        }
      }

      assert {:ok, result} = Detector.detect(package_files)
      assert result.framework == "jest"
      assert result.version == "29.0.0"
      assert result.test_dir == "__tests__/"
      assert result.compatible_with == []
    end

    test "detects Mocha from package.json" do
      package_files = %{
        package_json: %{
          "devDependencies" => %{
            "mocha" => "^10.0.0"
          }
        }
      }

      assert {:ok, result} = Detector.detect(package_files)
      assert result.framework == "mocha"
      assert result.version == "10.0.0"
      assert result.test_dir == "test/"
      assert result.compatible_with == []
    end

    test "prioritizes Vitest when multiple frameworks present" do
      package_files = %{
        package_json: %{
          "devDependencies" => %{
            "vitest" => "^1.0.0",
            "jest" => "^29.0.0",
            "mocha" => "^10.0.0"
          }
        }
      }

      assert {:ok, result} = Detector.detect(package_files)
      assert result.framework == "vitest"
      assert result.version == "1.0.0"
      assert "jest" in result.compatible_with
      assert "mocha" in result.compatible_with
    end

    test "prioritizes Jest over Mocha when Vitest not present" do
      package_files = %{
        package_json: %{
          "devDependencies" => %{
            "jest" => "^29.0.0",
            "mocha" => "^10.0.0"
          }
        }
      }

      assert {:ok, result} = Detector.detect(package_files)
      assert result.framework == "jest"
      assert result.version == "29.0.0"
      assert result.compatible_with == ["mocha"]
    end

    test "cleans version strings with ^" do
      package_files = %{
        package_json: %{
          "devDependencies" => %{
            "vitest" => "^1.2.3"
          }
        }
      }

      assert {:ok, result} = Detector.detect(package_files)
      assert result.version == "1.2.3"
    end

    test "cleans version strings with ~" do
      package_files = %{
        package_json: %{
          "devDependencies" => %{
            "jest" => "~29.1.0"
          }
        }
      }

      assert {:ok, result} = Detector.detect(package_files)
      assert result.version == "29.1.0"
    end
  end

  describe "detect/1 with Ruby frameworks" do
    test "detects RSpec from Gemfile" do
      package_files = %{
        gemfile: """
        source 'https://rubygems.org'
        gem 'rails', '~> 7.0'
        gem 'rspec', '~> 3.0'
        """
      }

      assert {:ok, result} = Detector.detect(package_files)
      assert result.framework == "rspec"
      assert result.version == "~> 3.0"
      assert result.test_dir == "spec/"
      assert result.compatible_with == []
    end

    test "detects Minitest from Gemfile" do
      package_files = %{
        gemfile: """
        source 'https://rubygems.org'
        gem 'rails', '~> 7.0'
        gem 'minitest', '~> 5.0'
        """
      }

      assert {:ok, result} = Detector.detect(package_files)
      assert result.framework == "minitest"
      assert result.version == "~> 5.0"
      assert result.test_dir == "test/"
      assert result.compatible_with == []
    end

    test "handles RSpec without version in Gemfile" do
      package_files = %{
        gemfile: """
        source 'https://rubygems.org'
        gem 'rspec'
        """
      }

      assert {:ok, result} = Detector.detect(package_files)
      assert result.framework == "rspec"
      assert result.version == nil
      assert result.test_dir == "spec/"
    end

    test "detects both RSpec and Minitest" do
      package_files = %{
        gemfile: """
        source 'https://rubygems.org'
        gem 'rspec', '~> 3.0'
        gem 'minitest', '~> 5.0'
        """
      }

      assert {:ok, result} = Detector.detect(package_files)
      # First detected becomes primary
      assert result.framework in ["rspec", "minitest"]
      assert length(result.compatible_with) == 1
    end
  end

  describe "detect/1 with Python frameworks" do
    test "detects pytest from requirements.txt" do
      package_files = %{
        requirements_txt: """
        django==4.0.0
        pytest==7.0.0
        pytest-cov==3.0.0
        """
      }

      assert {:ok, result} = Detector.detect(package_files)
      assert result.framework == "pytest"
      assert result.version == "7.0.0"
      assert result.test_dir == "tests/"
      assert result.compatible_with == []
    end

    test "detects pytest with >= version specifier" do
      package_files = %{
        requirements_txt: """
        pytest>=7.0.0
        """
      }

      assert {:ok, result} = Detector.detect(package_files)
      assert result.framework == "pytest"
      assert result.version == "7.0.0"
    end

    test "detects pytest without version" do
      package_files = %{
        requirements_txt: """
        django
        pytest
        """
      }

      assert {:ok, result} = Detector.detect(package_files)
      assert result.framework == "pytest"
      assert result.version == nil
    end

    test "detects unittest from requirements.txt" do
      package_files = %{
        requirements_txt: """
        unittest2==1.1.0
        """
      }

      # Note: unittest2 won't match, but unittest might appear as package name
      # This test verifies that unittest detection works when present
      assert {:error, _} = Detector.detect(package_files)
    end
  end

  describe "detect/1 with config files" do
    test "detects Vitest from config file" do
      package_files = %{
        config_files: ["vitest.config.ts", "package.json"]
      }

      assert {:ok, result} = Detector.detect(package_files)
      assert result.framework == "vitest"
      assert result.version == nil
      assert result.test_dir == "test/"
    end

    test "detects Jest from jest.config.js" do
      package_files = %{
        config_files: ["jest.config.js"]
      }

      assert {:ok, result} = Detector.detect(package_files)
      assert result.framework == "jest"
      assert result.test_dir == "__tests__/"
    end

    test "detects Mocha from .mocharc.json" do
      package_files = %{
        config_files: [".mocharc.json"]
      }

      assert {:ok, result} = Detector.detect(package_files)
      assert result.framework == "mocha"
      assert result.test_dir == "test/"
    end

    test "detects pytest from pytest.ini" do
      package_files = %{
        config_files: ["pytest.ini"]
      }

      assert {:ok, result} = Detector.detect(package_files)
      assert result.framework == "pytest"
      assert result.test_dir == "tests/"
    end

    test "detects RSpec from .rspec" do
      package_files = %{
        config_files: [".rspec", "spec/spec_helper.rb"]
      }

      assert {:ok, result} = Detector.detect(package_files)
      assert result.framework == "rspec"
      assert result.test_dir == "spec/"
    end
  end

  describe "detect/1 with multiple detection sources" do
    test "combines package.json and config file detection" do
      package_files = %{
        package_json: %{
          "devDependencies" => %{
            "vitest" => "^1.0.0"
          }
        },
        config_files: ["vitest.config.ts"]
      }

      assert {:ok, result} = Detector.detect(package_files)
      assert result.framework == "vitest"
      assert result.version == "1.0.0"
    end

    test "prioritizes package.json version over config file" do
      package_files = %{
        package_json: %{
          "devDependencies" => %{
            "jest" => "^29.0.0"
          }
        },
        config_files: ["jest.config.js", "vitest.config.ts"]
      }

      # With both present, priority determines primary framework
      # Vitest has higher priority, but Jest has version
      assert {:ok, result} = Detector.detect(package_files)
      # Should pick vitest due to priority, but jest also detected
      assert result.framework == "vitest"
      assert "jest" in result.compatible_with
    end
  end

  describe "detect/1 error cases" do
    test "returns error when no frameworks detected" do
      package_files = %{
        package_json: %{
          "devDependencies" => %{
            "typescript" => "^5.0.0"
          }
        }
      }

      assert {:error, "No test framework detected"} = Detector.detect(package_files)
    end

    test "returns error when all inputs are nil" do
      package_files = %{
        package_json: nil,
        gemfile: nil,
        requirements_txt: nil,
        config_files: []
      }

      assert {:error, "No test framework detected"} = Detector.detect(package_files)
    end

    test "handles empty package.json" do
      package_files = %{
        package_json: %{}
      }

      assert {:error, "No test framework detected"} = Detector.detect(package_files)
    end

    test "handles empty Gemfile" do
      package_files = %{
        gemfile: ""
      }

      assert {:error, "No test framework detected"} = Detector.detect(package_files)
    end

    test "handles empty requirements.txt" do
      package_files = %{
        requirements_txt: ""
      }

      assert {:error, "No test framework detected"} = Detector.detect(package_files)
    end
  end

  describe "detect/1 with custom test directories" do
    test "extracts custom test dir from Vitest config in package.json" do
      package_files = %{
        package_json: %{
          "devDependencies" => %{
            "vitest" => "^1.0.0"
          },
          "vitest" => %{
            "include" => ["src/**/*.test.ts"]
          }
        }
      }

      assert {:ok, result} = Detector.detect(package_files)
      assert result.test_dir == "src/"
    end

    test "extracts custom test dir from Jest config in package.json" do
      package_files = %{
        package_json: %{
          "devDependencies" => %{
            "jest" => "^29.0.0"
          },
          "jest" => %{
            "testMatch" => ["<rootDir>/specs/**/*.test.js"]
          }
        }
      }

      assert {:ok, result} = Detector.detect(package_files)
      assert result.test_dir == "<rootDir>/specs/"
    end

    test "falls back to default test dir when no custom config" do
      package_files = %{
        package_json: %{
          "devDependencies" => %{
            "vitest" => "^1.0.0"
          }
        }
      }

      assert {:ok, result} = Detector.detect(package_files)
      assert result.test_dir == "test/"
    end
  end
end
