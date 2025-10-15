defmodule Rsolv.Security.Patterns.Ruby.LdapInjectionTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Ruby.LdapInjection
  alias Rsolv.Security.Pattern

  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = LdapInjection.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "ruby-ldap-injection"
      assert pattern.name == "LDAP Injection"
      assert pattern.severity == :high
      assert pattern.type == :ldap_injection
      assert pattern.languages == ["ruby"]
    end

    test "includes CWE and OWASP references" do
      pattern = LdapInjection.pattern()

      assert pattern.cwe_id == "CWE-90"
      assert pattern.owasp_category == "A03:2021"
    end

    test "has multiple regex patterns" do
      pattern = LdapInjection.pattern()

      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 4
    end
  end

  describe "regex matching" do
    setup do
      pattern = LdapInjection.pattern()
      {:ok, pattern: pattern}
    end

    test "matches Net::LDAP filter construction with interpolation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|Net::LDAP::Filter.construct("(uid=#{username})")|,
        ~S|filter = Net::LDAP::Filter.construct("(&(objectClass=person)(cn=#{name}))")|,
        ~S|Net::LDAP::Filter.construct("(memberOf=cn=#{group},ou=groups,dc=example,dc=com)")|,
        ~S|search_filter = Net::LDAP::Filter.construct("(mail=#{email})")|,
        ~S|Net::LDAP::Filter.construct("(&(objectClass=inetOrgPerson)(memberOf=cn=#{group},ou=Groups,dc=example,dc=org))")|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches LDAP search with filter interpolation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|ldap.search(filter: "(uid=#{params[:username]})")|,
        ~S|ldap.search(base: "dc=example,dc=com", filter: "(cn=#{user_name})")|,
        ~S|connection.search(filter: "(&(objectClass=person)(mail=#{email}))")|,
        ~S|ldap.search(filter: "(memberOf=#{group_dn})", scope: Net::LDAP::SearchScope_WholeSubtree)|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches ldap_search method calls with interpolation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|ldap_search("(uid=#{username})")|,
        ~S|perform_ldap_search("(&(objectClass=user)(sAMAccountName=#{account}))")|,
        ~S|search_ldap("(cn=#{common_name})")|,
        ~S|find_ldap_entry("(mail=#{user_email})")|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches Net::LDAP authentication with interpolation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|ldap.auth("uid=#{username},ou=people,dc=example,dc=com", password)|,
        ~S|connection.auth("cn=#{user},ou=users,dc=company,dc=org", user_password)|,
        ~S|ldap.auth("#{user_dn}", credentials)|,
        ~S|ldap.authenticate("uid=#{login_name},ou=people,dc=example,dc=com", pass)|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "does not match safe LDAP patterns", %{pattern: pattern} do
      safe_code = [
        ~S|filter = Net::LDAP::Filter.eq("uid", username)|,
        ~S|escaped_name = Net::LDAP::Filter.escape(user_input)|,
        ~S|ldap.search(filter: Net::LDAP::Filter.eq("cn", name))|,
        ~S|filter = Net::LDAP::Filter.construct("(uid=static_user)")|,
        ~S|ldap.auth("cn=admin,dc=example,dc=com", password)|,
        ~S|puts "Searching for user: #{username}"|,
        ~S|ldap.search(filter: "(objectClass=person)", attributes: ["cn", "mail"])|
      ]

      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should not match: #{code}"
      end
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = LdapInjection.vulnerability_metadata()

      assert metadata.description =~ "LDAP injection"
      assert length(metadata.references) >= 3
      assert length(metadata.attack_vectors) >= 5
      assert length(metadata.real_world_impact) >= 3
      assert length(metadata.cve_examples) >= 2
    end

    test "includes real-world incident references" do
      metadata = LdapInjection.vulnerability_metadata()

      impact = Enum.join(metadata.real_world_impact, " ")
      assert impact =~ "Net::LDAP" || impact =~ "FluidAttacks" || impact =~ "LDAP injection"
    end

    test "includes proper references" do
      metadata = LdapInjection.vulnerability_metadata()

      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = LdapInjection.ast_enhancement()

      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)

      assert enhancement.min_confidence >= 0.7
    end

    test "includes LDAP-specific AST rules" do
      enhancement = LdapInjection.ast_enhancement()

      assert enhancement.ast_rules.node_type == "CallExpression"
      assert "construct" in enhancement.ast_rules.method_names
    end

    test "has proper context detection" do
      enhancement = LdapInjection.ast_enhancement()

      assert enhancement.context_rules.check_ldap_context
      assert "Net::LDAP::Filter.escape" in enhancement.context_rules.safe_functions
    end
  end
end
