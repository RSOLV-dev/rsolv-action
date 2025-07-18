Application.ensure_all_started(:postgrex)
{:ok, _} = Rsolv.Repo.start_link()

# Enable admin_dashboard
result1 = Rsolv.Repo.query("""
INSERT INTO fun_with_flags_toggles (flag_name, gate_type, enabled, inserted_at, updated_at)
VALUES ('admin_dashboard', 'boolean', true, NOW(), NOW())
ON CONFLICT (flag_name, gate_type) 
DO UPDATE SET enabled = true, updated_at = NOW()
""")

# Enable metrics_dashboard  
result2 = Rsolv.Repo.query("""
INSERT INTO fun_with_flags_toggles (flag_name, gate_type, enabled, inserted_at, updated_at)
VALUES ('metrics_dashboard', 'boolean', true, NOW(), NOW())
ON CONFLICT (flag_name, gate_type) 
DO UPDATE SET enabled = true, updated_at = NOW()
""")

IO.inspect(result1, label: "admin_dashboard")
IO.inspect(result2, label: "metrics_dashboard")
IO.puts("Feature flags enabled")