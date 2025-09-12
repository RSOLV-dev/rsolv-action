#!/usr/bin/env elixir

# Generate bcrypt hashes for seed passwords
passwords = [
  {"AdminP@ssw0rd2025!", "Admin"},
  {"StaffP@ssw0rd2025!", "Staff"},
  {"TestP@ssw0rd2025!", "Test"},
  {"DemoP@ssw0rd2025!", "Demo"}
]

for {password, label} <- passwords do
  hash = Bcrypt.hash_pwd_salt(password)
  IO.puts("#{label}: #{hash}")
end