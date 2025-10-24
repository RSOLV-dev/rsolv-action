[
  import_deps: [:ecto, :ecto_sql, :phoenix],
  subdirectories: ["priv/*/migrations"],
  plugins: [Phoenix.LiveView.HTMLFormatter],
  inputs: [
    "*.{heex,ex,exs}",
    "{config,test}/**/*.{heex,ex,exs}",
    "lib/**/*.{ex,exs}",
    # Include most .heex files but exclude docs_html directory
    "lib/rsolv_web/**/*.heex",
    "priv/*/seeds.exs"
  ],
  # Exclude documentation HTML templates - they're content-heavy and conflict with trailing whitespace checks
  # The HTMLFormatter adds indented blank lines which git hooks reject
  exclude: ["lib/rsolv_web/controllers/docs_html/**/*.heex"]
]
