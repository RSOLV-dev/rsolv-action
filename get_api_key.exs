alias Rsolv.Repo
import Ecto.Query

# Get a valid API key from the database
query =
  from a in "api_keys",
    where: a.is_active == true,
    limit: 1,
    select: a.key

case Repo.one(query) do
  nil -> IO.puts("No active API keys found")
  key -> IO.puts("API_KEY=#{key}")
end
