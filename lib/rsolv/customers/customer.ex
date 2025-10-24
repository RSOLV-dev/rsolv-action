defmodule Rsolv.Customers.Customer do
  use Ecto.Schema
  import Ecto.Changeset

  schema "customers" do
    field :name, :string
    field :email, :string
    field :monthly_limit, :integer, default: 100
    field :current_usage, :integer, default: 0
    field :active, :boolean, default: true
    field :metadata, :map, default: %{}

    # Authentication fields
    field :password, :string, virtual: true, redact: true
    field :password_hash, :string, redact: true
    field :is_staff, :boolean, default: false
    field :admin_level, :string

    # Billing fields (consolidated from former Billing.Customer)
    field :trial_fixes_used, :integer, default: 0
    field :trial_fixes_limit, :integer, default: 5
    field :stripe_customer_id, :string
    field :subscription_plan, :string, default: "trial"
    field :subscription_status, :string, default: "active"
    field :rollover_fixes, :integer, default: 0
    field :payment_method_added_at, :utc_datetime
    field :trial_expired_at, :utc_datetime
    field :fixes_used_this_month, :integer, default: 0
    field :fixes_quota_this_month, :integer, default: 0
    field :has_payment_method, :boolean, default: false

    # Onboarding fields (RFC-065)
    field :auto_provisioned, :boolean, default: false
    # auto/hidden/shown
    field :wizard_preference, :string, default: "auto"
    field :first_scan_at, :utc_datetime

    has_many :api_keys, Rsolv.Customers.ApiKey
    has_many :fix_attempts, Rsolv.Billing.FixAttempt
    has_many :forge_accounts, Rsolv.Customers.ForgeAccount

    timestamps()
  end

  @admin_levels ~w(read_only limited full)

  @doc false
  def changeset(customer, attrs) do
    customer
    |> cast(attrs, [
      :name,
      :email,
      :monthly_limit,
      :current_usage,
      :active,
      :metadata,
      :trial_fixes_used,
      :trial_fixes_limit,
      :stripe_customer_id,
      :subscription_plan,
      :subscription_status,
      :rollover_fixes,
      :payment_method_added_at,
      :trial_expired_at,
      :fixes_used_this_month,
      :fixes_quota_this_month,
      :has_payment_method,
      :is_staff,
      :admin_level,
      :auto_provisioned,
      :wizard_preference,
      :first_scan_at
    ])
    |> validate_required([:name, :email])
    |> validate_format(:email, ~r/^[^\s]+@[^\s]+$/, message: "must have the @ sign and no spaces")
    |> unique_constraint(:email)
    |> validate_number(:monthly_limit, greater_than_or_equal_to: 0)
    |> validate_admin_level()
  end

  @doc """
  Checks if the customer's trial has expired.

  Returns true if trial_expired_at is set and in the past.
  """
  def trial_expired?(%__MODULE__{trial_expired_at: nil}), do: false

  def trial_expired?(%__MODULE__{trial_expired_at: expired_at}) do
    DateTime.compare(expired_at, DateTime.utc_now()) == :lt
  end

  @doc """
  Changeset for customer registration with password.
  """
  def registration_changeset(customer, attrs) do
    customer
    |> changeset(attrs)
    |> cast(attrs, [:password])
    |> validate_required([:password])
    |> validate_length(:password, min: 12, max: 72)
    |> validate_format(:password, ~r/[a-z]/,
      message: "must contain at least one lowercase letter"
    )
    |> validate_format(:password, ~r/[A-Z]/,
      message: "must contain at least one uppercase letter"
    )
    |> validate_format(:password, ~r/[0-9]/, message: "must contain at least one number")
    |> validate_format(:password, ~r/[!@#$%^&*(),.?":{}|<>]/,
      message: "must contain at least one special character"
    )
    |> hash_password()
  end

  @doc """
  Validates a password against the hashed password.
  """
  def valid_password?(%__MODULE__{password_hash: hashed_password}, password)
      when is_binary(hashed_password) and byte_size(password) > 0 do
    Bcrypt.verify_pass(password, hashed_password)
  end

  def valid_password?(_, _) do
    # Perform a dummy check to prevent timing attacks
    Bcrypt.no_user_verify()
    false
  end

  defp hash_password(changeset) do
    case changeset do
      %Ecto.Changeset{valid?: true, changes: %{password: password}} ->
        put_change(changeset, :password_hash, Bcrypt.hash_pwd_salt(password, log_rounds: 12))
        |> delete_change(:password)

      _ ->
        changeset
    end
  end

  defp validate_admin_level(changeset) do
    case get_change(changeset, :admin_level) do
      nil -> changeset
      level when level in @admin_levels -> changeset
      _ -> add_error(changeset, :admin_level, "is invalid")
    end
  end
end

# Implement the FunWithFlags.Actor protocol for Customer
defimpl FunWithFlags.Actor, for: Rsolv.Customers.Customer do
  def id(%{id: id}), do: "customer:#{id}"
end
