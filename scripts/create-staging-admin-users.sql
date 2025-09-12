-- Create admin users for staging environment
-- Based on priv/repo/seeds.exs

-- Admin user
INSERT INTO customers (
    name, 
    email, 
    password_hash,
    is_staff,
    admin_level,
    active,
    trial_fixes_limit,
    trial_fixes_used,
    subscription_plan,
    has_payment_method,
    metadata,
    inserted_at,
    updated_at
) VALUES (
    'RSOLV Admin',
    'admin@rsolv.dev',
    -- Password: AdminP@ssw0rd2025!
    '$2b$12$rAa2ryPo27qbTAtYKcp9S.DRRs6r5oh1df3zyzp4F3SKvaMIgOowO',
    true,
    'full',
    true,
    999999,
    0,
    'enterprise',
    true,
    '{"type": "internal", "purpose": "administration"}',
    NOW(),
    NOW()
) ON CONFLICT (email) DO UPDATE SET
    is_staff = EXCLUDED.is_staff,
    admin_level = EXCLUDED.admin_level,
    active = EXCLUDED.active;

-- Staff user
INSERT INTO customers (
    name, 
    email, 
    password_hash,
    is_staff,
    admin_level,
    active,
    trial_fixes_limit,
    trial_fixes_used,
    subscription_plan,
    has_payment_method,
    metadata,
    inserted_at,
    updated_at
) VALUES (
    'RSOLV Staff',
    'staff@rsolv.dev',
    -- Password: StaffP@ssw0rd2025!
    '$2b$12$ZpHiJYDMuC7R7J3XXcjseu25we.Tvh2LecOg2u7qPJE7quAzzfPVG',
    true,
    'limited',
    true,
    999999,
    0,
    'enterprise',
    true,
    '{"type": "internal", "purpose": "support"}',
    NOW(),
    NOW()
) ON CONFLICT (email) DO UPDATE SET
    is_staff = EXCLUDED.is_staff,
    admin_level = EXCLUDED.admin_level,
    active = EXCLUDED.active;

-- Test customer
INSERT INTO customers (
    name, 
    email, 
    password_hash,
    is_staff,
    admin_level,
    active,
    trial_fixes_limit,
    trial_fixes_used,
    subscription_plan,
    has_payment_method,
    metadata,
    inserted_at,
    updated_at
) VALUES (
    'Test Customer',
    'test@example.com',
    -- Password: TestP@ssw0rd2025!
    '$2b$12$1AA0Wd1fcJsktfSEaO3wVescmfMuAy42FEdpjHhQB6UDmHa.m4VkG',
    false,
    null,
    true,
    100,
    0,
    'trial',
    false,
    '{"type": "test", "purpose": "integration_testing"}',
    NOW(),
    NOW()
) ON CONFLICT (email) DO UPDATE SET
    active = EXCLUDED.active,
    trial_fixes_limit = EXCLUDED.trial_fixes_limit;

-- Demo customer
INSERT INTO customers (
    name, 
    email, 
    password_hash,
    is_staff,
    admin_level,
    active,
    trial_fixes_limit,
    trial_fixes_used,
    subscription_plan,
    has_payment_method,
    metadata,
    inserted_at,
    updated_at
) VALUES (
    'Demo Customer',
    'demo@example.com',
    -- Password: DemoP@ssw0rd2025!
    '$2b$12$QIXAq8dXEVKWJchI3.WNsuEh8WJEfWXu0vbYWb.t.dNf0AUVH0LKa',
    false,
    null,
    true,
    50,
    0,
    'trial',
    false,
    '{"type": "demo", "purpose": "demonstrations"}',
    NOW(),
    NOW()
) ON CONFLICT (email) DO UPDATE SET
    active = EXCLUDED.active,
    trial_fixes_limit = EXCLUDED.trial_fixes_limit;

-- Add API keys for each user
WITH admin_id AS (
    SELECT id FROM customers WHERE email = 'admin@rsolv.dev'
)
INSERT INTO api_keys (
    customer_id,
    name,
    key,
    active,
    inserted_at,
    updated_at
) VALUES (
    (SELECT id FROM admin_id),
    'Admin API Key',
    'rsolv_admin_key_staging_2025',
    true,
    NOW(),
    NOW()
) ON CONFLICT (key) DO NOTHING;

WITH staff_id AS (
    SELECT id FROM customers WHERE email = 'staff@rsolv.dev'
)
INSERT INTO api_keys (
    customer_id,
    name,
    key,
    active,
    inserted_at,
    updated_at
) VALUES (
    (SELECT id FROM staff_id),
    'Staff API Key',
    'rsolv_staff_key_staging_2025',
    true,
    NOW(),
    NOW()
) ON CONFLICT (key) DO NOTHING;

WITH test_id AS (
    SELECT id FROM customers WHERE email = 'test@example.com'
)
INSERT INTO api_keys (
    customer_id,
    name,
    key,
    active,
    inserted_at,
    updated_at
) VALUES (
    (SELECT id FROM test_id),
    'Test API Key',
    'rsolv_test_key_123',
    true,
    NOW(),
    NOW()
) ON CONFLICT (key) DO NOTHING;

WITH demo_id AS (
    SELECT id FROM customers WHERE email = 'demo@example.com'
)
INSERT INTO api_keys (
    customer_id,
    name,
    key,
    active,
    inserted_at,
    updated_at
) VALUES (
    (SELECT id FROM demo_id),
    'Demo API Key',
    'rsolv_demo_key_456',
    true,
    NOW(),
    NOW()
) ON CONFLICT (key) DO NOTHING;

-- Show created users
SELECT 
    name, 
    email, 
    is_staff, 
    admin_level, 
    subscription_plan,
    trial_fixes_limit
FROM customers 
WHERE email IN ('admin@rsolv.dev', 'staff@rsolv.dev', 'test@example.com', 'demo@example.com')
ORDER BY is_staff DESC, email;