-- Create super_users table
CREATE TABLE IF NOT EXISTS super_users (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Seed super user 'upendra_upx'
DO $$
DECLARE
    v_user_id INTEGER;
BEGIN
    -- Check if user exists
    SELECT id INTO v_user_id FROM users WHERE username = 'upendra_upx';
    
    IF v_user_id IS NULL THEN
        -- Create user
        INSERT INTO users (username, email, password_hash, role, is_active)
        VALUES ('upendra_upx', 'upendra_upx@starlighterp.com', 'fb1b944e399c151b88a5dd2e3486befbaf05909fe4515c942bbd8dd8a55c47df', 'SuperAdmin', TRUE)
        RETURNING id INTO v_user_id;
        RAISE NOTICE 'Created user upendra_upx with id %', v_user_id;
    END IF;

    -- Insert into super_users
    INSERT INTO super_users (user_id)
    VALUES (v_user_id)
    ON CONFLICT (user_id) DO NOTHING;
    
    RAISE NOTICE 'Seeded super user upendra_upx';
END $$;
