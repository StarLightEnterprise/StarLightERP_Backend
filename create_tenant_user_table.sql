-- Create tenant_user relationship table for many-to-many user-tenant mapping
-- This table enables one user to belong to multiple tenants

CREATE TABLE IF NOT EXISTS tenant_user (
    -- Composite primary key
    tenant_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    
    -- Additional fields
    role_in_tenant VARCHAR(100),
    is_primary BOOLEAN DEFAULT FALSE,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    assigned_by INTEGER,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Constraints
    PRIMARY KEY (tenant_id, user_id),
    
    -- Foreign key constraints with CASCADE delete
    CONSTRAINT fk_tenant_user_tenant
        FOREIGN KEY (tenant_id) 
        REFERENCES tenants(tenant_id) 
        ON DELETE CASCADE,
    
    CONSTRAINT fk_tenant_user_user
        FOREIGN KEY (user_id) 
        REFERENCES users(id) 
        ON DELETE CASCADE,
    
    CONSTRAINT fk_tenant_user_assigned_by
        FOREIGN KEY (assigned_by) 
        REFERENCES users(id) 
        ON DELETE SET NULL,
    
    -- Prevent self-assignment
    CONSTRAINT check_not_self_assigned
        CHECK (user_id != assigned_by OR assigned_by IS NULL)
);

-- Create indexes for performance optimization
CREATE INDEX IF NOT EXISTS idx_tenant_user_user_id ON tenant_user(user_id);
CREATE INDEX IF NOT EXISTS idx_tenant_user_is_primary ON tenant_user(is_primary) WHERE is_primary = TRUE;
CREATE INDEX IF NOT EXISTS idx_tenant_user_assigned_by ON tenant_user(assigned_by) WHERE assigned_by IS NOT NULL;

-- Create trigger function for updating updated_at timestamp
CREATE OR REPLACE FUNCTION update_tenant_user_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger to automatically update updated_at on row modification
DROP TRIGGER IF EXISTS update_tenant_user_updated_at ON tenant_user;
CREATE TRIGGER update_tenant_user_updated_at
    BEFORE UPDATE ON tenant_user
    FOR EACH ROW
    EXECUTE FUNCTION update_tenant_user_updated_at_column();

-- Add comments to table
COMMENT ON TABLE tenant_user IS 'Many-to-many relationship between users and tenants. Enables users to belong to multiple tenants.';
COMMENT ON COLUMN tenant_user.tenant_id IS 'Foreign key to tenants table';
COMMENT ON COLUMN tenant_user.user_id IS 'Foreign key to users table';
COMMENT ON COLUMN tenant_user.role_in_tenant IS 'User role within this specific tenant context';
COMMENT ON COLUMN tenant_user.is_primary IS 'Indicates if this is the user default tenant on login';
COMMENT ON COLUMN tenant_user.assigned_by IS 'User ID who created this tenant-user assignment';

