-- Create customer_user relationship table for many-to-many user-customer mapping
-- This table enables one user to belong to multiple customers (tenants)

CREATE TABLE IF NOT EXISTS customer_user (
    -- Composite primary key
    customer_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    
    -- Additional fields
    role_in_customer VARCHAR(100),
    is_primary BOOLEAN DEFAULT FALSE,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    assigned_by INTEGER,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Constraints
    PRIMARY KEY (customer_id, user_id),
    
    -- Foreign key constraints with CASCADE delete
    CONSTRAINT fk_customer_user_customer
        FOREIGN KEY (customer_id) 
        REFERENCES customers(customer_id) 
        ON DELETE CASCADE,
    
    CONSTRAINT fk_customer_user_user
        FOREIGN KEY (user_id) 
        REFERENCES users(id) 
        ON DELETE CASCADE,
    
    CONSTRAINT fk_customer_user_assigned_by
        FOREIGN KEY (assigned_by) 
        REFERENCES users(id) 
        ON DELETE SET NULL,
    
    -- Prevent self-assignment
    CONSTRAINT check_not_self_assigned
        CHECK (user_id != assigned_by OR assigned_by IS NULL)
);

-- Create indexes for performance optimization
CREATE INDEX IF NOT EXISTS idx_customer_user_user_id ON customer_user(user_id);
CREATE INDEX IF NOT EXISTS idx_customer_user_is_primary ON customer_user(is_primary) WHERE is_primary = TRUE;
CREATE INDEX IF NOT EXISTS idx_customer_user_assigned_by ON customer_user(assigned_by) WHERE assigned_by IS NOT NULL;

-- Create trigger function for updating updated_at timestamp
CREATE OR REPLACE FUNCTION update_customer_user_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger to automatically update updated_at on row modification
DROP TRIGGER IF EXISTS update_customer_user_updated_at ON customer_user;
CREATE TRIGGER update_customer_user_updated_at
    BEFORE UPDATE ON customer_user
    FOR EACH ROW
    EXECUTE FUNCTION update_customer_user_updated_at_column();

-- Add comments to table
COMMENT ON TABLE customer_user IS 'Many-to-many relationship between users and customers. Enables users to belong to multiple tenants.';
COMMENT ON COLUMN customer_user.customer_id IS 'Foreign key to customers table (tenant identifier)';
COMMENT ON COLUMN customer_user.user_id IS 'Foreign key to users table';
COMMENT ON COLUMN customer_user.role_in_customer IS 'User role within this specific customer/tenant context';
COMMENT ON COLUMN customer_user.is_primary IS 'Indicates if this is the user default customer on login';
COMMENT ON COLUMN customer_user.assigned_by IS 'User ID who created this customer-user assignment';
