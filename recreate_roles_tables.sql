-- Drop existing tables if they exist (reverse order of dependencies)
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS role_items; -- In case it exists from a previous run
DROP TABLE IF EXISTS roles;

-- Create roles table (Header)
CREATE TABLE roles (
    tenant_id INTEGER NOT NULL,
    role_id SERIAL,
    role_name VARCHAR(100) NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (tenant_id, role_id),
    CONSTRAINT fk_roles_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Create role_items table (Items/Permissions)
CREATE TABLE role_items (
    tenant_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    app_id VARCHAR(50) NOT NULL,
    can_create BOOLEAN DEFAULT FALSE,
    can_read BOOLEAN DEFAULT FALSE,
    can_update BOOLEAN DEFAULT FALSE,
    can_delete BOOLEAN DEFAULT FALSE,
    can_execute BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (tenant_id, role_id, app_id),
    CONSTRAINT fk_role_items_role FOREIGN KEY (tenant_id, role_id) REFERENCES roles(tenant_id, role_id) ON DELETE CASCADE
);

-- Create user_roles table (Assignment)
CREATE TABLE user_roles (
    tenant_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (tenant_id, user_id, role_id),
    CONSTRAINT fk_user_roles_role FOREIGN KEY (tenant_id, role_id) REFERENCES roles(tenant_id, role_id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes
CREATE INDEX idx_roles_tenant_id ON roles(tenant_id);
CREATE INDEX idx_role_items_role_id ON role_items(tenant_id, role_id);
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(tenant_id, role_id);

-- Create trigger functions for updated_at
-- Reuse existing function if possible, or create specific ones

-- Trigger for roles
DROP TRIGGER IF EXISTS update_roles_updated_at ON roles;
CREATE TRIGGER update_roles_updated_at
    BEFORE UPDATE ON roles
    FOR EACH ROW
    EXECUTE FUNCTION update_roles_updated_at_column();

-- Trigger for role_items
CREATE OR REPLACE FUNCTION update_role_items_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS update_role_items_updated_at ON role_items;
CREATE TRIGGER update_role_items_updated_at
    BEFORE UPDATE ON role_items
    FOR EACH ROW
    EXECUTE FUNCTION update_role_items_updated_at_column();
