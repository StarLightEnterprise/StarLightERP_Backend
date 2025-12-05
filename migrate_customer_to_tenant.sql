-- Migration script to rename 'customer' to 'tenant'

BEGIN;

-- 1. Rename tables
ALTER TABLE IF EXISTS customers RENAME TO tenants;
ALTER TABLE IF EXISTS customer_user RENAME TO tenant_user;

-- 2. Rename columns in 'tenants' (formerly customers)
ALTER TABLE tenants RENAME COLUMN customer_id TO tenant_id;
ALTER TABLE tenants RENAME COLUMN customer_name TO tenant_name;
ALTER TABLE tenants RENAME COLUMN customer_category TO tenant_category;
ALTER TABLE tenants RENAME COLUMN customer_type TO tenant_type;

-- 3. Rename columns in 'tenant_user' (formerly customer_user)
ALTER TABLE tenant_user RENAME COLUMN customer_id TO tenant_id;
ALTER TABLE tenant_user RENAME COLUMN role_in_customer TO role_in_tenant;

-- 4. Rename columns in 'roles'
ALTER TABLE roles RENAME COLUMN customer_id TO tenant_id;

-- Roles Items Table
ALTER TABLE role_items RENAME COLUMN customer_id TO tenant_id;

-- 5. Rename columns in 'user_roles'
ALTER TABLE user_roles RENAME COLUMN customer_id TO tenant_id;

-- 6. Rename sequences
ALTER SEQUENCE IF EXISTS customers_id_seq RENAME TO tenants_id_seq;

-- 7. Rename indexes (optional but good for consistency)
-- tenants table indexes
ALTER INDEX IF EXISTS idx_customers_email RENAME TO idx_tenants_email;
ALTER INDEX IF EXISTS idx_customers_category RENAME TO idx_tenants_category;
ALTER INDEX IF EXISTS idx_customers_is_active RENAME TO idx_tenants_is_active;
ALTER INDEX IF EXISTS idx_customers_tax_id RENAME TO idx_tenants_tax_id;

-- tenant_user table indexes
-- idx_customer_user_user_id might be fine, but let's be consistent if we can,
-- although standard index names often auto-generated.
-- If we manually named them:
ALTER INDEX IF EXISTS idx_customer_user_user_id RENAME TO idx_tenant_user_user_id;
ALTER INDEX IF EXISTS idx_customer_user_is_primary RENAME TO idx_tenant_user_is_primary;
ALTER INDEX IF EXISTS idx_customer_user_assigned_by RENAME TO idx_tenant_user_assigned_by;

-- roles table indexes
ALTER INDEX IF EXISTS idx_roles_customer_id RENAME TO idx_roles_tenant_id;

-- 8. Update specific constraints if necessary (Postgres usually handles FK renames automatically, but let's be safe)
-- Renaming constraints for clarity
ALTER TABLE tenants RENAME CONSTRAINT customers_pkey TO tenants_pkey;
ALTER TABLE tenant_user RENAME CONSTRAINT customer_user_pkey TO tenant_user_pkey;

-- 9. Update data values if 'customer' word is used in data (e.g. roles?)
-- Assuming 'role_in_customer' values are generic like 'ADMIN', 'USER', not 'CUSTOMER_ADMIN'.
-- If they are specific, update them here:
-- UPDATE tenant_user SET role_in_tenant = REPLACE(role_in_tenant, 'CUSTOMER', 'TENANT');

-- 10. Recreate triggers/functions if they used specific names or logic
-- Dropping old triggers/functions
DROP TRIGGER IF EXISTS update_customers_updated_at ON tenants;
DROP FUNCTION IF EXISTS update_customers_updated_at_column();

DROP TRIGGER IF EXISTS update_customer_user_updated_at ON tenant_user;
DROP FUNCTION IF EXISTS update_customer_user_updated_at_column();

-- Recreating them with new names
CREATE OR REPLACE FUNCTION update_tenants_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_tenants_updated_at
    BEFORE UPDATE ON tenants
    FOR EACH ROW
    EXECUTE FUNCTION update_tenants_updated_at_column();

CREATE OR REPLACE FUNCTION update_tenant_user_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_tenant_user_updated_at
    BEFORE UPDATE ON tenant_user
    FOR EACH ROW
    EXECUTE FUNCTION update_tenant_user_updated_at_column();

COMMIT;
