-- Setup Test Schema
DROP SCHEMA IF EXISTS test CASCADE;
CREATE SCHEMA test;
SET search_path TO test;

-- 1. Create customers table
CREATE SEQUENCE IF NOT EXISTS customers_id_seq
    START WITH 10000000
    INCREMENT BY 1
    MINVALUE 10000000
    MAXVALUE 99999999
    NO CYCLE;

CREATE TABLE IF NOT EXISTS customers (
    customer_id INTEGER PRIMARY KEY DEFAULT nextval('customers_id_seq'),
    customer_name VARCHAR(255) NOT NULL,
    customer_category VARCHAR(50) NOT NULL CHECK (customer_category IN ('SCHOOL', 'SHOP', 'WAREHOUSE')),
    customer_type VARCHAR(50) NOT NULL CHECK (customer_type IN ('Contract', 'Permanent')),
    contact_person VARCHAR(255),
    email VARCHAR(100) UNIQUE NOT NULL,
    phone VARCHAR(20),
    address_line1 TEXT,
    address_line2 TEXT,
    city VARCHAR(100),
    state VARCHAR(100),
    postal_code VARCHAR(20),
    country VARCHAR(100) DEFAULT 'India',
    tax_id VARCHAR(50) UNIQUE,
    registration_number VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_customers_email ON customers(email);
CREATE INDEX IF NOT EXISTS idx_customers_category ON customers(customer_category);
CREATE INDEX IF NOT EXISTS idx_customers_is_active ON customers(is_active);
CREATE INDEX IF NOT EXISTS idx_customers_tax_id ON customers(tax_id) WHERE tax_id IS NOT NULL;

CREATE OR REPLACE FUNCTION update_customers_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_customers_updated_at
    BEFORE UPDATE ON customers
    FOR EACH ROW
    EXECUTE FUNCTION update_customers_updated_at_column();

-- 2. Create users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- 3. Create customer_user table
CREATE TABLE IF NOT EXISTS customer_user (
    customer_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    role_in_customer VARCHAR(100),
    is_primary BOOLEAN DEFAULT FALSE,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    assigned_by INTEGER,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (customer_id, user_id),
    CONSTRAINT fk_customer_user_customer FOREIGN KEY (customer_id) REFERENCES customers(customer_id) ON DELETE CASCADE,
    CONSTRAINT fk_customer_user_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_customer_user_assigned_by FOREIGN KEY (assigned_by) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT check_not_self_assigned CHECK (user_id != assigned_by OR assigned_by IS NULL)
);

CREATE INDEX IF NOT EXISTS idx_customer_user_user_id ON customer_user(user_id);
CREATE INDEX IF NOT EXISTS idx_customer_user_is_primary ON customer_user(is_primary) WHERE is_primary = TRUE;
CREATE INDEX IF NOT EXISTS idx_customer_user_assigned_by ON customer_user(assigned_by) WHERE assigned_by IS NOT NULL;

CREATE OR REPLACE FUNCTION update_customer_user_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_customer_user_updated_at
    BEFORE UPDATE ON customer_user
    FOR EACH ROW
    EXECUTE FUNCTION update_customer_user_updated_at_column();

-- 4. Create roles tables
CREATE TABLE IF NOT EXISTS roles (
    customer_id INTEGER NOT NULL,
    role_id SERIAL,
    app_id VARCHAR(50),
    role_name VARCHAR(100),
    can_create BOOLEAN DEFAULT FALSE,
    can_read BOOLEAN DEFAULT FALSE,
    can_update BOOLEAN DEFAULT FALSE,
    can_delete BOOLEAN DEFAULT FALSE,
    can_execute BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (customer_id, role_id),
    CONSTRAINT fk_roles_customer FOREIGN KEY (customer_id) REFERENCES customers(customer_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_roles (
    customer_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (customer_id, user_id, role_id),
    CONSTRAINT fk_user_roles_role FOREIGN KEY (customer_id, role_id) REFERENCES roles(customer_id, role_id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_customer FOREIGN KEY (customer_id) REFERENCES customers(customer_id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_roles_customer_id ON roles(customer_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);

CREATE OR REPLACE FUNCTION update_roles_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_roles_updated_at
    BEFORE UPDATE ON roles
    FOR EACH ROW
    EXECUTE FUNCTION update_roles_updated_at_column();
