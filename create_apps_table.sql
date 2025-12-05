-- Create apps table
CREATE TABLE IF NOT EXISTS apps (
    app_id VARCHAR(20) PRIMARY KEY,
    description TEXT,
    is_admin_app BOOLEAN DEFAULT FALSE
);

-- Insert initial records
INSERT INTO apps (app_id, description, is_admin_app) VALUES
('A000001', 'Maintain Users', TRUE),
('A000002', 'Maintain Tenants', TRUE)
ON CONFLICT (app_id) DO NOTHING;
