-- Create export_logs table
CREATE TABLE IF NOT EXISTS export_logs (
    id BIGSERIAL PRIMARY KEY,
    admin_id BIGINT REFERENCES admin_users(id),

    export_type VARCHAR(20), -- Excel / CSV / PDF
    applied_filters JSONB,

    record_count INT,
    exported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for export tracking
CREATE INDEX IF NOT EXISTS idx_export_logs_admin ON export_logs(admin_id);
CREATE INDEX IF NOT EXISTS idx_export_logs_type ON export_logs(export_type);
CREATE INDEX IF NOT EXISTS idx_export_logs_exported ON export_logs(exported_at);
