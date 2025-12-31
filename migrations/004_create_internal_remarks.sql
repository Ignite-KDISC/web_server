-- Create internal_remarks table
CREATE TABLE IF NOT EXISTS internal_remarks (
    id BIGSERIAL PRIMARY KEY,
    problem_statement_id BIGINT NOT NULL REFERENCES problem_statements(id) ON DELETE CASCADE,
    admin_id BIGINT NOT NULL REFERENCES admin_users(id),

    remark TEXT NOT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

-- Create indexes for faster lookups
CREATE INDEX IF NOT EXISTS idx_internal_remarks_problem ON internal_remarks(problem_statement_id);
CREATE INDEX IF NOT EXISTS idx_internal_remarks_admin ON internal_remarks(admin_id);
