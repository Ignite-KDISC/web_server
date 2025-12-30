-- Create problem_documents table
CREATE TABLE IF NOT EXISTS problem_documents (
    id BIGSERIAL PRIMARY KEY,
    problem_statement_id BIGINT NOT NULL REFERENCES problem_statements(id) ON DELETE CASCADE,

    original_file_name VARCHAR(255),
    stored_file_name VARCHAR(255),
    file_type VARCHAR(20),
    file_size BIGINT,

    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_problem_statement_id ON problem_documents(problem_statement_id);
