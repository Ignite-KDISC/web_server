-- Create submission_status enum lookup table
CREATE TABLE IF NOT EXISTS submission_status_enum (
    id SERIAL PRIMARY KEY,
    status_name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default submission statuses
INSERT INTO submission_status_enum (status_name, description) VALUES
    ('Active', 'Problem statement is currently active'),
    ('PoC', 'Proof of Concept stage'),
    ('Closed', 'Problem statement is closed')
ON CONFLICT (status_name) DO NOTHING;

-- Create review_decision enum lookup table
CREATE TABLE IF NOT EXISTS review_decision_enum (
    id SERIAL PRIMARY KEY,
    decision_name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default review decisions
INSERT INTO review_decision_enum (decision_name, description) VALUES
    ('Under Review', 'Submission is under review'),
    ('Accepted', 'Submission has been accepted'),
    ('Rejected', 'Submission has been rejected')
ON CONFLICT (decision_name) DO NOTHING;

-- Add constraints to problem_statements table to validate against enum tables
-- Note: These constraints will be enforced by application logic for existing tables
-- For new implementations, you could add CHECK constraints or foreign keys
