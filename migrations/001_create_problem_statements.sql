-- Create problem_statements table
CREATE TABLE IF NOT EXISTS problem_statements (
    id BIGSERIAL PRIMARY KEY,
    reference_id VARCHAR(20) UNIQUE NOT NULL,

    submitter_name VARCHAR(150) NOT NULL,
    department_name VARCHAR(200) NOT NULL,
    designation VARCHAR(150),
    contact_number VARCHAR(20),
    email VARCHAR(150) NOT NULL,

    title VARCHAR(255) NOT NULL,
    problem_description TEXT NOT NULL,
    current_challenges TEXT,
    expected_outcome TEXT,

    submission_status VARCHAR(20) NOT NULL DEFAULT 'Active',
    review_decision VARCHAR(20) NOT NULL DEFAULT 'Under Review',

    assigned_admin_id BIGINT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_problem_status ON problem_statements(submission_status);
CREATE INDEX IF NOT EXISTS idx_review_decision ON problem_statements(review_decision);
CREATE INDEX IF NOT EXISTS idx_department ON problem_statements(department_name);
CREATE INDEX IF NOT EXISTS idx_created_at ON problem_statements(created_at);
