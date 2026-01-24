-- Add assigned_reviewer column to problem_statements table
ALTER TABLE problem_statements ADD COLUMN IF NOT EXISTS assigned_reviewer VARCHAR(255);

-- Create index for faster reviewer lookups
CREATE INDEX IF NOT EXISTS idx_assigned_reviewer ON problem_statements(assigned_reviewer);
