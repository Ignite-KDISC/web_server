-- Create admin_users table
CREATE TABLE IF NOT EXISTS admin_users (
    id BIGSERIAL PRIMARY KEY,

    name VARCHAR(150),
    email VARCHAR(150) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,

    role VARCHAR(50) DEFAULT 'ADMIN',

    is_active BOOLEAN DEFAULT TRUE,
    last_login_at TIMESTAMP,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create index for faster email lookups
CREATE INDEX IF NOT EXISTS idx_admin_email ON admin_users(email);
CREATE INDEX IF NOT EXISTS idx_admin_active ON admin_users(is_active);
