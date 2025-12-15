-- Create enterprise database with user tables containing hashed passwords
CREATE DATABASE IF NOT EXISTS enterprise;
USE enterprise;

-- Create users table with MD5 hashed passwords (weak, common in legacy apps)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100),
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert users with MD5 hashed passwords (easily crackable)
-- password123 = 482c811da5d5b4bc6d497ffa98491e38
-- admin123 = 0192023a7bbd73250516f069df18b500
-- letmein = 0d107d09f5bbe40cade3de5c71e9e9b7
-- qwerty = d8578edf8458ce06fbc5bb76a58c5ca4
-- secret = 5ebe2294ecd0e0f08eab7690d2a6ee69
INSERT INTO users (username, email, password_hash, role) VALUES
('admin', 'admin@enterprise.local', '0192023a7bbd73250516f069df18b500', 'admin'),
('root', 'root@enterprise.local', '63a9f0ea7bb98050796b649e85481845', 'admin'),
('jsmith', 'john.smith@enterprise.local', '482c811da5d5b4bc6d497ffa98491e38', 'user'),
('mjones', 'mary.jones@enterprise.local', '0d107d09f5bbe40cade3de5c71e9e9b7', 'user'),
('dbadmin', 'dbadmin@enterprise.local', 'd8578edf8458ce06fbc5bb76a58c5ca4', 'admin'),
('backup', 'backup@enterprise.local', '5ebe2294ecd0e0f08eab7690d2a6ee69', 'service'),
('webapp', 'webapp@enterprise.local', 'e10adc3949ba59abbe56e057f20f883e', 'service'),
('api_user', 'api@enterprise.local', '25d55ad283aa400af464c76d713c07ad', 'api');

-- Create API keys table with SHA256 hashed tokens
CREATE TABLE IF NOT EXISTS api_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    key_hash VARCHAR(64) NOT NULL,
    description VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Insert API keys (SHA256 hashes)
INSERT INTO api_keys (user_id, key_hash, description) VALUES
(1, '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', 'Admin API Key'),
(6, '5e884898da28047d9169e1abed4d01d1c60b3d83a3a8a9bca9d5a8a8f8f8a8f8', 'Backup Service Key');

-- Create sessions table (for session hijacking practice)
CREATE TABLE IF NOT EXISTS sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    session_token VARCHAR(64) NOT NULL,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Create password_history for credential stuffing practice
CREATE TABLE IF NOT EXISTS password_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    old_password_hash VARCHAR(255) NOT NULL,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Insert some password history (SHA1 hashes - also weak)
-- password = 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
-- 123456 = 7c4a8d09ca3762af61e59520943dc26494f8941b
INSERT INTO password_history (user_id, old_password_hash) VALUES
(1, '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8'),
(3, '7c4a8d09ca3762af61e59520943dc26494f8941b');

-- Grant access to admin user (MySQL 8.0+ syntax)
GRANT ALL PRIVILEGES ON enterprise.* TO 'admin'@'%';
GRANT ALL PRIVILEGES ON wordpress.* TO 'admin'@'%';
FLUSH PRIVILEGES;
