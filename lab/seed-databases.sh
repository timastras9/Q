#!/bin/bash
# Seed data script for Enterprise Vulnerable Lab
# Creates realistic data in all databases for pentesting practice

set -e

echo "=== Enterprise Lab Database Seeding ==="
echo "Waiting for databases to be ready..."
sleep 5

# MySQL seed data
echo "[*] Seeding MySQL database..."
docker exec lab-mysql mysql -uroot -proot123 <<'MYSQL_EOF'
-- Create enterprise database
CREATE DATABASE IF NOT EXISTS enterprise_hr;
USE enterprise_hr;

-- Employee table with sensitive PII
CREATE TABLE IF NOT EXISTS employees (
    id INT AUTO_INCREMENT PRIMARY KEY,
    employee_id VARCHAR(20) UNIQUE,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    email VARCHAR(100),
    ssn VARCHAR(11),
    salary DECIMAL(10,2),
    department VARCHAR(50),
    hire_date DATE,
    password_hash VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert employee data
INSERT INTO employees (employee_id, first_name, last_name, email, ssn, salary, department, password_hash) VALUES
('EMP001', 'John', 'Smith', 'jsmith@enterprise.local', '123-45-6789', 85000.00, 'Engineering', MD5('password123')),
('EMP002', 'Jane', 'Doe', 'jdoe@enterprise.local', '234-56-7890', 92000.00, 'Engineering', MD5('letmein')),
('EMP003', 'Robert', 'Johnson', 'rjohnson@enterprise.local', '345-67-8901', 120000.00, 'Management', MD5('admin123')),
('EMP004', 'Emily', 'Williams', 'ewilliams@enterprise.local', '456-78-9012', 78000.00, 'HR', MD5('hr2024!')),
('EMP005', 'Michael', 'Brown', 'mbrown@enterprise.local', '567-89-0123', 95000.00, 'Finance', MD5('finance$$')),
('EMP006', 'Sarah', 'Davis', 'sdavis@enterprise.local', '678-90-1234', 88000.00, 'Engineering', MD5('sarah2024')),
('EMP007', 'David', 'Miller', 'dmiller@enterprise.local', '789-01-2345', 150000.00, 'Executive', MD5('ceo_secure')),
('EMP008', 'Lisa', 'Wilson', 'lwilson@enterprise.local', '890-12-3456', 72000.00, 'Support', MD5('support1')),
('EMP009', 'James', 'Taylor', 'jtaylor@enterprise.local', '901-23-4567', 105000.00, 'Security', MD5('sec_admin')),
('EMP010', 'Jennifer', 'Anderson', 'janderson@enterprise.local', '012-34-5678', 68000.00, 'Marketing', MD5('market2024'));

-- API Keys table (sensitive)
CREATE TABLE IF NOT EXISTS api_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    service_name VARCHAR(100),
    api_key VARCHAR(255),
    api_secret VARCHAR(255),
    environment VARCHAR(20),
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO api_keys (service_name, api_key, api_secret, environment, created_by) VALUES
('AWS Production', 'AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'production', 1),
('Stripe Live', 'sk_live_51234567890abcdefghijklmnop', 'whsec_abcdefghijklmnopqrstuvwxyz123456', 'production', 3),
('SendGrid', 'SG.1234567890abcdefghijklmnop.qrstuvwxyz', NULL, 'production', 4),
('Twilio', 'AC1234567890abcdef1234567890abcdef', 'auth_token_1234567890abcdef', 'staging', 6),
('GitHub Token', 'ghp_1234567890abcdefghijklmnopqrstuvwxyz', NULL, 'development', 2);

-- Credit card data (test data for PCI compliance testing)
CREATE TABLE IF NOT EXISTS payment_methods (
    id INT AUTO_INCREMENT PRIMARY KEY,
    customer_id INT,
    card_type VARCHAR(20),
    card_number VARCHAR(19),
    expiry_date VARCHAR(5),
    cvv VARCHAR(4),
    cardholder_name VARCHAR(100)
);

INSERT INTO payment_methods (customer_id, card_type, card_number, expiry_date, cvv, cardholder_name) VALUES
(1, 'Visa', '4532015112830366', '12/25', '123', 'JOHN SMITH'),
(2, 'MasterCard', '5425233430109903', '06/26', '456', 'JANE DOE'),
(3, 'Amex', '374245455400126', '03/25', '7890', 'ROBERT JOHNSON'),
(4, 'Visa', '4916338506082832', '09/27', '321', 'EMILY WILLIAMS'),
(5, 'MasterCard', '5506900140100107', '11/26', '654', 'MICHAEL BROWN');

-- System credentials (internal passwords)
CREATE TABLE IF NOT EXISTS system_credentials (
    id INT AUTO_INCREMENT PRIMARY KEY,
    system_name VARCHAR(100),
    username VARCHAR(50),
    password VARCHAR(255),
    server VARCHAR(100),
    notes TEXT
);

INSERT INTO system_credentials (system_name, username, password, server, notes) VALUES
('Domain Admin', 'admin', 'P@ssw0rd2024!', 'dc01.enterprise.local', 'Primary domain controller'),
('Database Root', 'dba_admin', 'Db@dmin#2024', 'db.enterprise.local', 'Production database'),
('VPN Gateway', 'vpnadmin', 'Vpn$ecure99', 'vpn.enterprise.local', 'Corporate VPN'),
('Backup Server', 'backup_svc', 'B4ckup!Srv', 'backup.enterprise.local', 'Daily backups at 2AM'),
('Jenkins CI', 'jenkins', 'j3nk1ns_bu1ld', 'ci.enterprise.local', 'CI/CD pipeline');

GRANT ALL PRIVILEGES ON enterprise_hr.* TO 'wordpress'@'%';
FLUSH PRIVILEGES;
MYSQL_EOF
echo "[+] MySQL seeded successfully"

# PostgreSQL seed data
echo "[*] Seeding PostgreSQL database..."
docker exec lab-postgres psql -U admin -d enterprise <<'POSTGRES_EOF'
-- Customer data table
CREATE TABLE IF NOT EXISTS customers (
    id SERIAL PRIMARY KEY,
    customer_id VARCHAR(20) UNIQUE,
    company_name VARCHAR(100),
    contact_name VARCHAR(100),
    email VARCHAR(100),
    phone VARCHAR(20),
    address TEXT,
    credit_limit DECIMAL(12,2),
    tax_id VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO customers (customer_id, company_name, contact_name, email, phone, address, credit_limit, tax_id) VALUES
('CUST001', 'Acme Corporation', 'Wile E. Coyote', 'wcoyote@acme.com', '555-0100', '123 Desert Road, AZ 85001', 500000.00, '12-3456789'),
('CUST002', 'Stark Industries', 'Tony Stark', 'tony@stark.com', '555-0200', '200 Park Ave, NY 10001', 10000000.00, '98-7654321'),
('CUST003', 'Wayne Enterprises', 'Bruce Wayne', 'bwayne@wayne.com', '555-0300', '1 Wayne Tower, Gotham', 25000000.00, '11-2233445'),
('CUST004', 'Oscorp', 'Norman Osborn', 'nosborn@oscorp.com', '555-0400', '500 5th Ave, NY 10001', 5000000.00, '55-6677889'),
('CUST005', 'LexCorp', 'Lex Luthor', 'lluthor@lexcorp.com', '555-0500', '1 LexCorp Plaza, Metropolis', 15000000.00, '99-8877665');

-- Financial transactions
CREATE TABLE IF NOT EXISTS transactions (
    id SERIAL PRIMARY KEY,
    transaction_id VARCHAR(36),
    customer_id VARCHAR(20),
    amount DECIMAL(12,2),
    transaction_type VARCHAR(20),
    bank_account VARCHAR(30),
    routing_number VARCHAR(9),
    status VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO transactions (transaction_id, customer_id, amount, transaction_type, bank_account, routing_number, status) VALUES
('TXN-001-2024', 'CUST001', 150000.00, 'WIRE', '****4567', '021000021', 'completed'),
('TXN-002-2024', 'CUST002', 2500000.00, 'ACH', '****8901', '021000089', 'completed'),
('TXN-003-2024', 'CUST003', 5000000.00, 'WIRE', '****2345', '021000021', 'pending'),
('TXN-004-2024', 'CUST001', 75000.00, 'ACH', '****4567', '021000021', 'completed'),
('TXN-005-2024', 'CUST004', 800000.00, 'WIRE', '****6789', '021000089', 'failed');

-- Internal audit logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id VARCHAR(50),
    action VARCHAR(100),
    resource VARCHAR(200),
    ip_address VARCHAR(45),
    details JSONB
);

INSERT INTO audit_logs (user_id, action, resource, ip_address, details) VALUES
('admin', 'LOGIN', '/admin/dashboard', '192.168.1.100', '{"success": true, "mfa": false}'),
('jsmith', 'EXPORT', '/reports/financial', '10.0.0.50', '{"rows": 15000, "format": "csv"}'),
('admin', 'CONFIG_CHANGE', '/settings/security', '192.168.1.100', '{"setting": "password_policy", "old": "weak", "new": "medium"}'),
('system', 'BACKUP', '/data/customers', '127.0.0.1', '{"size_mb": 2500, "duration_sec": 120}'),
('rjohnson', 'DELETE', '/customers/CUST099', '10.0.0.75', '{"reason": "duplicate"}');
POSTGRES_EOF
echo "[+] PostgreSQL seeded successfully"

# MongoDB seed data
echo "[*] Seeding MongoDB..."
docker exec lab-mongodb mongosh --quiet <<'MONGO_EOF'
use enterprise

// User sessions collection (sensitive)
db.sessions.insertMany([
    {
        sessionId: "sess_abc123def456",
        userId: "user001",
        email: "admin@enterprise.local",
        role: "admin",
        accessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        refreshToken: "rt_xyz789ghi012",
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 86400000)
    },
    {
        sessionId: "sess_mno345pqr678",
        userId: "user002",
        email: "developer@enterprise.local",
        role: "developer",
        accessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5ODc2NTQzMjEwIiwibmFtZSI6IkRldiIsImlhdCI6MTUxNjIzOTAyMn0.tbDepxpstvGdW8TC3G8zg4B6rUYAOvfzdceoH48wgRQ",
        refreshToken: "rt_stu901vwx234",
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 86400000)
    }
]);

// Application secrets
db.secrets.insertMany([
    {
        name: "database_encryption_key",
        value: "aes-256-cbc:s3cr3t-k3y-f0r-3ncrypt10n",
        environment: "production",
        rotatedAt: new Date()
    },
    {
        name: "jwt_signing_key",
        value: "super-secret-jwt-key-do-not-share-2024",
        environment: "production",
        rotatedAt: new Date()
    },
    {
        name: "oauth_client_secret",
        value: "oauth-cl13nt-s3cr3t-v4lu3",
        environment: "production",
        rotatedAt: new Date()
    }
]);

// Customer PII
db.customer_profiles.insertMany([
    {
        customerId: "CUST001",
        profile: {
            firstName: "John",
            lastName: "Doe",
            dateOfBirth: "1985-03-15",
            ssn: "123-45-6789",
            driversLicense: "D1234567",
            passport: "US123456789"
        },
        preferences: {
            marketing: true,
            smsAlerts: true
        }
    },
    {
        customerId: "CUST002",
        profile: {
            firstName: "Jane",
            lastName: "Smith",
            dateOfBirth: "1990-07-22",
            ssn: "987-65-4321",
            driversLicense: "S9876543",
            passport: "US987654321"
        },
        preferences: {
            marketing: false,
            smsAlerts: true
        }
    }
]);

print("MongoDB seeded successfully");
MONGO_EOF
echo "[+] MongoDB seeded successfully"

# Redis seed data
echo "[*] Seeding Redis..."
docker exec lab-redis redis-cli <<'REDIS_EOF'
SET session:admin:token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.admin_session_token"
SET session:user123:token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.user123_session"
SET api:rate_limit:config '{"requests_per_minute": 100, "burst": 20}'
SET cache:user:admin '{"id": 1, "role": "admin", "permissions": ["read", "write", "delete", "admin"]}'
SET cache:user:developer '{"id": 2, "role": "developer", "permissions": ["read", "write"]}'
HSET config:database host "db.enterprise.local"
HSET config:database port "5432"
HSET config:database user "db_admin"
HSET config:database password "Pr0d_Db_P@ss!"
LPUSH queue:jobs '{"job_id": "job001", "type": "export", "data": "customers"}'
LPUSH queue:jobs '{"job_id": "job002", "type": "report", "data": "financial"}'
SADD admin:users "admin@enterprise.local" "superadmin@enterprise.local"
SET secret:api_key "sk_live_enterprise_secret_key_2024"
REDIS_EOF
echo "[+] Redis seeded successfully"

# Elasticsearch seed data
echo "[*] Seeding Elasticsearch..."
sleep 3
curl -s -X PUT "http://localhost:9200/enterprise-logs" -H "Content-Type: application/json" -d '{
  "mappings": {
    "properties": {
      "timestamp": { "type": "date" },
      "level": { "type": "keyword" },
      "message": { "type": "text" },
      "user": { "type": "keyword" },
      "ip": { "type": "ip" }
    }
  }
}' > /dev/null

# Add log entries
curl -s -X POST "http://localhost:9200/enterprise-logs/_doc" -H "Content-Type: application/json" -d '{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "message": "User admin logged in successfully",
  "user": "admin",
  "ip": "192.168.1.100"
}' > /dev/null

curl -s -X POST "http://localhost:9200/enterprise-logs/_doc" -H "Content-Type: application/json" -d '{
  "timestamp": "2024-01-15T10:35:00Z",
  "level": "WARNING",
  "message": "Failed login attempt for user root - password: P@ssw0rd",
  "user": "root",
  "ip": "203.0.113.50"
}' > /dev/null

curl -s -X POST "http://localhost:9200/enterprise-logs/_doc" -H "Content-Type: application/json" -d '{
  "timestamp": "2024-01-15T11:00:00Z",
  "level": "ERROR",
  "message": "Database connection string: postgresql://admin:admin123@db:5432/enterprise",
  "user": "system",
  "ip": "127.0.0.1"
}' > /dev/null

curl -s -X POST "http://localhost:9200/enterprise-logs/_doc" -H "Content-Type: application/json" -d '{
  "timestamp": "2024-01-15T11:15:00Z",
  "level": "DEBUG",
  "message": "API Key used: sk_live_51234567890abcdefghijklmnop",
  "user": "api-service",
  "ip": "10.0.0.50"
}' > /dev/null
echo "[+] Elasticsearch seeded successfully"

echo ""
echo "=== Database Seeding Complete ==="
echo ""
echo "Sensitive data planted in:"
echo "  - MySQL: employee SSNs, API keys, credit cards, system credentials"
echo "  - PostgreSQL: customer data, financial transactions, audit logs"
echo "  - MongoDB: user sessions, JWT tokens, customer PII"
echo "  - Redis: session tokens, database credentials, API keys"
echo "  - Elasticsearch: logs with leaked credentials"
echo ""
echo "Ready for penetration testing!"
