const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const xml2js = require('xml2js');
const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;

// VULNERABILITY: Hardcoded secret (should be in env)
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key-123';

// VULNERABILITY: Debug mode exposes sensitive info
const DEBUG = process.env.DEBUG === 'true';

app.use(cors()); // VULNERABILITY: CORS too permissive
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.text({ type: 'application/xml' }));

// Simulated database
const users = [
  { id: 1, username: 'admin', password: 'admin123', role: 'admin' },
  { id: 2, username: 'user', password: 'password', role: 'user' },
  { id: 3, username: 'guest', password: 'guest', role: 'guest' }
];

const secrets = [
  { id: 1, userId: 1, data: 'AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE' },
  { id: 2, userId: 1, data: 'DATABASE_URL=postgres://admin:supersecret@db.internal:5432/prod' },
  { id: 3, userId: 2, data: 'API_KEY=sk-prod-1234567890abcdef' }
];

// ============================================
// VULNERABILITY 1: JWT Algorithm Confusion
// ============================================
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  // VULNERABILITY: Timing attack on password comparison
  const user = users.find(u => u.username === username && u.password === password);

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // VULNERABILITY: Algorithm not enforced - accepts 'none' and 'HS256'
  const token = jwt.sign(
    { userId: user.id, role: user.role, username: user.username },
    JWT_SECRET,
    { algorithm: 'HS256', expiresIn: '1h' }
  );

  res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
});

// VULNERABILITY: JWT verification doesn't enforce algorithm
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    // VULNERABILITY: algorithms array allows 'none'
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256', 'none'] });
    req.user = decoded;
    next();
  } catch (err) {
    // VULNERABILITY: Detailed error messages
    res.status(403).json({ error: 'Invalid token', details: err.message });
  }
}

// ============================================
// VULNERABILITY 2: IDOR - Insecure Direct Object Reference
// ============================================
app.get('/api/users/:id', verifyToken, (req, res) => {
  const userId = parseInt(req.params.id);

  // VULNERABILITY: No authorization check - any user can access any user's data
  const user = users.find(u => u.id === userId);

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  // VULNERABILITY: Returns password hash
  res.json(user);
});

// ============================================
// VULNERABILITY 3: NoSQL Injection
// ============================================
app.post('/api/search', verifyToken, (req, res) => {
  const { query } = req.body;

  // VULNERABILITY: Query passed directly - allows NoSQL injection
  // Example payload: {"query": {"$gt": ""}}
  const results = users.filter(u => {
    if (typeof query === 'object') {
      // This simulates MongoDB-like query handling
      if (query.$gt !== undefined) return u.username > query.$gt;
      if (query.$regex) return new RegExp(query.$regex).test(u.username);
    }
    return u.username.includes(query);
  });

  res.json(results.map(u => ({ id: u.id, username: u.username })));
});

// ============================================
// VULNERABILITY 4: Command Injection
// ============================================
app.get('/api/ping', (req, res) => {
  const { host } = req.query;

  if (!host) {
    return res.status(400).json({ error: 'Host parameter required' });
  }

  // VULNERABILITY: Direct command injection
  // Example: ?host=127.0.0.1;cat /etc/passwd
  exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
    res.json({
      output: stdout || stderr,
      error: error ? error.message : null
    });
  });
});

// ============================================
// VULNERABILITY 5: Path Traversal / LFI
// ============================================
app.get('/api/files/:filename', (req, res) => {
  const { filename } = req.params;

  // VULNERABILITY: No path sanitization
  // Example: /api/files/....//....//....//etc/passwd
  const filepath = path.join(__dirname, 'uploads', filename);

  try {
    const content = fs.readFileSync(filepath, 'utf8');
    res.send(content);
  } catch (err) {
    res.status(404).json({ error: 'File not found', path: filepath }); // Info leak
  }
});

// ============================================
// VULNERABILITY 6: XML External Entity (XXE)
// ============================================
app.post('/api/xml/parse', (req, res) => {
  const xmlData = req.body;

  // VULNERABILITY: XML parser with external entities enabled
  const parser = new xml2js.Parser({
    explicitArray: false,
    // These settings make XXE possible
  });

  parser.parseString(xmlData, (err, result) => {
    if (err) {
      return res.status(400).json({ error: 'Invalid XML', details: err.message });
    }
    res.json(result);
  });
});

// ============================================
// VULNERABILITY 7: Server-Side Template Injection (SSTI)
// ============================================
app.get('/api/render', (req, res) => {
  const { template } = req.query;

  if (!template) {
    return res.status(400).json({ error: 'Template parameter required' });
  }

  // VULNERABILITY: User input in template
  // Example: ?template=<%= process.env %>
  try {
    const ejs = require('ejs');
    const output = ejs.render(template, { user: req.user || {} });
    res.send(output);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================
// VULNERABILITY 8: Mass Assignment
// ============================================
app.put('/api/users/:id', verifyToken, (req, res) => {
  const userId = parseInt(req.params.id);
  const userIndex = users.findIndex(u => u.id === userId);

  if (userIndex === -1) {
    return res.status(404).json({ error: 'User not found' });
  }

  // VULNERABILITY: Mass assignment - user can set their own role
  // Payload: {"role": "admin"}
  Object.assign(users[userIndex], req.body);

  res.json(users[userIndex]);
});

// ============================================
// VULNERABILITY 9: Sensitive Data Exposure
// ============================================
app.get('/api/secrets', verifyToken, (req, res) => {
  // VULNERABILITY: Returns all secrets regardless of user
  if (DEBUG) {
    res.json({ secrets, jwt_secret: JWT_SECRET }); // Exposes JWT secret!
  } else {
    res.json({ secrets: secrets.filter(s => s.userId === req.user.userId) });
  }
});

// ============================================
// VULNERABILITY 10: Open Redirect
// ============================================
app.get('/api/redirect', (req, res) => {
  const { url } = req.query;

  // VULNERABILITY: Open redirect - no validation
  // Example: /api/redirect?url=https://evil.com
  if (url) {
    res.redirect(url);
  } else {
    res.status(400).json({ error: 'URL parameter required' });
  }
});

// ============================================
// VULNERABILITY 11: GraphQL Introspection
// ============================================
app.post('/api/graphql', (req, res) => {
  const { query } = req.body;

  // Simplified GraphQL-like endpoint
  // VULNERABILITY: Introspection enabled, exposes schema
  if (query && query.includes('__schema')) {
    return res.json({
      data: {
        __schema: {
          types: [
            { name: 'User', fields: ['id', 'username', 'password', 'role', 'ssn', 'creditCard'] },
            { name: 'Secret', fields: ['id', 'userId', 'data', 'apiKey', 'awsSecret'] },
            { name: 'Query', fields: ['users', 'secrets', 'admin'] }
          ]
        }
      }
    });
  }

  res.json({ data: null, errors: [{ message: 'Query not supported' }] });
});

// ============================================
// VULNERABILITY 12: Debug/Admin Endpoints
// ============================================
app.get('/api/debug', (req, res) => {
  // VULNERABILITY: Exposed debug endpoint
  res.json({
    env: process.env,
    memory: process.memoryUsage(),
    uptime: process.uptime(),
    cwd: process.cwd(),
    users: users
  });
});

app.get('/api/admin/config', (req, res) => {
  // VULNERABILITY: No auth on admin endpoint
  res.json({
    database: 'mongodb://admin:password@localhost:27017/prod',
    redis: 'redis://:secretpass@localhost:6379',
    aws: {
      accessKey: 'AKIAIOSFODNN7EXAMPLE',
      secretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    }
  });
});

// ============================================
// VULNERABILITY 13: Rate Limit Bypass
// ============================================
// No rate limiting implemented at all!

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: '1.0.0' });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Vulnerable API running on port ${PORT}`);
  console.log(`JWT Secret: ${JWT_SECRET}`);
  console.log(`Debug mode: ${DEBUG}`);
});
