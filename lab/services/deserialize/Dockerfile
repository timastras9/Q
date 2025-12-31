# Java Deserialization Vulnerable Service
# Simulates insecure deserialization (CWE-502)
FROM python:3.9-slim

WORKDIR /app

RUN pip install flask pyyaml

# Create vulnerable deserialization service
RUN cat > /app/deserialize_vuln.py << 'PYTHON'
from flask import Flask, request, Response
import pickle
import base64
import yaml
import subprocess
import json
import os

app = Flask(__name__)

# Simulated "database" of user sessions
sessions = {}

class User:
    def __init__(self, username, role="user"):
        self.username = username
        self.role = role
        self.data = {}

    def __reduce__(self):
        # This makes pickle deserialization exploitable
        return (os.system, (f"echo 'User {self.username} loaded'",))

@app.route('/')
def index():
    return """
    <!DOCTYPE html>
    <html>
    <head><title>Session Manager</title></head>
    <body>
    <h1>Session Management API</h1>
    <h2>Endpoints:</h2>
    <ul>
        <li>POST /api/session - Create session (JSON body)</li>
        <li>GET /api/session/&lt;id&gt; - Get session</li>
        <li>POST /api/deserialize - Restore session from backup (base64 pickle)</li>
        <li>POST /api/yaml-import - Import config (YAML)</li>
        <li>POST /api/xml-import - Import data (XML)</li>
    </ul>
    <h3>Example - Create Session:</h3>
    <pre>curl -X POST -H "Content-Type: application/json" -d '{"username":"admin"}' /api/session</pre>
    <h3>Example - Deserialize (VULNERABLE):</h3>
    <pre>curl -X POST -H "Content-Type: application/octet-stream" -d 'BASE64_PICKLE_DATA' /api/deserialize</pre>
    </body>
    </html>
    """

@app.route('/api/session', methods=['POST'])
def create_session():
    data = request.json or {}
    username = data.get('username', 'anonymous')
    role = data.get('role', 'user')

    user = User(username, role)
    session_id = base64.b64encode(os.urandom(16)).decode()
    sessions[session_id] = user

    # Return serialized session for "backup"
    serialized = base64.b64encode(pickle.dumps(user)).decode()

    return json.dumps({
        "session_id": session_id,
        "username": username,
        "role": role,
        "backup_token": serialized  # Exposes pickle for exploitation
    })

@app.route('/api/session/<session_id>')
def get_session(session_id):
    if session_id in sessions:
        user = sessions[session_id]
        return json.dumps({
            "username": user.username,
            "role": user.role
        })
    return Response("Session not found", status=404)

@app.route('/api/deserialize', methods=['POST'])
def deserialize_session():
    """
    VULNERABLE: Deserializes untrusted pickle data
    Attacker can craft malicious pickle to execute arbitrary code
    """
    try:
        data = request.data
        if not data:
            return Response("No data provided", status=400)

        # Try to decode base64
        try:
            decoded = base64.b64decode(data)
        except:
            decoded = data

        # VULNERABLE: Deserializing untrusted data
        obj = pickle.loads(decoded)

        return json.dumps({
            "status": "restored",
            "type": str(type(obj)),
            "data": str(obj) if hasattr(obj, '__str__') else "Object restored"
        })
    except Exception as e:
        return Response(f"Deserialization error: {str(e)}", status=500)

@app.route('/api/yaml-import', methods=['POST'])
def yaml_import():
    """
    VULNERABLE: Uses yaml.load() instead of yaml.safe_load()
    Allows arbitrary Python object instantiation via YAML
    """
    try:
        data = request.data.decode('utf-8')

        # VULNERABLE: Using unsafe yaml.load
        # Attacker can use: !!python/object/apply:os.system ["id"]
        config = yaml.load(data, Loader=yaml.UnsafeLoader)

        return json.dumps({
            "status": "imported",
            "config": str(config)
        })
    except Exception as e:
        return Response(f"YAML error: {str(e)}", status=500)

@app.route('/api/xml-import', methods=['POST'])
def xml_import():
    """
    Simulates XXE vulnerability
    """
    try:
        data = request.data.decode('utf-8')

        # Check for XXE patterns
        if '<!ENTITY' in data or 'SYSTEM' in data:
            # Simulate XXE file read
            import re
            entity_match = re.search(r'SYSTEM\s+"file://([^"]+)"', data)
            if entity_match:
                filepath = entity_match.group(1)
                try:
                    with open(filepath, 'r') as f:
                        content = f.read()
                    return Response(
                        f"XML Parse Error: Entity expansion failed\n\n{content}",
                        status=500
                    )
                except Exception as e:
                    return Response(f"XML Parse Error: {str(e)}", status=500)

        return json.dumps({"status": "imported", "data": "XML processed"})
    except Exception as e:
        return Response(f"XML error: {str(e)}", status=500)

@app.route('/api/eval', methods=['POST'])
def eval_endpoint():
    """
    VULNERABLE: Direct code evaluation
    Simulates template injection or eval() misuse
    """
    try:
        expr = request.form.get('expr') or request.args.get('expr', '')

        if expr:
            # VULNERABLE: eval on user input
            result = eval(expr)
            return json.dumps({"result": str(result)})

        return Response("Missing 'expr' parameter", status=400)
    except Exception as e:
        return Response(f"Eval error: {str(e)}", status=500)

if __name__ == '__main__':
    print("Deserialization vulnerable service running on port 8092")
    print("Endpoints vulnerable to: Pickle, YAML, XXE, Eval")
    app.run(host='0.0.0.0', port=8092)
PYTHON

EXPOSE 8092

CMD ["python", "/app/deserialize_vuln.py"]
