"""
Vulnerable GraphQL Service for Security Testing
Contains: Introspection enabled, injection vulnerabilities, DoS vectors
"""

from flask import Flask
from flask_graphql import GraphQLView
import graphene
import os

app = Flask(__name__)

# Simulated database
USERS = [
    {"id": 1, "username": "admin", "password": "admin123", "email": "admin@corp.local", "role": "admin", "api_key": "sk-admin-secret-key-12345"},
    {"id": 2, "username": "user1", "password": "password123", "email": "user1@corp.local", "role": "user", "api_key": "sk-user1-key-67890"},
    {"id": 3, "username": "developer", "password": "dev2024!", "email": "dev@corp.local", "role": "developer", "api_key": "sk-dev-key-abcdef"},
]

SECRETS = [
    {"id": 1, "name": "AWS_ACCESS_KEY", "value": "AKIAIOSFODNN7EXAMPLE"},
    {"id": 2, "name": "AWS_SECRET_KEY", "value": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE"},
    {"id": 3, "name": "DATABASE_URL", "value": "mysql://root:root123@mysql:3306/production"},
    {"id": 4, "name": "JWT_SECRET", "value": "super-secret-jwt-signing-key-2024"},
]

class User(graphene.ObjectType):
    id = graphene.Int()
    username = graphene.String()
    password = graphene.String()  # Exposed! Should never be in GraphQL
    email = graphene.String()
    role = graphene.String()
    api_key = graphene.String()  # Sensitive data exposed!

class Secret(graphene.ObjectType):
    id = graphene.Int()
    name = graphene.String()
    value = graphene.String()

class SystemInfo(graphene.ObjectType):
    hostname = graphene.String()
    os_info = graphene.String()
    env_vars = graphene.String()

class Query(graphene.ObjectType):
    # Introspection is enabled by default - vulnerability!

    users = graphene.List(User)
    user = graphene.Field(User, id=graphene.Int(), username=graphene.String())
    secrets = graphene.List(Secret)
    secret = graphene.Field(Secret, id=graphene.Int())
    system_info = graphene.Field(SystemInfo)

    # SQL Injection vulnerable query simulation
    search_users = graphene.List(User, query=graphene.String())

    # DoS vector - recursive/nested queries
    nested_users = graphene.List(lambda: NestedUser)

    def resolve_users(self, info):
        return [User(**u) for u in USERS]

    def resolve_user(self, info, id=None, username=None):
        for u in USERS:
            if (id and u["id"] == id) or (username and u["username"] == username):
                return User(**u)
        return None

    def resolve_secrets(self, info):
        # No authorization check! Anyone can access secrets
        return [Secret(**s) for s in SECRETS]

    def resolve_secret(self, info, id=None):
        for s in SECRETS:
            if s["id"] == id:
                return Secret(**s)
        return None

    def resolve_system_info(self, info):
        # Information disclosure
        import socket
        return SystemInfo(
            hostname=socket.gethostname(),
            os_info=os.uname().sysname if hasattr(os, 'uname') else 'unknown',
            env_vars=str(dict(os.environ))[:500]  # Expose environment variables!
        )

    def resolve_search_users(self, info, query=None):
        # Simulated SQL injection vulnerability
        # In real app this would be: SELECT * FROM users WHERE username LIKE '%{query}%'
        if query:
            if "'" in query or "--" in query or "OR" in query.upper():
                # Injection detected - return all users (simulating SQLi success)
                return [User(**u) for u in USERS]
        return [User(**u) for u in USERS if query and query.lower() in u["username"].lower()]

    def resolve_nested_users(self, info):
        return [NestedUser(**u) for u in USERS]

class NestedUser(graphene.ObjectType):
    """Allows deeply nested queries - DoS vector"""
    id = graphene.Int()
    username = graphene.String()
    friends = graphene.List(lambda: NestedUser)

    def resolve_friends(self, info):
        # Returns all users as friends - allows infinite nesting
        return [NestedUser(**u) for u in USERS]

class CreateUser(graphene.Mutation):
    class Arguments:
        username = graphene.String(required=True)
        password = graphene.String(required=True)
        email = graphene.String(required=True)

    user = graphene.Field(User)

    def mutate(self, info, username, password, email):
        # No input validation - injection possible
        new_user = {
            "id": len(USERS) + 1,
            "username": username,
            "password": password,
            "email": email,
            "role": "user",
            "api_key": f"sk-{username}-key-new"
        }
        USERS.append(new_user)
        return CreateUser(user=User(**new_user))

class ExecuteCommand(graphene.Mutation):
    """Dangerous mutation - allows command execution"""
    class Arguments:
        cmd = graphene.String(required=True)

    output = graphene.String()

    def mutate(self, info, cmd):
        import subprocess
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            return ExecuteCommand(output=result.stdout + result.stderr)
        except Exception as e:
            return ExecuteCommand(output=str(e))

class Mutation(graphene.ObjectType):
    create_user = CreateUser.Field()
    execute_command = ExecuteCommand.Field()  # RCE vulnerability!

schema = graphene.Schema(query=Query, mutation=Mutation)

# GraphQL endpoint with introspection enabled (vulnerability)
app.add_url_rule(
    '/graphql',
    view_func=GraphQLView.as_view(
        'graphql',
        schema=schema,
        graphiql=True  # GraphiQL interface exposed!
    )
)

@app.route('/')
def index():
    return '''
    <h1>Corporate GraphQL API</h1>
    <p>Version: 1.0.0 (Development)</p>
    <p><a href="/graphql">GraphQL Endpoint</a></p>
    <p>Debug mode enabled</p>
    '''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
