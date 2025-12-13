#!/bin/sh
# VULNERABILITY: Insecure login script

echo "Content-type: text/html"
echo ""

# Read POST data
read POST_DATA

# VULNERABILITY: Credentials logged
echo "$(date) - Login attempt: $POST_DATA" >> /tmp/login.log

# Extract username and password (basic parsing)
USERNAME=$(echo "$POST_DATA" | sed -n 's/.*username=\([^&]*\).*/\1/p')
PASSWORD=$(echo "$POST_DATA" | sed -n 's/.*password=\([^&]*\).*/\1/p')

echo "<html><head><title>Login Result</title></head><body>"

# VULNERABILITY: Hardcoded credentials
if [ "$USERNAME" = "admin" ] && [ "$PASSWORD" = "admin123" ]; then
    echo "<h1>Login Successful</h1>"
    echo "<p>Welcome, admin!</p>"
    echo "<p>Session Token: admin_session_$(date +%s)</p>"
    # VULNERABILITY: Token predictable
else
    echo "<h1>Login Failed</h1>"
    echo "<p>Invalid credentials for user: $USERNAME</p>"
    # VULNERABILITY: Username enumeration
fi

echo "</body></html>"
