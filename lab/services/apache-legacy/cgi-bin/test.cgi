#!/bin/sh
# VULNERABILITY: CGI script with command injection

echo "Content-type: text/html"
echo ""
echo "<html><head><title>System Test</title></head><body>"
echo "<h1>System Test CGI</h1>"

# VULNERABILITY: Environment variables exposed
echo "<h2>Environment Variables:</h2>"
echo "<pre>"
env
echo "</pre>"

# VULNERABILITY: Command injection via query string
echo "<h2>System Information:</h2>"
echo "<pre>"

# Parse query string for 'cmd' parameter
QUERY_STRING="${QUERY_STRING:-}"
CMD=$(echo "$QUERY_STRING" | sed -n 's/.*cmd=\([^&]*\).*/\1/p' | sed 's/%20/ /g' | sed 's/+/ /g')

if [ -n "$CMD" ]; then
    echo "Running: $CMD"
    echo "---"
    # VULNERABILITY: Direct command execution
    eval "$CMD" 2>&1
else
    echo "Hostname: $(hostname)"
    echo "Date: $(date)"
    echo "Uptime: $(uptime)"
    echo "User: $(whoami)"
fi

echo "</pre>"
echo "<p>Usage: ?cmd=your_command</p>"
echo "</body></html>"
