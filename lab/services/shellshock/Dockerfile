# Shellshock Vulnerable CGI (CVE-2014-6271)
# Simulates the bash environment variable injection vulnerability
FROM debian:bullseye-slim

# Install Apache with CGI support
RUN apt-get update && apt-get install -y \
    apache2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Enable CGI
RUN a2enmod cgi

# Create vulnerable CGI scripts
RUN mkdir -p /usr/lib/cgi-bin

# Main vulnerable CGI script - simulates Shellshock by evaluating User-Agent
RUN cat > /usr/lib/cgi-bin/vuln.cgi << 'CGI'
#!/bin/bash
echo "Content-type: text/html"
echo ""

# VULNERABLE: Check for shellshock pattern and execute
# Real shellshock: () { :;}; command
# We simulate by checking for the pattern and executing
if [[ "$HTTP_USER_AGENT" == *"() {"* ]]; then
    # Extract command after () { :;};
    CMD=$(echo "$HTTP_USER_AGENT" | sed 's/.*() { :;}; //')
    eval "$CMD" 2>&1
    exit 0
fi

echo "<html><head><title>System Status</title></head><body>"
echo "<h1>System Status Page</h1>"
echo "<p>Date: $(date)</p>"
echo "<p>Uptime: $(uptime)</p>"
echo "<p>Hostname: $(hostname)</p>"
echo "</body></html>"
CGI

# User-Agent logger (vulnerable endpoint)
RUN cat > /usr/lib/cgi-bin/log.cgi << 'CGI'
#!/bin/bash
echo "Content-type: text/plain"
echo ""

# VULNERABLE: Shellshock simulation
if [[ "$HTTP_USER_AGENT" == *"() {"* ]]; then
    CMD=$(echo "$HTTP_USER_AGENT" | sed 's/.*() { :;}; //')
    eval "$CMD" 2>&1
    exit 0
fi

echo "Your request has been logged."
echo "User-Agent: $HTTP_USER_AGENT"
echo "Remote IP: $REMOTE_ADDR"
CGI

# Environment dumper (shows all env vars - info leak + shellshock)
RUN cat > /usr/lib/cgi-bin/env.cgi << 'CGI'
#!/bin/bash
echo "Content-type: text/plain"
echo ""

# VULNERABLE: Check any header for shellshock pattern
for var in HTTP_USER_AGENT HTTP_REFERER HTTP_ACCEPT HTTP_COOKIE; do
    val="${!var}"
    if [[ "$val" == *"() {"* ]]; then
        CMD=$(echo "$val" | sed 's/.*() { :;}; //')
        eval "$CMD" 2>&1
        exit 0
    fi
done

echo "=== Environment Variables ==="
env | sort
CGI

# Ping utility (command injection + shellshock)
RUN cat > /usr/lib/cgi-bin/ping.cgi << 'CGI'
#!/bin/bash
echo "Content-type: text/plain"
echo ""

# VULNERABLE: Shellshock check
if [[ "$HTTP_USER_AGENT" == *"() {"* ]]; then
    CMD=$(echo "$HTTP_USER_AGENT" | sed 's/.*() { :;}; //')
    eval "$CMD" 2>&1
    exit 0
fi

if [ -n "$QUERY_STRING" ]; then
    HOST=$(echo "$QUERY_STRING" | sed 's/host=//')
    echo "Pinging $HOST..."
    # VULNERABLE: Command injection via unescaped input
    ping -c 1 $HOST 2>&1
else
    echo "Usage: ?host=example.com"
    echo ""
    echo "Try: ?host=localhost;id"
fi
CGI

RUN chmod +x /usr/lib/cgi-bin/*.cgi

# Create an index page
RUN cat > /var/www/html/index.html << 'HTML'
<!DOCTYPE html>
<html>
<head><title>Legacy Server</title></head>
<body>
<h1>Legacy Internal Server</h1>
<p>CGI Endpoints:</p>
<ul>
    <li><a href="/cgi-bin/vuln.cgi">System Status</a></li>
    <li><a href="/cgi-bin/log.cgi">Request Logger</a></li>
    <li><a href="/cgi-bin/env.cgi">Environment Info</a></li>
    <li><a href="/cgi-bin/ping.cgi?host=localhost">Ping Utility</a></li>
</ul>
<p><small>Apache/2.4 (Debian Stretch) - Internal Use Only</small></p>
</body>
</html>
HTML

# Apache config for CGI
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf

EXPOSE 80

CMD ["apachectl", "-D", "FOREGROUND"]
