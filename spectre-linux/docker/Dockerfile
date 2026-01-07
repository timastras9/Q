#
# Sentinel Linux Docker Test Environment
# =======================================
# This container simulates the Sentinel Linux experience
# for testing without needing physical hardware
#

FROM almalinux:9

LABEL maintainer="Spectre Security"
LABEL description="Sentinel Linux Test Environment"
LABEL version="1.0.0"

# Install EPEL and base packages
RUN dnf install -y epel-release && \
    dnf update -y && \
    dnf install -y --allowerasing \
    python3 \
    python3-pip \
    python3-requests \
    openssl \
    ca-certificates \
    curl \
    jq \
    iptables \
    iproute \
    procps-ng \
    util-linux \
    shadow-utils \
    sudo \
    openssh-server \
    openssh-clients \
    audit \
    bash \
    nano \
    less \
    nmap \
    nmap-ncat \
    vim-enhanced \
    htop \
    ncurses \
    findutils \
    grep \
    coreutils \
    file \
    bind-utils \
    whois \
    tcpdump \
    lsof \
    strace \
    git \
    perl \
    wget \
    which \
    policycoreutils-python-utils \
    yum-utils \
    firewalld \
    # Database servers for pentest testing
    redis \
    mysql \
    mysql-server \
    postgresql \
    postgresql-server \
    # Web server
    nginx \
    # FTP server
    vsftpd \
    && dnf clean all

# Install Lynis from CISOfy repo
RUN curl -s https://packages.cisofy.com/keys/cisofy-software-rpms-public.key | \
    gpg --dearmor -o /etc/pki/rpm-gpg/RPM-GPG-KEY-cisofy && \
    cat > /etc/yum.repos.d/lynis.repo << 'EOF'
[lynis]
name=Lynis Repository
baseurl=https://packages.cisofy.com/community/lynis/rpm/
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-cisofy
EOF
RUN dnf install -y lynis 2>/dev/null || echo "Lynis install skipped"

# Install rkhunter
RUN dnf install -y rkhunter 2>/dev/null || \
    (cd /tmp && \
    wget https://downloads.sourceforge.net/project/rkhunter/rkhunter/1.4.6/rkhunter-1.4.6.tar.gz && \
    tar xzf rkhunter-1.4.6.tar.gz && \
    cd rkhunter-1.4.6 && \
    ./installer.sh --install && \
    cd / && rm -rf /tmp/rkhunter*)

# Initialize rkhunter database
RUN rkhunter --propupd 2>/dev/null || true

# Install Python packages for Sentinel
RUN pip3 install --no-cache-dir \
    anthropic \
    requests \
    watchdog \
    psutil \
    python-dotenv \
    rich

# Create Sentinel directory structure
RUN mkdir -p /opt/sentinel/{config,data,baseline,logs} \
    && mkdir -p /etc/sentinel \
    && mkdir -p /var/log/sentinel \
    && mkdir -p /var/lib/sentinel

# Create sentinel user
RUN useradd -m -s /bin/bash -G wheel sentinel && \
    echo 'sentinel:sentinel' | chpasswd && \
    echo '%wheel ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

# Copy Sentinel daemon
COPY sentinel/ /opt/sentinel/

# Create sentinelctl command
RUN cat > /usr/local/bin/sentinelctl << 'SENTINELCTL'
#!/bin/bash
# Sentinel Control Utility

case "$1" in
    status)
        if pgrep -f "daemon.py" > /dev/null; then
            echo "Sentinel daemon is running (PID: $(pgrep -f daemon.py))"
        else
            echo "Sentinel daemon is not running"
        fi
        ;;
    start)
        if pgrep -f "daemon.py" > /dev/null; then
            echo "Sentinel daemon is already running"
        else
            echo "Starting Sentinel daemon..."
            cd /opt/sentinel && python3 daemon.py &
            sleep 2
            echo "Sentinel daemon started"
        fi
        ;;
    stop)
        echo "Stopping Sentinel daemon..."
        pkill -f "daemon.py" 2>/dev/null || echo "Daemon not running"
        ;;
    restart)
        $0 stop
        sleep 1
        $0 start
        ;;
    logs)
        if [ -f /var/log/sentinel/sentinel.log ]; then
            tail -f /var/log/sentinel/sentinel.log
        else
            echo "No log file found. Checking daemon output..."
            tail -f /opt/sentinel/sentinel.log 2>/dev/null || echo "No logs available"
        fi
        ;;
    scan)
        shift
        cd /opt/sentinel && python3 daemon.py --scan "$@"
        ;;
    scan-quick)
        cd /opt/sentinel && python3 daemon.py --scan --mode quick
        ;;
    scan-deep)
        cd /opt/sentinel && python3 daemon.py --scan --mode deep
        ;;
    config)
        nano /etc/sentinel/config.json
        ;;
    dashboard)
        cd /opt/sentinel && python3 dashboard.py
        ;;
    dashboard-demo)
        cd /opt/sentinel && python3 dashboard.py --demo
        ;;
    version)
        echo "Sentinel Linux v1.0.0 (guardian)"
        echo "Security daemon version: $(grep -o 'VERSION.*' /opt/sentinel/daemon.py 2>/dev/null | head -1 || echo 'unknown')"
        ;;
    help|*)
        echo ""
        echo "███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗"
        echo "██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║"
        echo "███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║"
        echo "╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║"
        echo "███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗"
        echo "╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝"
        echo ""
        echo "Sentinel Linux Control Utility"
        echo ""
        echo "Usage: sentinelctl <command>"
        echo ""
        echo "Commands:"
        echo "  status      - Check daemon status"
        echo "  start       - Start the daemon"
        echo "  stop        - Stop the daemon"
        echo "  restart     - Restart the daemon"
        echo "  logs        - View daemon logs"
        echo "  dashboard   - Interactive security dashboard"
        echo "  scan        - Run manual security scan"
        echo "  scan-quick  - Run quick scan (5 min intervals)"
        echo "  scan-deep   - Run deep scan (comprehensive)"
        echo "  config      - Edit configuration"
        echo "  version     - Show version info"
        echo "  help        - Show this help"
        echo ""
        ;;
esac
SENTINELCTL
RUN chmod +x /usr/local/bin/sentinelctl

# Create OS release file
RUN cat > /etc/sentinel-release << 'OSRELEASE'
NAME="Sentinel Linux"
VERSION="1.0.0"
ID=sentinel
ID_LIKE=rhel
VERSION_ID=1.0.0
PRETTY_NAME="Sentinel Linux 1.0.0 (guardian)"
HOME_URL="https://github.com/spectre-sec/sentinel-linux"
BUG_REPORT_URL="https://github.com/spectre-sec/sentinel-linux/issues"
OSRELEASE

# Create MOTD
RUN cat > /etc/motd << 'MOTD'

███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝

         Sentinel Linux 1.0.0 - AI-Powered Security

Quick Start:
  sentinelctl status    - Check daemon status
  sentinelctl start     - Start security daemon
  sentinelctl logs      - View security logs
  sentinelctl scan      - Run security scan
  sentinelctl help      - Show all commands

MOTD

# Configure SSH - generate host keys and allow root login (intentionally weak for testing)
RUN ssh-keygen -A && \
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config && \
    echo 'root:toor' | chpasswd

# Configure Redis - no authentication (intentionally vulnerable)
RUN sed -i 's/^bind .*/bind 0.0.0.0/' /etc/redis/redis.conf 2>/dev/null || \
    echo "bind 0.0.0.0" >> /etc/redis.conf && \
    sed -i 's/^protected-mode yes/protected-mode no/' /etc/redis/redis.conf 2>/dev/null || \
    echo "protected-mode no" >> /etc/redis.conf

# Configure nginx with a basic vulnerable page
RUN mkdir -p /usr/share/nginx/html && \
    echo '<html><head><title>Sentinel Test Server</title></head><body><h1>Welcome to Sentinel Linux</h1><p>Server Status: Running</p></body></html>' > /usr/share/nginx/html/index.html

# Configure FTP - allow anonymous (intentionally vulnerable)
RUN echo "anonymous_enable=YES" >> /etc/vsftpd/vsftpd.conf 2>/dev/null || true && \
    echo "local_enable=YES" >> /etc/vsftpd/vsftpd.conf 2>/dev/null || true

# Create startup script
RUN cat > /start.sh << 'STARTUP'
#!/bin/bash
echo ""
cat /etc/motd
echo ""

echo "[*] Starting vulnerable services for pentest testing..."

# Start SSH server
echo "[+] Starting SSH server on port 22..."
/usr/sbin/sshd

# Start Redis server
echo "[+] Starting Redis server on port 6379..."
redis-server /etc/redis.conf --daemonize yes 2>/dev/null || \
redis-server --daemonize yes --protected-mode no --bind 0.0.0.0

# Start nginx web server
echo "[+] Starting nginx web server on port 80..."
nginx

# Start FTP server
echo "[+] Starting FTP server on port 21..."
vsftpd &

sleep 1
echo "[+] All services started"
echo ""

# Start Sentinel daemon in background
if [ -f /opt/sentinel/daemon.py ]; then
    echo "[*] Starting Sentinel Security Daemon..."
    cd /opt/sentinel && python3 daemon.py &
    sleep 2
    echo "[+] Sentinel daemon started"
fi

echo ""
echo "Exposed services for pentest testing:"
echo "  - SSH:   port 22  (root:toor, sentinel:sentinel)"
echo "  - HTTP:  port 80  (nginx)"
echo "  - Redis: port 6379 (no auth)"
echo "  - FTP:   port 21  (anonymous)"
echo ""

# Keep container running
exec /bin/bash
STARTUP
RUN chmod +x /start.sh

WORKDIR /opt/sentinel

# Expose all service ports for pentest testing
EXPOSE 21 22 80 443 3306 5432 6379 8443

CMD ["/start.sh"]
