# Sentinel - Autonomous Security Daemon
# =============================================
# Based on Rocky Linux 9 (RHEL-compatible)
# Autonomous self-healing security for Linux

FROM rockylinux:9

LABEL maintainer="PentestAI"
LABEL description="Sentinel - Autonomous self-healing security daemon"
LABEL version="2.0.0"

# Environment
ENV PYTHONUNBUFFERED=1
ENV SENTINEL_LOG_LEVEL=INFO
ENV TZ=UTC

# Install base packages
RUN dnf update -y && \
    dnf install -y --allowerasing \
        python3 \
        python3-pip \
        nmap \
        curl \
        jq \
        firewalld \
        policycoreutils-python-utils \
        yum-utils \
        procps-ng \
        iproute \
        net-tools \
        which \
        && dnf clean all

# Install Lynis (security auditing tool)
RUN curl -s https://packages.cisofy.com/keys/cisofy-software-rpms-public.key | \
    gpg --dearmor -o /etc/pki/rpm-gpg/RPM-GPG-KEY-cisofy && \
    echo -e "[lynis]\nname=Lynis Repository\nbaseurl=https://packages.cisofy.com/community/lynis/rpm/\nenabled=1\ngpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-cisofy" > /etc/yum.repos.d/lynis.repo && \
    dnf install -y lynis || echo "Lynis installation optional"

# Install Python dependencies
RUN pip3 install --no-cache-dir \
    requests \
    anthropic

# Create directory structure
RUN mkdir -p /opt/sentinel/{config,data,scripts} \
             /var/log/sentinel

# Copy daemon script
COPY daemon.py /opt/sentinel/daemon.py
RUN chmod +x /opt/sentinel/daemon.py

# Copy configuration
COPY config/ /opt/sentinel/config/

# Health check - verify daemon is responsive
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD pgrep -f "daemon.py" || exit 1

# Working directory
WORKDIR /opt/sentinel

# Default command
CMD ["python3", "/opt/sentinel/daemon.py"]
