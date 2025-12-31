# Vulnerable SSH Server for Penetration Testing
# Contains multiple privilege escalation vectors for demonstration

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH and common tools
RUN apt-get update && apt-get install -y \
    openssh-server \
    sudo \
    vim \
    nano \
    curl \
    wget \
    python3 \
    python3-pip \
    nmap \
    netcat-openbsd \
    git \
    cron \
    docker.io \
    awscli \
    && rm -rf /var/lib/apt/lists/*

# Create users
RUN useradd -m -s /bin/bash admin && \
    echo "admin:admin123" | chpasswd && \
    useradd -m -s /bin/bash developer && \
    echo "developer:dev123" | chpasswd && \
    useradd -m -s /bin/bash dbadmin && \
    echo "dbadmin:database!" | chpasswd

# ============================================
# PRIVILEGE ESCALATION VECTOR 1: SUDO NOPASSWD
# ============================================
# Admin can run vim, find, python3, and env without password
RUN echo "admin ALL=(ALL) NOPASSWD: /usr/bin/vim, /usr/bin/find, /usr/bin/python3, /usr/bin/env, /usr/bin/less" >> /etc/sudoers && \
    echo "developer ALL=(ALL) NOPASSWD: /usr/bin/nmap" >> /etc/sudoers

# ============================================
# PRIVILEGE ESCALATION VECTOR 2: SUID BINARIES
# ============================================
# Set SUID on exploitable binaries
RUN chmod u+s /usr/bin/find && \
    chmod u+s /usr/bin/vim.basic && \
    chmod u+s /usr/bin/python3.10

# Create a vulnerable custom SUID binary
COPY --chmod=4755 suid-wrapper.sh /usr/local/bin/backup-tool

# ============================================
# PRIVILEGE ESCALATION VECTOR 3: WRITABLE PATHS
# ============================================
RUN chmod 777 /usr/local/bin

# ============================================
# PRIVILEGE ESCALATION VECTOR 4: CRON JOBS
# ============================================
# Create a cron job running as root with writable script
RUN echo "* * * * * root /opt/scripts/backup.sh" >> /etc/crontab
RUN mkdir -p /opt/scripts && \
    echo '#!/bin/bash\ntar -czf /backup/data.tar.gz /var/log 2>/dev/null' > /opt/scripts/backup.sh && \
    chmod 777 /opt/scripts/backup.sh

# ============================================
# SENSITIVE DATA: AWS CREDENTIALS
# ============================================
RUN mkdir -p /root/.aws /home/admin/.aws /home/developer/.aws && \
    echo "[default]\naws_access_key_id = AKIAIOSFODNN7REALKEY\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYzREALSECRET\nregion = us-east-1" > /root/.aws/credentials && \
    echo "[default]\naws_access_key_id = AKIAPRODADMINKEY12345\naws_secret_access_key = ProductionSecretKeyDoNotShare2024abc\nregion = us-west-2" > /home/admin/.aws/credentials && \
    chmod 600 /root/.aws/credentials /home/admin/.aws/credentials

# ============================================
# SENSITIVE DATA: SSH KEYS FOR LATERAL MOVEMENT
# ============================================
RUN mkdir -p /root/.ssh /home/admin/.ssh /home/developer/.ssh && \
    ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519 -N "" -C "root@prod-server" && \
    ssh-keygen -t rsa -b 2048 -f /home/admin/.ssh/id_rsa -N "" -C "admin@jumpbox" && \
    ssh-keygen -t rsa -b 2048 -f /home/developer/.ssh/id_rsa -N "" -C "developer@gitlab" && \
    echo "prod-db-01 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample" >> /root/.ssh/known_hosts && \
    echo "prod-app-01 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample" >> /root/.ssh/known_hosts && \
    echo "192.168.1.50 ssh-rsa AAAAB3NzaExample" >> /home/admin/.ssh/known_hosts && \
    echo "gitlab.internal ssh-rsa AAAAB3NzaExample" >> /home/developer/.ssh/known_hosts && \
    chown -R admin:admin /home/admin/.ssh && \
    chown -R developer:developer /home/developer/.ssh && \
    chmod 600 /home/admin/.ssh/id_rsa /home/developer/.ssh/id_rsa

# ============================================
# SENSITIVE DATA: DATABASE CREDENTIALS & CONFIGS
# ============================================
RUN mkdir -p /opt/app/config && \
    echo 'DATABASE_URL=mysql://root:SuperSecretDBPass123!@mysql.internal:3306/production\nREDIS_URL=redis://:redis_password_123@redis.internal:6379\nAPI_KEY=sk-live-abcdef123456789\nJWT_SECRET=super-secret-jwt-key-never-share\nAWS_S3_BUCKET=company-confidential-data' > /opt/app/config/.env && \
    echo 'spring.datasource.url=jdbc:mysql://mysql.internal:3306/prod\nspring.datasource.username=appuser\nspring.datasource.password=AppUserPass789!' > /opt/app/config/application.properties

# ============================================
# SENSITIVE DATA: BASH HISTORY WITH SECRETS
# ============================================
RUN echo 'mysql -u root -pSuperSecretDBPass123! production\nssh admin@192.168.1.50\nexport AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYzREALSECRET\ncurl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.admin.secret" https://api.internal/users\npsql -h db.internal -U postgres -W\nsudo su -' > /home/admin/.bash_history && \
    echo 'git clone https://developer:GitHubToken123@github.com/company/private-repo.git\nnpm config set //registry.npmjs.org/:_authToken=npm_supersecrettoken123\ndocker login -u admin -p DockerHubPass123' > /home/developer/.bash_history && \
    chown admin:admin /home/admin/.bash_history && \
    chown developer:developer /home/developer/.bash_history

# ============================================
# SENSITIVE DATA: /etc/shadow readable (misconfiguration)
# ============================================
RUN chmod 644 /etc/shadow

# ============================================
# GCP SERVICE ACCOUNT (simulated)
# ============================================
RUN mkdir -p /opt/gcp && \
    echo '{"type":"service_account","project_id":"prod-company-123","private_key_id":"abc123","private_key":"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA2Z3qX2BTLS4e...SIMULATED...XYZ\n-----END RSA PRIVATE KEY-----","client_email":"app-service@prod-company-123.iam.gserviceaccount.com","client_id":"123456789","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token"}' > /opt/gcp/service-account.json && \
    chmod 644 /opt/gcp/service-account.json

# ============================================
# SSH CONFIGURATION
# ============================================
RUN mkdir /var/run/sshd && \
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config && \
    echo "root:toor" | chpasswd

# Add admin to docker group (for docker socket exploitation)
RUN usermod -aG docker admin

# ============================================
# PRIVILEGE ESCALATION VECTOR 5: CAPABILITIES
# ============================================
# Python with cap_setuid allows privilege escalation
RUN apt-get update && apt-get install -y libcap2-bin && rm -rf /var/lib/apt/lists/*
RUN cp /usr/bin/python3.10 /usr/bin/python3-cap && \
    setcap cap_setuid+ep /usr/bin/python3-cap
# Perl with cap_setuid
RUN apt-get update && apt-get install -y perl && rm -rf /var/lib/apt/lists/* && \
    cp /usr/bin/perl /usr/bin/perl-cap && \
    setcap cap_setuid+ep /usr/bin/perl-cap

# ============================================
# PRIVILEGE ESCALATION VECTOR 6: WILDCARD INJECTION
# ============================================
# Script that uses wildcards unsafely (tar with *)
RUN mkdir -p /opt/backup && \
    echo '#!/bin/bash\ncd /home/developer\ntar -czf /opt/backup/home-backup.tar.gz *' > /opt/scripts/wildcard-backup.sh && \
    chmod 755 /opt/scripts/wildcard-backup.sh && \
    echo "*/5 * * * * root /opt/scripts/wildcard-backup.sh" >> /etc/crontab

# ============================================
# PRIVILEGE ESCALATION VECTOR 7: PATH HIJACKING
# ============================================
# Script that calls commands without full path
RUN echo '#!/bin/bash\nps aux | grep apache\nservice apache2 status' > /opt/scripts/check-services.sh && \
    chmod 755 /opt/scripts/check-services.sh && \
    echo "admin ALL=(root) NOPASSWD: /opt/scripts/check-services.sh" >> /etc/sudoers

# ============================================
# PRIVILEGE ESCALATION VECTOR 8: LD_PRELOAD
# ============================================
# Allow LD_PRELOAD in sudo for certain commands
RUN echo 'Defaults env_keep += "LD_PRELOAD"' >> /etc/sudoers.d/ld_preload && \
    echo "developer ALL=(root) NOPASSWD: /usr/bin/id" >> /etc/sudoers.d/ld_preload

# ============================================
# PRIVILEGE ESCALATION VECTOR 9: NFS no_root_squash simulation
# ============================================
RUN mkdir -p /exports/shared && chmod 777 /exports/shared && \
    echo "/exports/shared *(rw,sync,no_root_squash)" > /etc/exports.vulnerable

# ============================================
# PRIVILEGE ESCALATION VECTOR 10: Writable /etc/passwd
# ============================================
RUN chmod 666 /etc/passwd

# ============================================
# SENSITIVE DATA: Kubernetes configs
# ============================================
RUN mkdir -p /home/admin/.kube && \
    echo 'apiVersion: v1\nclusters:\n- cluster:\n    server: https://k8s-master.internal:6443\n    certificate-authority-data: LS0tLS1CRUdJTi...\n  name: production\ncontexts:\n- context:\n    cluster: production\n    user: admin\n  name: prod-context\ncurrent-context: prod-context\nusers:\n- name: admin\n  user:\n    token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lIjoiYWRtaW4ifQ.SIGNATURE' > /home/admin/.kube/config && \
    chown -R admin:admin /home/admin/.kube && chmod 600 /home/admin/.kube/config

# ============================================
# SENSITIVE DATA: Vault/Secrets tokens
# ============================================
RUN echo 'VAULT_TOKEN=hvs.CAESIG_realvaulttoken123456789\nVAULT_ADDR=https://vault.internal:8200' > /home/admin/.vault-token && \
    echo 'export VAULT_TOKEN=hvs.CAESIG_realvaulttoken123456789' >> /home/admin/.bashrc

# ============================================
# PRIVILEGE ESCALATION VECTOR 11: Systemd timer with writable script
# ============================================
RUN mkdir -p /etc/systemd/system && \
    echo '[Unit]\nDescription=Cleanup temp files\n[Service]\nType=oneshot\nExecStart=/opt/scripts/cleanup.sh\n[Install]\nWantedBy=multi-user.target' > /etc/systemd/system/cleanup.service && \
    echo '#!/bin/bash\nrm -rf /tmp/*' > /opt/scripts/cleanup.sh && \
    chmod 777 /opt/scripts/cleanup.sh

# ============================================
# GTFOBins additions - more sudo paths
# ============================================
RUN echo "admin ALL=(root) NOPASSWD: /usr/bin/awk" >> /etc/sudoers && \
    echo "admin ALL=(root) NOPASSWD: /usr/bin/perl" >> /etc/sudoers && \
    echo "developer ALL=(root) NOPASSWD: /usr/bin/less" >> /etc/sudoers && \
    echo "dbadmin ALL=(root) NOPASSWD: /usr/bin/mysql" >> /etc/sudoers

# Create entrypoint script to set up hosts file at runtime
RUN echo '#!/bin/bash\n\
echo "192.168.1.10 mysql.internal db.internal" >> /etc/hosts\n\
echo "192.168.1.11 redis.internal cache.internal" >> /etc/hosts\n\
echo "192.168.1.20 gitlab.internal git.internal" >> /etc/hosts\n\
echo "192.168.1.30 jenkins.internal ci.internal" >> /etc/hosts\n\
echo "192.168.1.50 jumpbox.internal bastion.internal" >> /etc/hosts\n\
echo "10.0.0.100 prod-db-01" >> /etc/hosts\n\
echo "10.0.0.101 prod-app-01" >> /etc/hosts\n\
echo "10.0.0.102 prod-app-02" >> /etc/hosts\n\
service cron start\n\
exec /usr/sbin/sshd -D\n' > /entrypoint.sh && chmod +x /entrypoint.sh

EXPOSE 22

CMD ["/entrypoint.sh"]
