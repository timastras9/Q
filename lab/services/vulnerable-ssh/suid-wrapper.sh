#!/bin/bash
# Vulnerable backup tool - SUID root
# Can be exploited via command injection

if [ -z "$1" ]; then
    echo "Usage: backup-tool <directory>"
    echo "Backs up the specified directory"
    exit 1
fi

# Vulnerable to command injection!
eval "tar -czf /tmp/backup_$(date +%s).tar.gz $1"
