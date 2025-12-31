# Simulated Cloud Metadata Services
# Mimics AWS, GCP, and Azure metadata endpoints for training
# These are what you'd find exposed via SSRF or misconfigured instances

FROM python:3.9-slim

WORKDIR /app

RUN pip install flask

# Create the simulated metadata service
RUN cat > /app/metadata.py << 'PYTHON'
from flask import Flask, request, jsonify, Response
import json

app = Flask(__name__)

# ============================================
# AWS EC2 Metadata Service (169.254.169.254)
# ============================================

# Simulated AWS credentials (fake but realistic format)
AWS_CREDS = {
    "Code": "Success",
    "LastUpdated": "2024-01-15T12:00:00Z",
    "Type": "AWS-HMAC",
    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "Token": "AQoDYXdzEJr...<long_session_token>...EXAMPLETOKEN",
    "Expiration": "2024-12-31T23:59:59Z"
}

AWS_INSTANCE_IDENTITY = {
    "devpayProductCodes": None,
    "marketplaceProductCodes": None,
    "availabilityZone": "us-east-1a",
    "privateIp": "10.0.1.100",
    "version": "2017-09-30",
    "instanceId": "i-0abc123def456789",
    "billingProducts": None,
    "instanceType": "t3.large",
    "accountId": "123456789012",
    "imageId": "ami-0abcdef1234567890",
    "pendingTime": "2024-01-01T00:00:00Z",
    "architecture": "x86_64",
    "kernelId": None,
    "ramdiskId": None,
    "region": "us-east-1"
}

@app.route('/latest/meta-data/')
@app.route('/latest/meta-data')
def aws_metadata_root():
    return """ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/
hostname
iam/
instance-action
instance-id
instance-life-cycle
instance-type
local-hostname
local-ipv4
mac
network/
placement/
profile
public-hostname
public-ipv4
public-keys/
reservation-id
security-groups
services/"""

@app.route('/latest/meta-data/iam/')
def aws_iam():
    return "info\nsecurity-credentials/"

@app.route('/latest/meta-data/iam/info')
def aws_iam_info():
    return json.dumps({
        "Code": "Success",
        "LastUpdated": "2024-01-15T12:00:00Z",
        "InstanceProfileArn": "arn:aws:iam::123456789012:instance-profile/prod-ec2-role",
        "InstanceProfileId": "AIPAXXXXXXXXXXXXXXXXX"
    })

@app.route('/latest/meta-data/iam/security-credentials/')
def aws_security_credentials():
    return "prod-ec2-role"

@app.route('/latest/meta-data/iam/security-credentials/<role>')
def aws_role_credentials(role):
    return jsonify(AWS_CREDS)

@app.route('/latest/meta-data/instance-id')
def aws_instance_id():
    return "i-0abc123def456789"

@app.route('/latest/meta-data/local-ipv4')
def aws_local_ip():
    return "10.0.1.100"

@app.route('/latest/meta-data/public-ipv4')
def aws_public_ip():
    return "54.123.45.67"

@app.route('/latest/meta-data/hostname')
def aws_hostname():
    return "ip-10-0-1-100.ec2.internal"

@app.route('/latest/meta-data/placement/availability-zone')
def aws_az():
    return "us-east-1a"

@app.route('/latest/dynamic/instance-identity/document')
def aws_identity_document():
    return jsonify(AWS_INSTANCE_IDENTITY)

@app.route('/latest/user-data')
def aws_user_data():
    # Often contains secrets in real environments!
    return """#!/bin/bash
# Production deployment script
export DB_PASSWORD="SuperSecretProdPassword123!"
export API_KEY="sk-prod-xxxxxxxxxxxxxxxxxxxx"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Deploy application
cd /opt/app && ./deploy.sh
"""

# ============================================
# GCP Metadata Service (metadata.google.internal)
# ============================================

GCP_SERVICE_ACCOUNT = {
    "aliases": ["default"],
    "email": "prod-compute@my-project-123456.iam.gserviceaccount.com",
    "scopes": [
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/compute",
        "https://www.googleapis.com/auth/devstorage.full_control"
    ]
}

GCP_ACCESS_TOKEN = {
    "access_token": "ya29.EXAMPLE_GCP_ACCESS_TOKEN_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "expires_in": 3599,
    "token_type": "Bearer"
}

@app.route('/computeMetadata/v1/')
@app.route('/computeMetadata/v1')
def gcp_metadata_root():
    # Check for required header
    if request.headers.get('Metadata-Flavor') != 'Google':
        return Response("Missing Metadata-Flavor header", status=403)
    return "instance/\nproject/"

@app.route('/computeMetadata/v1/instance/')
def gcp_instance():
    if request.headers.get('Metadata-Flavor') != 'Google':
        return Response("Missing Metadata-Flavor header", status=403)
    return """attributes/
cpu-platform
description
disks/
guest-attributes/
hostname
id
image
machine-type
name
network-interfaces/
scheduling/
service-accounts/
tags
zone"""

@app.route('/computeMetadata/v1/instance/service-accounts/')
def gcp_service_accounts():
    if request.headers.get('Metadata-Flavor') != 'Google':
        return Response("Missing Metadata-Flavor header", status=403)
    return "default/\nprod-compute@my-project-123456.iam.gserviceaccount.com/"

@app.route('/computeMetadata/v1/instance/service-accounts/default/')
def gcp_default_sa():
    if request.headers.get('Metadata-Flavor') != 'Google':
        return Response("Missing Metadata-Flavor header", status=403)
    return jsonify(GCP_SERVICE_ACCOUNT)

@app.route('/computeMetadata/v1/instance/service-accounts/default/token')
def gcp_access_token():
    if request.headers.get('Metadata-Flavor') != 'Google':
        return Response("Missing Metadata-Flavor header", status=403)
    return jsonify(GCP_ACCESS_TOKEN)

@app.route('/computeMetadata/v1/instance/attributes/')
def gcp_attributes():
    if request.headers.get('Metadata-Flavor') != 'Google':
        return Response("Missing Metadata-Flavor header", status=403)
    return "startup-script\nssh-keys\nkube-env"

@app.route('/computeMetadata/v1/instance/attributes/kube-env')
def gcp_kube_env():
    if request.headers.get('Metadata-Flavor') != 'Google':
        return Response("Missing Metadata-Flavor header", status=403)
    # Kubernetes secrets often leaked here
    return """KUBERNETES_MASTER_NAME: k8s-master.internal
CA_CERT: -----BEGIN CERTIFICATE-----
MIIC5zCCAc+gAwIBAgIJALxxxxxxxxxx
-----END CERTIFICATE-----
KUBELET_CERT: -----BEGIN CERTIFICATE-----
MIIDDzCCAfegAwIBAgIJALyyyyyyyyyy
-----END CERTIFICATE-----
KUBELET_KEY: -----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
-----END RSA PRIVATE KEY-----
"""

@app.route('/computeMetadata/v1/project/')
def gcp_project():
    if request.headers.get('Metadata-Flavor') != 'Google':
        return Response("Missing Metadata-Flavor header", status=403)
    return "attributes/\nnumeric-project-id\nproject-id"

@app.route('/computeMetadata/v1/project/project-id')
def gcp_project_id():
    if request.headers.get('Metadata-Flavor') != 'Google':
        return Response("Missing Metadata-Flavor header", status=403)
    return "my-project-123456"

# ============================================
# Azure IMDS (169.254.169.254)
# ============================================

AZURE_INSTANCE = {
    "compute": {
        "azEnvironment": "AzurePublicCloud",
        "location": "eastus",
        "name": "prod-vm-01",
        "resourceGroupName": "production-rg",
        "resourceId": "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/production-rg/providers/Microsoft.Compute/virtualMachines/prod-vm-01",
        "subscriptionId": "12345678-1234-1234-1234-123456789abc",
        "vmId": "abcd1234-ab12-cd34-ef56-abcdef123456",
        "vmSize": "Standard_D4s_v3"
    },
    "network": {
        "interface": [{
            "ipv4": {
                "ipAddress": [{"privateIpAddress": "10.0.0.4", "publicIpAddress": "52.123.45.67"}]
            }
        }]
    }
}

AZURE_ACCESS_TOKEN = {
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ixxxxxxxxxxxxxxxxxxxxxxxxx.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMTIzNDU2NzgtMTIzNC0xMjM0LTEyMzQtMTIzNDU2Nzg5YWJjLyIsImlhdCI6MTYwMDAwMDAwMCwibmJmIjoxNjAwMDAwMDAwLCJleHAiOjE2MDAwODY0MDAsImFpbyI6IkUyWmdZREE9IiwiYXBwaWQiOiIxMjM0NTY3OC0xMjM0LTEyMzQtMTIzNC0xMjM0NTY3ODlhYmMiLCJhcHBpZGFjciI6IjEiLCJpZHAiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8xMjM0NTY3OC0xMjM0LTEyMzQtMTIzNC0xMjM0NTY3ODlhYmMvIiwib2lkIjoiMTIzNDU2NzgtMTIzNC0xMjM0LTEyMzQtMTIzNDU2Nzg5YWJjIiwic3ViIjoiMTIzNDU2NzgtMTIzNC0xMjM0LTEyMzQtMTIzNDU2Nzg5YWJjIiwidGlkIjoiMTIzNDU2NzgtMTIzNC0xMjM0LTEyMzQtMTIzNDU2Nzg5YWJjIiwidXRpIjoiYWJjZGVmZ2hpamtsbW5vcHFyc3QiLCJ2ZXIiOiIxLjAifQ.SIGNATURE_HERE",
    "client_id": "12345678-1234-1234-1234-123456789abc",
    "expires_in": "86400",
    "expires_on": "1600086400",
    "ext_expires_in": "86400",
    "not_before": "1600000000",
    "resource": "https://management.azure.com/",
    "token_type": "Bearer"
}

@app.route('/metadata/instance')
def azure_instance():
    if request.headers.get('Metadata') != 'true':
        return Response("Bad Request. Required metadata header not specified.", status=400)
    return jsonify(AZURE_INSTANCE)

@app.route('/metadata/identity/oauth2/token')
def azure_token():
    if request.headers.get('Metadata') != 'true':
        return Response("Bad Request. Required metadata header not specified.", status=400)
    return jsonify(AZURE_ACCESS_TOKEN)

# ============================================
# Kubernetes API (commonly exposed)
# ============================================

@app.route('/api/v1/namespaces')
def k8s_namespaces():
    return jsonify({
        "apiVersion": "v1",
        "items": [
            {"metadata": {"name": "default"}},
            {"metadata": {"name": "kube-system"}},
            {"metadata": {"name": "production"}},
            {"metadata": {"name": "staging"}}
        ],
        "kind": "NamespaceList"
    })

@app.route('/api/v1/secrets')
def k8s_secrets():
    return jsonify({
        "apiVersion": "v1",
        "items": [
            {
                "metadata": {"name": "db-credentials", "namespace": "production"},
                "data": {
                    "username": "YWRtaW4=",  # base64: admin
                    "password": "UHJvZFBhc3N3b3JkMTIzIQ=="  # base64: ProdPassword123!
                }
            },
            {
                "metadata": {"name": "api-keys", "namespace": "production"},
                "data": {
                    "stripe-key": "c2tfbGl2ZV94eHh4eHh4eHh4eHh4eHh4",
                    "sendgrid-key": "U0cuYWJjZGVmZ2hpamtsbW5vcA=="
                }
            }
        ],
        "kind": "SecretList"
    })

@app.route('/api/v1/configmaps')
def k8s_configmaps():
    return jsonify({
        "apiVersion": "v1",
        "items": [
            {
                "metadata": {"name": "app-config", "namespace": "production"},
                "data": {
                    "DATABASE_URL": "postgresql://admin:ProdPassword123!@db.internal:5432/prod",
                    "REDIS_URL": "redis://:redis_secret@redis.internal:6379",
                    "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"
                }
            }
        ],
        "kind": "ConfigMapList"
    })

# ============================================
# Health check
# ============================================

@app.route('/')
def index():
    return """<h1>Cloud Metadata Simulation</h1>
<p>Simulated cloud metadata endpoints for penetration testing training.</p>
<h2>AWS (169.254.169.254)</h2>
<ul>
    <li><a href="/latest/meta-data/">/latest/meta-data/</a></li>
    <li><a href="/latest/meta-data/iam/security-credentials/">/latest/meta-data/iam/security-credentials/</a></li>
    <li><a href="/latest/user-data">/latest/user-data</a></li>
</ul>
<h2>GCP (metadata.google.internal)</h2>
<ul>
    <li><a href="/computeMetadata/v1/">/computeMetadata/v1/</a> (requires Metadata-Flavor: Google header)</li>
</ul>
<h2>Azure (169.254.169.254)</h2>
<ul>
    <li><a href="/metadata/instance">/metadata/instance</a> (requires Metadata: true header)</li>
</ul>
<h2>Kubernetes</h2>
<ul>
    <li><a href="/api/v1/secrets">/api/v1/secrets</a></li>
    <li><a href="/api/v1/configmaps">/api/v1/configmaps</a></li>
</ul>
"""

if __name__ == '__main__':
    print("Cloud Metadata Simulation running on port 80")
    print("Endpoints: AWS, GCP, Azure, Kubernetes")
    app.run(host='0.0.0.0', port=80)
PYTHON

EXPOSE 80

CMD ["python", "/app/metadata.py"]
