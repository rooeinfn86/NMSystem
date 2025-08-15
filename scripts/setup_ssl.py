import os
import requests
from google.cloud import secretmanager

def setup_ssl():
    """Setup SSL certificate for database connection"""
    # Create certs directory if it doesn't exist
    os.makedirs('certs', exist_ok=True)
    
    # Download server CA certificate
    ca_cert_url = 'https://storage.googleapis.com/cloud-sql-connectors/cloud-sql-proxy/v2/server-ca.pem'
    response = requests.get(ca_cert_url)
    
    if response.status_code == 200:
        # Save the certificate locally
        cert_path = 'certs/server-ca.pem'
        with open(cert_path, 'wb') as f:
            f.write(response.content)
        print(f"✅ Server CA certificate downloaded to {cert_path}")
        
        try:
            # Store certificate in Secret Manager
            client = secretmanager.SecretManagerServiceClient()
            parent = f"projects/{os.getenv('PROJECT_ID')}"
            
            # Create secret
            secret = client.create_secret(
                request={
                    "parent": parent,
                    "secret_id": "database-ca-cert",
                    "secret": {"replication": {"automatic": {}}},
                }
            )
            
            # Add certificate as new version
            with open(cert_path, 'rb') as f:
                payload = f.read()
            
            version = client.add_secret_version(
                request={
                    "parent": secret.name,
                    "payload": {"data": payload},
                }
            )
            print("✅ Server CA certificate stored in Secret Manager")
            
        except Exception as e:
            print(f"⚠️ Failed to store certificate in Secret Manager: {e}")
            print("✅ Certificate is still available locally")
    else:
        print(f"❌ Failed to download certificate: {response.status_code}")

if __name__ == '__main__':
    setup_ssl() 