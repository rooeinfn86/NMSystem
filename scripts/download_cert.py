import os
import requests

def download_certificate():
    # Create certs directory if it doesn't exist
    os.makedirs('certs', exist_ok=True)
    
    # Download the certificate
    url = 'https://storage.googleapis.com/cloud-sql-connectors/cloud-sql-proxy/v2/server-ca.pem'
    response = requests.get(url)
    
    if response.status_code == 200:
        # Save the certificate
        with open('certs/server-ca.pem', 'wb') as f:
            f.write(response.content)
        print("✅ Certificate downloaded successfully to certs/server-ca.pem")
    else:
        print(f"❌ Failed to download certificate: {response.status_code}")

if __name__ == '__main__':
    download_certificate() 