#!/usr/bin/env python3
"""
Script to clean sensitive data from configuration files
Run this script to sanitize any remaining sensitive information
"""

import json
import re
import os

def clean_config_history():
    """Clean sensitive data from config_history.json"""
    config_file = "data/config_history.json"
    
    if not os.path.exists(config_file):
        print(f"❌ File {config_file} not found")
        return
    
    try:
        with open(config_file, 'r') as f:
            data = json.load(f)
        
        # Clean usernames that look like passwords
        cleaned_data = []
        for entry in data:
            if isinstance(entry, dict):
                # Replace suspicious usernames
                if 'username' in entry:
                    username = entry['username']
                    if any(sensitive in username.lower() for sensitive in ['admin123', 'password', 'secret']):
                        entry['username'] = 'admin'
                
                cleaned_data.append(entry)
            else:
                cleaned_data.append(entry)
        
        # Write back the cleaned data
        with open(config_file, 'w') as f:
            json.dump(cleaned_data, f, indent=2)
        
        print(f"✅ Cleaned sensitive data from {config_file}")
        
    except Exception as e:
        print(f"❌ Error cleaning {config_file}: {e}")

def clean_docker_files():
    """Clean sensitive data from Docker files"""
    files_to_clean = [
        "docker-compose.yml",
        "docker-compose.dev.yml"
    ]
    
    for filename in files_to_clean:
        if os.path.exists(filename):
            try:
                with open(filename, 'r') as f:
                    content = f.read()
                
                # Replace hardcoded passwords
                content = re.sub(r'admin123', 'YOUR_PASSWORD_HERE', content)
                content = re.sub(r'your-secret-key-here', 'YOUR_SECRET_KEY_HERE', content)
                
                with open(filename, 'w') as f:
                    f.write(content)
                
                print(f"✅ Cleaned {filename}")
                
            except Exception as e:
                print(f"❌ Error cleaning {filename}: {e}")

def main():
    """Main function to clean all sensitive data"""
    print("🧹 Cleaning sensitive data from configuration files...")
    
    clean_config_history()
    clean_docker_files()
    
    print("\n🎉 Sensitive data cleanup completed!")
    print("\n⚠️  Remember to:")
    print("   1. Set real credentials via Google Cloud Secret Manager")
    print("   2. Use environment variables for local development")
    print("   3. Never commit real secrets to version control")

if __name__ == "__main__":
    main() 