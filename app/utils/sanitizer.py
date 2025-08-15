
import re
import ipaddress
from typing import Optional, List, Tuple
import logging

logger = logging.getLogger(__name__)

def clean_cli_output(raw_text: str) -> str:
    """Clean CLI output by removing prompts and formatting."""
    lines = raw_text.strip().splitlines()
    cleaned_lines = []

    # Regex to match and strip CLI prompt like "Switch(config)#"
    prompt_pattern = re.compile(r'^.*?#\s*')

    for line in lines:
        line = line.strip()

        # Skip markdown, empty lines, or natural language
        if not line or line.startswith("```"):
            continue
        if any(phrase in line.lower() for phrase in [
            "here is", "to configure", "use the following", "you can", "sure", "this is", "below is"
        ]):
            continue

        cleaned_line = prompt_pattern.sub('', line)
        if cleaned_line:
            cleaned_lines.append(cleaned_line)

    return "\n".join(cleaned_lines)

def validate_ip_address(ip: str) -> Tuple[bool, str]:
    """
    Validate IP address format and check for private/public ranges.
    Returns (is_valid, error_message)
    """
    try:
        # Parse the IP address
        ip_obj = ipaddress.ip_address(ip)
        
        # Check for invalid IP ranges
        if ip_obj.is_loopback:
            return False, "Loopback addresses are not allowed"
        if ip_obj.is_multicast:
            return False, "Multicast addresses are not allowed"
        if ip_obj.is_link_local:
            return False, "Link-local addresses are not allowed"
        if ip_obj.is_unspecified:
            return False, "Unspecified addresses are not allowed"
        
        # Allow private networks (RFC 1918)
        if ip_obj.is_private:
            return True, ""
        
        # Allow public IPs but log for monitoring
        logger.info(f"Public IP address used: {ip}")
        return True, ""
        
    except ValueError:
        return False, "Invalid IP address format"

def validate_username(username: str) -> Tuple[bool, str]:
    """
    Validate username format and content.
    Returns (is_valid, error_message)
    """
    if not username:
        return False, "Username cannot be empty"
    
    if len(username) > 50:
        return False, "Username too long (max 50 characters)"
    
    # Check for dangerous characters that could be used in command injection
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '{', '}', '[', ']', '<', '>', '"', "'"]
    for char in dangerous_chars:
        if char in username:
            return False, f"Username contains invalid character: {char}"
    
    # Check for common attack patterns
    attack_patterns = [
        r'\.\./',  # Directory traversal
        r'\.\.\\',  # Windows directory traversal
        r'javascript:',  # XSS
        r'data:',  # Data URI
        r'vbscript:',  # VBScript
    ]
    
    for pattern in attack_patterns:
        if re.search(pattern, username, re.IGNORECASE):
            return False, f"Username contains suspicious pattern: {pattern}"
    
    return True, ""

def validate_password(password: str) -> Tuple[bool, str]:
    """
    Validate password format and content.
    Returns (is_valid, error_message)
    """
    if not password:
        return False, "Password cannot be empty"
    
    if len(password) > 100:
        return False, "Password too long (max 100 characters)"
    
    # Check for dangerous characters
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '{', '}', '[', ']', '<', '>', '"', "'"]
    for char in dangerous_chars:
        if char in password:
            return False, f"Password contains invalid character: {char}"
    
    return True, ""

def validate_command(command: str) -> Tuple[bool, str]:
    """
    Validate command format and check for dangerous commands.
    Returns (is_valid, error_message)
    """
    if not command:
        return False, "Command cannot be empty"
    
    if len(command) > 500:
        return False, "Command too long (max 500 characters)"
    
    # Check for dangerous characters
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '{', '}', '[', ']', '<', '>', '"', "'"]
    for char in dangerous_chars:
        if char in command:
            return False, f"Command contains invalid character: {char}"
    
    # Check for dangerous command patterns
    dangerous_patterns = [
        r'\brm\s+-rf\b',  # Remove recursively
        r'\bdel\b',  # Delete
        r'\bformat\b',  # Format
        r'\bdd\b',  # Disk dump
        r'\b>.*\b',  # Output redirection
        r'\b<.*\b',  # Input redirection
        r'\b\|\s*sh\b',  # Pipe to shell
        r'\b\|\s*bash\b',  # Pipe to bash
        r'\b\|\s*cmd\b',  # Pipe to cmd
        r'\b\|\s*powershell\b',  # Pipe to PowerShell
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, command, re.IGNORECASE):
            return False, f"Command contains dangerous pattern: {pattern}"
    
    return True, ""

def validate_config(config: str) -> Tuple[bool, str]:
    """
    Validate configuration commands.
    Returns (is_valid, error_message)
    """
    if not config:
        return False, "Configuration cannot be empty"
    
    if len(config) > 2000:
        return False, "Configuration too long (max 2000 characters)"
    
    # Check for dangerous characters
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '{', '}', '[', ']', '<', '>', '"', "'"]
    for char in dangerous_chars:
        if char in config:
            return False, f"Configuration contains invalid character: {char}"
    
    # Check for dangerous configuration patterns
    dangerous_patterns = [
        r'\bno\s+service\s+password-encryption\b',  # Disable password encryption
        r'\bno\s+enable\s+secret\b',  # Remove enable secret
        r'\bno\s+username\b',  # Remove users
        r'\bno\s+access-list\b',  # Remove access lists
        r'\bno\s+ip\s+access-list\b',  # Remove IP access lists
        r'\bno\s+line\s+console\b',  # Remove console access
        r'\bno\s+line\s+vty\b',  # Remove SSH/Telnet access
        r'\bno\s+ip\s+http\b',  # Disable HTTP
        r'\bno\s+ip\s+https\b',  # Disable HTTPS
        r'\bno\s+snmp-server\b',  # Remove SNMP
        r'\bno\s+ntp\b',  # Remove NTP
        r'\bno\s+logging\b',  # Remove logging
        r'\bno\s+clock\b',  # Remove clock settings
        r'\bno\s+hostname\b',  # Remove hostname
        r'\bno\s+domain-name\b',  # Remove domain name
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, config, re.IGNORECASE):
            return False, f"Configuration contains dangerous pattern: {pattern}"
    
    return True, ""

def sanitize_input(input_str: str, max_length: int = 1000) -> str:
    """
    Sanitize input string by removing dangerous characters and limiting length.
    """
    if not input_str:
        return ""
    
    # Remove null bytes and control characters
    sanitized = ''.join(char for char in input_str if ord(char) >= 32)
    
    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized.strip()

def validate_device_credentials(ip: str, username: str, password: str) -> Tuple[bool, str]:
    """
    Validate all device credentials at once.
    Returns (is_valid, error_message)
    """
    # Validate IP
    ip_valid, ip_error = validate_ip_address(ip)
    if not ip_valid:
        return False, f"IP validation failed: {ip_error}"
    
    # Validate username
    username_valid, username_error = validate_username(username)
    if not username_valid:
        return False, f"Username validation failed: {username_error}"
    
    # Validate password
    password_valid, password_error = validate_password(password)
    if not password_valid:
        return False, f"Password validation failed: {password_error}"
    
    return True, ""
