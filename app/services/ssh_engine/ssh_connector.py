from netmiko import ConnectHandler
import paramiko
import time
import subprocess
import platform
import logging
from app.utils.sanitizer import validate_device_credentials, validate_command, validate_config

logger = logging.getLogger(__name__)


def send_config_to_device(ip: str, username: str, password: str, config: str):
    try:
        # Validate all inputs before proceeding
        is_valid, error_msg = validate_device_credentials(ip, username, password)
        if not is_valid:
            logger.error(f"Device credentials validation failed: {error_msg}")
            return False, f"Validation failed: {error_msg}"
        
        # Validate configuration
        is_valid, error_msg = validate_config(config)
        if not is_valid:
            logger.error(f"Configuration validation failed: {error_msg}")
            return False, f"Configuration validation failed: {error_msg}"
        
        # Log the operation for security monitoring
        logger.info(f"Applying configuration to device {ip} with user {username}")
        
        # Config will be applied via SSH
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, look_for_keys=False)

        shell = ssh.invoke_shell()
        shell.send("enable\n")
        time.sleep(1)
        shell.send("configure terminal\n")
        time.sleep(1)

        for cmd in config.strip().split('\n'):
            shell.send(cmd.strip() + '\n')
            time.sleep(0.5)

        shell.send("end\n")
        shell.send("write memory\n")
        time.sleep(1)

        shell.close()
        ssh.close()

        logger.info(f"Configuration applied successfully to {ip}")
        return True, "Configuration applied successfully"
    except Exception as e:
        logger.error(f"Failed to apply configuration to {ip}: {str(e)}")
        return False, str(e)


def run_show_command(ip: str, username: str, password: str, command: str):
    try:
        # Validate all inputs before proceeding
        is_valid, error_msg = validate_device_credentials(ip, username, password)
        if not is_valid:
            logger.error(f"Device credentials validation failed: {error_msg}")
            return f"❌ Validation failed: {error_msg}"
        
        # Validate command
        is_valid, error_msg = validate_command(command)
        if not is_valid:
            logger.error(f"Command validation failed: {error_msg}")
            return f"❌ Command validation failed: {error_msg}"
        
        # Log the operation for security monitoring
        logger.info(f"Running show command on device {ip} with user {username}: {command}")
        
        device = {
            'device_type': 'cisco_ios',
            'host': ip,
            'username': username,
            'password': password,
            'secret': password,
            'fast_cli': False,
        }

        net_connect = ConnectHandler(**device)
        net_connect.set_base_prompt()
        net_connect.enable()

        output = net_connect.send_command(
            command,
            expect_string=r"#",
            delay_factor=2,
            read_timeout=20
        )

        net_connect.disconnect()
        logger.info(f"Show command executed successfully on {ip}")
        return output
    except Exception as e:
        logger.error(f"Failed to run show command on {ip}: {str(e)}")
        return f"❌ Error running show command: {str(e)}"


def is_ssh_reachable(ip: str, username: str, password: str, timeout: int = 5) -> bool:
    """
    Check if a device is reachable over SSH.
    Returns True if successful, False otherwise.
    """
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=ip,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            timeout=timeout,
        )
        client.close()
        return True
    except Exception as e:
        logger.debug(f"Device {ip} unreachable: {e}")
        return False


def ping_device(ip: str, count: int = 1, timeout: int = 1) -> bool:
    """
    Perform a simple ping to the given IP address.
    Works cross-platform (Windows/Linux/macOS).
    """
    try:
        system = platform.system().lower()
        if "windows" in system:
            command = ["ping", "-n", str(count), "-w", str(timeout * 1000), ip]
        else:
            command = ["ping", "-c", str(count), "-W", str(timeout), ip]

        logger.debug(f"Pinging {ip} - OS: {system}, Command: {' '.join(command)}")

        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.debug(f"Ping result for {ip}: return code {result.returncode}")

        return result.returncode == 0
    except Exception as e:
        logger.debug(f"Failed to ping {ip}: {e}")
        return False



def check_device_status(ip: str, username: str, password: str) -> dict:
    """
    Returns a dictionary with both ping and ssh results.
    """
    ping_result = ping_device(ip)
    ssh_result = is_ssh_reachable(ip, username, password) if ping_result else False

    status = "up" if ping_result and ssh_result else "partial" if ping_result else "down"

    return {
        "ping": ping_result,
        "ssh": ssh_result,
        "status": status
    }


def get_hostname(ip: str, username: str, password: str) -> str:
    try:
        device = {
            'device_type': 'cisco_ios',
            'host': ip,
            'username': username,
            'password': password,
            'secret': password,
        }

        net_connect = ConnectHandler(**device)
        net_connect.enable()
        hostname = net_connect.find_prompt().strip()
        net_connect.disconnect()
        return hostname
    except Exception as e:
        logger.debug(f"Failed to get hostname for {ip}: {e}")
        return "device"
