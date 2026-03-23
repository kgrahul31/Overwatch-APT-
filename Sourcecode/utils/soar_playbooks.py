import subprocess
import logging

logging.basicConfig(level=logging.INFO)

def auto_block_ip(ip_address: str):
    """
    SOAR Autopilot Action:
    Automatically adds a Windows Firewall rule to block an attacking IP.
    """
    try:
        rule_name = f"OW-APT_AutoBlock_{ip_address.replace('.', '_')}"
        # Check if rule already exists
        check_cmd = f'netsh advfirewall firewall show rule name="{rule_name}"'
        check_res = subprocess.run(check_cmd, shell=True, capture_output=True)
        
        if check_res.returncode == 0:
            return True, f"IP {ip_address} is already blocked."
            
        cmd = (
            f'netsh advfirewall firewall add rule name="{rule_name}" '
            f'dir=in action=block remoteip="{ip_address}"'
        )
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            logging.info(f"Auto-blocked IP {ip_address}")
            return True, f"Automatically blocked attacking IP: {ip_address}"
        else:
            return False, f"Failed to block IP {ip_address}: {result.stderr}"
    except Exception as e:
        return False, f"Error blocking IP: {str(e)}"

def auto_disable_user(username: str):
    """
    SOAR Autopilot Action:
    Automatically disables a compromised local user account.
    """
    try:
        # Prevent disabling Administrator by accident during testing
        if username.lower() == "administrator":
            return False, "Safety Catch: Cannot auto-disable the built-in Administrator account."
            
        cmd = f'net user {username} /active:no'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            logging.info(f"Auto-disabled account: {username}")
            return True, f"Automatically disabled compromised account: {username}"
        else:
            return False, f"Failed to disable account {username}: {result.stderr}"
    except Exception as e:
        return False, f"Error disabling account: {str(e)}"
