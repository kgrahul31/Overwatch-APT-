import subprocess
import psutil
import logging

logging.basicConfig(level=logging.INFO)

def kill_process(pid: int) -> bool:
    """Terminates a process given its PID immediately."""
    try:
        p = psutil.Process(pid)
        name = p.name()
        p.terminate()
        p.wait(timeout=3)
        logging.info(f"Successfully killed process {name} (PID: {pid})")
        return True, f"Successfully terminated {name} (PID: {pid})"
    except psutil.NoSuchProcess:
        return False, f"Process {pid} no longer exists."
    except psutil.AccessDenied:
        return False, f"Access denied. Try running Overwatch-APT as Administrator."
    except Exception as e:
        return False, f"Error killing {pid}: {str(e)}"

def isolate_host() -> bool:
    """
    Blocks all inbound network connections using Windows Firewall.
    This effectively quarantines the host from lateral movement.
    """
    try:
        cmd = "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            logging.info("Host isolated successfully.")
            return True, "Host isolated successfully. All inbound connections blocked."
        else:
            return False, f"Failed to isolate host: {result.stderr}"
    except Exception as e:
        return False, f"Error isolating host: {str(e)}"

def restore_host() -> bool:
    """Restores Windows Firewall to default inbound behavior (block inbound unless allowed)."""
    try:
        cmd = "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return True, "Host network restored."
    except Exception as e:
        return False, f"Error restoring host: {str(e)}"
