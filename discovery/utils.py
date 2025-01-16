import subprocess
import socket
import platform
import logging

logger = logging.getLogger(__name__)

def get_arp_table():
    """Retrieve the ARP table using platform-specific commands."""
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output("arp -a", shell=True, text=True)
        else:
            output = subprocess.check_output(["arp", "-n"], text=True)
        
        logger.debug(f"ARP Table:\n{output}")
        return output
    except Exception as e:
        logger.error(f"Error retrieving ARP table: {e}")
        return ""

def parse_arp_table(arp_output):
    """Parse the ARP table output to extract IP and MAC addresses."""
    devices = []
    lines = arp_output.splitlines()
    for line in lines:
        parts = line.split()
        if len(parts) >= 2:
            ip = parts[0]
            mac = parts[1] if ":" in parts[1] or "-" in parts[1] else None
            if mac:
                devices.append({"ip": ip, "mac": mac})
    return devices

def ping_device(ip):
    """Ping a device to check if it is active."""
    try:
        if platform.system() == "Windows":
            result = subprocess.run(["ping", "-n", "1", ip], stdout=subprocess.PIPE, text=True)
        else:
            result = subprocess.run(["ping", "-c", "1", ip], stdout=subprocess.PIPE, text=True)
        
        if result.returncode == 0:
            logger.debug(f"Device {ip} is reachable.")
            return True
        else:
            logger.debug(f"Device {ip} is not reachable.")
            return False
    except Exception as e:
        logger.error(f"Error pinging {ip}: {e}")
        return False

def get_hostname(ip):
    """Retrieve the hostname using reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"
