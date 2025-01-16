import logging
from .utils import get_arp_table, parse_arp_table, ping_device, get_hostname
from .device_info import DeviceInfo

logger = logging.getLogger(__name__)

class NetworkDiscovery:
    def __init__(self):
        self.devices = []

    def discover(self):
        """Discover devices using ARP and ping."""
        logger.info("Starting network discovery...")
        
        # Retrieve and parse the ARP table
        arp_output = get_arp_table()
        arp_entries = parse_arp_table(arp_output)

        for entry in arp_entries:
            ip = entry["ip"]
            mac = entry["mac"]
            
            if ping_device(ip):
                hostname = get_hostname(ip)
                device = DeviceInfo(ip=ip, mac=mac, hostname=hostname)
                self.devices.append(device)
                logger.info(f"Discovered Device: {device}")

        logger.info("Discovery complete.")
        return self.devices
