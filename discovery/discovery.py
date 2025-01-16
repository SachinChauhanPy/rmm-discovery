import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor
from .utils import arp_scan, get_hostname
from .device_info import DeviceInfo

logger = logging.getLogger(__name__)

class NetworkDiscovery:
    def __init__(self, cidr):
        self.cidr = ipaddress.ip_network(cidr, strict=False)
        self.devices = []

    def discover(self, max_threads=50):
        """Discover devices within the network."""
        logger.info(f"Starting discovery for network: {self.cidr}")

        def scan_ip(ip):
            """Scan a single IP address."""
            logger.debug(f"Scanning IP: {ip}")
            arp_result = arp_scan(str(ip))
            if arp_result:
                hostname = get_hostname(arp_result["ip"]) or "Unknown"
                device = DeviceInfo(ip=arp_result["ip"], mac=arp_result["mac"], hostname=hostname)
                logger.info(f"Discovered Device: {device}")
                self.devices.append(device)
            else:
                logger.debug(f"No response from IP: {ip}")

        with ThreadPoolExecutor(max_threads) as executor:
            executor.map(scan_ip, self.cidr.hosts())

        logger.info("Discovery complete.")
        return self.devices
