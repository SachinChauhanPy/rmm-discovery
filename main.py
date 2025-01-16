import logging
from discovery.discovery import NetworkDiscovery

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def main():
    cidr_range = input("Enter CIDR range (e.g., 192.168.1.0/24): ")
    discovery = NetworkDiscovery(cidr_range)

    logger.info("Starting network discovery...")
    devices = discovery.discover()

    print("\nDiscovered Devices:")
    for device in devices:
        print(f"IP: {device.ip}, MAC: {device.mac}, Hostname: {device.hostname}")

if __name__ == "__main__":
    main()
