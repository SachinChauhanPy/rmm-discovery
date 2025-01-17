import asyncio
import ipaddress
import platform
import subprocess
import logging
import csv
import socket
import uuid
from typing import List, Tuple, Dict

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class NetworkScanner:
    @staticmethod
    async def ping(ip: str) -> bool:
        """Ping an IP address to check if it's active."""
        system = platform.system().lower()
        cmd = ["ping", "-n", "1", "-w", "1000", ip] if system == "windows" else ["ping", "-c", "1", "-W", "1", ip]

        try:
            result = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, _ = await result.communicate()
            return result.returncode == 0
        except Exception as e:
            logging.error(f"Error pinging {ip}: {e}")
            return False

    @staticmethod
    async def resolve_hostname(ip: str) -> str:
        """Resolve the hostname for an IP address with special handling for the probe machine."""
        try:
            # Get all local IPs for the probe machine
            local_ips = [addr[4][0] for addr in socket.getaddrinfo(socket.gethostname(), None)]
            
            # Check if the IP matches the probe machine's IP
            if ip in local_ips:
                return socket.gethostname()  # Return the probe machine's hostname

            # Attempt DNS-based reverse lookup for other IPs
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except socket.herror:
            logging.warning(f"Reverse DNS lookup failed for {ip}.")
            return "Unknown"
        except Exception as e:
            logging.error(f"Error resolving hostname for {ip}: {e}")
            return "Unknown"

    @staticmethod
    def get_mac_address(ip: str) -> str:
        """Get the MAC address of a device, including the probe machine."""
        try:
            # Check if the IP belongs to the probe machine
            local_ips = [addr[4][0] for addr in socket.getaddrinfo(socket.gethostname(), None)]
            if ip in local_ips:
                # Retrieve the MAC address of the local machine
                mac = uuid.getnode()
                mac_address = ':'.join(f'{(mac >> i) & 0xff:02x}' for i in range(40, -1, -8))
                return mac_address

            # Use ARP for other IPs
            cmd = ["arp", "-a", ip] if platform.system().lower() == "windows" else ["arp", "-n", ip]
            result = subprocess.run(cmd, capture_output=True, text=True)

            for line in result.stdout.splitlines():
                if ip in line:
                    parts = line.split()
                    for part in parts:
                        if ":" in part or "-" in part:
                            return part
            return "N/A"
        except Exception as e:
            logging.error(f"Error getting MAC address for {ip}: {e}")
            return "N/A"

    @staticmethod
    def detect_os_ttl(ttl: int) -> str:
        """Detect the operating system based on TTL values."""
        if 64 <= ttl <= 128:
            return "Linux/Unix" if ttl <= 64 else "Windows"
        return "Unknown"

    @staticmethod
    async def extended_ping(ip: str) -> Tuple[bool, int]:
        """Extended ping to return both status and TTL value."""
        system = platform.system().lower()
        cmd = ["ping", "-n", "1", "-w", "1000", ip] if system == "windows" else ["ping", "-c", "1", "-W", "1", ip]

        try:
            result = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, _ = await result.communicate()
            if result.returncode == 0:
                for line in stdout.decode().splitlines():
                    if "TTL=" in line:
                        ttl_value = int(line.split("TTL=")[-1].strip())
                        return True, ttl_value
            return False, 0
        except Exception as e:
            logging.error(f"Error pinging {ip}: {e}")
            return False, 0

    @staticmethod
    def validate_cidr(cidr: str) -> List[str]:
        """Validate and expand a CIDR range into individual IP addresses."""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError as e:
            logging.error(f"Invalid CIDR range {cidr}: {e}")
            return []

    async def scan_ip(self, ip: str) -> Dict[str, str]:
        """Scan a single IP address for details."""
        active, ttl = await self.extended_ping(ip)
        if not active:
            return {}

        hostname = await self.resolve_hostname(ip)
        mac_address = self.get_mac_address(ip)
        os_type = self.detect_os_ttl(ttl)

        return {
            "IP Address": ip,
            "Hostname": hostname,
            "MAC Address": mac_address,
            "OS Type": os_type,
            "Device Type": "N/A",  # Placeholder for future SNMP implementation
        }

    async def scan_network(self, cidr: str) -> List[Dict[str, str]]:
        """Scan a network range specified by a CIDR."""
        ips = self.validate_cidr(cidr)
        if not ips:
            logging.error("No IPs to scan.")
            return []

        logging.info(f"Scanning {len(ips)} IP addresses in network {cidr}.")

        results = []
        tasks = [self.scan_ip(ip) for ip in ips]

        for result in asyncio.as_completed(tasks):
            data = await result
            if data:
                results.append(data)

        return results

    @staticmethod
    def save_results_to_csv(results: List[Dict[str, str]], filename: str):
        """Save the scan results to a CSV file."""
        try:
            with open(filename, mode='w', newline='', encoding='utf-8') as file:
                writer = csv.DictWriter(file, fieldnames=["IP Address", "Hostname", "MAC Address", "OS Type", "Device Type"])
                writer.writeheader()
                writer.writerows(results)
            logging.info(f"Results saved to {filename}.")
        except Exception as e:
            logging.error(f"Error saving results to CSV: {e}")


def main():
    """Main function to execute the network discovery."""
    cidr = input("Enter the CIDR range to scan (e.g., 192.168.1.0/24): ").strip()
    
    # Set the event loop policy for Windows
    if platform.system().lower() == "windows":
            asyncio.set_event_loop_policy(
                asyncio.WindowsProactorEventLoopPolicy())
    
    scanner = NetworkScanner()

    # Run the scan
    results = asyncio.run(scanner.scan_network(cidr))

    # Output results
    if results:
        logging.info("Scan complete. Results:")
        for device in results:
            logging.info(device)

        # Save to CSV
        scanner.save_results_to_csv(results, "network_scan_results.csv")
    else:
        logging.info("No active devices found.")


if __name__ == "__main__":
    main()
